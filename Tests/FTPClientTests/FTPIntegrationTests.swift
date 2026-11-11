#if os(macOS)
import Darwin
import Foundation
import Testing
import FTPClient
import FTPClientCore
import FTPClientFacade
@testable import FTPClientSync

private final class ProgressRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [UInt64] = []
    func record(_ value: UInt64) { lock.lock(); defer { lock.unlock() }; recorded.append(value) }
    var values: [UInt64] { lock.lock(); defer { lock.unlock() }; return recorded }
}

private final class RetryRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [(Int, FTPError, Data?)] = []
    func record(_ attempt: Int, _ error: FTPError, _ data: Data?) {
        lock.lock(); defer { lock.unlock() }; recorded.append((attempt, error, data))
    }
    var values: [(Int, FTPError, Data?)] { lock.lock(); defer { lock.unlock() }; return recorded }
}

private actor DownloadCollector {
    private(set) var data = Data()
    func append(_ chunk: Data) { data.append(chunk) }
}

private final class SyncPathSwap: @unchecked Sendable {
    private let lock = NSLock()
    private var swapped = false
    private(set) var error: String?
    func perform(original: URL, moved: URL, replacement: URL) {
        lock.lock()
        defer { lock.unlock() }
        guard !swapped else { return }
        swapped = true
        do {
            try FileManager.default.moveItem(at: original, to: moved)
            try FileManager.default.createSymbolicLink(at: original, withDestinationURL: replacement)
        } catch { self.error = String(describing: error) }
    }
    func result() -> String? { lock.lock(); defer { lock.unlock() }; return error }
}

/// Minimal loopback-only FTP server used to exercise actual control/data sockets.
private final class LoopbackFTPServer: @unchecked Sendable {
    private let listener: Int32
    let port: Int
    private let suppressGreeting: Bool
    private let supportsEPSV: Bool
    private let supportsMLSD: Bool
    private let ipv6: Bool
    private let failTransferCompletion: Bool
    private let stallDownload: Bool
    private let supportsRestart: Bool
    private let ignoresRestart: Bool
    private let supportsEPRT: Bool
    private let refuseActiveConnection: Bool
    private let injectUnexpectedPeer: Bool
    private let failSetModificationTime: Bool
    private let unsupportedMFMT: Bool
    private let xcrcResponse: String?
    private let rejectUTF8Option: Bool
    private let supportsSize: Bool
    private let wildcardListing: String?
    private let connectionLimit: Int
    private let failFirstTransfer: Bool
    private let onActivePreliminary: (@Sendable () -> Void)?
    private let onControlAccepted: (@Sendable () -> Void)?
    private let onRemoteListing: (@Sendable () -> Void)?
    private let payload = Data([0, 10, 13, 255, 65, 66])

    init(suppressGreeting: Bool = false, supportsEPSV: Bool = true, supportsMLSD: Bool = true, ipv6: Bool = false, failTransferCompletion: Bool = false, stallDownload: Bool = false, supportsRestart: Bool = true, ignoresRestart: Bool = false, supportsEPRT: Bool = true, refuseActiveConnection: Bool = false, injectUnexpectedPeer: Bool = false, failSetModificationTime: Bool = false, unsupportedMFMT: Bool = false, xcrcResponse: String? = nil, rejectUTF8Option: Bool = false, supportsSize: Bool = true, wildcardListing: String? = nil, connectionLimit: Int = 1, failFirstTransfer: Bool = false, onActivePreliminary: (@Sendable () -> Void)? = nil, onControlAccepted: (@Sendable () -> Void)? = nil, onRemoteListing: (@Sendable () -> Void)? = nil) throws {
        let (fd, port) = try Self.listen(ipv6: ipv6)
        self.listener = fd
        self.port = port
        self.suppressGreeting = suppressGreeting
        self.supportsEPSV = supportsEPSV
        self.supportsMLSD = supportsMLSD
        self.ipv6 = ipv6
        self.failTransferCompletion = failTransferCompletion
        self.stallDownload = stallDownload
        self.supportsRestart = supportsRestart
        self.ignoresRestart = ignoresRestart
        self.supportsEPRT = supportsEPRT
        self.refuseActiveConnection = refuseActiveConnection
        self.injectUnexpectedPeer = injectUnexpectedPeer
        self.failSetModificationTime = failSetModificationTime
        self.unsupportedMFMT = unsupportedMFMT
        self.xcrcResponse = xcrcResponse
        self.rejectUTF8Option = rejectUTF8Option
        self.supportsSize = supportsSize
        self.wildcardListing = wildcardListing
        self.connectionLimit = connectionLimit
        self.failFirstTransfer = failFirstTransfer
        self.onActivePreliminary = onActivePreliminary
        self.onControlAccepted = onControlAccepted
        self.onRemoteListing = onRemoteListing
        DispatchQueue.global().async { [self] in serve() }
    }

    private static func listen(ipv6: Bool = false) throws -> (Int32, Int) {
        if ipv6 {
            let fd = socket(AF_INET6, SOCK_STREAM, 0)
            guard fd >= 0 else { throw POSIXError(.EIO) }
            var address = sockaddr_in6()
            address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            address.sin6_family = sa_family_t(AF_INET6)
            address.sin6_addr = in6addr_loopback
            let bound = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
            guard bound == 0, Darwin.listen(fd, 1) == 0 else { close(fd); throw POSIXError(.EIO) }
            var length = socklen_t(MemoryLayout<sockaddr_in6>.size)
            let result = withUnsafeMutablePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
            }
            guard result == 0 else { close(fd); throw POSIXError(.EIO) }
            return (fd, Int(UInt16(bigEndian: address.sin6_port)))
        }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.EIO) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr = in_addr(s_addr: in_addr_t(INADDR_LOOPBACK).bigEndian)
        address.sin_port = 0
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0, Darwin.listen(fd, 1) == 0 else {
            close(fd)
            throw POSIXError(.EIO)
        }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let result = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        guard result == 0 else { close(fd); throw POSIXError(.EIO) }
        return (fd, Int(UInt16(bigEndian: address.sin_port)))
    }

    private static func sendAll(_ data: Data, to fd: Int32) {
        data.withUnsafeBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            var sent = 0
            while sent < bytes.count {
                let count = Darwin.send(fd, base.advanced(by: sent), bytes.count - sent, 0)
                if count <= 0 { return }
                sent += count
            }
        }
    }

    private static func reply(_ text: String, to fd: Int32) {
        sendAll(Data(text.utf8), to: fd)
    }

    private func serve() {
        defer { close(listener) }
        for connectionIndex in 0..<connectionLimit {
            let control = accept(listener, nil, nil)
            guard control >= 0 else { return }
            serve(control: control, connectionIndex: connectionIndex)
        }
    }

    private func serve(control: Int32, connectionIndex: Int) {
        onControlAccepted?()
        defer { close(control) }
        var timeout = timeval(tv_sec: 15, tv_usec: 0)
        _ = setsockopt(control, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        if suppressGreeting {
            var byte: UInt8 = 0
            _ = recv(control, &byte, 1, 0)
            return
        }
        Self.reply("220 Test server ready\r\n", to: control)
        var buffer = Data()
        var passive: Int32 = -1
        var active: (host: String, port: Int, ipv6: Bool)?
        var uploaded: Data?
        var files: [String: Data] = [:]
        var directories: Set<String> = ["/remote"]
        var renameFrom: String?
        var restartOffset = 0
        defer { if passive >= 0 { close(passive) } }
        var bytes = [UInt8](repeating: 0, count: 4096)
        func connectActive(_ endpoint: (host: String, port: Int, ipv6: Bool), wrongPeer: Bool = false) -> Int32 {
            let fd = socket(endpoint.ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else { return -1 }
            if endpoint.ipv6 {
                var address = sockaddr_in6()
                address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                address.sin6_family = sa_family_t(AF_INET6)
                address.sin6_port = UInt16(endpoint.port).bigEndian
                guard inet_pton(AF_INET6, endpoint.host, &address.sin6_addr) == 1 else { close(fd); return -1 }
                let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
                if result != 0 { close(fd); return -1 }
            } else {
                if wrongPeer {
                    var source = sockaddr_in()
                    source.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                    source.sin_family = sa_family_t(AF_INET)
                    _ = inet_pton(AF_INET, "127.0.0.2", &source.sin_addr)
                    let result = withUnsafePointer(to: &source) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
                    if result != 0 { close(fd); return -1 }
                }
                var address = sockaddr_in()
                address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                address.sin_family = sa_family_t(AF_INET)
                address.sin_port = UInt16(endpoint.port).bigEndian
                guard inet_pton(AF_INET, endpoint.host, &address.sin_addr) == 1 else { close(fd); return -1 }
                let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
                if result != 0 { close(fd); return -1 }
            }
            return fd
        }
        func dataSocket() -> Int32 {
            if passive >= 0 {
                let data = accept(passive, nil, nil)
                close(passive)
                passive = -1
                return data
            }
            guard let endpoint = active else { return -1 }
            active = nil
            if injectUnexpectedPeer && !endpoint.ipv6 {
                let attacker = connectActive(endpoint, wrongPeer: true)
                if attacker >= 0 { close(attacker) }
            }
            return connectActive(endpoint)
        }
        while true {
            let count = recv(control, &bytes, bytes.count, 0)
            if count <= 0 { return }
            buffer.append(contentsOf: bytes[..<count])
            while let end = buffer.range(of: Data([13, 10])) {
                var command = String(decoding: buffer[..<end.lowerBound], as: UTF8.self)
                buffer.removeSubrange(..<end.upperBound)
                if command == "RETR /sample" || command == "RETR /missing" {
                    command.remove(at: command.index(command.startIndex, offsetBy: 5))
                }
                switch command {
                case "USER demo": Self.reply("331 Password required\r\n", to: control)
                case let cmd where cmd.hasPrefix("USER demo@"):
                    Self.reply("331 Password required\r\n", to: control)
                case "PASS secret": Self.reply("230 Logged in\r\n", to: control)
                case "TYPE I": Self.reply("200 Binary\r\n", to: control)
                case "TYPE A": Self.reply("200 ASCII\r\n", to: control)
                case "PWD": Self.reply("257 \"/remote\" is current directory\r\n", to: control)
                case "CWD /remote": Self.reply("250 Directory changed\r\n", to: control)
                case "SYST": Self.reply("215 UNIX Type: L8\r\n", to: control)
                case "FEAT": Self.reply("211-Features\r\n UTF8\r\n MLST type*;size*;modify*;\r\n MODE Z\r\n\(xcrcResponse == nil ? "" : " XCRC\r\n")211 End\r\n", to: control)
                case "OPTS UTF8 ON": Self.reply(rejectUTF8Option ? "502 UTF8 option unavailable\r\n" : "200 UTF8 enabled\r\n", to: control)
                case let cmd where cmd.hasPrefix("ALLO "): Self.reply("202 Allocation unnecessary\r\n", to: control)
                case let cmd where cmd.hasPrefix("MFMT "):
                    Self.reply(unsupportedMFMT ? "502 MFMT unsupported\r\n" : (failSetModificationTime ? "550 Timestamp unsupported\r\n" : "213 Modification time set\r\n"), to: control)
                case let cmd where cmd.hasPrefix("MDTM 20240102030405 "):
                    Self.reply("213 Modification time set\r\n", to: control)
                case let cmd where cmd.hasPrefix("SITE "): Self.reply("200 SITE accepted\r\n", to: control)
                case "STAT": Self.reply("211 Server status\r\n", to: control)
                case "DELE sample": Self.reply("250 Deleted\r\n", to: control)
                case let cmd where cmd.hasPrefix("REST "):
                    if supportsRestart, let offset = Int(cmd.dropFirst(5)), offset >= 0 {
                        restartOffset = ignoresRestart ? 0 : offset
                        Self.reply("350 Restart accepted\r\n", to: control)
                    } else { Self.reply("502 Restart unavailable\r\n", to: control) }
                case "SIZE sample": Self.reply(supportsSize ? "213 \((uploaded ?? payload).count)\r\n" : "502 SIZE unsupported\r\n", to: control)
                case "SIZE invalid": Self.reply("213 -1\r\n", to: control)
                case "SIZE missing": Self.reply("550 Not found\r\n", to: control)
                case "MDTM sample": Self.reply("213 20240102030405.5\r\n", to: control)
                case "MDTM invalid": Self.reply("213 20240230030405\r\n", to: control)
                case let cmd where cmd.hasPrefix("XCRC "):
                    Self.reply(xcrcResponse.map { "250 \($0)\r\n" } ?? "502 XCRC unsupported\r\n", to: control)
                case let cmd where cmd.hasPrefix("EPRT "):
                    guard supportsEPRT else { Self.reply("502 Unsupported\r\n", to: control); continue }
                    let pieces = cmd.dropFirst(5).split(separator: "|", omittingEmptySubsequences: false)
                    if pieces.count == 5, let family = Int(pieces[1]), let port = Int(pieces[3]), (1...65535).contains(port), family == 1 || family == 2 {
                        active = (String(pieces[2]), port, family == 2)
                        Self.reply("200 Active endpoint\r\n", to: control)
                    } else { Self.reply("501 Invalid endpoint\r\n", to: control) }
                case let cmd where cmd.hasPrefix("PORT "):
                    let pieces = cmd.dropFirst(5).split(separator: ",").compactMap { UInt8($0) }
                    if pieces.count == 6 {
                        active = (pieces[0...3].map(String.init).joined(separator: "."), Int(pieces[4]) * 256 + Int(pieces[5]), false)
                        Self.reply("200 Active endpoint\r\n", to: control)
                    } else { Self.reply("501 Invalid endpoint\r\n", to: control) }
                case "EPSV":
                    guard supportsEPSV else { Self.reply("502 Not supported\r\n", to: control); continue }
                    if passive >= 0 { close(passive) }
                    guard let (fd, port) = try? Self.listen(ipv6: ipv6) else { return }
                    passive = fd
                    Self.reply("229 Entering Extended Passive Mode (|||\(port)|)\r\n", to: control)
                case "PASV":
                    if passive >= 0 { close(passive) }
                    guard let (fd, port) = try? Self.listen(ipv6: ipv6) else { return }
                    passive = fd
                    // Deliberately advertise a wrong host: clients should use the control host.
                    Self.reply("227 Entering Passive Mode (10,0,0,1,\(port / 256),\(port % 256))\r\n", to: control)
                case "RETR missing":
                    if passive >= 0 { close(passive); passive = -1 }
                    Self.reply("550 Not found\r\n", to: control)
                case "MLSD" where !supportsMLSD:
                    if passive >= 0 { close(passive); passive = -1 }
                    Self.reply("502 MLSD unsupported\r\n", to: control)
                case let cmd where cmd.hasPrefix("LIST "):
                    let data = dataSocket()
                    guard data >= 0 else { return }
                    onRemoteListing?()
                    Self.reply("150 Opening data\r\n", to: control)
                    Self.sendAll(Data((wildcardListing ?? "-rw-r--r-- 1 owner group 6 Jan 02 2024 sample\r\n").utf8), to: data)
                    close(data)
                    Self.reply("226 Transfer complete\r\n", to: control)
                case let cmd where cmd.hasPrefix("MKD /remote/"):
                    directories.insert(String(cmd.dropFirst(4)))
                    Self.reply("257 Created\r\n", to: control)
                case let cmd where cmd.hasPrefix("RNFR /remote/"):
                    let path = String(cmd.dropFirst(5))
                    if files[path] != nil { renameFrom = path; Self.reply("350 Rename\r\n", to: control) }
                    else { Self.reply("550 Not found\r\n", to: control) }
                case let cmd where cmd.hasPrefix("RNTO /remote/"):
                    if let from = renameFrom, let data = files.removeValue(forKey: from) {
                        files[String(cmd.dropFirst(5))] = data
                        renameFrom = nil
                        Self.reply("250 Renamed\r\n", to: control)
                    } else { Self.reply("503 Bad sequence\r\n", to: control) }
                case let cmd where cmd.hasPrefix("DELE /remote/"):
                    if files.removeValue(forKey: String(cmd.dropFirst(5))) != nil { Self.reply("250 Deleted\r\n", to: control) }
                    else { Self.reply("550 Not found\r\n", to: control) }
                case let cmd where cmd.hasPrefix("MLSD /remote") || cmd.hasPrefix("STOR /remote/") || cmd.hasPrefix("RETR /remote/"):
                    let data = dataSocket()
                    guard data >= 0 else { return }
                    Self.reply("150 Opening data\r\n", to: control)
                    if cmd.hasPrefix("MLSD ") {
                        let directory = String(cmd.dropFirst(5))
                        let prefix = directory + "/"
                        var listing = ""
                        for item in directories.sorted() where item.hasPrefix(prefix) {
                            let name = String(item.dropFirst(prefix.count))
                            if !name.contains("/") { listing += "type=dir; \(name)\r\n" }
                        }
                        for (path, content) in files.sorted(by: { $0.key < $1.key }) where path.hasPrefix(prefix) {
                            let name = String(path.dropFirst(prefix.count))
                            if !name.contains("/") { listing += "type=file;size=\(content.count);modify=20240102030405; \(name)\r\n" }
                        }
                        Self.sendAll(Data(listing.utf8), to: data)
                        onRemoteListing?()
                    } else if cmd.hasPrefix("STOR ") {
                        var result = Data()
                        while true {
                            let n = recv(data, &bytes, bytes.count, 0)
                            if n <= 0 { break }
                            result.append(contentsOf: bytes[..<n])
                        }
                        files[String(cmd.dropFirst(5))] = result
                    } else {
                        Self.sendAll(files[String(cmd.dropFirst(5))] ?? Data(), to: data)
                    }
                    close(data)
                    Self.reply("226 Transfer complete\r\n", to: control)
                case "NLST", "LIST", "MLSD", "RETR sample", "STOR sample", "APPE sample", "STOR exported.m4a":
                    if refuseActiveConnection && active != nil {
                        active = nil
                        Self.reply("150 Opening data\r\n", to: control)
                        onActivePreliminary?()
                        continue
                    }
                    let data = dataSocket()
                    guard data >= 0 else { return }
                    // Replies may arrive in the same receive call.
                    Self.reply("150 Opening data\r\n", to: control)
                    if command == "RETR sample" && stallDownload {
                        _ = recv(data, &bytes, bytes.count, 0)
                        close(data)
                        return
                    }
                    if command.hasPrefix("STOR ") || command.hasPrefix("APPE ") {
                        var result = Data()
                        while true {
                            let n = recv(data, &bytes, bytes.count, 0)
                            if n <= 0 { break }
                            result.append(contentsOf: bytes[..<n])
                        }
                        if command.hasPrefix("APPE ") {
                            uploaded = (uploaded ?? Data()) + result
                        } else {
                            uploaded = Data((uploaded ?? payload).prefix(restartOffset)) + result
                            restartOffset = 0
                        }
                    } else if command == "RETR sample" {
                        let contents = uploaded ?? payload
                        Self.sendAll(Data(contents.dropFirst(restartOffset)), to: data)
                        restartOffset = 0
                    } else if command == "MLSD" {
                        Self.sendAll(Data("type=file;size=6;modify=20240102030405;create=20230102030405;perm=rad; sample\r\n".utf8), to: data)
                    } else if command == "LIST" {
                        Self.sendAll(Data("-rw-r--r-- 1 owner group 6 Jan 02 2024 sample\r\n".utf8), to: data)
                    } else {
                        Self.sendAll(Data(" file with spaces \r\nsecond\r\n".utf8), to: data)
                    }
                    close(data)
                    let fail = failTransferCompletion || (failFirstTransfer && connectionIndex == 0 && command == "RETR sample")
                    Self.reply(fail ? "451 Transfer failed\r\n" : "226 Transfer complete\r\n", to: control)
                case "NOOP": Self.reply("200 OK\r\n", to: control)
                default: Self.reply("500 Unknown command\r\n", to: control)
                }
            }
        }
    }
}

@Test func loopbackPlainFTPTransferRoundTrip() async throws {
    let server = try LoopbackFTPServer()
    let channel = FTPControlChannel()
    let configuration = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
    try await channel.connect(configuration: configuration)
    try await channel.login()
    await #expect(throws: FTPError.self) { try await channel.sendCommand("NOOP\r\nDELE sample") }
    let names = try await channel.listNames()
    #expect(names == [" file with spaces ", "second"])
    #expect(try await channel.listDetails() == ["-rw-r--r-- 1 owner group 6 Jan 02 2024 sample"])
    #expect(try await channel.fileSize(path: "sample") == 6)
    #expect(try await channel.modificationTime(path: "sample") == Date(timeIntervalSince1970: 1_704_164_645.5))
    await #expect(throws: FTPError.protocolViolation(description: "Invalid SIZE response")) { try await channel.fileSize(path: "invalid") }
    await #expect(throws: FTPError.serverReply(code: 550, message: "550 Not found")) { try await channel.fileSize(path: "missing") }
    await #expect(throws: FTPError.protocolViolation(description: "Invalid FTP timestamp")) { try await channel.modificationTime(path: "invalid") }
    let entries = try await channel.listEntries()
    #expect(entries.count == 1)
    #expect(entries.first?.name == "sample")
    #expect(entries.first?.size == 6)
    let original = Data([0, 10, 13, 255, 65, 66])
    try await channel.storeFileData(original, remotePath: "sample")
    let downloaded = try await channel.retrieveFileData(remotePath: "sample")
    #expect(downloaded == original)
    try await channel.noop()
    await channel.disconnect()
}

@Test func timeoutClosesControlConnection() async throws {
    let server = try LoopbackFTPServer(suppressGreeting: true)
    let channel = FTPControlChannel()
    let configuration = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 2, readTimeout: 0.1)
    await #expect(throws: FTPError.timeout(operation: "read")) {
        try await channel.connect(configuration: configuration)
    }
    #expect(await channel.isConnected == false)
}

@Test func facadeConnectsWithDefaultPlainFTPSettings() async throws {
    let server = try LoopbackFTPServer(supportsEPSV: false)
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    try await client.connect()
    try await client.loginAfterConnectOnly()
    #expect(try await client.quote("NOOP") == "200 OK")
    #expect(try await client.sendCommand("NOOP") == "200 OK")
    await #expect(throws: FTPError.serverReply(code: 500, message: "500 Unknown command")) {
        try await client.quote("UNSUPPORTED")
    }
    #expect(client.lastReply == "500 Unknown command")
    let names = try await client.nlst()
    #expect(names == [" file with spaces ", "second"])
    #expect(try await client.list() == ["-rw-r--r-- 1 owner group 6 Jan 02 2024 sample"])
    #expect(try await client.getSize("sample") == 6)
    #expect(try await client.getLastModified("sample") == Date(timeIntervalSince1970: 1_704_164_645.5))
    await client.disconnect()
}

@Test func facadeTransferMetricsRetainIndependentCounters() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    try await client.connect()
    let initial = await client.transferMetrics()
    #expect(initial.receivedBytes == 0 && initial.sentBytes == 0)
    #expect(initial.lastUploadSucceeded == nil && initial.lastDownloadSucceeded == nil)
    try await client.putFile(fromBinaryData: "sample", binaryData: Data("123456".utf8))
    #expect(await client.curBytesSent == 6)
    #expect(await client.curBytesSentStr == "6")
    #expect(try await client.getRemoteFileBinaryData("sample") == Data("123456".utf8))
    let transferred = await client.transferMetrics()
    #expect(transferred.sentBytes == 6 && transferred.receivedBytes == 6)
    #expect(transferred.lastUploadSucceeded == true && transferred.lastDownloadSucceeded == true)
    #expect(transferred.activeDirection == nil)
    #expect(await client.curBytesReceived == 6)
    #expect(await client.curBytesReceivedStr == "6")
    _ = try await client.nlst()
    #expect(await client.transferMetrics() == transferred)
    try await client.appendFile(fromBinaryData: "sample", binaryData: Data("abc".utf8))
    #expect(await client.curBytesSent == 3)
    #expect(await client.curBytesReceived == 6)
    let source = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: source) }
    try Data("chunked".utf8).write(to: source)
    try await client.largeFileUpload(localPath: source.path, remotePath: "sample", chunkSize: 2)
    let chunked = await client.transferMetrics()
    #expect(chunked.sentBytes == 7 && chunked.lastUploadSucceeded == true)
    await #expect(throws: FTPError.self) { try await client.getRemoteFileBinaryData("missing") }
    let failed = await client.transferMetrics()
    #expect(failed.receivedBytes == 0 && failed.lastDownloadSucceeded == false)
    #expect(failed.sentBytes == 7 && failed.lastUploadSucceeded == true)
    await client.disconnect()
    #expect(await client.transferMetrics() == failed)
}

@Test func chunkedUploadRejectsConcurrentCommandsBetweenChunks() async throws {
    let server = try LoopbackFTPServer()
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 5, readTimeout: 5)
    try await channel.connect(configuration: config)
    try await channel.login()
    try await FTPChunkedUploadScope.$identifier.withValue(UUID()) {
        try await channel.beginChunkedUploadMetrics()
        let unrelated = Task.detached {
            try await channel.noop()
        }
        await #expect(throws: FTPError.invalidState(description: "Another FTP operation is in progress")) { try await unrelated.value }
        #expect(await channel.transferMetrics().activeDirection == .upload)
        try await channel.storeFileData(Data("abc".utf8), remotePath: "sample")
        try await channel.storeFileData(Data("def".utf8), remotePath: "sample", append: true)
        await channel.finishChunkedUploadMetrics(succeeded: true)
    }
    let result = await channel.transferMetrics()
    #expect(result.sentBytes == 6 && result.lastUploadSucceeded == true && result.activeDirection == nil)
    try await channel.noop()
    await channel.disconnect()
}

@Test func disconnectClearsAnAbandonedChunkedUpload() async throws {
    let server = try LoopbackFTPServer()
    let channel = FTPControlChannel()
    try await channel.connect(configuration: FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 5, readTimeout: 5))
    try await channel.login()
    try await FTPChunkedUploadScope.$identifier.withValue(UUID()) {
        try await channel.beginChunkedUploadMetrics(expectedBytes: 10)
    }
    await channel.disconnect()
    let metrics = await channel.transferMetrics()
    #expect(metrics.activeDirection == nil && metrics.lastUploadSucceeded == false)
    await #expect(throws: FTPError.invalidState(description: "No active connection")) { try await channel.noop() }
}

@Test func sizeProgressSupportsHintsResumeAndEmptyFiles() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.keepSessionLog = true
    try await client.connect()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let target = root.appendingPathComponent("download")
    client.autoGetSizeForProgress = true
    client.progressMonSize64 = 12
    await client.clearSessionLog()
    try await client.getFile(remoteFilename: "sample", localPath: target.path)
    var metrics = await client.transferMetrics()
    #expect(metrics.expectedDownloadBytes == 12 && metrics.downloadFractionCompleted == 0.5)
    #expect(client.progressMonSize64 == 0)
    #expect(!(await client.sessionLog()).contains("> SIZE sample"))
    try await client.getFile(remoteFilename: "sample", localPath: target.path)
    metrics = await client.transferMetrics()
    #expect(metrics.expectedDownloadBytes == 6 && metrics.downloadFractionCompleted == 1)
    #expect((await client.sessionLog()).contains("> SIZE sample"))
    try Data([0, 10, 13]).write(to: target)
    try await client.getFile(remoteFilename: "sample", localPath: target.path, resume: true)
    metrics = await client.transferMetrics()
    #expect(metrics.expectedDownloadBytes == 3 && metrics.receivedBytes == 3 && metrics.downloadFractionCompleted == 1)
    let source = root.appendingPathComponent("empty")
    try Data().write(to: source)
    try await client.largeFileUpload(localPath: source.path, remotePath: "sample", chunkSize: 4)
    metrics = await client.transferMetrics()
    #expect(metrics.expectedUploadBytes == 0 && metrics.sentBytes == 0 && metrics.uploadFractionCompleted == 1)
    try Data("abcdef".utf8).write(to: source)
    try await client.largeFileUpload(localPath: source.path, remotePath: "sample", chunkSize: 2)
    metrics = await client.transferMetrics()
    #expect(metrics.expectedUploadBytes == 6 && metrics.sentBytes == 6 && metrics.uploadFractionCompleted == 1)
    try await client.putFile(fromBinaryData: "sample", binaryData: Data("abc".utf8))
    try await client.putFile(localPath: source.path, remoteFilename: "sample", resume: true)
    metrics = await client.transferMetrics()
    #expect(metrics.expectedUploadBytes == 3 && metrics.sentBytes == 3 && metrics.uploadFractionCompleted == 1)
    await client.disconnect()
}

@Test func sizeProgressFallsBackWhenUnsupported() async throws {
    let server = try LoopbackFTPServer(supportsSize: false)
    let channel = FTPControlChannel()
    try await channel.connect(configuration: FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 5, readTimeout: 5))
    try await channel.login()
    let target = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: target) }
    try await channel.downloadFile(remotePath: "sample", to: target, querySizeForProgress: true)
    let metrics = await channel.transferMetrics()
    #expect(metrics.expectedDownloadBytes == nil && metrics.downloadFractionCompleted == nil && metrics.lastDownloadSucceeded == true)
    #expect(try Data(contentsOf: target) == Data([0, 10, 13, 255, 65, 66]))
    await channel.disconnect()
}

@Test func sizeProgressDistinguishesFailedCompletionAndASCII() async throws {
    let target = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: target) }
    let failureServer = try LoopbackFTPServer(failTransferCompletion: true)
    let failing = FTPClientFacade()
    failing.hostname = "127.0.0.1"
    failing.port = failureServer.port
    failing.username = "demo"
    failing.password = "secret"
    try await failing.connect()
    failing.progressMonSize64 = 6
    await #expect(throws: FTPError.serverReply(code: 451, message: "451 Transfer failed")) {
        try await failing.getFile(remoteFilename: "sample", localPath: target.path)
    }
    let failed = await failing.transferMetrics()
    #expect(failing.progressMonSize64 == 0)
    #expect(failed.downloadFractionCompleted == 1 && failed.lastDownloadSucceeded == false)
    #expect(!FileManager.default.fileExists(atPath: target.path))
    await failing.disconnect()

    let asciiServer = try LoopbackFTPServer()
    let ascii = FTPClientFacade()
    ascii.hostname = "127.0.0.1"
    ascii.port = asciiServer.port
    ascii.username = "demo"
    ascii.password = "secret"
    ascii.keepSessionLog = true
    ascii.autoGetSizeForProgress = true
    try await ascii.connect()
    try await ascii.setTypeAscii()
    await ascii.clearSessionLog()
    try await ascii.getFile(remoteFilename: "sample", localPath: target.path)
    let unknown = await ascii.transferMetrics()
    #expect(unknown.expectedDownloadBytes == nil && unknown.downloadFractionCompleted == nil)
    #expect(!(await ascii.sessionLog()).contains("> SIZE sample"))
    await ascii.disconnect()
}

@Test func partialTransferReportsUnknownAndKnownFailures() async throws {
    let target = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: target) }
    for (hint, expected) in [(UInt64(0), Optional<Bool>.none), (6, false), (12, true)] {
        let server = try LoopbackFTPServer(failTransferCompletion: true)
        let client = FTPClientFacade()
        client.hostname = "127.0.0.1"
        client.port = server.port
        client.username = "demo"
        client.password = "secret"
        try await client.connect()
        #expect(await client.partialTransfer == nil)
        client.progressMonSize64 = hint
        await #expect(throws: FTPError.serverReply(code: 451, message: "451 Transfer failed")) {
            try await client.getFile(remoteFilename: "sample", localPath: target.path)
        }
        #expect(await client.partialTransfer == expected)
        #expect((await client.transferMetrics()).receivedBytes == 6)
        await client.disconnect()
    }
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    try await client.connect()
    await #expect(throws: FTPError.self) { try await client.getFile(remoteFilename: "missing", localPath: target.path) }
    #expect(await client.partialTransfer == false)
    await client.disconnect()
}

@Test func retryDownloadUsesFreshSessionAndPreservesDestinationUntilSuccess() async throws {
    let server = try LoopbackFTPServer(connectionLimit: 2, failFirstTransfer: true)
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 10, readTimeout: 10)
    let target = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: target) }
    let original = Data("original".utf8)
    try original.write(to: target)
    let retries = RetryRecorder()
    let progress = ProgressRecorder()
    try await FTPDownloadRetry.download(configuration: config, remotePath: "/sample", destination: target,
        retryPolicy: FTPRetryPolicy(maximumAttempts: 2, initialDelay: 0, maximumDelay: 0),
        progress: { progress.record($0) },
        onRetry: { attempt, error in retries.record(attempt, error, try? Data(contentsOf: target)) })
    #expect(try Data(contentsOf: target) == Data([0, 10, 13, 255, 65, 66]))
    #expect(retries.values.count == 1)
    #expect(retries.values.first?.0 == 2)
    #expect(retries.values.first?.1 == FTPError.serverReply(code: 451, message: "451 Transfer failed"))
    #expect(retries.values.first?.2 == original)
    #expect(progress.values.filter { $0 == 0 }.count == 2)
}

@Test func retryDownloadStopsOnPermanentErrorOrExhaustion() async throws {
    let target = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: target) }
    let original = Data("existing".utf8)
    try original.write(to: target)
    let policy = FTPRetryPolicy(maximumAttempts: 2, initialDelay: 0, maximumDelay: 0)
    let missing = try LoopbackFTPServer()
    let missingConfig = FTPClientConfiguration(host: "127.0.0.1", port: missing.port, username: "demo", password: "secret", connectTimeout: 10, readTimeout: 10)
    let permanentRetries = RetryRecorder()
    await #expect(throws: FTPError.serverReply(code: 550, message: "550 Not found")) {
        try await FTPDownloadRetry.download(configuration: missingConfig, remotePath: "/missing", destination: target, retryPolicy: policy,
            onRetry: { attempt, error in permanentRetries.record(attempt, error, nil) })
    }
    #expect(permanentRetries.values.isEmpty)
    #expect(try Data(contentsOf: target) == original)
    let failing = try LoopbackFTPServer(failTransferCompletion: true, connectionLimit: 2)
    let failingConfig = FTPClientConfiguration(host: "127.0.0.1", port: failing.port, username: "demo", password: "secret", connectTimeout: 10, readTimeout: 10)
    let retries = RetryRecorder()
    await #expect(throws: FTPError.serverReply(code: 451, message: "451 Transfer failed")) {
        try await FTPDownloadRetry.download(configuration: failingConfig, remotePath: "/sample", destination: target, retryPolicy: policy,
            onRetry: { attempt, error in retries.record(attempt, error, nil) })
    }
    #expect(retries.values.map(\.0) == [2])
    #expect(try Data(contentsOf: target) == original)
    await #expect(throws: FTPError.invalidState(description: "Retried download requires an absolute remote path")) {
        try await FTPDownloadRetry.download(configuration: failingConfig, remotePath: "relative", destination: target, retryPolicy: policy)
    }
    await #expect(throws: FTPError.invalidState(description: "Invalid download retry policy")) {
        try await FTPDownloadRetry.download(configuration: failingConfig, remotePath: "/sample", destination: target,
            retryPolicy: FTPRetryPolicy(maximumAttempts: 0))
    }
}

@Test func retryDownloadCancellationInterruptsBackoff() async throws {
    let server = try LoopbackFTPServer(failTransferCompletion: true)
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 10, readTimeout: 10)
    let target = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: target) }
    try Data("existing".utf8).write(to: target)
    let (events, signal) = AsyncStream<Int>.makeStream()
    let task = Task {
        try await FTPDownloadRetry.download(configuration: config, remotePath: "/sample", destination: target,
            retryPolicy: FTPRetryPolicy(maximumAttempts: 2, initialDelay: 30, maximumDelay: 30),
            onRetry: { attempt, _ in signal.yield(attempt) })
    }
    let observed = await withTaskGroup(of: Bool.self, returning: Bool.self) { group in
        group.addTask { var iterator = events.makeAsyncIterator(); return await iterator.next() == 2 }
        group.addTask { try? await Task.sleep(nanoseconds: 10_000_000_000); return false }
        let value = await group.next() ?? false
        group.cancelAll()
        return value
    }
    guard observed else {
        task.cancel()
        _ = try? await task.value
        signal.finish()
        Issue.record("Retry did not enter backoff before the deadline")
        return
    }
    task.cancel()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(try Data(contentsOf: target) == Data("existing".utf8))
    signal.finish()
}

@Test func facadeConnectionAndRawCommandSemantics() async throws {
    for staged in [false, true] {
        let server = try LoopbackFTPServer()
        let client = FTPClientFacade()
        client.hostname = "127.0.0.1"
        client.port = server.port
        client.username = "demo"
        client.password = "secret"
        client.commandCharset = "iso-8859-1"
        client.autoOptsUtf8 = false
        client.keepSessionLog = true
        if staged {
            try await client.connectOnly()
            #expect(!(await client.isLoggedIn()))
            #expect(!(await client.sessionLog()).contains("> USER"))
            try await client.loginAfterConnectOnly()
        } else {
            try await client.connect()
        }
        #expect(await client.isLoggedIn())
        try await client.loginAfterConnectOnly() // Backward-compatible no-op.
        #expect((await client.sessionLog()).components(separatedBy: "> USER").count == 2)
        await #expect(throws: FTPError.self) { try await client.quote("NOOP 😀") }
        await #expect(throws: FTPError.serverReply(code: 500, message: "500 Unknown command")) {
            try await client.sendCommand("NOOP 😀")
        }
        #expect(client.lastReply == "500 Unknown command")
        client.commandCharset = "utf-8"
        await #expect(throws: FTPError.serverReply(code: 500, message: "500 Unknown command")) {
            try await client.quote("NOOP 😀")
        }
        client.commandCharset = "iso-8859-1"
        await #expect(throws: FTPError.invalidState(description: "FTP command cannot be represented safely in the selected character set")) {
            try await client.quote("NOOP 😀")
        }
        await client.disconnect()
    }
}

@Test func facadeDefaultSettingsAndAutoFix() async throws {
    let client = FTPClientFacade()
    #expect(client.username == "anonymous")
    #expect(client.autoFix && client.autoFeat && client.autoSyst && client.autoOptsUtf8)
    #expect(client.readTimeout == 60)
    client.port = 990
    client.authTls = true
    client.authSsl = true
    await #expect(throws: FTPError.self) { try await client.connectOnly() }
    #expect(client.implicitTls && !client.authTls && !client.authSsl)
    client.port = 21
    client.authTls = true
    await #expect(throws: FTPError.self) { try await client.connectOnly() }
    #expect(!client.implicitTls && client.authTls)
    client.port = 990
    client.autoFix = false
    await #expect(throws: FTPError.self) { try await client.connectOnly() }
    #expect(!client.implicitTls && client.authTls)
}

@Test func facadeUpdatesUTF8SettingsAfterCapabilityDiscovery() async throws {
    for automatic in [false, true] {
        let server = try LoopbackFTPServer(rejectUTF8Option: true)
        let client = FTPClientFacade()
        client.hostname = "127.0.0.1"
        client.port = server.port
        client.username = "demo"
        client.password = "secret"
        client.commandCharset = "iso-8859-1"
        client.dirListingCharset = "iso-8859-1"
        client.autoOptsUtf8 = automatic
        client.keepSessionLog = true
        try await client.connect()
        #expect(client.commandCharset == (automatic ? "utf-8" : "iso-8859-1"))
        #expect(client.dirListingCharset == (automatic ? "utf-8" : "iso-8859-1"))
        let log = await client.sessionLog()
        let syst = try #require(log.range(of: "> SYST"))
        let feat = try #require(log.range(of: "> FEAT"))
        #expect(syst.lowerBound < feat.lowerBound)
        #expect(log.contains("> OPTS UTF8 ON") == automatic)
        if !automatic {
            client.autoOptsUtf8 = true
            _ = try await client.feat()
            #expect(client.commandCharset == "utf-8")
            #expect(client.dirListingCharset == "utf-8")
            #expect((await client.sessionLog()).contains("> OPTS UTF8 ON"))
        }
        await client.disconnect()
    }
}

@Test func facadeAppliesLiveDataConnectionSettings() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.keepSessionLog = true
    try await client.connect()
    #expect(try await client.nlst() == [" file with spaces ", "second"])
    client.useEpsv = false
    #expect(try await client.nlst() == [" file with spaces ", "second"])
    client.passive = false
    client.forcePortIpAddress = "control"
    #expect(try await client.nlst() == [" file with spaces ", "second"])
    let log = await client.sessionLog()
    #expect(log.contains("> EPSV"))
    #expect(log.contains("> PASV"))
    #expect(log.contains("> EPRT "))
    client.activePortRangeStart = -1
    await #expect(throws: FTPError.invalidState(description: "Invalid active port range")) { try await client.noop() }
    #expect(await client.checkConnection())
    client.activePortRangeStart = 0
    client.passive = true
    client.maximumBufferedBytes = 1
    await #expect(throws: FTPError.invalidState(description: "Buffered FTP response exceeds configured limit")) { try await client.nlst() }
    #expect(!(await client.checkConnection()))
}

@Test(.enabled(if: nodeExecutable != nil)) func socks5BindSupportsPlainFTPAndLiveModeChanges() async throws {
    let server = try LoopbackFTPServer()
    let proxy = try LocalFTPProxy(mode: "socks5")
    defer { proxy.stop() }
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.proxy = .socks5(host: "127.0.0.1", port: proxy.port, username: "alice", password: "secret")
    client.keepSessionLog = true
    var stage = "connect"
    do {
        try await client.connect()
        stage = "passive listing"
        #expect(try await client.nlst() == [" file with spaces ", "second"])
        client.passive = false
        stage = "active listing"
        #expect(try await client.nlst() == [" file with spaces ", "second"])
        let payload = Data("SOCKS5 active data".utf8)
        stage = "upload"
        try await client.putFile(fromBinaryData: "sample", binaryData: payload)
        stage = "download"
        #expect(try await client.getRemoteFileBinaryData("sample") == payload)
        #expect((await client.sessionLog()).contains("> EPRT |1|127.0.0.1|"))
        await client.disconnect()
    } catch {
        Issue.record("SOCKS5 BIND failed during \(stage): \(error); protocol log: \(await client.sessionLog())")
        throw error
    }
}

@Test(.enabled(if: nodeExecutable != nil)) func socks5PreservesCoalescedReplyAndDataEOF() async throws {
    let server = try LoopbackFTPServer()
    let proxy = try LocalFTPProxy(mode: "socks5coalesce")
    defer { proxy.stop() }
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret",
        connectTimeout: 5, readTimeout: 5, proxy: .socks5(host: "127.0.0.1", port: proxy.port, username: "alice", password: "secret"))
    try await channel.connect(configuration: config)
    try await channel.login()
    for _ in 0..<10 { #expect(try await channel.listNames() == [" file with spaces ", "second"]) }
    await channel.disconnect()
}

@Test(.enabled(if: nodeExecutable != nil)) func socks4BindSupportsPlainFTPAndLiveModeChanges() async throws {
    let server = try LoopbackFTPServer()
    let proxy = try LocalFTPProxy(mode: "socks4")
    defer { proxy.stop() }
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.proxy = .socks4(host: "127.0.0.1", port: proxy.port, userID: "alice")
    client.keepSessionLog = true
    try await client.connect()
    #expect(try await client.nlst() == [" file with spaces ", "second"])
    client.passive = false
    #expect(try await client.nlst() == [" file with spaces ", "second"])
    let payload = Data("SOCKS4 active data".utf8)
    try await client.putFile(fromBinaryData: "sample", binaryData: payload)
    #expect(try await client.getRemoteFileBinaryData("sample") == payload)
    #expect((await client.sessionLog()).contains("> EPRT |1|127.0.0.1|"))
    await client.disconnect()
}

@Test func facadeConnectFailureClosesConnectionAndPreservesReply() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "wrong"
    await #expect(throws: FTPError.serverReply(code: 500, message: "500 Unknown command")) {
        try await client.connect()
    }
    #expect(!(await client.checkConnection()))
    #expect(client.lastReply == "500 Unknown command")
}

@Test func asciiDownloadConversionAcrossTransferAPIs() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    try await client.connect()
    let raw = Data("a\r\nb\nc\rd\r".utf8)
    try await client.putFile(fromBinaryData: "sample", binaryData: raw)
    try await client.setTypeAscii()
    client.crlfMode = 2
    let expected = Data("a\nb\nc\nd\n".utf8)
    #expect(try await client.getRemoteFileBinaryData("sample") == expected)
    let collector = DownloadCollector()
    try await client.getFileToStream(remoteFilename: "sample") { await collector.append($0) }
    #expect(await collector.data == expected)
    let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: file) }
    try await client.getFile(remoteFilename: "sample", localPath: file.path)
    #expect(try Data(contentsOf: file) == expected)
    client.crlfMode = 1
    #expect(try await client.getRemoteFileBinaryData("sample") == Data("a\r\nb\r\nc\r\nd\r\n".utf8))
    try await client.setTypeBinary()
    #expect(try await client.getRemoteFileBinaryData("sample") == raw)
    client.crlfMode = 4
    await #expect(throws: FTPError.self) { try await client.getRemoteFileBinaryData("sample") }
    await client.disconnect()
}

@Test func asciiConversionRespectsBufferedOutputLimit() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.maximumBufferedBytes = 3
    try await client.connect()
    try await client.putFile(fromBinaryData: "sample", binaryData: Data("a\nb".utf8))
    try await client.setTypeAscii()
    client.crlfMode = 1
    await #expect(throws: FTPError.invalidState(description: "Buffered FTP response exceeds configured limit")) {
        try await client.getRemoteFileBinaryData("sample")
    }
    #expect(!(await client.checkConnection()))
}

@Test func automaticUploadCRCVerifiesDataFileStreamAndResume() async throws {
    let server = try LoopbackFTPServer(xcrcResponse: "0xCBF43926")
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.autoFeat = true
    client.keepSessionLog = true
    try await client.connect()
    client.autoXcrc = true
    let payload = Data("123456789".utf8)
    try await client.putFile(fromBinaryData: "sample", binaryData: payload)
    let stream = AsyncThrowingStream<Data, Error> { continuation in
        for value in ["123", "456", "789"] { continuation.yield(Data(value.utf8)) }
        continuation.finish()
    }
    try await client.putFileFromStream(remoteFilename: "sample", source: stream)
    let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: file) }
    try payload.write(to: file)
    try await client.putFile(localPath: file.path, remoteFilename: "sample")
    client.autoXcrc = false
    try await client.putFile(fromBinaryData: "sample", binaryData: Data("1234".utf8))
    client.autoXcrc = true
    client.restartNext = true
    try await client.putFile(fromBinaryData: "sample", binaryData: payload)
    client.autoXcrc = false
    try await client.putFile(fromBinaryData: "sample", binaryData: Data("1234".utf8))
    client.autoXcrc = true
    try await client.putFile(localPath: file.path, remoteFilename: "sample", resume: true)
    #expect((await client.sessionLog()).components(separatedBy: "> XCRC sample").count == 6)
    await #expect(throws: FTPError.invalidState(description: "Automatic XCRC requires a binary, non-append upload")) {
        try await client.appendFile(fromBinaryData: "sample", binaryData: Data("oops".utf8))
    }
    await #expect(throws: FTPError.invalidState(description: "Automatic XCRC cannot verify chunked append uploads")) {
        try await client.largeFileUpload(localPath: file.path, remotePath: "sample", chunkSize: 2)
    }
    #expect(try await client.getRemoteFileBinaryData("sample") == payload)
    try await client.setTypeAscii()
    await #expect(throws: FTPError.invalidState(description: "Automatic XCRC requires a binary, non-append upload")) {
        try await client.putFile(fromBinaryData: "sample", binaryData: Data("oops".utf8))
    }
    await client.disconnect()
}

@Test func automaticUploadCRCRejectsBadReplies() async throws {
    for (response, description) in [("00000000", "XCRC upload checksum mismatch"), ("not-a-checksum", "Invalid XCRC response")] {
        let server = try LoopbackFTPServer(xcrcResponse: response)
        let client = FTPClientFacade()
        client.hostname = "127.0.0.1"
        client.port = server.port
        client.username = "demo"
        client.password = "secret"
        client.autoFeat = true
        client.autoXcrc = true
        try await client.connect()
        await #expect(throws: FTPError.protocolViolation(description: description)) {
            try await client.putFile(fromBinaryData: "sample", binaryData: Data("123456789".utf8))
        }
        #expect(await client.checkConnection())
        #expect(client.lastReply == "250 \(response)")
        await client.disconnect()
    }
}

@Test func automaticUploadCRCSkipsUnadvertisedExtension() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.autoFeat = true
    client.autoXcrc = true
    client.keepSessionLog = true
    try await client.connect()
    try await client.putFile(fromBinaryData: "sample", binaryData: Data("123".utf8))
    try await client.appendFile(fromBinaryData: "sample", binaryData: Data("4".utf8))
    #expect(!(await client.sessionLog()).contains("> XCRC"))
    #expect(try await client.getRemoteFileBinaryData("sample") == Data("1234".utf8))
    await client.disconnect()
}

@Test func failedSyncChecksumCleansUpStagedUpload() async throws {
    let server = try LoopbackFTPServer(xcrcResponse: "00000000")
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.autoFeat = true
    client.autoXcrc = true
    client.keepSessionLog = true
    try await client.connect()
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    try Data("123456789".utf8).write(to: folder.appendingPathComponent("sample"))
    await #expect(throws: FTPError.protocolViolation(description: "XCRC upload checksum mismatch")) {
        try await client.syncRemoteTree(localRoot: folder.path, mode: 0)
    }
    #expect(await client.checkConnection())
    #expect((await client.sessionLog()).contains("> DELE /remote/.ftp-sync-"))
    #expect(try await client.mlsd("/remote").isEmpty)
    await client.disconnect()
}

@Test func streamedFileRoundTripAndFailedDownloadIsAtomic() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.readTimeout = 5
    try await client.connect()
    try await client.loginAfterConnectOnly()

    let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    let source = folder.appendingPathComponent("source")
    let target = folder.appendingPathComponent("target")
    let original = Data((0..<1_000_123).map { UInt8(truncatingIfNeeded: $0) })
    let uploadProgress = ProgressRecorder()
    let downloadProgress = ProgressRecorder()
    try original.write(to: source)
    try Data("old".utf8).write(to: target)
    try await client.putFile(localPath: source.path, remoteFilename: "sample") { uploadProgress.record($0) }
    try await client.getFile(remoteFilename: "sample", localPath: target.path) { downloadProgress.record($0) }
    for values in [uploadProgress.values, downloadProgress.values] {
        #expect(values.first == 0)
        #expect(values.last == UInt64(original.count))
        #expect(zip(values, values.dropFirst()).allSatisfy { $0 < $1 })
    }
    #expect(try Data(contentsOf: target) == original)
    try Data("suffix".utf8).write(to: source)
    let appendProgress = ProgressRecorder()
    try await client.appendFile(localPath: source.path, remoteFilename: "sample") { appendProgress.record($0) }
    #expect(appendProgress.values == [0, 6])
    try await client.getFile(remoteFilename: "sample", localPath: target.path)
    #expect(try Data(contentsOf: target) == original + Data("suffix".utf8))
    await #expect(throws: FTPError.self) {
        try await client.getFile(remoteFilename: "missing", localPath: target.path)
    }
    #expect(try Data(contentsOf: target) == original + Data("suffix".utf8))
    #expect(try FileManager.default.contentsOfDirectory(atPath: folder.path).sorted() == ["source", "target"])

    try Data().write(to: source)
    let emptyUpload = ProgressRecorder()
    let emptyDownload = ProgressRecorder()
    try await client.putFile(localPath: source.path, remoteFilename: "sample") { emptyUpload.record($0) }
    try await client.getFile(remoteFilename: "sample", localPath: target.path) { emptyDownload.record($0) }
    #expect(emptyUpload.values == [0])
    #expect(emptyDownload.values == [0])
    #expect(try Data(contentsOf: target).isEmpty)
    await client.disconnect()
}

@Test func extendedPassiveModeWorksOverIPv6() async throws {
    let server = try LoopbackFTPServer(ipv6: true)
    let channel = FTPControlChannel()
    let configuration = FTPClientConfiguration(host: "::1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
    try await channel.connect(configuration: configuration)
    try await channel.login()
    let names = try await channel.listNames()
    #expect(names == [" file with spaces ", "second"])
    await channel.disconnect()
}

@Test func activeFTPTransfersOverIPv4AndIPv6() async throws {
    for (ipv6, supportsEPRT, unexpectedPeer) in [(false, true, true), (false, false, false), (true, true, false)] {
        let server = try LoopbackFTPServer(ipv6: ipv6, supportsEPRT: supportsEPRT, injectUnexpectedPeer: unexpectedPeer)
        let channel = FTPControlChannel()
        let config = FTPClientConfiguration(host: ipv6 ? "::1" : "127.0.0.1", port: server.port, username: "demo", password: "secret", dataConnectionMode: .active, connectTimeout: 3, readTimeout: 3)
        try await channel.connect(configuration: config)
        try await channel.login()
        #expect(try await channel.listNames() == [" file with spaces ", "second"])
        let payload = Data((0..<100_123).map { UInt8(truncatingIfNeeded: $0) })
        try await channel.storeFileData(payload, remotePath: "sample")
        #expect(try await channel.retrieveFileData(remotePath: "sample") == payload)
        try await channel.noop()
        await channel.disconnect()
    }
}

@Test func activeFTPRejectsUnsupportedIPv6AndTimesOut() async throws {
    let server = try LoopbackFTPServer(ipv6: true, supportsEPRT: false)
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "::1", port: server.port, username: "demo", password: "secret", dataConnectionMode: .active, connectTimeout: 5, readTimeout: 10)
    try await channel.connect(configuration: config)
    try await channel.login()
    await #expect(throws: FTPError.serverReply(code: 502, message: "502 Unsupported")) { try await channel.listNames() }
    try await channel.noop()
    await channel.disconnect()

    let stalledServer = try LoopbackFTPServer(refuseActiveConnection: true)
    let stalled = FTPControlChannel()
    let stalledConfig = FTPClientConfiguration(host: "127.0.0.1", port: stalledServer.port, username: "demo", password: "secret", dataConnectionMode: .active, connectTimeout: 0.2, readTimeout: 10)
    try await stalled.connect(configuration: stalledConfig)
    try await stalled.login()
    await #expect(throws: FTPError.timeout(operation: "active data connection")) { try await stalled.listNames() }
    #expect(await stalled.isConnected == false)
}

@Test func facadeUsesActiveFTP() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.passive = false
    try await client.connect()
    try await client.loginAfterConnectOnly()
    #expect(try await client.nlst() == [" file with spaces ", "second"])
    await client.disconnect()
}

@Test func fallsBackToLegacyListAndCachesListing() async throws {
    let server = try LoopbackFTPServer(supportsMLSD: false)
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.keepSessionLog = true
    try await client.connect()
    try await client.loginAfterConnectOnly()
    #expect(try await client.getDirCount() == 1)
    #expect(try await client.getFilename(0) == "sample")
    #expect(try await client.getOwner(0) == "owner")
    #expect(try await client.getPermissions(0) == "rw-r--r--")
    client.listPattern = "*.TXT"
    #expect(try await client.getDirCount() == 0)
    let log = await client.sessionLog()
    #expect(log.contains("MLSD"))
    #expect(log.contains("LIST"))
    #expect(!log.contains("secret"))
    #expect(!log.contains("demo"))
    await client.clearSessionLog()
    #expect(await client.sessionLog().isEmpty)
    await client.disconnect()
}

@Test func facadeUsesCachedMetadataByIndexAndName() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    try await client.connect()
    try await client.loginAfterConnectOnly()
    #expect(try await client.getDirCount() == 1)
    #expect(try await client.getFilename(index: 0) == "sample")
    #expect(try await client.getSize64(index: 0) == 6)
    #expect(try await client.getSize64(byName: "sample") == 6)
    #expect(try await client.getSizeStr(byName: "sample") == "6")
    #expect(try await client.getPermissions(index: 0) == "rad")
    #expect(try await client.getPermType(index: 0) == "mlsd")
    #expect(try await client.getLastModifiedTimeStr(index: 0) == client.getLastModifiedTime(byNameStr: "sample"))
    #expect(try await client.getCreateTimeStr(index: 0) == client.getCreateTime(byNameStr: "sample"))
    #expect(try await client.getCreateTimeStr(index: 0) != client.getLastModifiedTimeStr(index: 0))
    await #expect(throws: FTPError.self) { try await client.getSize64(byName: "../sample") }
    await client.disconnect()
}

@Test func facadeSupportsListingPreferencesAndOptions() async throws {
    let server = try LoopbackFTPServer(supportsMLSD: false)
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.keepSessionLog = true
    client.preferNlst = true
    try await client.connect()
    try await client.loginAfterConnectOnly()
    #expect(try await client.getDirCount() == 2)
    #expect(try await client.getFilename(index: 0) == " file with spaces ")
    await #expect(throws: FTPError.invalidState(description: "Listing does not identify entry types")) {
        try await client.getIsDirectory(index: 0)
    }
    client.clearDirCache()
    client.allowMlsd = false
    client.preferNlst = false
    client.listOption = "-a"
    #expect(try await client.getDirCount() == 1)
    #expect(try await client.getFilename(index: 0) == "sample")
    #expect((await client.sessionLog()).contains("> LIST -a"))
    await client.disconnect()
}

@Test func timestampSetterFallsBackToLegacyMDTMWhenUnsupported() async throws {
    let server = try LoopbackFTPServer(unsupportedMFMT: true)
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
    await channel.setSessionLogging(true)
    try await channel.connect(configuration: config)
    try await channel.login()
    try await channel.setModificationTime(Date(timeIntervalSince1970: 1_704_164_645), path: "sample")
    let log = await channel.sessionLog()
    #expect(log.contains("MFMT 20240102030405 sample"))
    #expect(log.contains("MDTM 20240102030405 sample"))
    await channel.disconnect()
}

@Test func syncMirrorPreviewsAndDeletesOnlySelectedFiles() async throws {
    let server = try LoopbackFTPServer()
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
    try await channel.connect(configuration: config)
    try await channel.login()
    try await channel.storeFileData(Data("old".utf8), remotePath: "/remote/obsolete.txt")
    try await channel.storeFileData(Data("keep".utf8), remotePath: "/remote/keep.tmp")
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let engine = FTPSyncEngine(channel: channel)
    var plan = FTPSyncPlan(direction: .localToRemote, mode: .mirrorWithDelete, localRootPath: root.path, remoteRootPath: "/remote", filter: FTPSyncFilter(includePatterns: ["*.txt"]), dryRun: true)
    let preview = try await engine.run(plan)
    #expect(preview.map(\.relativePath) == ["obsolete.txt"])
    #expect(preview.map(\.action) == [.deleteRemoteFile])
    #expect(try await channel.listEntries(path: "/remote").count == 2)
    plan.dryRun = false
    #expect(try await engine.run(plan) == preview)
    #expect(try await channel.listEntries(path: "/remote").map(\.name) == ["keep.tmp"])
    await channel.disconnect()
}

@Test func syncMirrorDeletesSelectedLocalFilesOnly() async throws {
    let server = try LoopbackFTPServer()
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
    try await channel.connect(configuration: config)
    try await channel.login()
    try await channel.makeDirectory(path: "/remote/nested")
    try await channel.storeFileData(Data("keep".utf8), remotePath: "/remote/nested/keep.txt")
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let nested = root.appendingPathComponent("nested")
    try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try Data("keep".utf8).write(to: nested.appendingPathComponent("keep.txt"))
    try Data("obsolete".utf8).write(to: nested.appendingPathComponent("obsolete.txt"))
    try Data("excluded".utf8).write(to: nested.appendingPathComponent("excluded.tmp"))
    let engine = FTPSyncEngine(channel: channel)
    let plan = FTPSyncPlan(direction: .remoteToLocal, mode: .deleteDestinationOnly, localRootPath: root.path, remoteRootPath: "/remote", filter: FTPSyncFilter(includePatterns: ["*.txt"]))
    let operations = try await engine.run(plan)
    #expect(operations.map(\.action) == [.deleteLocalFile])
    #expect(operations.map(\.relativePath) == ["nested/obsolete.txt"])
    #expect(try FileManager.default.contentsOfDirectory(atPath: nested.path).sorted() == ["excluded.tmp", "keep.txt"])
    await channel.disconnect()
}

@Test func synchronizationPreservesModificationTimesWhenRequested() async throws {
    let server = try LoopbackFTPServer()
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
    await channel.setSessionLogging(true)
    try await channel.connect(configuration: config)
    try await channel.login()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let source = root.appendingPathComponent("source")
    let target = root.appendingPathComponent("target")
    try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let sourceFile = source.appendingPathComponent("file.txt")
    try Data("timestamped".utf8).write(to: sourceFile)
    let expected = Date(timeIntervalSince1970: 1_704_164_645)
    try FileManager.default.setAttributes([.modificationDate: expected], ofItemAtPath: sourceFile.path)
    let engine = FTPSyncEngine(channel: channel)
    let upload = FTPSyncPlan(direction: .localToRemote, mode: .all, localRootPath: source.path, remoteRootPath: "/remote", preserveModificationTimes: true)
    let actions = try await engine.run(upload)
    #expect(actions.first?.sourceModificationTime == expected)
    let log = await channel.sessionLog()
    #expect(log.contains("MFMT 20240102030405 /remote/.ftp-sync-"))
    let download = FTPSyncPlan(direction: .remoteToLocal, mode: .all, localRootPath: target.path, remoteRootPath: "/remote", preserveModificationTimes: true)
    try await engine.run(download)
    let targetFile = target.appendingPathComponent("file.txt")
    #expect(try Data(contentsOf: targetFile) == Data("timestamped".utf8))
    let result = try #require(targetFile.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate)
    #expect(abs(result.timeIntervalSince(expected)) < 0.001)
    await channel.disconnect()
}

@Test func facadeCanPreserveDownloadModificationTime() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.preserveDownloadModificationTime = true
    try await client.connect()
    try await client.loginAfterConnectOnly()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let file = root.appendingPathComponent("sample")
    try await client.getFile(remoteFilename: "sample", localPath: file.path)
    let modified = try #require(file.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate)
    #expect(abs(modified.timeIntervalSince1970 - 1_704_164_645.5) < 0.001)
    await client.disconnect()
}

@Test func invalidDownloadTimestampPreservesDestination() async throws {
    let server = try LoopbackFTPServer()
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
    try await channel.connect(configuration: config)
    try await channel.login()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let file = root.appendingPathComponent("sample")
    try Data("original".utf8).write(to: file)
    await #expect(throws: FTPError.invalidState(description: "Invalid file modification time")) {
        try await channel.downloadFile(remotePath: "sample", to: file, modificationTime: Date(timeIntervalSince1970: 1e15))
    }
    #expect(try Data(contentsOf: file) == Data("original".utf8))
    #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["sample"])
    await channel.disconnect()
}

@Test func failedSyncTimestampDoesNotPublishTemporaryUpload() async throws {
    let server = try LoopbackFTPServer(failSetModificationTime: true)
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
    try await channel.connect(configuration: config)
    try await channel.login()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try Data("data".utf8).write(to: root.appendingPathComponent("file.txt"))
    let engine = FTPSyncEngine(channel: channel)
    let plan = FTPSyncPlan(direction: .localToRemote, mode: .all, localRootPath: root.path, remoteRootPath: "/remote", preserveModificationTimes: true)
    await #expect(throws: FTPError.serverReply(code: 550, message: "550 Timestamp unsupported")) { try await engine.run(plan) }
    #expect(try await channel.listEntries(path: "/remote").isEmpty)
    await channel.disconnect()
}

@Test func ftpStreamAndRepresentationModes() async throws {
    let server = try LoopbackFTPServer()
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 10, readTimeout: 10, autoSyst: true, autoFeat: true)
    try await channel.connect(configuration: config)
    try await channel.login()
    #expect(await channel.serverFeatures.contains("UTF8"))
    #expect(await channel.serverFeatures.contains("MODEZ"))
    try await channel.setTransferType(.ascii)
    await #expect(throws: FTPError.self) { try await channel.retrieveFileData(remotePath: "sample", restartOffset: 1) }
    try await channel.setTransferType(.binary)
    let source = AsyncThrowingStream<Data, Error> { continuation in
        continuation.yield(Data("abc".utf8))
        continuation.yield(Data("def".utf8))
        continuation.finish()
    }
    try await channel.uploadStream(remotePath: "sample", source: source)
    actor Sink { var data = Data(); func append(_ chunk: Data) { data.append(chunk) } }
    let sink = Sink()
    try await channel.downloadStream(remotePath: "sample") { await sink.append($0) }
    #expect(await sink.data == Data("abcdef".utf8))
    await channel.disconnect()
}

@Test func ftpExportReproducesLegacyUploadWorkflow() async throws {
    let server = try LoopbackFTPServer()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let source = root.appendingPathComponent("recording.m4a")
    let payload = Data([0, 10, 13, 255, 65, 66, 77])
    try payload.write(to: source)
    let progress = ProgressRecorder()
    let result = try await FTPExport.upload(
        file: source,
        remoteFilename: "exported.m4a",
        options: FTPExportOptions(username: "demo", password: "secret", host: "ftp://127.0.0.1", port: server.port, remoteDirectory: "/remote", passive: true),
        progress: { total, processed in
            #expect(total == 7)
            progress.record(processed)
        })
    #expect(result.remotePath == "exported.m4a")
    #expect(result.sentBytes == 7)
    #expect(progress.values.first == 0 && progress.values.last == 7)
}

@Test func transferBufferLimitAndThrottleAreEnforced() async throws {
    let server = try LoopbackFTPServer()
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3, bandwidthThrottleUp: 100, maximumBufferedBytes: 4)
    try await channel.connect(configuration: config)
    try await channel.login()
    let clock = ContinuousClock()
    let start = clock.now
    try await channel.storeFileData(Data("0123456789".utf8), remotePath: "sample")
    #expect(start.duration(to: clock.now) >= .milliseconds(80))
    await #expect(throws: FTPError.invalidState(description: "Buffered FTP response exceeds configured limit")) {
        try await channel.retrieveFileData(remotePath: "sample")
    }
    #expect(await channel.isConnected == false)
}

@Test func facadeSyncModesAndOneShotTransferOptions() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.keepSessionLog = true
    try await client.connect()
    try await client.loginAfterConnectOnly()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root.appendingPathComponent("empty"), withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try Data("hello".utf8).write(to: root.appendingPathComponent("A.TXT"))
    client.syncMustMatch = "*.txt"
    try await client.syncRemoteTree2(localRoot: root.path, mode: 1, descend: true, previewOnly: true)
    #expect(client.syncedFiles == ["A.TXT"])
    #expect(client.syncPreview.contains("A.TXT"))
    #expect(try await client.mlsd("/remote").isEmpty)
    try await client.syncRemoteTree(localRoot: root.path, mode: 0)
    #expect(try await client.mlsd("/remote").map(\.name).sorted() == ["A.TXT", "empty"])
    client.allocateSize = 3
    try await client.putFile(fromBinaryData: "sample", binaryData: Data("abc".utf8))
    #expect(client.allocateSize == 0)
    #expect((await client.sessionLog()).contains("ALLO 3"))
    client.restartNext = true
    try await client.putFile(fromBinaryData: "sample", binaryData: Data("abcdef".utf8))
    #expect(!client.restartNext)
    #expect(try await client.getRemoteFileBinaryData("sample") == Data("abcdef".utf8))
    var existing = Data("abc".utf8)
    client.restartNext = true
    try await client.getFileBd(remoteFilename: "sample", data: &existing)
    #expect(existing == Data("abcdef".utf8))
    try await client.setTypeAscii()
    try await client.setTypeBinary()
    try await client.setRemoteFileDate(Date(timeIntervalSince1970: 1_704_164_645), remoteFilename: "sample")
    try await client.site("HELP")
    #expect(try await client.stat() == "211 Server status")
    #expect(client.lastReply == "211 Server status")
    await client.disconnect()
}

@Test func nativeMemoryTransferMethodsHandleUnicodeBOMsAndResume() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    try await client.connect()
    let examples: [(String, [UInt8], [UInt8])] = [
        ("utf-8", [0xef, 0xbb, 0xbf], [0x41, 0x42]),
        ("utf-16le", [0xff, 0xfe], [0x41, 0, 0x42, 0]),
        ("utf-16be", [0xfe, 0xff], [0, 0x41, 0, 0x42]),
        ("utf-32le", [0xff, 0xfe, 0, 0], [0x41, 0, 0, 0, 0x42, 0, 0, 0]),
        ("utf-32be", [0, 0, 0xfe, 0xff], [0, 0, 0, 0x41, 0, 0, 0, 0x42])
    ]
    for (charset, marker, content) in examples {
        for include in [false, true] {
            try await client.putFileSb(sb: "AB", charset: charset, includeBom: include, remoteFilePath: "sample")
            let actual = try await client.getRemoteFileBinaryData("sample")
            #expect(actual == Data((include ? marker : []) + content))
        }
    }
    for (charset, encoding, markerLength) in [("utf-16", String.Encoding.utf16, 2), ("utf-32", String.Encoding.utf32, 4)] {
        let foundation = try #require("AB".data(using: encoding))
        try await client.putFileSb(sb: "AB", charset: charset, includeBom: true, remoteFilePath: "sample")
        #expect(try await client.getRemoteFileBinaryData("sample") == foundation)
        try await client.putFileSb(sb: "AB", charset: charset, includeBom: false, remoteFilePath: "sample")
        #expect(try await client.getRemoteFileBinaryData("sample") == Data(foundation.dropFirst(markerLength)))
    }
    try await client.putFileSb(sb: "", charset: "utf-8", includeBom: true, remoteFilePath: "sample")
    #expect(try await client.getRemoteFileBinaryData("sample") == Data([0xef, 0xbb, 0xbf]))
    try await client.appendFileSb(remoteFilename: "sample", sb: "AB", charset: "utf-8")
    try await client.appendFileBd(remoteFilename: "sample", bd: Data([0x21]))
    #expect(try await client.getRemoteFileBinaryData("sample") == Data([0xef, 0xbb, 0xbf, 0x41, 0x42, 0x21]))
    try await client.putFileBd(binData: Data("he".utf8), remoteFilePath: "sample")
    client.restartNext = true
    try await client.putFileSb(sb: "hello", charset: "utf-8", includeBom: false, remoteFilePath: "sample")
    var bytes = Data("he".utf8)
    client.restartNext = true
    try await client.getFileBd(remoteFilePath: "sample", binData: &bytes)
    #expect(bytes == Data("hello".utf8))
    var text = "he"
    client.restartNext = true
    try await client.getFileSb(remoteFilePath: "sample", charset: "utf-8", sb: &text)
    #expect(text == "hello")
    #expect(try await client.getRemoteFileTextData(remoteFilename: "sample") == "hello")
    await #expect(throws: FTPError.self) {
        try await client.putFileSb(sb: "💙", charset: "us-ascii", includeBom: false, remoteFilePath: "sample")
    }
    #expect(try await client.getRemoteFileBinaryData("sample") == Data("hello".utf8))
    await client.disconnect()
}

@Test func streamingCallbacksReportCumulativeProcessedBytes() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    try await client.connect()
    let sent = ProgressRecorder()
    let source = AsyncThrowingStream<Data, Error> { continuation in
        continuation.yield(Data("abc".utf8))
        continuation.yield(Data("defg".utf8))
        continuation.finish()
    }
    try await client.putFileFromStream(remoteFilename: "sample", source: source, progress: { sent.record($0) })
    #expect(sent.values == [0, 3, 7])
    let received = ProgressRecorder()
    let sink = DownloadCollector()
    try await client.getFileToStream(remoteFilename: "sample", progress: { received.record($0) }) { await sink.append($0) }
    #expect(await sink.data == Data("abcdefg".utf8))
    #expect(received.values.first == 0 && received.values.last == 7)
    #expect(received.values == received.values.sorted())
    let emptySent = ProgressRecorder()
    let empty = AsyncThrowingStream<Data, Error> { $0.finish() }
    try await client.putFileFromStream(remoteFilename: "sample", source: empty, progress: { emptySent.record($0) })
    #expect(emptySent.values == [0])
    let emptyReceived = ProgressRecorder()
    try await client.getFileToStream(remoteFilename: "sample", progress: { emptyReceived.record($0) }) { _ in
        Issue.record("Empty download produced a data chunk")
    }
    #expect(emptyReceived.values == [0])
    await client.disconnect()
}

@Test func facadeBulkOperationsAndUploadPlan() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    try await client.connect()
    try await client.loginAfterConnectOnly()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let source = root.appendingPathComponent("source")
    let downloads = root.appendingPathComponent("downloads")
    try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: downloads, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try Data("plan".utf8).write(to: source.appendingPathComponent("planned.txt"))
    let plan = try await client.createPlan(localDir: source.path)
    let log = root.appendingPathComponent("plan.log").path
    try await client.putPlan(plan, planLogFilePath: log)
    try await client.putPlan(plan, planLogFilePath: log)
    #expect(try await client.mlsd("/remote").map(\.name) == ["planned.txt"])
    await #expect(throws: FTPError.self) { try await client.putPlan(plan + " ", planLogFilePath: log) }
    #expect(try await client.mGetFiles(remotePattern: "sample", localDir: downloads.path) == 1)
    #expect(try Data(contentsOf: downloads.appendingPathComponent("sample")) == Data([0,10,13,255,65,66]))
    #expect(try await client.delete(matching: "sample") == 1)
    #expect(try await client.nlstXml().contains("<nlst>"))
    #expect(try await client.getXmlDirListing().contains("<remoteDir>"))
    await client.disconnect()
}

@Test func treeXMLHonorsSyncFiltersAndReportsMetadata() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.keepSessionLog = true
    try await client.connect()
    try await client.createRemoteDir("/remote/KEEP")
    try await client.createRemoteDir("/remote/KEEPtmp")
    try await client.createRemoteDir("/remote/skip")
    try await client.putFile(fromBinaryData: "/remote/root & file.TXT", binaryData: Data("root".utf8))
    try await client.putFile(fromBinaryData: "/remote/ignore.csv", binaryData: Data("ignore".utf8))
    try await client.putFile(fromBinaryData: "/remote/KEEP/inside.txt", binaryData: Data("inside".utf8))
    try await client.putFile(fromBinaryData: "/remote/KEEP/ignore.tmp.txt", binaryData: Data("ignored".utf8))
    try await client.putFile(fromBinaryData: "/remote/skip/hidden.txt", binaryData: Data("hidden".utf8))
    client.syncMustMatch = "*.txt"
    client.syncMustNotMatch = "*.tmp.txt"
    client.syncMustMatchDir = "keep*"
    client.syncMustNotMatchDir = "*tmp*"
    await client.clearSessionLog()
    let tree = try await client.dirTreeXml()
    #expect(tree.contains("root &amp; file.TXT"))
    #expect(tree.contains("<dir name=\"KEEP\">"))
    #expect(tree.contains("inside.txt"))
    #expect(tree.contains(" sz=\"4\""))
    #expect(tree.contains(" dt=\""))
    #expect(!tree.contains("ignore"))
    #expect(!tree.contains("skip"))
    #expect(!tree.contains("KEEPtmp"))
    #expect(!(await client.sessionLog()).contains("> MLSD /remote/skip"))
    let listing = try await client.getXmlDirListing()
    #expect(listing.contains("<lastModTime full=\""))
    await client.disconnect()
}

@Test func treeXMLRejectsInvalidXMLCharacters() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    try await client.connect()
    try await client.putFile(fromBinaryData: "/remote/bad\u{1}.txt", binaryData: Data("x".utf8))
    await #expect(throws: FTPError.invalidState(description: "Filename cannot be represented in XML 1.0")) {
        try await client.dirTreeXml()
    }
    await client.disconnect()
}

@Test func uploadPlanRejectsReplacedSourcesAndUnsafeLogs() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    try await client.connect()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let source = root.appendingPathComponent("source")
    try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let file = source.appendingPathComponent("planned.txt")
    let outside = root.appendingPathComponent("outside")
    let log = root.appendingPathComponent("plan.log")
    try Data("original".utf8).write(to: file)
    try Data("private".utf8).write(to: outside)
    let plan = try await client.createPlan(localDir: source.path)

    try FileManager.default.removeItem(at: file)
    try FileManager.default.createSymbolicLink(at: file, withDestinationURL: outside)
    await #expect(throws: POSIXError.self) { try await client.putPlan(plan, planLogFilePath: log.path) }
    #expect(try await client.mlsd("/remote").isEmpty)
    try FileManager.default.removeItem(at: file)
    #expect(mkfifo(file.path, 0o600) == 0)
    await #expect(throws: FTPError.invalidState(description: "Upload plan source must be a regular file")) {
        try await client.putPlan(plan, planLogFilePath: log.path)
    }
    try FileManager.default.removeItem(at: file)
    try Data("original".utf8).write(to: file)

    let linkLog = root.appendingPathComponent("link.log")
    try FileManager.default.createSymbolicLink(at: linkLog, withDestinationURL: outside)
    await #expect(throws: POSIXError.self) { try await client.putPlan(plan, planLogFilePath: linkLog.path) }
    #expect(try Data(contentsOf: outside) == Data("private".utf8))

    let locked = Darwin.open(log.path, O_RDWR | O_CLOEXEC)
    #expect(locked >= 0)
    guard locked >= 0 else { throw POSIXError(.EIO) }
    #expect(flock(locked, LOCK_EX | LOCK_NB) == 0)
    await #expect(throws: POSIXError.self) { try await client.putPlan(plan, planLogFilePath: log.path) }
    _ = flock(locked, LOCK_UN)
    Darwin.close(locked)

    let handle = try FileHandle(forWritingTo: log)
    try handle.seekToEnd()
    try handle.write(contentsOf: Data("F:unfinished".utf8))
    try handle.close()
    await #expect(throws: FTPError.invalidState(description: "Upload plan log has an incomplete record")) {
        try await client.putPlan(plan, planLogFilePath: log.path)
    }
    #expect(try await client.mlsd("/remote").isEmpty)
    await client.disconnect()
}

@Test func uploadPlanRejectsReplacedDirectories() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    try await client.connect()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let source = root.appendingPathComponent("source")
    let child = source.appendingPathComponent("sub")
    let outside = root.appendingPathComponent("outside")
    try FileManager.default.createDirectory(at: child, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try Data("original".utf8).write(to: child.appendingPathComponent("planned.txt"))
    try Data("private".utf8).write(to: outside.appendingPathComponent("planned.txt"))
    let plan = try await client.createPlan(localDir: source.path)
    let movedRoot = root.appendingPathComponent("original-source")
    try FileManager.default.moveItem(at: source, to: movedRoot)
    try FileManager.default.createSymbolicLink(at: source, withDestinationURL: outside)
    await #expect(throws: POSIXError.self) { try await client.putPlan(plan, planLogFilePath: root.appendingPathComponent("root.log").path) }
    try FileManager.default.removeItem(at: source)
    try FileManager.default.moveItem(at: movedRoot, to: source)
    let movedChild = root.appendingPathComponent("original-sub")
    try FileManager.default.moveItem(at: child, to: movedChild)
    try FileManager.default.createSymbolicLink(at: child, withDestinationURL: outside)
    await #expect(throws: POSIXError.self) { try await client.putPlan(plan, planLogFilePath: root.appendingPathComponent("child.log").path) }
    #expect(try await client.mlsd("/remote/sub").isEmpty)
    await client.disconnect()
}

@Test func wildcardDownloadsRemainAnchoredWhenDestinationIsReplaced() async throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let destination = root.appendingPathComponent("destination")
    let moved = root.appendingPathComponent("moved")
    let outside = root.appendingPathComponent("outside")
    try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let swap = SyncPathSwap()
    let server = try LoopbackFTPServer(onRemoteListing: { swap.perform(original: destination, moved: moved, replacement: outside) })
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    try await client.connect()
    #expect(try await client.mGetFiles(remotePattern: "sample", localDir: destination.path) == 1)
    #expect(swap.result() == nil)
    #expect(try Data(contentsOf: moved.appendingPathComponent("sample")) == Data([0, 10, 13, 255, 65, 66]))
    #expect(try FileManager.default.contentsOfDirectory(atPath: outside.path).isEmpty)
    await client.disconnect()
}

@Test func wildcardDownloadsRejectAmbiguousNamesBeforeWriting() async throws {
    let listing = "-rw-r--r-- 1 owner group 6 Jan 02 2024 sample\r\n-rw-r--r-- 1 owner group 6 Jan 02 2024 SAMPLE\r\n"
    let server = try LoopbackFTPServer(wildcardListing: listing)
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    try await client.connect()
    let destination = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: destination) }
    await #expect(throws: FTPError.invalidState(description: "Ambiguous wildcard download name: SAMPLE")) {
        try await client.mGetFiles(remotePattern: "*", localDir: destination.path)
    }
    #expect(try FileManager.default.contentsOfDirectory(atPath: destination.path).isEmpty)
    await client.disconnect()
}

@Test func wildcardDeleteValidatesEveryNameBeforeDeleting() async throws {
    let listing = "-rw-r--r-- 1 owner group 6 Jan 02 2024 sample\r\n-rw-r--r-- 1 owner group 6 Jan 02 2024 ../unsafe\r\n"
    let server = try LoopbackFTPServer(wildcardListing: listing)
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.keepSessionLog = true
    try await client.connect()
    await client.clearSessionLog()
    await #expect(throws: FTPError.protocolViolation(description: "Unsafe remote entry name")) {
        try await client.delete(matching: "*")
    }
    #expect(!(await client.sessionLog()).contains("> DELE"))
    await client.disconnect()
}

@Test func activePortRangeSkipsOccupiedPort() async throws {
    func bindListener(_ port: Int) -> Int32? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr = in_addr(s_addr: in_addr_t(INADDR_LOOPBACK).bigEndian)
        address.sin_port = UInt16(port).bigEndian
        let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard bound == 0, listen(fd, 1) == 0 else { close(fd); return nil }
        return fd
    }
    var occupied: Int32 = -1
    var port = 0
    let start = Int.random(in: 20_000...39_000)
    for candidate in start..<(start + 500) {
        guard let first = bindListener(candidate) else { continue }
        if let second = bindListener(candidate + 1) {
            close(second)
            occupied = first
            port = candidate
            break
        }
        close(first)
    }
    guard occupied >= 0 else { throw POSIXError(.EADDRINUSE) }
    defer { close(occupied) }
    let server = try LoopbackFTPServer()
    let channel = FTPControlChannel()
    await channel.setSessionLogging(true)
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", dataConnectionMode: .active, connectTimeout: 1, readTimeout: 3, activePortRangeStart: port, activePortRangeEnd: port + 1)
    try await channel.connect(configuration: config)
    try await channel.login()
    #expect(try await channel.listNames() == [" file with spaces ", "second"])
    #expect((await channel.sessionLog()).contains("> EPRT |1|127.0.0.1|\(port + 1)|"))
    await channel.disconnect()
}

@Test func traditionalFTPProxyLoginAndData() async throws {
    let proxy = try LoopbackFTPServer()
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "target.example", username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3, proxy: .traditional(host: "127.0.0.1", port: proxy.port, method: 2))
    try await channel.connect(configuration: config)
    try await channel.login()
    #expect(try await channel.listNames() == [" file with spaces ", "second"])
    await channel.disconnect()
}

@Test func activeFTPDataWaitSupportsCancellation() async throws {
    let (events, continuation) = AsyncStream<Void>.makeStream()
    let server = try LoopbackFTPServer(refuseActiveConnection: true, onActivePreliminary: { continuation.yield(()) })
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", dataConnectionMode: .active, connectTimeout: 10, readTimeout: 10)
    try await channel.connect(configuration: config)
    try await channel.login()
    let task = Task { try await channel.listNames() }
    var iterator = events.makeAsyncIterator()
    _ = await iterator.next()
    let clock = ContinuousClock()
    let start = clock.now
    task.cancel()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(start.duration(to: clock.now) < .seconds(3))
    #expect(await channel.isConnected == false)
    continuation.finish()
}

@Test func doesNotFallBackToPASVOverIPv6() async throws {
    let server = try LoopbackFTPServer(supportsEPSV: false, ipv6: true)
    let channel = FTPControlChannel()
    let configuration = FTPClientConfiguration(host: "::1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
    try await channel.connect(configuration: configuration)
    try await channel.login()
    await #expect(throws: FTPError.serverReply(code: 502, message: "502 Not supported")) {
        try await channel.listNames()
    }
    await channel.disconnect()
}

@Test func failedCompletionPreservesLocalFile() async throws {
    let server = try LoopbackFTPServer(failTransferCompletion: true)
    let channel = FTPControlChannel()
    let configuration = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
    try await channel.connect(configuration: configuration)
    try await channel.login()
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    let target = folder.appendingPathComponent("target")
    let existing = Data("existing".utf8)
    let progress = ProgressRecorder()
    try existing.write(to: target)
    await #expect(throws: FTPError.serverReply(code: 451, message: "451 Transfer failed")) {
        try await channel.downloadFile(remotePath: "sample", to: target) { progress.record($0) }
    }
    #expect(progress.values.first == 0)
    #expect(progress.values.last == 6)
    #expect(try Data(contentsOf: target) == existing)
    #expect(try FileManager.default.contentsOfDirectory(atPath: folder.path) == ["target"])
    #expect(await channel.isConnected == false)
}

@Test func cancellationInterruptsStalledGreeting() async throws {
    let (events, continuation) = AsyncStream<Void>.makeStream()
    let server = try LoopbackFTPServer(suppressGreeting: true, onControlAccepted: { continuation.yield(()) })
    let channel = FTPControlChannel()
    let configuration = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 10, readTimeout: 10)
    let connect = Task { try await channel.connect(configuration: configuration) }
    var iterator = events.makeAsyncIterator()
    _ = await iterator.next()
    let clock = ContinuousClock()
    let start = clock.now
    connect.cancel()
    await #expect(throws: CancellationError.self) { try await connect.value }
    #expect(start.duration(to: clock.now) < .seconds(3))
    #expect(await channel.isConnected == false)
    continuation.finish()
}

@Test func cancellationInterruptsStalledDownloadAndPreservesDestination() async throws {
    let server = try LoopbackFTPServer(stallDownload: true)
    let channel = FTPControlChannel()
    let configuration = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 10, readTimeout: 10)
    try await channel.connect(configuration: configuration)
    try await channel.login()
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    let target = folder.appendingPathComponent("target")
    try Data("existing".utf8).write(to: target)
    let (events, continuation) = AsyncStream<UInt64>.makeStream()
    let transfer = Task {
        try await channel.downloadFile(remotePath: "sample", to: target) { continuation.yield($0) }
    }
    var iterator = events.makeAsyncIterator()
    #expect(await iterator.next() == 0)
    let clock = ContinuousClock()
    let start = clock.now
    transfer.cancel()
    await #expect(throws: CancellationError.self) { try await transfer.value }
    #expect(start.duration(to: clock.now) < .seconds(3))
    #expect(try Data(contentsOf: target) == Data("existing".utf8))
    #expect(try FileManager.default.contentsOfDirectory(atPath: folder.path) == ["target"])
    #expect(await channel.isConnected == false)
    continuation.finish()
}

@Test func rejectsInvalidPortsWithoutTrapping() async {
    let channel = FTPControlChannel()
    let configuration = FTPClientConfiguration(host: "127.0.0.1", port: -1, username: "demo", password: "secret")
    await #expect(throws: FTPError.self) { try await channel.connect(configuration: configuration) }
}

@Test func connectRejectsInvalidCharacterSetAndPortRange() async {
    let channel = FTPControlChannel()
    let badCharset = FTPClientConfiguration(host: "localhost", username: "demo", password: "secret", commandCharset: "utf-16")
    await #expect(throws: FTPError.self) { try await channel.connect(configuration: badCharset) }
    let badRange = FTPClientConfiguration(host: "localhost", username: "demo", password: "secret", activePortRangeStart: -1)
    await #expect(throws: FTPError.self) { try await channel.connect(configuration: badRange) }
}

@Test func resumedDownloadsAreValidatedAndAtomic() async throws {
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    let target = folder.appendingPathComponent("download")
    let prefix = Data([0, 10, 13])
    for mode in 0..<4 {
        let server = try LoopbackFTPServer(failTransferCompletion: mode == 3, supportsRestart: mode != 1, ignoresRestart: mode == 2)
        let channel = FTPControlChannel()
        let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
        try await channel.connect(configuration: config)
        try await channel.login()
        try prefix.write(to: target)
        let progress = ProgressRecorder()
        if mode == 0 {
            try await channel.downloadFile(remotePath: "sample", to: target, resume: true) { progress.record($0) }
            #expect(try Data(contentsOf: target) == Data([0, 10, 13, 255, 65, 66]))
            #expect(progress.values.first == 0)
            #expect(progress.values.last == 3)
            try await channel.downloadFile(remotePath: "sample", to: target, resume: true)
            #expect(try Data(contentsOf: target) == Data([0, 10, 13, 255, 65, 66]))
            try Data().write(to: target)
            try await channel.downloadFile(remotePath: "sample", to: target, resume: true)
            #expect(try Data(contentsOf: target) == Data([0, 10, 13, 255, 65, 66]))
            try Data(repeating: 1, count: 7).write(to: target)
            await #expect(throws: FTPError.invalidState(description: "Local resume prefix exceeds remote size")) {
                try await channel.downloadFile(remotePath: "sample", to: target, resume: true)
            }
            #expect(try Data(contentsOf: target) == Data(repeating: 1, count: 7))
            try FileManager.default.removeItem(at: target)
            await #expect(throws: POSIXError.self) { try await channel.downloadFile(remotePath: "sample", to: target, resume: true) }
            try FileManager.default.createSymbolicLink(at: target, withDestinationURL: URL(fileURLWithPath: "/tmp"))
            await #expect(throws: POSIXError.self) { try await channel.downloadFile(remotePath: "sample", to: target, resume: true) }
            try FileManager.default.removeItem(at: target)
            try prefix.write(to: target)
        } else if mode == 1 {
            await #expect(throws: FTPError.serverReply(code: 502, message: "502 Restart unavailable")) {
                try await channel.downloadFile(remotePath: "sample", to: target, resume: true)
            }
            #expect(try Data(contentsOf: target) == prefix)
        } else {
            await #expect(throws: FTPError.self) { try await channel.downloadFile(remotePath: "sample", to: target, resume: true) }
            #expect(try Data(contentsOf: target) == prefix)
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: folder.path) == ["download"])
        await channel.disconnect()
    }
}

@Test func uploadResumeValidatesOffsetsAndServerBehavior() async throws {
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    let source = folder.appendingPathComponent("source")
    let content = Data([0, 10, 13, 255, 65, 66])
    try content.write(to: source)
    for mode in 0..<3 {
        let server = try LoopbackFTPServer(supportsRestart: mode != 1, ignoresRestart: mode == 2)
        let channel = FTPControlChannel()
        let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
        try await channel.connect(configuration: config)
        try await channel.login()
        try await channel.storeFileData(Data(content.prefix(3)), remotePath: "sample")
        let progress = ProgressRecorder()
        if mode == 0 {
            try await channel.uploadFile(from: source, remotePath: "sample", resume: true) { progress.record($0) }
            #expect(try await channel.retrieveFileData(remotePath: "sample") == content)
            #expect(progress.values.first == 0)
            #expect(progress.values.last == 3)
            let completeProgress = ProgressRecorder()
            try await channel.uploadFile(from: source, remotePath: "sample", resume: true) { completeProgress.record($0) }
            #expect(completeProgress.values == [0])
            #expect(try await channel.retrieveFileData(remotePath: "sample") == content)
            try await channel.storeFileData(Data(), remotePath: "sample")
            try await channel.uploadFile(from: source, remotePath: "sample", resume: true)
            #expect(try await channel.retrieveFileData(remotePath: "sample") == content)
            try Data([0]).write(to: source)
            await #expect(throws: FTPError.invalidState(description: "Remote resume prefix exceeds local size")) {
                try await channel.uploadFile(from: source, remotePath: "sample", resume: true)
            }
            #expect(try await channel.retrieveFileData(remotePath: "sample") == content)
            try content.write(to: source)
            await #expect(throws: FTPError.invalidState(description: "Append and resume cannot both be enabled")) {
                try await channel.uploadFile(from: source, remotePath: "sample", append: true, resume: true)
            }
            await #expect(throws: FTPError.serverReply(code: 550, message: "550 Not found")) {
                try await channel.uploadFile(from: source, remotePath: "missing", resume: true)
            }
            await #expect(throws: FTPError.invalidState(description: "Resume source must be a regular file")) {
                try await channel.uploadFile(from: folder, remotePath: "sample", resume: true)
            }
        } else if mode == 1 {
            await #expect(throws: FTPError.serverReply(code: 502, message: "502 Restart unavailable")) {
                try await channel.uploadFile(from: source, remotePath: "sample", resume: true)
            }
            #expect(try await channel.retrieveFileData(remotePath: "sample") == Data(content.prefix(3)))
        } else {
            await #expect(throws: FTPError.protocolViolation(description: "Resumed upload size does not match local file")) {
                try await channel.uploadFile(from: source, remotePath: "sample", resume: true)
            }
            #expect(await channel.isConnected == false)
        }
        await channel.disconnect()
    }
}

@Test func uploadResumeRejectsFailedCompletion() async throws {
    let server = try LoopbackFTPServer(failTransferCompletion: true)
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
    try await channel.connect(configuration: config)
    try await channel.login()
    let source = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: source) }
    let original = Data([0, 10, 13, 255, 65, 66, 77])
    try original.write(to: source)
    await #expect(throws: FTPError.serverReply(code: 451, message: "451 Transfer failed")) {
        try await channel.uploadFile(from: source, remotePath: "sample", resume: true)
    }
    #expect(try Data(contentsOf: source) == original)
    #expect(await channel.isConnected == false)
}

@Test func synchronizationPreviewsAndTransfersBothDirections() async throws {
    let server = try LoopbackFTPServer()
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 10, readTimeout: 10)
    try await channel.connect(configuration: config)
    try await channel.login()
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let source = folder.appendingPathComponent("source")
    let target = folder.appendingPathComponent("target")
    defer { try? FileManager.default.removeItem(at: folder) }
    try FileManager.default.createDirectory(at: source.appendingPathComponent("sub"), withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
    let content = Data("hello sync".utf8)
    try content.write(to: source.appendingPathComponent("sub/file.txt"))
    try Data("excluded".utf8).write(to: source.appendingPathComponent("skip.tmp"))
    let engine = FTPSyncEngine(channel: channel)
    var plan = FTPSyncPlan(direction: .localToRemote, mode: .sizeOnly, localRootPath: source.path, remoteRootPath: "/remote", filter: FTPSyncFilter(includePatterns: ["*.txt"]), dryRun: true)
    let preview = try await engine.run(plan)
    #expect(preview.map(\.relativePath) == ["sub", "sub/file.txt"])
    #expect(preview.map(\.action) == [.createRemoteDirectory, .upload])
    #expect(try await channel.listEntries(path: "/remote").isEmpty)
    plan.dryRun = false
    #expect(try await engine.run(plan) == preview)
    #expect(try await engine.preview(plan).isEmpty)
    let download = FTPSyncPlan(direction: .remoteToLocal, mode: .sizeOnly, localRootPath: target.path, remoteRootPath: "/remote")
    let incoming = try await engine.run(download)
    #expect(incoming.map(\.action) == [.createLocalDirectory, .download])
    #expect(try Data(contentsOf: target.appendingPathComponent("sub/file.txt")) == content)
    #expect(try await engine.preview(download).isEmpty)
    await channel.disconnect()
}

@Test func synchronizationRejectsLocalSymlinks() async throws {
    let channel = FTPControlChannel()
    let engine = FTPSyncEngine(channel: channel)
    var plan = FTPSyncPlan(direction: .localToRemote, mode: .sizeOnly, localRootPath: "/tmp", remoteRootPath: "/remote")
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: folder) }
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    try FileManager.default.createSymbolicLink(at: folder.appendingPathComponent("link"), withDestinationURL: URL(fileURLWithPath: "/tmp"))
    plan.localRootPath = folder.path
    await #expect(throws: FTPError.invalidState(description: "Unsupported local entry: link")) { try await engine.preview(plan) }
}

@Test func synchronizationRejectsDirectorySwapAfterPlanning() async throws {
    for direction in [FTPSyncDirection.localToRemote, .remoteToLocal] {
        let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let root = base.appendingPathComponent("root")
        let nested = root.appendingPathComponent("nested")
        let moved = root.appendingPathComponent("moved")
        let outside = base.appendingPathComponent("outside")
        defer { try? FileManager.default.removeItem(at: base) }
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try Data("local".utf8).write(to: nested.appendingPathComponent("file"))
        let sentinel = outside.appendingPathComponent("file")
        try Data("outside-secret".utf8).write(to: sentinel)
        let swap = SyncPathSwap()
        let server = try LoopbackFTPServer(onRemoteListing: { swap.perform(original: nested, moved: moved, replacement: outside) })
        let channel = FTPControlChannel()
        await channel.setSessionLogging(true)
        let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
        try await channel.connect(configuration: config)
        try await channel.login()
        try await channel.makeDirectory(path: "/remote/nested")
        if direction == .remoteToLocal {
            try await channel.storeFileData(Data("remote".utf8), remotePath: "/remote/nested/file")
        }
        await channel.clearSessionLog()
        let plan = FTPSyncPlan(direction: direction, mode: .all, localRootPath: root.path, remoteRootPath: "/remote")
        await #expect(throws: Error.self) { try await FTPSyncEngine(channel: channel).run(plan) }
        #expect(swap.result() == nil)
        #expect(try Data(contentsOf: sentinel) == Data("outside-secret".utf8))
        let log = await channel.sessionLog()
        #expect(!log.contains("> STOR /remote/nested/.ftp-sync-"))
        #expect(!log.contains("> RETR /remote/nested/file"))
        await channel.disconnect()
    }
}

@Test func synchronizationRejectsCaseAndUnicodeNameCollisions() async throws {
    for unicode in [false, true] {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let localName = unicode ? "é.txt" : "FILE.txt"
        try Data("local".utf8).write(to: root.appendingPathComponent(localName))
        let actualName = try #require(FTPSafeLocalTree(root: root).snapshotDirectory("").first?.name)
        let composed = "é.txt", decomposed = "e\u{301}.txt"
        let remoteName = unicode ? (actualName.utf8.elementsEqual(composed.utf8) ? decomposed : composed) : "file.txt"
        #expect(!actualName.utf8.elementsEqual(remoteName.utf8))
        let server = try LoopbackFTPServer()
        let channel = FTPControlChannel()
        await channel.setSessionLogging(true)
        let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
        try await channel.connect(configuration: config)
        try await channel.login()
        try await channel.storeFileData(Data("remote".utf8), remotePath: "/remote/\(remoteName)")
        await channel.clearSessionLog()
        for direction in [FTPSyncDirection.localToRemote, .remoteToLocal] {
            let plan = FTPSyncPlan(direction: direction, mode: .all, localRootPath: root.path, remoteRootPath: "/remote")
            await #expect(throws: FTPError.self) { try await FTPSyncEngine(channel: channel).run(plan) }
        }
        let log = await channel.sessionLog()
        #expect(!log.contains("> STOR "))
        #expect(!log.contains("> RETR "))
        #expect(try Data(contentsOf: root.appendingPathComponent(localName)) == Data("local".utf8))
        await channel.disconnect()
    }
}

@Test func atomicDownloadAnchorsParentDuringDirectorySwap() async throws {
    let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let nested = base.appendingPathComponent("nested")
    let moved = base.appendingPathComponent("moved")
    let outside = base.appendingPathComponent("outside")
    defer { try? FileManager.default.removeItem(at: base) }
    try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    let sentinel = outside.appendingPathComponent("file")
    try Data("protected".utf8).write(to: sentinel)
    let server = try LoopbackFTPServer()
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
    try await channel.connect(configuration: config)
    try await channel.login()
    let swap = SyncPathSwap()
    try await channel.downloadFile(remotePath: "sample", to: nested.appendingPathComponent("file")) { _ in
        swap.perform(original: nested, moved: moved, replacement: outside)
    }
    #expect(swap.result() == nil)
    #expect(try Data(contentsOf: sentinel) == Data("protected".utf8))
    #expect(try Data(contentsOf: moved.appendingPathComponent("file")) == Data([0,10,13,255,65,66]))
    await channel.disconnect()
}

@Test func synchronizationComparisonsAndConflicts() async throws {
    let server = try LoopbackFTPServer()
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3)
    try await channel.connect(configuration: config)
    try await channel.login()
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    let file = folder.appendingPathComponent("file.txt")
    try Data("one".utf8).write(to: file)
    let engine = FTPSyncEngine(channel: channel)
    var plan = FTPSyncPlan(direction: .localToRemote, mode: .sizeOnly, localRootPath: folder.path, remoteRootPath: "/remote")
    try await engine.run(plan)
    let remoteDate = Date(timeIntervalSince1970: 1_704_164_645) // 2024-01-02 03:04:05 UTC
    try FileManager.default.setAttributes([.modificationDate: remoteDate.addingTimeInterval(-10)], ofItemAtPath: file.path)
    try Data("longer".utf8).write(to: file)
    try FileManager.default.setAttributes([.modificationDate: remoteDate.addingTimeInterval(-10)], ofItemAtPath: file.path)
    plan.mode = .sizeAndNewer
    #expect(try await engine.preview(plan).isEmpty)
    plan.mode = .sizeOnly
    #expect(try await engine.preview(plan).map(\.action) == [.upload])
    plan.mode = .newerOnly
    #expect(try await engine.preview(plan).isEmpty)
    try FileManager.default.setAttributes([.modificationDate: remoteDate], ofItemAtPath: file.path)
    #expect(try await engine.preview(plan).isEmpty)
    try FileManager.default.setAttributes([.modificationDate: remoteDate.addingTimeInterval(0.5)], ofItemAtPath: file.path)
    #expect(try await engine.preview(plan).map(\.action) == [.upload])
    plan.mode = .existingNewer
    #expect(try await engine.preview(plan).map(\.action) == [.upload])
    plan.mode = .sizeAndNewer
    #expect(try await engine.preview(plan).map(\.action) == [.upload])
    try FileManager.default.setAttributes([.modificationDate: remoteDate.addingTimeInterval(10)], ofItemAtPath: file.path)
    plan.mode = .sizeAndNewer
    #expect(try await engine.preview(plan).map(\.action) == [.upload])
    plan.filter.excludePatterns = ["*.txt"]
    #expect(try await engine.preview(plan).isEmpty)
    plan.filter.excludePatterns = []
    try FileManager.default.removeItem(at: file)
    try FileManager.default.createDirectory(at: file, withIntermediateDirectories: false)
    try Data("nested".utf8).write(to: file.appendingPathComponent("nested.txt"))
    await #expect(throws: FTPError.invalidState(description: "File/directory conflict: file.txt")) {
        try await engine.preview(plan)
    }
    await channel.disconnect()
}
@Test func sessionLogRedactionCanBeDisabledAndReenabled() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClient(configuration: FTPClientConfiguration(
        host: "127.0.0.1", port: server.port, username: "demo", password: "secret",
        redactSensitiveInformation: false
    ))
    await client.setSessionLogging(true)
    try await client.connect()
    let unredacted = await client.sessionLog()
    #expect(unredacted.contains("> USER demo"))
    #expect(unredacted.contains("> PASS secret"))
    await client.setRedactSensitiveInformation(true)
    await client.clearSessionLog()
    _ = try await client.sendRawCommand("USER demo")
    _ = try await client.sendRawCommand("PASS secret")
    let redacted = await client.sessionLog()
    #expect(redacted.contains("> USER [redacted]"))
    #expect(redacted.contains("> PASS [redacted]"))
    #expect(!redacted.contains("secret"))
    #expect(!redacted.contains("demo"))
    await client.disconnect()
}
@Test func emptyUsernameSendsAnonymousAndPreservesPassword() async throws {
    let server = try LoopbackFTPServer()
    let client = FTPClient(configuration: FTPClientConfiguration(
        host: "127.0.0.1", port: server.port, username: "", password: "supplied-password",
        redactSensitiveInformation: false
    ))
    await client.setSessionLogging(true)
    try await client.connect()
    let log = await client.sessionLog()
    #expect(log.contains("> USER anonymous"))
    #expect(log.contains("> PASS supplied-password"))
    #expect(await client.isAuthenticated())
    await client.disconnect()
}
#endif
