import Foundation
import Darwin
import CryptoKit
import FTPClientCore
import FTPClientSecurity
import FTPClientSync

public final class FTPClientFacade: @unchecked Sendable {
    public var hostname: String
    public var port: Int
    public var username: String
    public var password: String
    public var account: String?
    public var authTls: Bool
    public var authSsl: Bool
    public var implicitTls: Bool
    /// Apply conventional FTP/FTPS port settings when connecting.
    public var autoFix: Bool
    public var passive: Bool
    /// `control` and `private` protect FTPS data; `clear` explicitly permits unencrypted data.
    public var dataProtection: String
    public var enableTLSSessionResumption: Bool
    public var connectTimeout: TimeInterval
    public var readTimeout: TimeInterval
    public var requireSslCertVerify: Bool
    public var trustedRootCertificates: [Data]
    public var clientIdentity: FTPClientIdentity?
    public var pinnedPublicKeyHashes: [String]
    public var certificateRequirements: [FTPCertificateRequirement]
    public var proxy: FTPProxy?
    public var httpProxyHostname: String
    public var httpProxyPort: Int
    public var httpProxyUsername: String
    public var httpProxyPassword: String
    public var httpProxyAuthMethod: String
    public var httpProxyDomain: String
    public var socksHostname: String
    public var socksPort: Int
    public var socksUsername: String
    public var socksPassword: String
    public var socksVersion: Int
    public var proxyHostname: String
    public var proxyPort: Int
    public var proxyUsername: String
    public var proxyPassword: String
    public var proxyMethod: Int
    public var minimumTLSVersion: FTPTLSMinimumVersion
    public var maximumTLSVersion: FTPTLSMinimumVersion?
    public var allowedCipherSuites: [String]
    public var sslProtocol: String
    public var tlsPinSet: String
    public var sslAllowedCiphers: String
    public var ssl: Bool { get { implicitTls } set { implicitTls = newValue } }
    public var useEpsv: Bool
    public var passiveUseHostAddr: Bool
    public var clientIpAddress: String
    public var legacyListingTimeZoneIdentifier: String?
    public var maximumBufferedBytes: Int
    public var preserveDownloadModificationTime: Bool
    public var preserveSyncModificationTimes: Bool
    public var enableSecrets: Bool
    public var bandwidthThrottleUp: UInt64
    public var bandwidthThrottleDown: UInt64
    /// Send a NOOP once per minute while a transfer is active.
    public var largeFileMeasures: Bool
    /// Optional interval override for long-transfer keepalives.
    public var transferKeepAliveInterval: TimeInterval?
    public var activePortRangeStart: Int
    public var activePortRangeEnd: Int
    public var forcePortIpAddress: String
    public var transferType: FTPTransferType
    /// ASCII download conversion: 0 unchanged, 1 CRLF, 2 LF, 3 CR.
    public var crlfMode: Int
    public var commandCharset: String
    public var dirListingCharset: String
    public var replyCharset: String
    public var autoSyst: Bool
    public var autoFeat: Bool
    public var autoXcrc: Bool
    public var autoOptsUtf8: Bool
    public var restartNext: Bool
    /// Fetch SIZE before a binary file download when no explicit size is supplied.
    public var autoGetSizeForProgress: Bool
    /// Expected logical bytes for the next file download; zero means unspecified.
    public var progressMonSize64: UInt64
    public var progressMonSize: Int {
        get { Int(clamping: progressMonSize64) }
        set { progressMonSize64 = UInt64(max(0, newValue)) }
    }
    public var allocateSize: UInt64
    public var keepSessionLog: Bool
    public var syncMustMatch: String
    public var syncMustNotMatch: String
    public var syncMustMatchDir: String
    public var syncMustNotMatchDir: String
    public var syncCreateAllLocalDirs: Bool
    public private(set) var syncPreview: String
    public private(set) var syncedFiles: [String]
    public var oldestDownloadDate: Date?
    public var listPattern: String { didSet { listingCache = nil } }
    public var allowMlsd: Bool
    public var preferNlst: Bool
    public var listOption: String
    public private(set) var lastReply: String

    private let controlChannel: FTPControlChannel
    private var listingCache: [FTPDirectoryEntry]?

    private func withLastReply<T>(_ operation: () async throws -> T) async throws -> T {
        do {
            if await controlChannel.isConnected { try await applySessionSettings() }
            let result = try await operation()
            if let reply = await controlChannel.lastReply { lastReply = reply.message }
            return result
        } catch {
            if let reply = await controlChannel.lastReply { lastReply = reply.message }
            throw error
        }
    }

    public init(controlChannel: FTPControlChannel = FTPControlChannel()) {
        self.hostname = ""
        self.port = 21
        self.username = "anonymous"
        self.password = ""
        self.account = nil
        self.authTls = false
        self.authSsl = false
        self.implicitTls = false
        self.autoFix = true
        self.passive = true
        self.dataProtection = "control"
        self.enableTLSSessionResumption = false
        self.connectTimeout = 30
        self.readTimeout = 60
        self.requireSslCertVerify = true
        self.trustedRootCertificates = []
        self.clientIdentity = nil
        self.pinnedPublicKeyHashes = []
        self.certificateRequirements = []
        self.proxy = nil
        self.httpProxyHostname = ""
        self.httpProxyPort = 8080
        self.httpProxyUsername = ""
        self.httpProxyPassword = ""
        self.httpProxyAuthMethod = ""
        self.httpProxyDomain = ""
        self.socksHostname = ""
        self.socksPort = 1080
        self.socksUsername = ""
        self.socksPassword = ""
        self.socksVersion = 0
        self.proxyHostname = ""
        self.proxyPort = 21
        self.proxyUsername = ""
        self.proxyPassword = ""
        self.proxyMethod = 0
        self.minimumTLSVersion = .tls12
        self.maximumTLSVersion = nil
        self.allowedCipherSuites = []
        self.sslProtocol = "default"
        self.tlsPinSet = ""
        self.sslAllowedCiphers = ""
        self.useEpsv = true
        self.passiveUseHostAddr = true
        self.clientIpAddress = ""
        self.legacyListingTimeZoneIdentifier = nil
        self.maximumBufferedBytes = 268_435_456
        self.preserveDownloadModificationTime = false
        self.preserveSyncModificationTimes = false
        self.enableSecrets = false
        self.bandwidthThrottleUp = 0
        self.bandwidthThrottleDown = 0
        self.largeFileMeasures = false
        self.transferKeepAliveInterval = nil
        self.activePortRangeStart = 0
        self.activePortRangeEnd = 0
        self.forcePortIpAddress = ""
        self.transferType = .binary
        self.crlfMode = 0
        self.commandCharset = "utf-8"
        self.dirListingCharset = "utf-8"
        self.replyCharset = "utf-8"
        self.autoSyst = true
        self.autoFeat = true
        self.autoXcrc = false
        self.autoOptsUtf8 = true
        self.restartNext = false
        self.autoGetSizeForProgress = false
        self.progressMonSize64 = 0
        self.allocateSize = 0
        self.keepSessionLog = false
        self.syncMustMatch = ""
        self.syncMustNotMatch = ""
        self.syncMustMatchDir = ""
        self.syncMustNotMatchDir = ""
        self.syncCreateAllLocalDirs = true
        self.syncPreview = ""
        self.syncedFiles = []
        self.oldestDownloadDate = nil
        self.listPattern = "*"
        self.allowMlsd = true
        self.preferNlst = false
        self.listOption = ""
        self.listingCache = nil
        self.lastReply = ""
        self.controlChannel = controlChannel
    }

    /// Establishes and authenticates a session unless the username is empty.
    public func connect() async throws {
        try await connectOnly()
        guard !username.isEmpty else { return }
        do {
            try await loginAfterConnectOnly()
        } catch {
            // Preserve the failed login reply in the facade, even if QUIT succeeds.
            await controlChannel.disconnect()
            listingCache = nil
            throw error
        }
    }

    /// Establishes the control connection without sending USER or PASS.
    public func connectOnly() async throws {
        if await controlChannel.isConnected { await controlChannel.disconnect() }
        listingCache = nil
        if autoFix {
            if port == 21 { implicitTls = false }
            else if port == 990 { implicitTls = true; authTls = false; authSsl = false }
        }
        let security: FTPTransportSecurity = implicitTls ? .implicitTLS : (authTls ? .explicitTLS : (authSsl ? .explicitSSL : .none))
        let mode: FTPDataConnectionMode = passive ? .passive : .active
        let protection: FTPDataProtection
        switch dataProtection.lowercased() {
        case "control": protection = .matchControl
        case "private": protection = .privateData
        case "clear": protection = .clear
        default: throw FTPError.invalidState(description: "Invalid FTP data protection setting")
        }
        let resolvedPassword = try resolveSecret(password)
        let configuredProxy: FTPProxy?
        let configuredCount = (proxy == nil ? 0 : 1) + (httpProxyHostname.isEmpty ? 0 : 1) + (socksVersion == 0 ? 0 : 1) + (proxyMethod == 0 ? 0 : 1)
        guard configuredCount <= 1 else { throw FTPError.invalidState(description: "Configure only one FTP proxy") }
        if let proxy { configuredProxy = proxy }
        else if !httpProxyHostname.isEmpty {
            if httpProxyAuthMethod.caseInsensitiveCompare("ntlm") == .orderedSame {
                configuredProxy = .httpNTLM(host: httpProxyHostname, port: httpProxyPort, username: httpProxyUsername,
                                             password: httpProxyPassword, domain: httpProxyDomain)
            } else {
                guard httpProxyAuthMethod.isEmpty || httpProxyAuthMethod.caseInsensitiveCompare("basic") == .orderedSame else {
                    throw FTPError.notImplemented(feature: "HTTP proxy authentication method")
                }
                configuredProxy = .httpConnect(host: httpProxyHostname, port: httpProxyPort,
                                               username: httpProxyUsername.isEmpty ? nil : httpProxyUsername,
                                               password: httpProxyUsername.isEmpty ? nil : httpProxyPassword)
            }
        } else if socksVersion == 4 {
            configuredProxy = .socks4(host: socksHostname, port: socksPort, userID: socksUsername)
        } else if socksVersion == 5 {
            configuredProxy = .socks5(host: socksHostname, port: socksPort,
                                      username: socksUsername.isEmpty ? nil : socksUsername,
                                      password: socksUsername.isEmpty ? nil : socksPassword)
        } else if socksVersion != 0 {
            throw FTPError.invalidState(description: "Unsupported SOCKS version")
        } else if proxyMethod != 0 {
            configuredProxy = .traditional(host: proxyHostname, port: proxyPort, method: proxyMethod, username: proxyUsername, password: proxyPassword)
        } else { configuredProxy = nil }
        let resolvedProxy: FTPProxy?
        if let proxy = configuredProxy {
            switch proxy {
            case .httpConnect(let host, let port, let username, let password):
                resolvedProxy = .httpConnect(host: host, port: port, username: username, password: try password.map(resolveSecret))
            case .httpNTLM(let host, let port, let username, let password, let domain):
                resolvedProxy = .httpNTLM(host: host, port: port, username: username, password: try resolveSecret(password), domain: domain)
            case .socks5(let host, let port, let username, let password):
                resolvedProxy = .socks5(host: host, port: port, username: username, password: try password.map(resolveSecret))
            case .socks4: resolvedProxy = proxy
            case .traditional(let host, let port, let method, let username, let password):
                resolvedProxy = .traditional(host: host, port: port, method: method, username: username, password: try resolveSecret(password))
            }
        } else { resolvedProxy = nil }
        var minimum = minimumTLSVersion
        var maximum = maximumTLSVersion
        switch sslProtocol.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "", "default": break
        case "tls 1.2": minimum = .tls12; maximum = .tls12
        case "tls 1.3": minimum = .tls13; maximum = .tls13
        case "tls 1.2 or higher": minimum = .tls12; maximum = nil
        case "tls 1.3 or higher": minimum = .tls13; maximum = nil
        default: throw FTPError.invalidState(description: "Unsupported TLS protocol setting")
        }
        var pins = pinnedPublicKeyHashes
        var ciphers = allowedCipherSuites
        if !sslAllowedCiphers.isEmpty {
            ciphers.append(contentsOf: sslAllowedCiphers.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) })
        }
        if !tlsPinSet.isEmpty {
            let parts = tlsPinSet.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            guard parts.count >= 3, parts[0].lowercased() == "sha256", parts[1].lowercased() == "base64" else {
                throw FTPError.invalidState(description: "Only SHA-256 base64 TLS pins are supported")
            }
            pins.append(contentsOf: parts.dropFirst(2))
        }
        let advertised = forcePortIpAddress.lowercased() == "control" ? "" : forcePortIpAddress
        let bindAdvertised = advertised.lowercased().hasPrefix("bind-")
        let advertisedAddress = bindAdvertised ? String(advertised.dropFirst(5)) : advertised

        guard let lineEnding = FTPASCIILineEnding(rawValue: crlfMode) else {
            throw FTPError.invalidState(description: "Invalid ASCII line-ending mode")
        }

        let configuration = FTPClientConfiguration(
            host: hostname,
            port: port,
            username: username,
            password: resolvedPassword,
            account: account,
            security: security,
            dataConnectionMode: mode,
            dataProtection: protection,
            enableTLSSessionResumption: enableTLSSessionResumption,
            connectTimeout: connectTimeout,
            readTimeout: readTimeout,
            trustedRootCertificates: trustedRootCertificates,
            clientIdentity: clientIdentity,
            requireServerCertificateValidation: requireSslCertVerify,
            pinnedPublicKeyHashes: pins,
            certificateRequirements: certificateRequirements,
            proxy: resolvedProxy,
            minimumTLSVersion: minimum,
            maximumTLSVersion: maximum,
            allowedCipherSuites: ciphers,
            bandwidthThrottleUp: bandwidthThrottleUp,
            bandwidthThrottleDown: bandwidthThrottleDown,
            transferKeepAliveInterval: transferKeepAliveInterval ?? (largeFileMeasures ? 60 : nil),
            activePortRangeStart: activePortRangeStart,
            activePortRangeEnd: activePortRangeEnd,
            activeAdvertisedIPv4: advertisedAddress.isEmpty ? nil : advertisedAddress,
            bindActiveAdvertisedIPv4: bindAdvertised,
            transferType: transferType,
            asciiLineEnding: lineEnding,
            commandCharset: commandCharset,
            replyCharset: replyCharset,
            directoryListingCharset: dirListingCharset,
            autoSyst: autoSyst,
            autoFeat: autoFeat,
            automaticUploadCRC: autoXcrc,
            autoOptsUtf8: autoOptsUtf8,
            preferEPSV: useEpsv,
            usePASVAdvertisedAddress: !passiveUseHostAddr,
            localIPAddress: clientIpAddress.isEmpty ? nil : clientIpAddress,
            legacyListingTimeZoneIdentifier: legacyListingTimeZoneIdentifier,
            maximumBufferedBytes: maximumBufferedBytes,
            preserveDownloadModificationTime: preserveDownloadModificationTime
        )

        let policy = FTPSecurityPolicy(requireServerCertificateValidation: requireSslCertVerify, pinnedPublicKeyHashes: pinnedPublicKeyHashes, trustedRootCertificates: trustedRootCertificates)
        try FTPSecurityEvaluator().evaluate(policy: policy, for: configuration)
        await controlChannel.setSessionLogging(keepSessionLog)
        try await withLastReply { try await controlChannel.connect(configuration: configuration) }
    }

    public func loginAfterConnectOnly() async throws {
        if await controlChannel.isAuthenticated { return }
        try await withLastReply { try await controlChannel.login() }
        await updateEffectiveCharsets()
    }

    public func convertToTls() async throws { try await withLastReply { try await controlChannel.convertToTLS() } }

    public func quote(_ command: String) async throws -> String {
        try await withLastReply {
            let reply = try await controlChannel.sendCommand(command)
            guard let code = reply.code, (100..<400).contains(code) else {
                throw FTPError.serverReply(code: reply.code, message: reply.message)
            }
            return reply.message
        }
    }

    public func sendCommand(_ command: String) async throws -> String {
        try await withLastReply {
            let reply = try await controlChannel.sendUTF8Command(command)
            guard let code = reply.code, (100..<400).contains(code) else {
                throw FTPError.serverReply(code: reply.code, message: reply.message)
            }
            return reply.message
        }
    }

    public func noop() async throws {
        try await withLastReply { try await controlChannel.noop() }
    }

    public func feat() async throws -> String {
        let reply = try await withLastReply { try await controlChannel.feat().message }
        await updateEffectiveCharsets()
        return reply
    }

    private func updateEffectiveCharsets() async {
        if let charsets = await controlChannel.effectiveCharsets() {
            commandCharset = charsets.command
            dirListingCharset = charsets.listing
        }
    }

    private func applySessionSettings() async throws {
        try await controlChannel.setSessionCharsets(command: commandCharset, listing: dirListingCharset, autoOptsUTF8: autoOptsUtf8)
        let advertised = forcePortIpAddress.lowercased() == "control" ? "" : forcePortIpAddress
        let bind = advertised.lowercased().hasPrefix("bind-")
        let address = bind ? String(advertised.dropFirst(5)) : advertised
        try await controlChannel.setSessionDataSettings(mode: passive ? .passive : .active, preferEPSV: useEpsv,
            usePASVAdvertisedAddress: !passiveUseHostAddr, throttleUp: bandwidthThrottleUp, throttleDown: bandwidthThrottleDown,
            activePortStart: activePortRangeStart, activePortEnd: activePortRangeEnd,
            activeIPv4: address.isEmpty ? nil : address, bindActiveIPv4: bind, maximumBufferedBytes: maximumBufferedBytes,
            keepAliveInterval: transferKeepAliveInterval ?? (largeFileMeasures ? 60 : nil))
    }

    public func syst() async throws -> String {
        try await withLastReply { try await controlChannel.syst().message }
    }

    public func getCurrentRemoteDir() async throws -> String {
        try await withLastReply { try await controlChannel.printWorkingDirectory().workingDirectoryPath() }
    }

    public func changeRemoteDir(_ path: String) async throws {
        try await withLastReply { try await controlChannel.changeWorkingDirectory(path: path) }
        listingCache = nil
    }

    public func nlst(_ path: String? = nil) async throws -> [String] {
        try await withLastReply { try await controlChannel.listNames(path: path) }
    }

    public func list(_ path: String? = nil) async throws -> [String] {
        try await withLastReply { try await controlChannel.listDetails(path: path, option: listOption) }
    }

    public func getTextDirListing(pattern: String = "") async throws -> String {
        try await list(pattern.isEmpty ? nil : pattern).joined(separator: "\r\n")
    }

    public func nlstXml(pattern: String = "") async throws -> String {
        let names = try await nlst(pattern.isEmpty ? nil : pattern)
        return "<nlst>" + (try names.map { "<e>\(try xmlEscape($0))</e>" }).joined() + "</nlst>"
    }

    public func getXmlDirListing(pattern: String = "") async throws -> String {
        let entries = pattern.isEmpty ? try await selectedListing() : try await wildcardEntries(pattern)
        let body = try entries.filter { $0.kind == .file || $0.kind == .directory }.map { entry in
            let name = try xmlEscape(entry.name)
            let modified = entry.modifiedAt.map(xmlListingDate)
            if entry.kind == .directory {
                let attribute = modified.map { " lastModTime=\"\($0)\"" } ?? ""
                return "<dir\(attribute)>\(name)</dir>"
            }
            let size = entry.size.map { "<size>\($0)</size>" } ?? ""
            let time = modified.map { "<lastModTime full=\"\($0)\"/>" } ?? ""
            return "<file><name>\(name)</name>\(size)\(time)</file>"
        }.joined()
        return "<remoteDir>" + body + "</remoteDir>"
    }

    public func dirTreeXml() async throws -> String {
        let root = try await getCurrentRemoteDir()
        let filter = syncFilter()
        var count = 0
        func visit(_ path: String, relative: String, depth: Int) async throws -> String {
            try Task.checkCancellation()
            guard depth <= 128 else { throw FTPError.invalidState(description: "Remote tree exceeds depth limit") }
            let entries = try await mlsd(path)
            var result = ""
            for entry in entries.sorted(by: { $0.name < $1.name }) {
                if entry.kind == .currentDirectory || entry.kind == .parentDirectory { continue }
                try validateRemoteName(entry.name)
                count += 1
                guard count <= 100_000 else { throw FTPError.invalidState(description: "Remote tree exceeds entry limit") }
                let childRelative = relative.isEmpty ? entry.name : "\(relative)/\(entry.name)"
                if entry.kind == .directory {
                    guard filter.includesDirectory(childRelative) else { continue }
                    let child = (path.hasSuffix("/") ? path : path + "/") + entry.name
                    let name = try xmlEscape(entry.name)
                    result += "<dir name=\"\(name)\">\(try await visit(child, relative: childRelative, depth: depth + 1))</dir>"
                } else if entry.kind == .file {
                    guard filter.includesFile(childRelative) else { continue }
                    let size = entry.size.map { " sz=\"\($0)\"" } ?? ""
                    let modified = entry.modifiedAt.map { " dt=\"\(rfc822($0))\"" } ?? ""
                    result += "<file\(size)\(modified)>\(try xmlEscape(entry.name))</file>"
                } else { throw FTPError.invalidState(description: "Unsupported remote tree entry") }
            }
            return result
        }
        return "<dirTree>\(try await visit(root, relative: "", depth: 0))</dirTree>"
    }

    private func xmlListingDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = TimeZone.current
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: date)
    }

    private func xmlEscape(_ value: String) throws -> String {
        guard value.unicodeScalars.allSatisfy({ scalar in
            let code = scalar.value
            return code == 0x09 || code == 0x0a || code == 0x0d || (0x20...0xd7ff).contains(code)
                || (0xe000...0xfffd).contains(code) || (0x10000...0x10ffff).contains(code)
        }) else { throw FTPError.invalidState(description: "Filename cannot be represented in XML 1.0") }
        return value.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }

    public func mlsd(_ path: String? = nil) async throws -> [FTPDirectoryEntry] {
        try await withLastReply { try await controlChannel.listEntries(path: path) }
    }

    public func clearDirCache() { listingCache = nil }

    private func cachedListing() async throws -> [FTPDirectoryEntry] {
        if let listingCache { return listingCache }
        let entries = try await selectedListing()
        let pattern = listPattern.lowercased()
        let filtered = entries.filter { entry in
            guard entry.kind != .currentDirectory && entry.kind != .parentDirectory else { return false }
            return pattern.withCString { pattern in entry.name.lowercased().withCString { fnmatch(pattern, $0, 0) == 0 } }
        }
        listingCache = filtered
        return filtered
    }

    private func cachedEntry(_ index: Int) async throws -> FTPDirectoryEntry {
        let entries = try await cachedListing()
        guard entries.indices.contains(index) else { throw FTPError.invalidState(description: "Directory listing index out of range") }
        return entries[index]
    }

    private func cachedEntry(named name: String) async throws -> FTPDirectoryEntry {
        guard !name.isEmpty, !name.contains("/"), name != ".", name != ".." else {
            throw FTPError.invalidState(description: "Listing lookup requires a filename")
        }
        let entries = try await cachedListing()
        guard let entry = entries.first(where: { $0.name == name }) else {
            throw FTPError.invalidState(description: "Directory listing entry not found: \(name)")
        }
        return entry
    }

    private func listingDate(_ entry: FTPDirectoryEntry, creation: Bool) throws -> Date {
        if creation, let raw = entry.facts["create"] { return try FTPMLSDParser.parseTimestamp(raw) }
        guard let date = entry.modifiedAt else { throw FTPError.invalidState(description: "Listing timestamp unavailable") }
        return date
    }

    private func rfc822(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = TimeZone.current
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
        return formatter.string(from: date)
    }

    public func getDirCount() async throws -> Int { try await cachedListing().count }
    public func getFilename(_ index: Int) async throws -> String { try await cachedEntry(index).name }
    public func getIsDirectory(_ index: Int) async throws -> Bool {
        let kind = try await cachedEntry(index).kind
        if kind == .other("unknown") { throw FTPError.invalidState(description: "Listing does not identify entry types") }
        return kind == .directory
    }
    public func getIsSymbolicLink(_ index: Int) async throws -> Bool {
        let kind = try await cachedEntry(index).kind
        if kind == .other("unknown") { throw FTPError.invalidState(description: "Listing does not identify entry types") }
        return kind == .other("symlink")
    }
    public func getSize(_ index: Int) async throws -> UInt64 {
        guard let size = try await cachedEntry(index).size else { throw FTPError.invalidState(description: "Listing size unavailable") }
        return size
    }
    public func getLastModified(_ index: Int) async throws -> Date {
        guard let date = try await cachedEntry(index).modifiedAt else { throw FTPError.invalidState(description: "Listing modification time unavailable") }
        return date
    }
    public func getOwner(_ index: Int) async throws -> String { try await cachedEntry(index).facts["unix.owner"] ?? "" }
    public func getGroup(_ index: Int) async throws -> String { try await cachedEntry(index).facts["unix.group"] ?? "" }
    public func getPermissions(_ index: Int) async throws -> String {
        let entry = try await cachedEntry(index)
        if let permissions = entry.facts["perm"] { return permissions }
        return entry.facts["unix.mode"].map { String($0.dropFirst().prefix(9)) } ?? ""
    }
    public func getPermType(_ index: Int) async throws -> String {
        let entry = try await cachedEntry(index)
        return entry.facts["perm"] != nil ? "mlsd" : (entry.facts["unix.mode"] != nil ? "unix" : "")
    }

    private func selectedListing() async throws -> [FTPDirectoryEntry] {
        let preference: FTPListingPreference = allowMlsd ? .machineReadable : (preferNlst ? .namesOnly : .legacyDetails)
        return try await withLastReply { try await controlChannel.listSelectedEntries(preference: preference, listOption: listOption, preferNamesOnFallback: preferNlst) }
    }

    public func getFilename(index: Int) async throws -> String { try await getFilename(index) }
    public func getIsDirectory(index: Int) async throws -> Bool { try await getIsDirectory(index) }
    public func getIsSymbolicLink(index: Int) async throws -> Bool { try await getIsSymbolicLink(index) }
    public func getSize64(index: Int) async throws -> UInt64 { try await getSize(index) }
    public func getSizeStr(index: Int) async throws -> String { String(try await getSize(index)) }
    public func getSize64(byName name: String) async throws -> UInt64 {
        guard let size = try await cachedEntry(named: name).size else { throw FTPError.invalidState(description: "Listing size unavailable") }
        return size
    }
    public func getSizeStr(byName name: String) async throws -> String { String(try await getSize64(byName: name)) }
    public func getOwner(index: Int) async throws -> String { try await getOwner(index) }
    public func getGroup(index: Int) async throws -> String { try await getGroup(index) }
    public func getPermissions(index: Int) async throws -> String { try await getPermissions(index) }
    public func getPermType(index: Int) async throws -> String { try await getPermType(index) }
    public func getCreateTimeStr(index: Int) async throws -> String { try rfc822(listingDate(await cachedEntry(index), creation: true)) }
    public func getCreateTime(byNameStr name: String) async throws -> String { try rfc822(listingDate(await cachedEntry(named: name), creation: true)) }
    public func getLastModifiedTimeStr(index: Int) async throws -> String { try rfc822(listingDate(await cachedEntry(index), creation: false)) }
    public func getLastModifiedTime(byNameStr name: String) async throws -> String { try rfc822(listingDate(await cachedEntry(named: name), creation: false)) }

    public func getSize(_ path: String) async throws -> UInt64 {
        try await withLastReply { try await controlChannel.fileSize(path: path) }
    }

    public func getLastModified(_ path: String) async throws -> Date {
        try await withLastReply { try await controlChannel.modificationTime(path: path) }
    }

    public func setRemoteFileDate(_ date: Date, remoteFilename: String) async throws {
        try await withLastReply { try await controlChannel.setModificationTime(date, path: remoteFilename) }
    }

    public func setRemoteFileDateTimeStr(_ value: String, remoteFilename: String) async throws {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
        formatter.isLenient = false
        guard let date = formatter.date(from: value) else { throw FTPError.invalidState(description: "Invalid RFC 822 date") }
        try await setRemoteFileDate(date, remoteFilename: remoteFilename)
    }

    public func site(_ command: String) async throws { try await withLastReply { try await controlChannel.site(command) } }
    public func setTypeAscii() async throws {
        try await withLastReply { try await controlChannel.setTransferType(.ascii) }
        transferType = .ascii
    }
    public func setTypeBinary() async throws {
        try await withLastReply { try await controlChannel.setTransferType(.binary) }
        transferType = .binary
    }
    public func setModeZ() async throws { try await withLastReply { try await controlChannel.setModeZ(true) } }
    public func setModeStream() async throws { try await withLastReply { try await controlChannel.setModeZ(false) } }
    public func stat() async throws -> String { try await withLastReply { try await controlChannel.serverStatus().message } }

    private func configureDownloadLineEnding() async throws {
        try await applySessionSettings()
        guard let mode = FTPASCIILineEnding(rawValue: crlfMode) else {
            throw FTPError.invalidState(description: "Invalid ASCII line-ending mode")
        }
        try await controlChannel.setASCIILineEnding(mode)
    }

    private func configureUploadCRC() async throws {
        try await applySessionSettings()
        try await controlChannel.setAutomaticUploadCRC(autoXcrc)
    }

    public func getRemoteFileBinaryData(_ remoteFilename: String) async throws -> Data {
        try await configureDownloadLineEnding()
        return try await withLastReply { try await controlChannel.retrieveFileData(remotePath: remoteFilename) }
    }

    public func getFileToStream(remoteFilename: String, progress: (@Sendable (UInt64) -> Void)? = nil, sink: @escaping @Sendable (Data) async throws -> Void) async throws {
        try await configureDownloadLineEnding()
        try await withLastReply { try await controlChannel.downloadStream(remotePath: remoteFilename, progress: progress, sink: sink) }
    }

    public func putFileFromStream(remoteFilename: String, source: AsyncThrowingStream<Data, Error>, append: Bool = false, progress: (@Sendable (UInt64) -> Void)? = nil) async throws {
        try await configureUploadCRC()
        let allocation = allocateSize
        allocateSize = 0
        await controlChannel.allocateNextUpload(allocation)
        try await withLastReply { try await controlChannel.uploadStream(remotePath: remoteFilename, source: source, append: append, progress: progress) }
    }

    public func putFile(fromBinaryData remoteFilename: String, binaryData: Data) async throws {
        try await configureUploadCRC()
        let resume = restartNext
        restartNext = false
        let allocation = allocateSize
        allocateSize = 0
        await controlChannel.allocateNextUpload(allocation)
        try await withLastReply { try await controlChannel.storeFileData(binaryData, remotePath: remoteFilename, resume: resume) }
    }

    public func appendFile(fromBinaryData remoteFilename: String, binaryData: Data) async throws {
        try await configureUploadCRC()
        let allocation = allocateSize
        allocateSize = 0
        await controlChannel.allocateNextUpload(allocation)
        try await withLastReply { try await controlChannel.storeFileData(binaryData, remotePath: remoteFilename, append: true) }
    }

    /// Appends a download to the supplied buffer; restart uses the existing byte count.
    public func getFileBd(remoteFilename: String, data: inout Data) async throws {
        try await configureDownloadLineEnding()
        let offset = restartNext ? UInt64(data.count) : nil
        restartNext = false
        let suffix = try await withLastReply { try await controlChannel.retrieveFileData(remotePath: remoteFilename, restartOffset: offset) }
        data.append(suffix)
    }

    public func getFileBd(remoteFilePath: String, binData: inout Data) async throws {
        try await getFileBd(remoteFilename: remoteFilePath, data: &binData)
    }

    public func putFileBd(data: Data, remoteFilename: String) async throws {
        try await putFile(fromBinaryData: remoteFilename, binaryData: data)
    }

    public func putFileBd(binData: Data, remoteFilePath: String) async throws {
        try await putFileBd(data: binData, remoteFilename: remoteFilePath)
    }

    public func appendFileBd(remoteFilename: String, data: Data) async throws {
        try await appendFile(fromBinaryData: remoteFilename, binaryData: data)
    }

    public func appendFileBd(remoteFilename: String, bd: Data) async throws {
        try await appendFileBd(remoteFilename: remoteFilename, data: bd)
    }

    public func getFileSb(remoteFilename: String, charset: String, text: inout String) async throws {
        try await configureDownloadLineEnding()
        let encoding = try FTPCharset.encoding(named: charset)
        let offset: UInt64?
        if restartNext {
            guard let existing = text.data(using: encoding) else { throw FTPError.invalidState(description: "Existing text cannot be encoded") }
            offset = UInt64(existing.count)
        } else { offset = nil }
        restartNext = false
        let data = try await withLastReply { try await controlChannel.retrieveFileData(remotePath: remoteFilename, restartOffset: offset) }
        guard var suffix = String(data: data, encoding: encoding) else { throw FTPError.invalidResponseEncoding }
        if offset == nil && suffix.first == "\u{feff}" { suffix.removeFirst() }
        text.append(suffix)
    }

    public func getFileSb(remoteFilePath: String, charset: String, sb: inout String) async throws {
        try await getFileSb(remoteFilename: remoteFilePath, charset: charset, text: &sb)
    }

    public func getRemoteFileText(_ remoteFilename: String, encoding: String.Encoding = .utf8) async throws -> String {
        let bytes = try await getRemoteFileBinaryData(remoteFilename)
        guard var text = String(data: bytes, encoding: encoding) else { throw FTPError.invalidResponseEncoding }
        if text.first == "\u{feff}" { text.removeFirst() }
        return text
    }

    public func getRemoteFileTextC(remoteFilename: String, charset: String) async throws -> String {
        try await getRemoteFileText(remoteFilename, encoding: FTPCharset.encoding(named: charset))
    }

    public func getRemoteFileTextData(remoteFilename: String) async throws -> String {
        try await getRemoteFileText(remoteFilename, encoding: FTPCharset.encoding(named: "ANSI"))
    }

    /// Uploads a native Swift string without requiring an object-wrapper type.
    public func putFileSb(text: String, charset: String, includeBom: Bool, remoteFilePath: String) async throws {
        let bytes = try encodedText(text, charset: charset, includeBom: includeBom)
        try await putFile(fromBinaryData: remoteFilePath, binaryData: bytes)
    }

    public func putFileSb(sb: String, charset: String, includeBom: Bool, remoteFilePath: String) async throws {
        try await putFileSb(text: sb, charset: charset, includeBom: includeBom, remoteFilePath: remoteFilePath)
    }

    /// Appends encoded text without adding a byte-order mark.
    public func appendFileSb(remoteFilename: String, text: String, charset: String) async throws {
        let bytes = try encodedText(text, charset: charset, includeBom: false)
        try await appendFile(fromBinaryData: remoteFilename, binaryData: bytes)
    }

    public func appendFileSb(remoteFilename: String, sb: String, charset: String) async throws {
        try await appendFileSb(remoteFilename: remoteFilename, text: sb, charset: charset)
    }

    private func encodedText(_ text: String, charset: String, includeBom: Bool) throws -> Data {
        let encoding = try FTPCharset.encoding(named: charset)
        guard var bytes = text.data(using: encoding) else {
            throw FTPError.invalidState(description: "Text cannot be encoded")
        }
        let marker: Data
        switch encoding {
        case .utf8: marker = Data([0xef, 0xbb, 0xbf])
        case .utf16BigEndian: marker = Data([0xfe, 0xff])
        case .utf16LittleEndian: marker = Data([0xff, 0xfe])
        case .utf32BigEndian: marker = Data([0x00, 0x00, 0xfe, 0xff])
        case .utf32LittleEndian: marker = Data([0xff, 0xfe, 0x00, 0x00])
        case .utf16:
            guard bytes.starts(with: [0xff, 0xfe]) || bytes.starts(with: [0xfe, 0xff]) else {
                throw FTPError.invalidState(description: "UTF-16 byte order is unavailable")
            }
            marker = Data(bytes.prefix(2))
            bytes.removeFirst(2)
        case .utf32:
            guard bytes.starts(with: [0xff, 0xfe, 0x00, 0x00]) || bytes.starts(with: [0x00, 0x00, 0xfe, 0xff]) else {
                throw FTPError.invalidState(description: "UTF-32 byte order is unavailable")
            }
            marker = Data(bytes.prefix(4))
            bytes.removeFirst(4)
        default: marker = Data()
        }
        if includeBom { bytes.insert(contentsOf: marker, at: bytes.startIndex) }
        return bytes
    }

    public func putFile(fromTextData remoteFilename: String, textData: String, encoding: String.Encoding = .utf8, append: Bool = false) async throws {
        guard let bytes = textData.data(using: encoding) else { throw FTPError.invalidState(description: "Text cannot be encoded") }
        if append { try await appendFile(fromBinaryData: remoteFilename, binaryData: bytes) }
        else { try await putFile(fromBinaryData: remoteFilename, binaryData: bytes) }
    }

    public func putFile(fromTextData remoteFilename: String, textData: String, charset: String) async throws {
        try await putFile(fromTextData: remoteFilename, textData: textData, encoding: FTPCharset.encoding(named: charset))
    }

    public func appendFile(fromTextData remoteFilename: String, textData: String, charset: String) async throws {
        try await putFile(fromTextData: remoteFilename, textData: textData, encoding: FTPCharset.encoding(named: charset), append: true)
    }

    public func setSslClientCertPfx(path: String, password: String) throws {
        clientIdentity = FTPClientIdentity(pkcs12Data: try Data(contentsOf: URL(fileURLWithPath: path)), passphrase: password)
    }

    /// Loads a client certificate and private key from PEM text or a local PEM file.
    public func setSslClientCertPem(pemDataOrFilename: String, pemPassword: String) throws {
        let data: Data
        if pemDataOrFilename.contains("-----BEGIN ") {
            data = Data(pemDataOrFilename.utf8)
        } else {
            let descriptor = Darwin.open(pemDataOrFilename, O_RDONLY | O_CLOEXEC | O_NONBLOCK)
            guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            defer { try? file.close() }
            var info = Darwin.stat()
            guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
                  info.st_size >= 0, info.st_size <= 8_388_608 else {
                throw FTPError.invalidState(description: "PEM source must be a regular file no larger than 8 MiB")
            }
            var contents = Data()
            while let chunk = try file.read(upToCount: 65_536), !chunk.isEmpty {
                guard chunk.count <= 8_388_608 - contents.count else { throw FTPError.invalidState(description: "PEM file is too large") }
                contents.append(chunk)
            }
            data = contents
        }
        clientIdentity = try FTPClientIdentity(pemData: data, passphrase: pemPassword)
    }

    /// Adds a requirement for the next control-channel TLS handshake.
    public func setSslCertRequirement(name: String, value: String) throws {
        let field: FTPCertificateRequirement.Field
        switch name.lowercased() {
        case "subjectdn": field = .subjectDN
        case "subjectcn": field = .subjectCN
        case "issuerdn": field = .issuerDN
        case "issuercn": field = .issuerCN
        case "san": field = .subjectAlternativeName
        default: throw FTPError.invalidState(description: "Unsupported certificate requirement field: \(name)")
        }
        guard !value.utf8.contains(0) else { throw FTPError.invalidState(description: "Invalid certificate requirement pattern") }
        certificateRequirements.append(FTPCertificateRequirement(field: field, pattern: value))
    }

    public func setPasswordFromKeychain(service: String, account: String, accessGroup: String? = nil) throws {
        password = try FTPKeychain.password(service: service, account: account, accessGroup: accessGroup)
    }

    private func resolveSecret(_ value: String) throws -> String {
        guard enableSecrets && value.hasPrefix("!!") else { return value }
        let parts = value.dropFirst(2).split(separator: "|", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else {
            throw FTPError.invalidState(description: "Keychain references must use !!service|account")
        }
        return try FTPKeychain.password(service: String(parts[0]), account: String(parts[1]))
    }

    public func createRemoteDir(_ path: String) async throws {
        try await withLastReply { try await controlChannel.makeDirectory(path: path) }
    }

    public func removeRemoteDir(_ path: String) async throws {
        try await withLastReply { try await controlChannel.removeDirectory(path: path) }
    }

    public func deleteRemoteFile(_ path: String) async throws {
        try await withLastReply { try await controlChannel.deleteFile(path: path) }
    }

    public func renameRemoteFile(existingPath: String, newPath: String) async throws {
        try await withLastReply { try await controlChannel.renameFile(from: existingPath, to: newPath) }
    }

    public func putFile(localPath: String, remoteFilename: String, resume: Bool = false, progress: (@Sendable (UInt64) -> Void)? = nil) async throws {
        try await configureUploadCRC()
        let useResume = resume || restartNext
        restartNext = false
        let allocation = allocateSize
        allocateSize = 0
        await controlChannel.allocateNextUpload(allocation)
        try await withLastReply { try await controlChannel.uploadFile(from: URL(fileURLWithPath: localPath), remotePath: remoteFilename, resume: useResume, progress: progress) }
    }

    public func appendFile(localPath: String, remoteFilename: String, progress: (@Sendable (UInt64) -> Void)? = nil) async throws {
        try await configureUploadCRC()
        let allocation = allocateSize
        allocateSize = 0
        await controlChannel.allocateNextUpload(allocation)
        try await withLastReply { try await controlChannel.uploadFile(from: URL(fileURLWithPath: localPath), remotePath: remoteFilename, append: true, progress: progress) }
    }

    /// Uploads consecutive chunks with STOR then APPE; failure can leave a partial remote file.
    public func largeFileUpload(localPath: String, remotePath: String, chunkSize: Int, progress: (@Sendable (UInt64) -> Void)? = nil) async throws {
        guard chunkSize > 0 else { throw FTPError.invalidState(description: "Chunk size must be positive") }
        if autoXcrc {
            let features = await controlChannel.serverFeatures
            if features.contains("XCRC") {
                throw FTPError.invalidState(description: "Automatic XCRC cannot verify chunked append uploads")
            }
        }
        restartNext = false
        let file = try FileHandle(forReadingFrom: URL(fileURLWithPath: localPath))
        defer { try? file.close() }
        var first = true
        var total: UInt64 = 0
        var sourceInfo = Darwin.stat()
        let expected = fstat(file.fileDescriptor, &sourceInfo) == 0 && (sourceInfo.st_mode & S_IFMT) == S_IFREG
            ? UInt64(exactly: sourceInfo.st_size) : nil
        try await FTPChunkedUploadScope.$identifier.withValue(UUID()) {
            try await controlChannel.beginChunkedUploadMetrics(expectedBytes: expected)
            do {
                progress?(0)
                while true {
                    try Task.checkCancellation()
                    let chunk = try file.read(upToCount: chunkSize) ?? Data()
                    if chunk.isEmpty && !first { break }
                    if first { try await putFile(fromBinaryData: remotePath, binaryData: chunk) }
                    else { try await appendFile(fromBinaryData: remotePath, binaryData: chunk) }
                    first = false
                    total += UInt64(chunk.count)
                    if !chunk.isEmpty { progress?(total) }
                    if chunk.isEmpty { break }
                }
                await controlChannel.finishChunkedUploadMetrics(succeeded: true)
            } catch {
                await controlChannel.finishChunkedUploadMetrics(succeeded: false)
                throw error
            }
        }
    }

    public func getFile(remoteFilename: String, localPath: String, resume: Bool = false, querySizeForProgress: Bool = false, progress: (@Sendable (UInt64) -> Void)? = nil) async throws {
        let useResume = resume || restartNext
        restartNext = false
        let expected = progressMonSize64 == 0 ? nil : progressMonSize64
        progressMonSize64 = 0
        try await configureDownloadLineEnding()
        let modified = preserveDownloadModificationTime ? try await getLastModified(remoteFilename) : nil
        try await withLastReply { try await controlChannel.downloadFile(remotePath: remoteFilename, to: URL(fileURLWithPath: localPath), resume: useResume, modificationTime: modified, expectedBytes: expected, querySizeForProgress: querySizeForProgress || autoGetSizeForProgress, progress: progress) }
    }

    public func syncRemoteTree(plan: FTPSyncPlan) async throws {
        guard plan.direction == .localToRemote else {
            throw FTPError.invalidState(description: "syncRemoteTree requires local-to-remote direction")
        }
        try await configureUploadCRC()
        _ = try await FTPSyncEngine(channel: controlChannel).run(plan)
    }

    /// Upload synchronization using the legacy numeric mode mapping.
    public func syncRemoteTree(localRoot: String, mode: Int) async throws {
        try await syncRemoteTree2(localRoot: localRoot, mode: mode, descend: true, previewOnly: false)
    }

    /// Preview is deliberately non-mutating, unlike servers that create directories during preview.
    public func syncRemoteTree2(localRoot: String, mode: Int, descend: Bool, previewOnly: Bool) async throws {
        syncPreview = ""
        syncedFiles = []
        let selected: FTPSyncMode
        switch mode {
        case 0: selected = .all
        case 1: selected = .missingOnly
        case 2: selected = .newerOnly
        case 3: selected = .existingNewer
        case 4: selected = .sizeOnly
        case 5: selected = .sizeOrNewer
        default: throw FTPError.invalidState(description: "Unsupported upload sync mode: \(mode)")
        }
        let remoteRoot = try await controlChannel.printWorkingDirectory().workingDirectoryPath()
        let plan = FTPSyncPlan(direction: .localToRemote, mode: selected, localRootPath: localRoot,
                               remoteRootPath: remoteRoot, filter: syncFilter(), dryRun: previewOnly,
                               descend: descend, includeEmptyDirectories: !previewOnly,
                               preserveModificationTimes: preserveSyncModificationTimes)
                    if !previewOnly { try await configureUploadCRC() }
        let operations = try await FTPSyncEngine(channel: controlChannel).run(plan)
        syncedFiles = operations.filter { $0.action == .upload }.map(\.relativePath)
        if previewOnly {
            let root = URL(fileURLWithPath: localRoot, isDirectory: true).standardizedFileURL
            syncPreview = syncedFiles.map { root.appendingPathComponent($0).path }.joined(separator: "\r\n")
        }
    }

    /// Download synchronization using the legacy numeric mode mapping.
    public func syncLocalTree(localRoot: String, mode: Int, descend: Bool = true, oldestSourceModification: Date? = nil) async throws {
        syncPreview = ""
        syncedFiles = []
        let selected: FTPSyncMode
        switch mode {
        case 0: selected = .all
        case 1: selected = .missingOnly
        case 2: selected = .newerOnly
        case 3: selected = .existingNewer
        case 5: selected = .sizeOnly
        case 6: selected = .sizeOrNewer
        case 99: selected = .deleteDestinationOnly
        default: throw FTPError.invalidState(description: "Unsupported download sync mode: \(mode)")
        }
        if mode != 99 { try await configureDownloadLineEnding() }
        let remoteRoot = try await controlChannel.printWorkingDirectory().workingDirectoryPath()
        let plan = FTPSyncPlan(direction: mode == 99 ? .localToRemote : .remoteToLocal, mode: selected,
                               localRootPath: localRoot, remoteRootPath: remoteRoot, filter: syncFilter(),
                               descend: descend, includeEmptyDirectories: mode != 99 && syncCreateAllLocalDirs,
                               oldestSourceModification: oldestSourceModification,
                               preserveModificationTimes: preserveSyncModificationTimes)
        let operations = try await FTPSyncEngine(channel: controlChannel).run(plan)
        syncedFiles = operations.filter { $0.action == .download || $0.action == .deleteRemoteFile }.map(\.relativePath)
    }

    public func syncLocalDir(localRoot: String, mode: Int) async throws {
        try await syncLocalTree(localRoot: localRoot, mode: mode, descend: false)
    }

    public func syncDeleteRemote(localRoot: String) async throws {
        try await syncLocalTree(localRoot: localRoot, mode: 99)
    }

    public func putTree(localDir: String) async throws {
        try await syncRemoteTree(localRoot: localDir, mode: 0)
    }

    private struct UploadPlan: Codable {
        struct Entry: Codable { let directory: Bool; let relativePath: String }
        let version: Int
        let localRoot: String
        let remoteRoot: String
        let entries: [Entry]
    }

    /// Generates a library-specific plan; contents are read when it is executed.
    public func createPlan(localDir: String) async throws -> String {
        let root = URL(fileURLWithPath: localDir, isDirectory: true).standardizedFileURL
        let remoteRoot = try await getCurrentRemoteDir()
        let plan = FTPSyncPlan(direction: .localToRemote, mode: .all, localRootPath: root.path,
                               remoteRootPath: remoteRoot, filter: syncFilter(), dryRun: true,
                               includeEmptyDirectories: true)
        let operations = try await FTPSyncEngine(channel: controlChannel).preview(plan)
        let entries = operations.compactMap { operation -> UploadPlan.Entry? in
            switch operation.action {
            case .createRemoteDirectory: return .init(directory: true, relativePath: operation.relativePath)
            case .upload: return .init(directory: false, relativePath: operation.relativePath)
            default: return nil
            }
        }
        let data = try JSONEncoder().encode(UploadPlan(version: 1, localRoot: root.path, remoteRoot: remoteRoot, entries: entries))
        guard let text = String(data: data, encoding: .utf8) else { throw FTPError.invalidResponseEncoding }
        return text
    }

    /// Executes a previously generated plan. The log must not be shared by other plans.
    public func putPlan(_ text: String, planLogFilePath: String) async throws {
        guard let bytes = text.data(using: .utf8) else { throw FTPError.invalidState(description: "Invalid upload plan") }
        let plan = try JSONDecoder().decode(UploadPlan.self, from: bytes)
        guard plan.version == 1, plan.localRoot.hasPrefix("/"), !plan.remoteRoot.isEmpty else {
            throw FTPError.invalidState(description: "Invalid upload plan")
        }
        let root = Darwin.open(plan.localRoot, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { Darwin.close(root) }
        let descriptor = Darwin.open(planLogFilePath, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let log = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? log.close() }
        var metadata = Darwin.stat()
        guard fstat(descriptor, &metadata) == 0, (metadata.st_mode & S_IFMT) == S_IFREG else {
            throw FTPError.invalidState(description: "Upload plan log must be a regular file")
        }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { _ = flock(descriptor, LOCK_UN) }
        var logData = Data()
        while let chunk = try log.read(upToCount: 65_536), !chunk.isEmpty {
            guard chunk.count <= 16_777_216 - logData.count else {
                throw FTPError.invalidState(description: "Upload plan log is too large")
            }
            logData.append(chunk)
        }
        guard let existing = String(data: logData, encoding: .utf8) else {
            throw FTPError.invalidState(description: "Upload plan log is not UTF-8")
        }
        guard logData.isEmpty || logData.last == 10 else {
            throw FTPError.invalidState(description: "Upload plan log has an incomplete record")
        }
        let lines = existing.split(separator: "\n").map(String.init)
        let header = "FTPPLAN1:" + Data(SHA256.hash(data: bytes)).base64EncodedString()
        guard lines.isEmpty || lines.first == header else { throw FTPError.invalidState(description: "Upload plan log belongs to another plan") }
        let completed = Set(lines.dropFirst())
        try log.seekToEnd()
        if lines.isEmpty {
            try log.write(contentsOf: Data((header + "\n").utf8))
            try log.synchronize()
        }
        for entry in plan.entries {
            try Task.checkCancellation()
            let components = entry.relativePath.split(separator: "/", omittingEmptySubsequences: false)
            guard !components.isEmpty else { throw FTPError.invalidState(description: "Invalid plan path") }
            for component in components { try validateRemoteName(String(component)) }
            let key = (entry.directory ? "D:" : "F:") + Data(entry.relativePath.utf8).base64EncodedString()
            if completed.contains(key) { continue }
            let remote = (plan.remoteRoot.hasSuffix("/") ? plan.remoteRoot : plan.remoteRoot + "/") + entry.relativePath
            if entry.directory { try await createRemoteDir(remote) }
            else {
                let source = try openPlanSource(root: root, components: components)
                defer { try? source.close() }
                let stream = AsyncThrowingStream<Data, Error>(unfolding: {
                    try Task.checkCancellation()
                    guard let chunk = try source.read(upToCount: 65_536), !chunk.isEmpty else { return nil }
                    return chunk
                })
                restartNext = false
                try await putFileFromStream(remoteFilename: remote, source: stream)
            }
            try log.write(contentsOf: Data((key + "\n").utf8))
            try log.synchronize()
        }
    }

    private func openPlanSource(root: Int32, components: [Substring]) throws -> FileHandle {
        var parent = dup(root)
        guard parent >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { Darwin.close(parent) }
        for component in components.dropLast() {
            let next = openat(parent, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            Darwin.close(parent)
            parent = next
        }
        guard let name = components.last else { throw FTPError.invalidState(description: "Invalid plan path") }
        let descriptor = openat(parent, String(name), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var metadata = Darwin.stat()
        guard fstat(descriptor, &metadata) == 0, (metadata.st_mode & S_IFMT) == S_IFREG else {
            Darwin.close(descriptor)
            throw FTPError.invalidState(description: "Upload plan source must be a regular file")
        }
        return FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    public func downloadTree(localRoot: String) async throws {
        try await syncLocalTree(localRoot: localRoot, mode: 0, oldestSourceModification: oldestDownloadDate)
    }

    public func setOldestDateStr(_ value: String) throws {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
        guard let date = formatter.date(from: value) else { throw FTPError.invalidState(description: "Invalid RFC 822 date") }
        oldestDownloadDate = date
    }

    /// Uploads regular local files selected by an operating-system glob.
    @discardableResult
    public func mPutFiles(pattern: String) async throws -> Int {
        guard !pattern.utf8.contains(0) else { throw FTPError.invalidState(description: "Invalid local wildcard") }
        var matches = glob_t()
        defer { globfree(&matches) }
        let result = pattern.withCString { Darwin.glob($0, GLOB_NOSORT, nil, &matches) }
        if result == GLOB_NOMATCH { return 0 }
        guard result == 0 else { throw FTPError.invalidState(description: "Unable to expand local wildcard") }
        guard let paths = matches.gl_pathv else { return 0 }
        var count = 0
        for index in 0..<Int(matches.gl_pathc) {
            try Task.checkCancellation()
            guard let pointer = paths[index] else { continue }
            let path = String(cString: pointer)
            let url = URL(fileURLWithPath: path)
            let info = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard info.isRegularFile == true, info.isSymbolicLink != true else { continue }
            try validateRemoteName(url.lastPathComponent)
            try await putFile(localPath: path, remoteFilename: url.lastPathComponent)
            count += 1
        }
        return count
    }

    /// Downloads files selected by the server's LIST wildcard; directories are ignored.
    @discardableResult
    public func mGetFiles(remotePattern: String, localDir: String) async throws -> Int {
        let root = Darwin.open(localDir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { Darwin.close(root) }
        let entries = try await wildcardEntries(remotePattern).filter { $0.kind == .file }
        var names: Set<String> = []
        for entry in entries {
            try validateRemoteName(entry.name)
            let canonical = entry.name.precomposedStringWithCanonicalMapping.lowercased()
            guard names.insert(canonical).inserted else {
                throw FTPError.invalidState(description: "Ambiguous wildcard download name: \(entry.name)")
            }
        }
        var count = 0
        for entry in entries {
            try Task.checkCancellation()
            let resume = restartNext
            restartNext = false
            let expected = progressMonSize64 == 0 ? nil : progressMonSize64
            progressMonSize64 = 0
            try await configureDownloadLineEnding()
            let modified = preserveDownloadModificationTime ? try await getLastModified(entry.name) : nil
            try await withLastReply {
                try await controlChannel.downloadFile(remotePath: entry.name, directoryDescriptor: root, filename: entry.name,
                    resume: resume, modificationTime: modified, expectedBytes: expected, querySizeForProgress: autoGetSizeForProgress)
            }
            count += 1
        }
        return count
    }

    /// Deletes server-selected files; directory entries are not removed.
    @discardableResult
    public func delete(matching pattern: String) async throws -> Int {
        let entries = try await wildcardEntries(pattern).filter { $0.kind == .file }
        for entry in entries { try validateRemoteName(entry.name) }
        var count = 0
        for entry in entries {
            try Task.checkCancellation()
            try await deleteRemoteFile(entry.name)
            count += 1
        }
        return count
    }

    private func wildcardEntries(_ pattern: String) async throws -> [FTPDirectoryEntry] {
        let lines = try await list(pattern.isEmpty ? nil : pattern)
        return try FTPLegacyListParser.parse(Data(lines.joined(separator: "\r\n").utf8))
    }

    private func validateRemoteName(_ name: String) throws {
        guard !name.isEmpty, name != ".", name != "..",
              !name.utf8.contains(where: { $0 == 0 || $0 == 10 || $0 == 13 || $0 == 47 }) else {
            throw FTPError.protocolViolation(description: "Unsafe remote entry name")
        }
    }

    /// Deletes descendants only, leaving the current remote directory in place.
    /// This operation is not transactional; review the target before calling it.
    public func deleteTree() async throws {
        let root = try await withLastReply { try await controlChannel.printWorkingDirectory().workingDirectoryPath() }
        var directories: [(path: String, depth: Int)] = [(root, 0)]
        var files: [String] = []
        var children: [(path: String, depth: Int)] = []
        var visited = 0
        while let (directory, depth) = directories.popLast() {
            try Task.checkCancellation()
            guard depth <= 128 else { throw FTPError.invalidState(description: "Remote tree exceeds depth limit") }
            for entry in try await withLastReply({ try await controlChannel.listEntries(path: directory) }) {
                if entry.kind == .currentDirectory || entry.kind == .parentDirectory { continue }
                guard !entry.name.isEmpty, entry.name != ".", entry.name != "..",
                      !entry.name.utf8.contains(where: { $0 == 0 || $0 == 10 || $0 == 13 || $0 == 47 }) else {
                    throw FTPError.protocolViolation(description: "Unsafe remote tree entry")
                }
                visited += 1
                guard visited <= 100_000 else { throw FTPError.invalidState(description: "Remote tree exceeds entry limit") }
                let path = (directory.hasSuffix("/") ? directory : directory + "/") + entry.name
                switch entry.kind {
                case .file: files.append(path)
                case .directory:
                    directories.append((path, depth + 1))
                    children.append((path, depth + 1))
                default: throw FTPError.invalidState(description: "Unsupported remote tree entry: \(entry.name)")
                }
            }
        }
        for path in files.sorted() {
            try Task.checkCancellation()
            try await deleteRemoteFile(path)
        }
        for directory in children.sorted(by: { $0.depth == $1.depth ? $0.path < $1.path : $0.depth > $1.depth }) {
            try Task.checkCancellation()
            try await removeRemoteDir(directory.path)
        }
    }

    private func syncFilter() -> FTPSyncFilter {
        func patterns(_ value: String, default defaults: [String]) -> [String] {
            let values = value.split(separator: ";").map(String.init).filter { !$0.isEmpty }
            return values.isEmpty ? defaults : values
        }
        return FTPSyncFilter(includePatterns: patterns(syncMustMatch, default: ["*"]),
                             excludePatterns: patterns(syncMustNotMatch, default: []),
                             includeDirectoryPatterns: patterns(syncMustMatchDir, default: ["*"]),
                             excludeDirectoryPatterns: patterns(syncMustNotMatchDir, default: []),
                             caseSensitive: false, matchBasenameOnly: true)
    }

    public func previewSync(plan: FTPSyncPlan) async throws -> [FTPSyncOperation] {
        try await FTPSyncEngine(channel: controlChannel).preview(plan)
    }

    @discardableResult
    public func runSync(plan: FTPSyncPlan) async throws -> [FTPSyncOperation] {
        if plan.direction == .remoteToLocal { try await configureDownloadLineEnding() }
        else { try await configureUploadCRC() }
        return try await FTPSyncEngine(channel: controlChannel).run(plan)
    }

    public func disconnect() async {
        await controlChannel.disconnect()
        if let reply = await controlChannel.lastReply { lastReply = reply.message }
        listingCache = nil
    }

    public func setSessionLogging(_ enabled: Bool) async {
        keepSessionLog = enabled
        await controlChannel.setSessionLogging(enabled)
    }

    public func sessionLog() async -> String { await controlChannel.sessionLog() }
    public func clearSessionLog() async { await controlChannel.clearSessionLog() }

    /// Safe to read during an operation; other mutable facade properties must remain serialized.
    public func transferMetrics() async -> FTPTransferMetrics { await controlChannel.transferMetrics() }
    public var curBytesReceived: UInt32 { get async { UInt32(truncatingIfNeeded: await controlChannel.transferMetrics().receivedBytes) } }
    public var curBytesReceivedStr: String { get async { String(await controlChannel.transferMetrics().receivedBytes) } }
    public var curBytesSent: UInt32 { get async { UInt32(truncatingIfNeeded: await controlChannel.transferMetrics().sentBytes) } }
    public var curBytesSentStr: String { get async { String(await controlChannel.transferMetrics().sentBytes) } }
    public var downloadTransferRate: Int { get async { Int(clamping: await controlChannel.transferMetrics().downloadBytesPerSecond) } }
    public var uploadTransferRate: Int { get async { Int(clamping: await controlChannel.transferMetrics().uploadBytesPerSecond) } }
    /// Nil means that the download is still running or its completeness is unknown.
    public var partialTransfer: Bool? { get async { await controlChannel.transferMetrics().partialDownload } }

    public func checkConnection() async -> Bool { await controlChannel.isConnected }
    public func isLoggedIn() async -> Bool { await controlChannel.isAuthenticated }
    public func connectionWasVerified() async -> Bool { await controlChannel.connectVerified }
    public func loginWasVerified() async -> Bool { await controlChannel.loginVerified }
    public func greeting() async -> String { await controlChannel.greeting?.message ?? "" }
    public func serverCapabilities() async -> Set<String> { await controlChannel.serverFeatures }
    public func hasModeZ() async -> Bool { await controlChannel.serverFeatures.contains("MODEZ") }
    public func tlsSessionInfo() async throws -> FTPTLSSessionInfo? { try await controlChannel.tlsSessionInfo() }
    public func getServerCertificateDER() async throws -> Data {
        guard let certificate = try await tlsSessionInfo()?.serverCertificateDER else {
            throw FTPError.invalidState(description: "No active TLS server certificate")
        }
        return certificate
    }
}
