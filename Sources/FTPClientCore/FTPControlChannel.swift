import Foundation
import Network
import Darwin
import Security

private final class ContinuationResumeGuard: @unchecked Sendable {
    private let lock = NSLock()
    private var hasResumed = false

    func tryResume() -> Bool {
        lock.lock()
        defer { lock.unlock() }

        if hasResumed {
            return false
        }

        hasResumed = true
        return true
    }
}

private final class FirstCertificate: @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    func record(_ certificate: sec_certificate_t) {
        let value = SecCertificateCopyData(sec_certificate_copy_ref(certificate).takeRetainedValue()) as Data
        lock.lock()
        if data == nil { data = value }
        lock.unlock()
    }
    func read() -> Data? { lock.lock(); defer { lock.unlock() }; return data }
}

private final class FTPDataConnection: @unchecked Sendable {
    let connection: NWConnection
    let tls: FTPExplicitTLSStream?
    let encoder: FTPZlibStream?
    let decoder: FTPZlibStream?
    private let identityOwner: FTPImportedIdentity?
    var prefetched: Data
        var prefetchedComplete: Bool
        init(connection: NWConnection, tls: FTPExplicitTLSStream?, prefetched: Data = Data(), compressed: Bool = false,
            prefetchedComplete: Bool = false, identityOwner: FTPImportedIdentity? = nil) throws {
        self.connection = connection
        self.tls = tls
        self.identityOwner = identityOwner
        self.prefetched = prefetched
        self.prefetchedComplete = prefetchedComplete
        self.encoder = compressed ? try FTPZlibStream(encoding: true) : nil
        self.decoder = compressed ? try FTPZlibStream(encoding: false) : nil
    }
    func cancel() { connection.cancel() }
}

public actor FTPControlChannel {
    public private(set) var isConnected: Bool
    public private(set) var isAuthenticated: Bool
    public private(set) var lastReply: FTPReply?
    public private(set) var serverFeatures: Set<String> = []
    public private(set) var serverSystem: String?
    public private(set) var connectVerified = false
    public private(set) var loginVerified = false
    public private(set) var greeting: FTPReply?

    private let queue: DispatchQueue
    private var connection: NWConnection?
    private var explicitTLSStream: FTPExplicitTLSStream?
    private var tlsSessionPeerID: Data?
    private var importedIdentity: FTPImportedIdentity?
    private var configuration: FTPClientConfiguration?
    private var replyParser = FTPReplyParser()
    private var prefetchedControl = Data()
    private var operationInProgress = false
    private var transferKeepAliveTask: Task<Void, Never>?
    private var transferKeepAliveStopped = true
    private var transferKeepAliveInFlight = false
    private var transferKeepAliveReply: FTPReply?
    private var transferKeepAliveError: Error?
    private struct TransferCounter {
        var bytes: UInt64 = 0
        var expectedBytes: UInt64?
        var started: TimeInterval = 0
        var rate: UInt64 = 0
        var succeeded: Bool?
    }
    private var downloadCounter = TransferCounter()
    private var uploadCounter = TransferCounter()
    private var activeTransferDirection: FTPTransferMetrics.Direction?
    private var aggregatingUpload = false
    private var aggregateUploadOwner: UUID?
    private var aggregateUploadFailed = false
    private var transferType: FTPTransferType = .binary
    private var dataProtected = false
    private var dataProtectionConfigured = false
    private var modeZEnabled = false
    private var nextAllocationSize: UInt64 = 0
    private var diagnosticLoggingEnabled = false
    private var redactSensitiveInformation = true
    private var diagnosticSecrets: [String] = []
    private let diagnosticID = UUID().uuidString.prefix(8)
    private var loggingEnabled = false
    private var logLines: [String] = []
    private var logBytes = 0
    private let maxLogBytes = 1_048_576

    public init() {
        self.isConnected = false
        self.isAuthenticated = false
        self.lastReply = nil
        self.queue = DispatchQueue(label: "FTPClientSwift.FTPControlChannel")
        self.connection = nil
        self.configuration = nil
    }

    /// Available during a transfer; reading metrics does not send an FTP command.
    public func transferMetrics() -> FTPTransferMetrics {
        let now = ProcessInfo.processInfo.systemUptime
        return FTPTransferMetrics(receivedBytes: downloadCounter.bytes, sentBytes: uploadCounter.bytes,
            downloadBytesPerSecond: activeTransferDirection == .download ? transferRate(downloadCounter, now: now) : downloadCounter.rate,
            uploadBytesPerSecond: activeTransferDirection == .upload ? transferRate(uploadCounter, now: now) : uploadCounter.rate,
            activeDirection: activeTransferDirection, lastDownloadSucceeded: downloadCounter.succeeded,
            lastUploadSucceeded: uploadCounter.succeeded, expectedDownloadBytes: downloadCounter.expectedBytes,
            expectedUploadBytes: uploadCounter.expectedBytes)
    }

    private func transferRate(_ counter: TransferCounter, now: TimeInterval) -> UInt64 {
        let elapsed = now - counter.started
        guard counter.bytes > 0, elapsed > 0 else { return 0 }
        let rate = Double(counter.bytes) / elapsed
        guard rate.isFinite else { return UInt64.max }
        return rate >= Double(UInt64.max) ? UInt64.max : UInt64(rate)
    }

    private func beginTransferMetrics(_ direction: FTPTransferMetrics.Direction) {
        if direction == .upload && aggregatingUpload { return }
        var counter = TransferCounter()
        counter.started = ProcessInfo.processInfo.systemUptime
        if direction == .download { downloadCounter = counter } else { uploadCounter = counter }
        activeTransferDirection = direction
        diagnostic("info", "Transfer started: \(direction)")
    }

    private func recordTransferBytes(_ count: Int) {
        diagnostic("debug", "Transfer chunk: \(count) bytes; direction=\(String(describing: activeTransferDirection))")
        guard count > 0, let direction = activeTransferDirection else { return }
        if direction == .download {
            let (value, overflow) = downloadCounter.bytes.addingReportingOverflow(UInt64(count))
            downloadCounter.bytes = overflow ? UInt64.max : value
        } else {
            let (value, overflow) = uploadCounter.bytes.addingReportingOverflow(UInt64(count))
            uploadCounter.bytes = overflow ? UInt64.max : value
        }
    }

    private func finishTransferMetrics(_ direction: FTPTransferMetrics.Direction, succeeded: Bool) {
        if direction == .upload && aggregatingUpload {
            if !succeeded { aggregateUploadFailed = true }
            return
        }
        let now = ProcessInfo.processInfo.systemUptime
        if direction == .download {
            downloadCounter.rate = transferRate(downloadCounter, now: now)
            downloadCounter.succeeded = succeeded
        } else {
            uploadCounter.rate = transferRate(uploadCounter, now: now)
            uploadCounter.succeeded = succeeded
        }
        let counter = direction == .download ? downloadCounter : uploadCounter
        diagnostic(succeeded ? "info" : "error", "Transfer finished: \(direction), success=\(succeeded), bytes=\(counter.bytes), bytes/sec=\(counter.rate)")
        activeTransferDirection = nil
    }

    /// Groups sequential STOR/APPE operations into one upload progress record.
    public func beginChunkedUploadMetrics(expectedBytes: UInt64? = nil) throws {
        try beginOperation()
        defer { operationInProgress = false }
        guard isConnected, !aggregatingUpload, let identifier = FTPChunkedUploadScope.identifier else {
            throw FTPError.invalidState(description: "Cannot begin chunked upload metrics")
        }
        beginTransferMetrics(.upload)
        uploadCounter.expectedBytes = expectedBytes
        aggregateUploadFailed = false
        aggregateUploadOwner = identifier
        aggregatingUpload = true
    }

    public func finishChunkedUploadMetrics(succeeded: Bool) {
        guard !operationInProgress, aggregatingUpload, FTPChunkedUploadScope.identifier == aggregateUploadOwner else { return }
        endChunkedUploadMetrics(succeeded: succeeded)
    }

    private func endChunkedUploadMetrics(succeeded: Bool) {
        aggregatingUpload = false
        aggregateUploadOwner = nil
        finishTransferMetrics(.upload, succeeded: succeeded && !aggregateUploadFailed)
        aggregateUploadFailed = false
    }

    public func connect(configuration: FTPClientConfiguration) async throws {
        diagnosticLoggingEnabled = configuration.loggingEnabled
        redactSensitiveInformation = configuration.redactSensitiveInformation
        diagnosticSecrets = FTPDiagnosticRedactor.secrets(in: configuration)
        diagnostic("info", "Connecting to \(configuration.host):\(configuration.port); security=\(configuration.security), dataMode=\(configuration.dataConnectionMode), connectTimeout=\(configuration.connectTimeout)s, readTimeout=\(configuration.readTimeout)s")
        if let proxy = configuration.proxy { diagnostic("info", "Proxy endpoint: \(proxy.endpoint.host):\(proxy.endpoint.port)") }
        if configuration.security == .none { diagnostic("warning", "Control connection is unencrypted") }
        if !configuration.requireServerCertificateValidation { diagnostic("warning", "Server certificate chain validation is disabled") }
        try beginOperation()
        defer { operationInProgress = false }
        if isConnected {
            return
        }
        connectVerified = false
        loginVerified = false
        greeting = nil
        lastReply = nil

        guard !configuration.host.isEmpty else {
            throw FTPError.invalidState(description: "Host must not be empty")
        }
        guard configuration.security != .none || configuration.dataProtection != .privateData else {
            throw FTPError.invalidState(description: "Private data protection requires a TLS control connection")
        }

        guard let portNumber = UInt16(exactly: configuration.port),
              let port = NWEndpoint.Port(rawValue: portNumber) else {
            throw FTPError.invalidState(description: "Invalid FTP port: \(configuration.port)")
        }
        guard configuration.connectTimeout.isFinite, configuration.connectTimeout > 0,
              configuration.readTimeout.isFinite, configuration.readTimeout > 0 else {
            throw FTPError.invalidState(description: "Timeouts must be finite and positive")
        }
        if let interval = configuration.transferKeepAliveInterval, !interval.isFinite || interval < 0.01 || interval > 86_400 {
            throw FTPError.invalidState(description: "Transfer keepalive interval must be between 0.01 and 86400 seconds")
        }
        guard configuration.maximumBufferedBytes > 0 else { throw FTPError.invalidState(description: "Maximum buffered bytes must be positive") }
        _ = try FTPTrustEvaluator.parsePins(configuration.pinnedPublicKeyHashes)
        guard configuration.certificateRequirements.allSatisfy({ !$0.pattern.utf8.contains(0) }) else {
            throw FTPError.invalidState(description: "Invalid certificate requirement pattern")
        }
        _ = try FTPTLSPolicy.cipherCodes(configuration.allowedCipherSuites)
        if configuration.minimumTLSVersion == .tls13 && configuration.maximumTLSVersion == .tls12 {
            throw FTPError.invalidState(description: "Invalid TLS version range")
        }
        if configuration.enableTLSSessionResumption && (configuration.minimumTLSVersion == .tls13 || configuration.maximumTLSVersion == .tls13) {
            throw FTPError.notImplemented(feature: "TLS 1.3 with FTPS session reuse")
        }
        _ = try FTPCharset.encoding(named: configuration.commandCharset, asciiCompatible: true)
        _ = try FTPCharset.encoding(named: configuration.directoryListingCharset, asciiCompatible: true)
        let replyEncoding = try FTPCharset.encoding(named: configuration.replyCharset, asciiCompatible: true)
        if let identifier = configuration.legacyListingTimeZoneIdentifier, TimeZone(identifier: identifier) == nil {
            throw FTPError.invalidState(description: "Unknown legacy LIST time zone")
        }
        guard (0...65535).contains(configuration.activePortRangeStart), (0...65535).contains(configuration.activePortRangeEnd) else {
            throw FTPError.invalidState(description: "Invalid active port range")
        }
        if let proxy = configuration.proxy, configuration.dataConnectionMode == .active {
            switch proxy {
            case .socks5: try validateSOCKS5ActiveConfiguration(configuration)
            case .socks4: try validateSOCKS4ActiveConfiguration(configuration)
            default: throw FTPError.notImplemented(feature: "Active FTP through this proxy")
            }
        }
        if let proxy = configuration.proxy, !proxy.isTunnel, configuration.security != .none {
            throw FTPError.notImplemented(feature: "FTPS through a traditional FTP proxy")
        }

        let destination = configuration.proxy?.endpoint
        if let destination {
            guard !destination.host.isEmpty, destination.host.utf8.allSatisfy({ $0 != 0 && $0 != 10 && $0 != 13 }) else {
                throw FTPError.invalidState(description: "Invalid proxy hostname")
            }
        }
        let physicalPort: NWEndpoint.Port
        if let destination {
            guard let raw = UInt16(exactly: destination.port), let value = NWEndpoint.Port(rawValue: raw) else {
                throw FTPError.invalidState(description: "Invalid proxy port")
            }
            physicalPort = value
        } else { physicalPort = port }
        let importedIdentity = configuration.security == .none ? nil : try configuration.clientIdentity.map(FTPImportedIdentity.load)
        let parameters = configuration.proxy != nil || configuration.security == .explicitTLS || configuration.security == .explicitSSL || configuration.enableTLSSessionResumption ? NWParameters.tcp : try connectionParameters(configuration: configuration, controlChannel: true, importedIdentity: importedIdentity)
        try configureLocalBinding(parameters, configuration: configuration)
        let connection = NWConnection(host: NWEndpoint.Host(destination?.host ?? configuration.host), port: physicalPort, using: parameters)
        self.connection = connection
        self.configuration = configuration
        self.importedIdentity = importedIdentity
        self.tlsSessionPeerID = configuration.enableTLSSessionResumption ? Data(UUID().uuidString.utf8) : nil
        self.transferType = configuration.transferType
        self.replyParser = FTPReplyParser(encoding: replyEncoding)

        do {
            try await waitForReady(connection: connection)
            connectVerified = true
            if let proxy = configuration.proxy, proxy.isTunnel {
                let prefetched = try await negotiateProxy(proxy, targetHost: configuration.host, targetPort: configuration.port, connection: connection)
                guard !prefetched.isComplete else { throw FTPError.connectionFailed(description: "Proxy control tunnel closed") }
                prefetchedControl = prefetched.data
            }
            if configuration.security == .implicitTLS && (configuration.proxy?.isTunnel == true || configuration.enableTLSSessionResumption) {
                guard prefetchedControl.isEmpty else { throw FTPError.protocolViolation(description: "Unexpected bytes before TLS handshake") }
                let stream = try FTPExplicitTLSStream(connection: connection, configuration: configuration, controlChannel: true, importedIdentity: importedIdentity, sessionPeerID: tlsSessionPeerID)
                try await stream.handshake()
                explicitTLSStream = stream
            }
            var greeting = try await readReply(using: connection)
            if greeting.code == 120 {
                greeting = try await readReply(using: connection)
            }
            guard greeting.code == 220 else {
                throw FTPError.serverReply(code: greeting.code, message: greeting.message)
            }
            lastReply = greeting
            self.greeting = greeting
            appendLog("< \(greeting.message)")
            if configuration.security == .explicitTLS || configuration.security == .explicitSSL {
                let command = configuration.security == .explicitSSL ? "AUTH SSL" : "AUTH TLS"
                appendLog("> \(command)")
                try await send(payload: Data("\(command)\r\n".utf8), connection: connection)
                let reply = try await readReply(using: connection)
                lastReply = reply
                appendLog("< \(reply.message)")
                guard reply.code == 234 else {
                    throw FTPError.serverReply(code: reply.code, message: reply.message)
                }
                guard !replyParser.hasBufferedBytes else {
                    throw FTPError.protocolViolation(description: "Unexpected plaintext after AUTH TLS reply")
                }
                let stream = try FTPExplicitTLSStream(connection: connection, configuration: configuration, controlChannel: true, importedIdentity: importedIdentity, sessionPeerID: tlsSessionPeerID)
                try await stream.handshake()
                guard self.connection === connection else {
                    throw FTPError.connectionFailed(description: "Connection closed during TLS handshake")
                }
                explicitTLSStream = stream
            }
            guard self.connection === connection else {
                throw FTPError.connectionFailed(description: "Connection closed during connect")
            }
            diagnostic("info", "Control connection ready; security=\(configuration.security)")
            isConnected = true
            isAuthenticated = false
            if diagnosticLoggingEnabled, let info = try? await tlsSessionInfo() {
                diagnostic("info", "TLS negotiated: \(info.protocolVersion), cipher=\(info.cipherSuite), chainValidationRequired=\(info.chainValidationRequired)")
            }
            if configuration.security != .none {
                try await configureDataProtection(configuration: configuration, allowLoginRequired: true)
            }
        } catch {
            diagnostic("error", "Operation failed: \(error)")
            resetConnection()
            if Task.isCancelled { throw CancellationError() }
            throw error
        }
    }

    public func login() async throws {
        try beginOperation()
        defer { operationInProgress = false }
        guard isConnected else {
            throw FTPError.invalidState(description: "Not connected")
        }

        guard let configuration else {
            throw FTPError.invalidState(description: "Missing configuration")
        }

        if case .traditional(_, _, let method, let proxyUsername, let proxyPassword) = configuration.proxy {
            try await loginThroughTraditionalProxy(configuration: configuration, method: method, proxyUsername: proxyUsername, proxyPassword: proxyPassword)
            try await finishLogin(configuration: configuration)
            return
        }

        let userReply = try await sendCommandLocked("USER \(configuration.loginUsername)")

        if userReply.code == 230 {
            try await finishLogin(configuration: configuration)
            return
        }

        guard userReply.code == 331 else {
            throw FTPError.serverReply(code: userReply.code, message: userReply.message)
        }

        let passReply = try await sendCommandLocked("PASS \(configuration.password)")
        guard passReply.code == 230 || passReply.code == 202 else {
            if passReply.code == 332, let account = configuration.account, !account.isEmpty {
                let accountReply = try await sendCommandLocked("ACCT \(account)")
                guard accountReply.code == 230 || accountReply.code == 202 else {
                    throw FTPError.serverReply(code: accountReply.code, message: accountReply.message)
                }
            } else {
                throw FTPError.serverReply(code: passReply.code, message: passReply.message)
            }
            try await finishLogin(configuration: configuration)
            return
        }

        try await finishLogin(configuration: configuration)
    }

    private func finishLogin(configuration: FTPClientConfiguration) async throws {
        if configuration.security != .none && !dataProtectionConfigured {
            try await configureDataProtection(configuration: configuration, allowLoginRequired: false)
        }
        isAuthenticated = true
        diagnostic("info", "Authentication completed")
        loginVerified = true
        if configuration.autoSyst {
            let reply = try await sendCommandLocked("SYST")
            if let code = reply.code, (200..<300).contains(code) { serverSystem = reply.message }
        }
        if configuration.autoFeat {
            let reply = try await sendCommandLocked("FEAT")
            if reply.code == 211 { try await processFeatures(reply) }
        }
    }

    private func loginThroughTraditionalProxy(configuration: FTPClientConfiguration, method: Int, proxyUsername: String, proxyPassword: String) async throws {
        let host = configuration.host.contains(":") ? "[\(configuration.host)]" : configuration.host
        let hostAndPort = "\(host):\(configuration.port)"
        func command(_ text: String, sensitive: Bool = false) async throws {
            let reply = try await sendCommandLocked(text, redact: sensitive)
            guard let code = reply.code, (200..<400).contains(code) else {
                throw FTPError.serverReply(code: reply.code, message: reply.message)
            }
        }
        func authenticate(_ username: String, _ password: String, account: String? = nil) async throws {
            let user = try await sendCommandLocked("USER \(username)")
            if user.code == 230 { return }
            guard user.code == 331 else { throw FTPError.serverReply(code: user.code, message: user.message) }
            let pass = try await sendCommandLocked("PASS \(password)")
            if pass.code == 230 || pass.code == 202 { return }
            if pass.code == 332, let account, !account.isEmpty {
                let reply = try await sendCommandLocked("ACCT \(account)")
                guard reply.code == 230 || reply.code == 202 else { throw FTPError.serverReply(code: reply.code, message: reply.message) }
                return
            }
            throw FTPError.serverReply(code: pass.code, message: pass.message)
        }
        switch method {
        case 1:
            try await authenticate(proxyUsername, proxyPassword)
            try await command("SITE \(host)")
            try await authenticate(configuration.loginUsername, configuration.password, account: configuration.account)
        case 2:
            try await authenticate("\(configuration.loginUsername)@\(hostAndPort)", configuration.password, account: configuration.account)
        case 3:
            try await authenticate(proxyUsername, proxyPassword)
            try await authenticate("\(configuration.loginUsername)@\(hostAndPort)", configuration.password, account: configuration.account)
        case 4:
            try await authenticate("\(configuration.loginUsername)@\(hostAndPort) \(proxyUsername)", configuration.password, account: proxyPassword)
        case 5:
            try await authenticate(proxyUsername, proxyPassword)
            try await command("OPEN \(host)")
            try await authenticate(configuration.loginUsername, configuration.password, account: configuration.account)
        case 6:
            try await command("USER \(proxyUsername)@\(host)", sensitive: true)
            try await authenticate(configuration.loginUsername, configuration.password, account: configuration.account)
        case 7:
            try await command("USER \(proxyUsername)", sensitive: true)
            try await command("USER \(proxyPassword)", sensitive: true)
            try await command("SITE \(hostAndPort)")
            try await authenticate(configuration.loginUsername, configuration.password, account: configuration.account)
        case 8:
            try await authenticate("\(configuration.loginUsername)@\(proxyUsername)@\(host)", "\(configuration.password)@\(proxyPassword)")
        case 9:
            try await command(proxyUsername, sensitive: true)
            try await command(proxyPassword, sensitive: true)
            try await command(configuration.loginUsername, sensitive: true)
            try await command(configuration.password, sensitive: true)
        default: throw FTPError.invalidState(description: "Unsupported FTP proxy method: \(method)")
        }
    }

    private func processFeatures(_ reply: FTPReply) async throws {
        serverFeatures = Set(reply.message.components(separatedBy: "\n").compactMap { line in
            let text = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let first = text.split(whereSeparator: { $0.isWhitespace }).first,
                  first.first?.isNumber == false else { return nil }
            if first.uppercased() == "MODE", text.uppercased().split(whereSeparator: { $0.isWhitespace }).dropFirst().contains("Z") { return "MODEZ" }
            return first.uppercased()
        })
        if configuration?.autoOptsUtf8 == true, serverFeatures.contains("UTF8") || serverFeatures.contains("UTF-8") {
            configuration?.commandCharset = "utf-8"
            configuration?.directoryListingCharset = "utf-8"
            _ = try await sendCommandLocked("OPTS UTF8 ON")
        }
    }

    /// Effective session charsets, including any automatic UTF-8 negotiation.
    public func effectiveCharsets() -> (command: String, listing: String)? {
        guard let configuration else { return nil }
        return (configuration.commandCharset, configuration.directoryListingCharset)
    }

    /// Applies charset changes to future commands and directory listings.
    public func setSessionCharsets(command: String, listing: String, autoOptsUTF8: Bool) throws {
        try beginOperation()
        defer { operationInProgress = false }
        guard configuration != nil else { throw FTPError.invalidState(description: "Not connected") }
        _ = try FTPCharset.encoding(named: command, asciiCompatible: true)
        _ = try FTPCharset.encoding(named: listing, asciiCompatible: true)
        configuration?.commandCharset = command
        configuration?.directoryListingCharset = listing
        configuration?.autoOptsUtf8 = autoOptsUTF8
    }

    /// Applies transport settings to subsequent data connections, not an active transfer.
    public func setSessionDataSettings(mode: FTPDataConnectionMode, preferEPSV: Bool, usePASVAdvertisedAddress: Bool,
                                       throttleUp: UInt64, throttleDown: UInt64, activePortStart: Int, activePortEnd: Int,
                                       activeIPv4: String?, bindActiveIPv4: Bool, maximumBufferedBytes: Int,
                                       keepAliveInterval: TimeInterval? = nil) throws {
        try beginOperation()
        defer { operationInProgress = false }
        guard let current = configuration, isConnected else { throw FTPError.invalidState(description: "Not connected") }
        guard (0...65535).contains(activePortStart), (0...65535).contains(activePortEnd) else {
            throw FTPError.invalidState(description: "Invalid active port range")
        }
        guard maximumBufferedBytes > 0 else { throw FTPError.invalidState(description: "Maximum buffered bytes must be positive") }
        if let interval = keepAliveInterval, !interval.isFinite || interval < 0.01 || interval > 86_400 {
            throw FTPError.invalidState(description: "Transfer keepalive interval must be between 0.01 and 86400 seconds")
        }
        if let proxy = current.proxy, mode == .active {
            var candidate = current
            candidate.dataConnectionMode = mode
            candidate.activePortRangeStart = activePortStart
            candidate.activePortRangeEnd = activePortEnd
            candidate.activeAdvertisedIPv4 = activeIPv4
            candidate.bindActiveAdvertisedIPv4 = bindActiveIPv4
            switch proxy {
            case .socks5: try validateSOCKS5ActiveConfiguration(candidate)
            case .socks4: try validateSOCKS4ActiveConfiguration(candidate)
            default: throw FTPError.notImplemented(feature: "Active FTP through this proxy")
            }
        }
        if let activeIPv4, !activeIPv4.isEmpty {
            var value = in_addr()
            guard inet_pton(AF_INET, activeIPv4, &value) == 1 else {
                throw FTPError.invalidState(description: "Active advertised address must be numeric IPv4")
            }
        }
        configuration?.dataConnectionMode = mode
        configuration?.preferEPSV = preferEPSV
        configuration?.usePASVAdvertisedAddress = usePASVAdvertisedAddress
        configuration?.bandwidthThrottleUp = throttleUp
        configuration?.bandwidthThrottleDown = throttleDown
        configuration?.activePortRangeStart = activePortStart
        configuration?.activePortRangeEnd = activePortEnd
        configuration?.activeAdvertisedIPv4 = activeIPv4
        configuration?.bindActiveAdvertisedIPv4 = bindActiveIPv4
        configuration?.maximumBufferedBytes = maximumBufferedBytes
        configuration?.transferKeepAliveInterval = keepAliveInterval
    }

    /// Upgrades an existing clear control channel without reconnecting.
    public func convertToTLS() async throws {
        try beginOperation()
        defer { operationInProgress = false }
        guard isConnected, !isAuthenticated, let connection, var configuration,
              configuration.security == .none, explicitTLSStream == nil else {
            throw FTPError.invalidState(description: "TLS upgrade requires an unauthenticated clear control connection")
        }
        do {
            let reply = try await sendCommandLocked("AUTH TLS")
            guard reply.code == 234 else { throw FTPError.serverReply(code: reply.code, message: reply.message) }
            guard !replyParser.hasBufferedBytes, prefetchedControl.isEmpty else {
                throw FTPError.protocolViolation(description: "Unexpected plaintext after AUTH TLS reply")
            }
            let identity = try importedIdentity ?? configuration.clientIdentity.map(FTPImportedIdentity.load)
            let stream = try FTPExplicitTLSStream(connection: connection, configuration: configuration, controlChannel: true, importedIdentity: identity, sessionPeerID: tlsSessionPeerID)
            try await stream.handshake()
            guard self.connection === connection else { throw FTPError.connectionFailed(description: "Connection closed during TLS handshake") }
            configuration.security = .explicitTLS
            self.configuration = configuration
            self.importedIdentity = identity
            explicitTLSStream = stream
            diagnostic("info", "Control channel upgraded to TLS")
            try await configureDataProtection(configuration: configuration, allowLoginRequired: true)
        } catch {
            diagnostic("error", "Operation failed: \(error)")
            resetConnection()
            if Task.isCancelled { throw CancellationError() }
            throw error
        }
    }

    private func configureDataProtection(configuration: FTPClientConfiguration, allowLoginRequired: Bool) async throws {
        guard configuration.security != .none else { return }
        do {
            let pbsz = try await sendCommandLocked("PBSZ 0")
            if allowLoginRequired && pbsz.code == 530 { return }
            try requirePositiveCompletion(pbsz, operation: "PBSZ")
            let requestedClear = configuration.dataProtection == .clear
            var prot = try await sendCommandLocked(requestedClear ? "PROT C" : "PROT P")
            if allowLoginRequired && prot.code == 530 { return }
            if requestedClear, let code = prot.code, (400..<600).contains(code) {
                prot = try await sendCommandLocked("PROT P")
                if allowLoginRequired && prot.code == 530 { return }
                try requirePositiveCompletion(prot, operation: "PROT P")
                dataProtected = true
                dataProtectionConfigured = true
                return
            }
            try requirePositiveCompletion(prot, operation: "PROT")
            dataProtected = !requestedClear
            dataProtectionConfigured = true
        } catch {
            diagnostic("error", "Operation failed: \(error)")
            resetConnection()
            if Task.isCancelled { throw CancellationError() }
            throw error
        }
    }

    private func connectionParameters(configuration: FTPClientConfiguration, controlChannel: Bool = false,
                                      importedIdentity: FTPImportedIdentity?) throws -> NWParameters {
        guard configuration.security != .none else { return .tcp }
        let options = NWProtocolTLS.Options()
        let securityOptions = options.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(securityOptions, configuration.minimumTLSVersion == .tls13 ? .TLSv13 : .TLSv12)
        if let maximum = configuration.maximumTLSVersion {
            sec_protocol_options_set_max_tls_protocol_version(securityOptions, maximum == .tls13 ? .TLSv13 : .TLSv12)
        }
        for code in try FTPTLSPolicy.cipherCodes(configuration.allowedCipherSuites) {
            guard let suite = tls_ciphersuite_t(rawValue: code) else {
                throw FTPError.invalidState(description: "TLS cipher suite is unavailable on this platform")
            }
            sec_protocol_options_append_tls_ciphersuite(securityOptions, suite)
        }
        configuration.host.withCString { sec_protocol_options_set_tls_server_name(securityOptions, $0) }
        if configuration.clientIdentity != nil {
            guard let imported = importedIdentity else { throw FTPError.invalidState(description: "Missing imported client identity") }
            guard let identity = sec_identity_create_with_certificates(imported.identity, imported.certificates as CFArray) else {
                throw FTPError.invalidState(description: "Unable to create TLS client identity")
            }
            sec_protocol_options_set_local_identity(securityOptions, identity)
        }
        let roots = try configuration.trustedRootCertificates.map { data -> SecCertificate in
            guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else {
                throw FTPError.invalidState(description: "Invalid DER-encoded trust anchor")
            }
            return certificate
        }
        // Data sockets may connect to the control peer's numeric IP, but must
        // authenticate the original server name, not that IP or the PASV host.
        let hostname = configuration.host
        let requireChainValidation = configuration.requireServerCertificateValidation
        let pins = try FTPTrustEvaluator.parsePins(configuration.pinnedPublicKeyHashes)
        let requirements = controlChannel ? configuration.certificateRequirements : []
        sec_protocol_options_set_verify_block(securityOptions, { _, trust, complete in
            let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
            guard FTPTrustEvaluator.evaluate(secTrust, hostname: hostname, roots: roots, requireChainValidation: requireChainValidation, pins: pins) else {
                complete(false)
                return
            }
            guard !requirements.isEmpty else { complete(true); return }
            guard let certificate = SecTrustGetCertificateAtIndex(secTrust, 0) else { complete(false); return }
            complete(FTPCertificateFields.satisfies(requirements, certificate: SecCertificateCopyData(certificate) as Data))
        }, queue)
        return NWParameters(tls: options, tcp: NWProtocolTCP.Options())
    }

    private func configureLocalBinding(_ parameters: NWParameters, configuration: FTPClientConfiguration) throws {
        guard let address = configuration.localIPAddress, !address.isEmpty else { return }
        var v4 = in_addr(), v6 = in6_addr()
        guard inet_pton(AF_INET, address, &v4) == 1 || inet_pton(AF_INET6, address, &v6) == 1 else {
            throw FTPError.invalidState(description: "Local bind address must be numeric IPv4 or IPv6")
        }
        parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(address), port: .any)
    }

    public func sendCommand(_ command: String) async throws -> FTPReply {
        try beginOperation()
        defer { operationInProgress = false }
        return try await sendCommandLocked(command)
    }

    /// Sends a raw UTF-8 command regardless of the configured path charset.
    public func sendUTF8Command(_ command: String) async throws -> FTPReply {
        try beginOperation()
        defer { operationInProgress = false }
        return try await sendCommandLocked(command, charset: "utf-8")
    }

    private func sendCommandLocked(_ command: String, redact: Bool = false, charset: String? = nil) async throws -> FTPReply {
        guard let connection else {
            throw FTPError.invalidState(description: "No active connection")
        }

        guard isConnected else {
            throw FTPError.invalidState(description: "Not connected")
        }

        guard !command.isEmpty, !command.utf8.contains(where: { $0 == 13 || $0 == 10 || $0 == 0 }) else {
            throw FTPError.invalidState(description: "FTP commands cannot contain CR, LF, or NUL")
        }
        let encoding = try FTPCharset.encoding(named: charset ?? configuration?.commandCharset ?? "utf-8")
        guard var payload = command.data(using: encoding), !payload.contains(where: { $0 == 0 || $0 == 10 || $0 == 13 }) else {
            throw FTPError.invalidState(description: "FTP command cannot be represented safely in the selected character set")
        }
        payload.append(contentsOf: [13, 10])
        let verb = command.split(whereSeparator: { $0.isWhitespace }).first?.uppercased() ?? ""
        let sensitive = redact || ["USER", "PASS", "ACCT", "ADAT", "SITE"].contains(verb)
        if sensitive {
            let argument = String(command.drop(while: { !$0.isWhitespace }).drop(while: { $0.isWhitespace }))
            if !argument.isEmpty, !diagnosticSecrets.contains(argument) { diagnosticSecrets.append(argument) }
        }
        appendLog(sensitive && redactSensitiveInformation ? "> \(verb) [redacted]" : "> \(command)")
        do {
            if let explicitTLSStream {
                try await explicitTLSStream.send(payload)
            } else {
                try await send(payload: payload, connection: connection)
            }
            let reply = try await readReply(using: connection)
            lastReply = reply
            appendLog(sensitive && redactSensitiveInformation ? "< \(reply.code.map(String.init) ?? "???") [redacted]" : "< \(reply.message)")
            if let code = reply.code, code >= 400 { diagnostic(code >= 500 ? "error" : "warning", "Server returned FTP status \(code)") }
            return reply
        } catch {
            diagnostic("error", "Operation failed: \(error)")
            resetConnection()
            if Task.isCancelled { throw CancellationError() }
            throw error
        }
    }

    public func noop() async throws {
        let reply = try await sendCommand("NOOP")
        try requirePositiveCompletion(reply, operation: "NOOP")
    }

    public func feat() async throws -> FTPReply {
        try beginOperation()
        defer { operationInProgress = false }
        let reply = try await sendCommandLocked("FEAT")
        guard reply.code == 211 || reply.code == 500 || reply.code == 502 else {
            throw FTPError.serverReply(code: reply.code, message: reply.message)
        }
        if reply.code == 211 { try await processFeatures(reply) }
        return reply
    }

    public func syst() async throws -> FTPReply {
        try beginOperation()
        defer { operationInProgress = false }
        let reply = try await sendCommandLocked("SYST")
        try requirePositiveCompletion(reply, operation: "SYST")
        serverSystem = reply.message
        return reply
    }

    public func printWorkingDirectory() async throws -> FTPReply {
        let reply = try await sendCommand("PWD")
        try requirePositiveCompletion(reply, operation: "PWD")
        return reply
    }

    public func changeWorkingDirectory(path: String) async throws {
        let reply = try await sendCommand("CWD \(path)")
        try requirePositiveCompletion(reply, operation: "CWD")
    }

    public func makeDirectory(path: String) async throws {
        let reply = try await sendCommand("MKD \(path)")
        try requirePositiveCompletion(reply, operation: "MKD")
    }

    public func removeDirectory(path: String) async throws {
        let reply = try await sendCommand("RMD \(path)")
        try requirePositiveCompletion(reply, operation: "RMD")
    }

    public func deleteFile(path: String) async throws {
        let reply = try await sendCommand("DELE \(path)")
        try requirePositiveCompletion(reply, operation: "DELE")
    }

    public func renameFile(from oldPath: String, to newPath: String) async throws {
        try beginOperation()
        defer { operationInProgress = false }
        let startReply = try await sendCommandLocked("RNFR \(oldPath)")
        guard startReply.code == 350 else {
            throw FTPError.serverReply(code: startReply.code, message: startReply.message)
        }

        let finishReply = try await sendCommandLocked("RNTO \(newPath)")
        try requirePositiveCompletion(finishReply, operation: "RNTO")
    }

    public func listNames(path: String? = nil) async throws -> [String] {
        try beginOperation()
        defer { operationInProgress = false }
        let listing = try await listData(command: "NLST", path: path)
        return try parseListingNames(from: listing)
    }

    /// Returns unparsed server-specific LIST records without guessing their format.
    public func listDetails(path: String? = nil, option: String? = nil) async throws -> [String] {
        try beginOperation()
        defer { operationInProgress = false }
        let argument = [option, path].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " ")
        let listing = try await listData(command: "LIST", path: argument)
        return try parseListingNames(from: listing)
    }

    public func listEntries(path: String? = nil) async throws -> [FTPDirectoryEntry] {
        try beginOperation()
        defer { operationInProgress = false }
        return try await machineListingLocked(path: path)
    }

    /// Fetches entries with the selected strategy. NLST cannot determine entry types.
    public func listSelectedEntries(path: String? = nil, preference: FTPListingPreference = .machineReadable, listOption: String? = nil, preferNamesOnFallback: Bool = false) async throws -> [FTPDirectoryEntry] {
        try beginOperation()
        defer { operationInProgress = false }
        switch preference {
        case .machineReadable:
            return try await machineListingLocked(path: path, preferNamesOnFallback: preferNamesOnFallback, listOption: listOption)
        case .legacyDetails:
            let argument = [listOption, path].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " ")
            let data = try await listData(command: "LIST", path: argument)
            let zone = configuration?.legacyListingTimeZoneIdentifier.flatMap(TimeZone.init(identifier:))
            return try FTPLegacyListParser.parse(data, encoding: FTPCharset.encoding(named: configuration?.directoryListingCharset ?? "utf-8"), assumedTimeZone: zone)
        case .namesOnly:
            let data = try await listData(command: "NLST", path: path)
            return try parseListingNames(from: data).map {
                FTPDirectoryEntry(name: $0, kind: .other("unknown"), size: nil, modifiedAt: nil, facts: [:])
            }
        }
    }

    private func machineListingLocked(path: String?, preferNamesOnFallback: Bool = false, listOption: String? = nil) async throws -> [FTPDirectoryEntry] {
        do {
            let listing = try await listData(command: "MLSD", path: path)
            return try FTPMLSDParser.parse(listing, encoding: FTPCharset.encoding(named: configuration?.directoryListingCharset ?? "utf-8"))
        } catch FTPError.serverReply(let code, _) where code.map({ [500, 501, 502, 504].contains($0) }) == true {
            if preferNamesOnFallback {
                let listing = try await listData(command: "NLST", path: path)
                return try parseListingNames(from: listing).map {
                    FTPDirectoryEntry(name: $0, kind: .other("unknown"), size: nil, modifiedAt: nil, facts: [:])
                }
            }
            let argument = [listOption, path].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " ")
            let listing = try await listData(command: "LIST", path: argument)
            let zone = configuration?.legacyListingTimeZoneIdentifier.flatMap(TimeZone.init(identifier:))
            return try FTPLegacyListParser.parse(listing, encoding: FTPCharset.encoding(named: configuration?.directoryListingCharset ?? "utf-8"), assumedTimeZone: zone)
        }
    }

    /// Returns SIZE in binary transfer mode, as required for byte offsets.
    public func fileSize(path: String) async throws -> UInt64 {
        try beginOperation()
        defer { operationInProgress = false }
        return try await binaryFileSizeLocked(path: path)
    }

    private func binaryFileSizeLocked(path: String) async throws -> UInt64 {
        let typeReply = try await sendCommandLocked("TYPE I")
        try requirePositiveCompletion(typeReply, operation: "TYPE I")
        let reply = try await sendCommandLocked("SIZE \(path)")
        let value = try metadataValue(reply, operation: "SIZE")
        guard !value.isEmpty, value.utf8.allSatisfy({ (48...57).contains($0) }),
              let size = UInt64(value) else {
            throw FTPError.protocolViolation(description: "Invalid SIZE response")
        }
        return size
    }

    /// Returns the server's UTC MDTM timestamp, including fractional seconds.
    public func modificationTime(path: String) async throws -> Date {
        try beginOperation()
        defer { operationInProgress = false }
        let reply = try await sendCommandLocked("MDTM \(path)")
        let value = try metadataValue(reply, operation: "MDTM")
        return try FTPMLSDParser.parseTimestamp(value)
    }

    /// Sets a remote timestamp with MFMT, falling back to the legacy MDTM setter only if MFMT is unsupported.
    public func setModificationTime(_ date: Date, path: String) async throws {
        try beginOperation()
        defer { operationInProgress = false }
        guard date.timeIntervalSince1970.isFinite else { throw FTPError.invalidState(description: "Invalid modification time") }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = TimeZone(secondsFromGMT: 0)!
        formatter.dateFormat = "yyyyMMddHHmmss"
        let value = formatter.string(from: date)
        let reply = try await sendCommandLocked("MFMT \(value) \(path)")
        if let code = reply.code, [500, 501, 502, 504].contains(code) {
            let fallback = try await sendCommandLocked("MDTM \(value) \(path)")
            try requirePositiveCompletion(fallback, operation: "MDTM")
        } else {
            try requirePositiveCompletion(reply, operation: "MFMT")
        }
    }

    public func site(_ command: String) async throws {
        let reply = try await sendCommand("SITE \(command)")
        try requirePositiveCompletion(reply, operation: "SITE")
    }

    public func setTransferType(_ type: FTPTransferType) async throws {
        try beginOperation()
        defer { operationInProgress = false }
        let command = type == .binary ? "TYPE I" : "TYPE A"
        let reply = try await sendCommandLocked(command)
        try requirePositiveCompletion(reply, operation: command)
        transferType = type
    }

    public func setModeZ(_ enabled: Bool) async throws {
        try beginOperation()
        defer { operationInProgress = false }
        let command = enabled ? "MODE Z" : "MODE S"
        let reply = try await sendCommandLocked(command)
        try requirePositiveCompletion(reply, operation: command)
        modeZEnabled = enabled
    }

    private func selectTransferTypeLocked() async throws {
        let command = transferType == .binary ? "TYPE I" : "TYPE A"
        let reply = try await sendCommandLocked(command)
        try requirePositiveCompletion(reply, operation: command)
    }

    public func serverStatus() async throws -> FTPReply {
        let reply = try await sendCommand("STAT")
        try requirePositiveCompletion(reply, operation: "STAT")
        return reply
    }

    private func metadataValue(_ reply: FTPReply, operation: String) throws -> String {
        guard reply.code == 213 else {
            throw FTPError.serverReply(code: reply.code, message: reply.message)
        }
        guard reply.message.hasPrefix("213 ") else {
            throw FTPError.protocolViolation(description: "Invalid \(operation) response")
        }
        return String(reply.message.dropFirst(4))
    }

    private func listData(command: String, path: String?) async throws -> Data {
        guard isConnected else {
            throw FTPError.invalidState(description: "Not connected")
        }
        let listingCommand: String
        if let path, !path.isEmpty {
            listingCommand = "\(command) \(path)"
        } else {
            listingCommand = command
        }

        let dataConnection = try await startDataTransfer(command: listingCommand)
        defer { dataConnection.cancel() }
        startTransferKeepAlive(dataConnection)

        do {
            let listingData = try await receiveAllData(connection: dataConnection)
            let completionReply = try await finishTransferKeepAlive()
            try requirePositiveCompletion(completionReply, operation: command)
            return listingData
        } catch {
            diagnostic("error", "Transfer failed: \(error)")
            let keepAliveError = await abortTransferKeepAlive(dataConnection)
            resetConnection()
            if Task.isCancelled { throw CancellationError() }
            throw keepAliveError ?? error
        }
    }

    public func retrieveFileData(remotePath: String, restartOffset: UInt64? = nil) async throws -> Data {
        try beginOperation()
        defer { operationInProgress = false }
        beginTransferMetrics(.download)
        var succeeded = false
        defer { finishTransferMetrics(.download, succeeded: succeeded) }
        guard isConnected else {
            throw FTPError.invalidState(description: "Not connected")
        }

        guard restartOffset == nil || transferType == .binary else { throw FTPError.invalidState(description: "Resume requires binary transfer mode") }
        let expectedSize: UInt64?
        if let restartOffset {
            let size = try await binaryFileSizeLocked(path: remotePath)
            guard restartOffset <= size else { throw FTPError.invalidState(description: "Resume offset exceeds remote size") }
            expectedSize = size
        } else { expectedSize = nil }
        if let expectedSize, let restartOffset { downloadCounter.expectedBytes = expectedSize - restartOffset }
        try await selectTransferTypeLocked()
        let dataConnection = try await startDataTransfer(command: "RETR \(remotePath)", restartOffset: restartOffset)
        defer { dataConnection.cancel() }
        startTransferKeepAlive(dataConnection)

        do {
            let payload = try await receiveAllData(connection: dataConnection, throttleRate: configuration?.bandwidthThrottleDown ?? 0, lineEnding: downloadLineEnding, trackDownload: true)
            let completionReply = try await finishTransferKeepAlive()
            try requirePositiveCompletion(completionReply, operation: "RETR")
            if let expectedSize, let restartOffset, UInt64(payload.count) != expectedSize - restartOffset {
                throw FTPError.protocolViolation(description: "Resumed download size does not match SIZE response")
            }
            succeeded = true
            return payload
        } catch {
            diagnostic("error", "Transfer failed: \(error)")
            let keepAliveError = await abortTransferKeepAlive(dataConnection)
            resetConnection()
            if Task.isCancelled { throw CancellationError() }
            throw keepAliveError ?? error
        }
    }

    public func storeFileData(_ data: Data, remotePath: String, append: Bool = false, resume: Bool = false) async throws {
        try beginOperation()
        defer { operationInProgress = false; nextAllocationSize = 0 }
        beginTransferMetrics(.upload)
        var succeeded = false
        defer { finishTransferMetrics(.upload, succeeded: succeeded) }
        guard isConnected else {
            throw FTPError.invalidState(description: "Not connected")
        }

        guard !(append && resume), !resume || transferType == .binary else {
            throw FTPError.invalidState(description: "Resume requires binary mode and cannot be combined with append")
        }
        let verifyCRC = try shouldVerifyUploadCRC(append: append)
        var crc = FTPCRC32()
        if verifyCRC {
            for position in stride(from: 0, to: data.count, by: 65_536) {
                try Task.checkCancellation()
                crc.update(Data(data.dropFirst(position).prefix(65_536)))
            }
        }
        let offset: UInt64?
        if resume {
            let size = try await binaryFileSizeLocked(path: remotePath)
            guard size <= UInt64(data.count) else { throw FTPError.invalidState(description: "Remote resume prefix exceeds local size") }
            offset = size
        } else { offset = nil }
        let content = offset.map { Data(data.dropFirst(Int($0))) } ?? data
        if !aggregatingUpload { uploadCounter.expectedBytes = UInt64(content.count) }
        try await selectTransferTypeLocked()
        try await allocateUploadLocked()
        let verb = append ? "APPE" : "STOR"
        let dataConnection = try await startDataTransfer(command: "\(verb) \(remotePath)", restartOffset: offset)
        defer { dataConnection.cancel() }
        startTransferKeepAlive(dataConnection)

        do {
            let rate = configuration?.bandwidthThrottleUp ?? 0
            let start = ProcessInfo.processInfo.systemUptime
            var sent: UInt64 = 0
            for offset in stride(from: 0, to: content.count, by: 65_536) {
                try Task.checkCancellation()
                let chunk = Data(content.dropFirst(offset).prefix(65_536))
                try await send(payload: chunk, connection: dataConnection)
                recordTransferBytes(chunk.count)
                sent += UInt64(chunk.count)
                try await throttle(bytes: sent, rate: rate, started: start)
            }
            try await finishSending(payload: Data(), connection: dataConnection)
            let completionReply = try await finishTransferKeepAlive()
            try requirePositiveCompletion(completionReply, operation: verb)
            if resume, try await binaryFileSizeLocked(path: remotePath) != UInt64(data.count) {
                throw FTPError.protocolViolation(description: "Resumed upload size does not match local data")
            }
        } catch {
            diagnostic("error", "Transfer failed: \(error)")
            let keepAliveError = await abortTransferKeepAlive(dataConnection)
            resetConnection()
            if Task.isCancelled { throw CancellationError() }
            throw keepAliveError ?? error
        }
        if verifyCRC { try await verifyUploadCRC(crc.value, path: remotePath) }
        succeeded = true
    }

    /// Streams chunks to the caller. A sink may receive partial data before a later failure.
    public func downloadStream(remotePath: String, progress: (@Sendable (UInt64) -> Void)? = nil, sink: @escaping @Sendable (Data) async throws -> Void) async throws {
        try beginOperation()
        defer { operationInProgress = false }
        beginTransferMetrics(.download)
        var succeeded = false
        defer { finishTransferMetrics(.download, succeeded: succeeded) }
        let dataConnection = try await beginFileTransfer(command: "RETR \(remotePath)")
        defer { dataConnection.cancel() }
        startTransferKeepAlive(dataConnection)
        do {
            let start = ProcessInfo.processInfo.systemUptime
            let rate = configuration?.bandwidthThrottleDown ?? 0
            var transferred: UInt64 = 0
            var delivered: UInt64 = 0
            var converter = FTPASCIINewlineConverter(downloadLineEnding)
            progress?(0)
            while true {
                try Task.checkCancellation()
                let chunk = try await receiveChunkWithCompletion(connection: dataConnection)
                let converted = converter.convert(chunk.data, final: chunk.isComplete)
                recordTransferBytes(converted.count)
                if !converted.isEmpty {
                    try await sink(converted)
                    delivered += UInt64(converted.count)
                    progress?(delivered)
                }
                if !chunk.data.isEmpty {
                    transferred += UInt64(chunk.data.count)
                    try await throttle(bytes: transferred, rate: rate, started: start)
                }
                if chunk.isComplete { break }
            }
            let reply = try await finishTransferKeepAlive()
            try requirePositiveCompletion(reply, operation: "RETR")
            succeeded = true
        } catch {
            diagnostic("error", "Transfer failed: \(error)")
            let keepAliveError = await abortTransferKeepAlive(dataConnection)
            resetConnection()
            if Task.isCancelled { throw CancellationError() }
            throw keepAliveError ?? error
        }
    }

    /// Streams a caller-provided async sequence to STOR or APPE without buffering the entire file.
    public func uploadStream(remotePath: String, source: AsyncThrowingStream<Data, Error>, append: Bool = false, progress: (@Sendable (UInt64) -> Void)? = nil) async throws {
        try beginOperation()
        defer { operationInProgress = false; nextAllocationSize = 0 }
        beginTransferMetrics(.upload)
        var succeeded = false
        defer { finishTransferMetrics(.upload, succeeded: succeeded) }
        let verifyCRC = try shouldVerifyUploadCRC(append: append)
        var crc = FTPCRC32()
        try await allocateUploadLocked()
        let verb = append ? "APPE" : "STOR"
        let dataConnection = try await beginFileTransfer(command: "\(verb) \(remotePath)")
        defer { dataConnection.cancel() }
        startTransferKeepAlive(dataConnection)
        do {
            let start = ProcessInfo.processInfo.systemUptime
            let rate = configuration?.bandwidthThrottleUp ?? 0
            var transferred: UInt64 = 0
            progress?(0)
            for try await chunk in source {
                try Task.checkCancellation()
                guard !chunk.isEmpty else { continue }
                for position in stride(from: 0, to: chunk.count, by: 65_536) {
                    try Task.checkCancellation()
                    let part = Data(chunk.dropFirst(position).prefix(65_536))
                    try await send(payload: part, connection: dataConnection)
                    recordTransferBytes(part.count)
                    if verifyCRC { crc.update(part) }
                    transferred += UInt64(part.count)
                    progress?(transferred)
                    try await throttle(bytes: transferred, rate: rate, started: start)
                }
            }
            try Task.checkCancellation()
            try await finishSending(payload: Data(), connection: dataConnection)
            let reply = try await finishTransferKeepAlive()
            try requirePositiveCompletion(reply, operation: verb)
        } catch {
            diagnostic("error", "Transfer failed: \(error)")
            let keepAliveError = await abortTransferKeepAlive(dataConnection)
            resetConnection()
            if Task.isCancelled { throw CancellationError() }
            throw keepAliveError ?? error
        }
        if verifyCRC { try await verifyUploadCRC(crc.value, path: remotePath) }
        succeeded = true
    }

    /// Downloads into a temporary sibling file and atomically replaces the destination
    /// only after the server acknowledges successful completion. Progress reports
    /// cumulative bytes written, not successful server acknowledgement.
    public func downloadFile(remotePath: String, to destination: URL, resume: Bool = false, modificationTime: Date? = nil, expectedBytes: UInt64? = nil, querySizeForProgress: Bool = false, progress: (@Sendable (UInt64) -> Void)? = nil) async throws {
        try beginOperation()
        defer { operationInProgress = false }
        beginTransferMetrics(.download)
        var succeeded = false
        defer { finishTransferMetrics(.download, succeeded: succeeded) }
        guard destination.isFileURL else {
            throw FTPError.invalidState(description: "Destination must be a file URL")
        }
        let parent = Darwin.open(destination.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard parent >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { Darwin.close(parent) }
        try await downloadFileLocked(remotePath: remotePath, directory: parent, name: destination.lastPathComponent,
                                     resume: resume, modificationTime: modificationTime, expectedBytes: expectedBytes,
                                     querySizeForProgress: querySizeForProgress, progress: progress)
        succeeded = true
    }

    /// Downloads relative to an open directory descriptor. The caller must keep
    /// the descriptor open until this method returns; this method duplicates it.
    public func downloadFile(remotePath: String, directoryDescriptor: Int32, filename: String, resume: Bool = false,
                             modificationTime: Date? = nil, expectedBytes: UInt64? = nil, querySizeForProgress: Bool = false,
                             progress: (@Sendable (UInt64) -> Void)? = nil) async throws {
        try beginOperation()
        defer { operationInProgress = false }
        beginTransferMetrics(.download)
        var succeeded = false
        defer { finishTransferMetrics(.download, succeeded: succeeded) }
        let parent = fcntl(directoryDescriptor, F_DUPFD_CLOEXEC, 0)
        guard parent >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { Darwin.close(parent) }
        var metadata = stat()
        guard fstat(parent, &metadata) == 0, (metadata.st_mode & S_IFMT) == S_IFDIR else {
            throw FTPError.invalidState(description: "Download parent must be an open directory")
        }
        try await downloadFileLocked(remotePath: remotePath, directory: parent, name: filename,
                                     resume: resume, modificationTime: modificationTime, expectedBytes: expectedBytes,
                                     querySizeForProgress: querySizeForProgress, progress: progress)
        succeeded = true
    }

    private func downloadFileLocked(remotePath: String, directory: Int32, name: String, resume: Bool,
                                    modificationTime: Date?, expectedBytes: UInt64?, querySizeForProgress: Bool,
                                    progress: (@Sendable (UInt64) -> Void)?) async throws {
        guard !name.isEmpty, name != ".", name != "..", !name.utf8.contains(where: { $0 == 0 || $0 == 47 }) else {
            throw FTPError.invalidState(description: "Invalid local download filename")
        }
        guard !resume || transferType == .binary else { throw FTPError.invalidState(description: "Resume requires binary transfer mode") }
        let temporary = ".ftp-\(UUID().uuidString).part"
        let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer {
            try? file.close()
            _ = unlinkat(directory, temporary, 0)
        }

        var prefixSize: UInt64 = 0
        if resume {
            let sourceFD = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            guard sourceFD >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            let source = FileHandle(fileDescriptor: sourceFD, closeOnDealloc: true)
            defer { try? source.close() }
            var info = stat()
            guard fstat(sourceFD, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
                throw FTPError.invalidState(description: "Resume source must be a regular file")
            }
            while true {
                try Task.checkCancellation()
                guard let chunk = try source.read(upToCount: 65_536), !chunk.isEmpty else { break }
                try file.write(contentsOf: chunk)
                prefixSize += UInt64(chunk.count)
            }
        }
        let expectedSize: UInt64?
        if resume {
            let size = try await binaryFileSizeLocked(path: remotePath)
            guard prefixSize <= size else {
                throw FTPError.invalidState(description: "Local resume prefix exceeds remote size")
            }
            expectedSize = size
        } else {
            expectedSize = nil
        }
        if let expectedSize {
            downloadCounter.expectedBytes = expectedSize - prefixSize
        } else if let expectedBytes {
            downloadCounter.expectedBytes = expectedBytes
        } else if querySizeForProgress && transferType == .binary {
            do {
                downloadCounter.expectedBytes = try await binaryFileSizeLocked(path: remotePath)
            } catch FTPError.serverReply(let code, _) where code.map({ [500, 501, 502, 504].contains($0) }) == true {
                // SIZE is optional. Continue without a percentage when unsupported.
            }
        }
        let dataConnection = try await beginFileTransfer(command: "RETR \(remotePath)", restartOffset: resume ? prefixSize : nil)
        defer { dataConnection.cancel() }
        startTransferKeepAlive(dataConnection)
        do {
            var transferred: UInt64 = 0
            let start = ProcessInfo.processInfo.systemUptime
            let rate = configuration?.bandwidthThrottleDown ?? 0
            var converter = FTPASCIINewlineConverter(downloadLineEnding)
            var received: UInt64 = 0
            progress?(transferred)
            while true {
                try Task.checkCancellation()
                let chunk = try await receiveChunkWithCompletion(connection: dataConnection)
                let converted = converter.convert(chunk.data, final: chunk.isComplete)
                if !converted.isEmpty {
                    try file.write(contentsOf: converted)
                    recordTransferBytes(converted.count)
                    transferred += UInt64(converted.count)
                    progress?(transferred)
                }
                if !chunk.data.isEmpty {
                    received += UInt64(chunk.data.count)
                    try await throttle(bytes: received, rate: rate, started: start)
                }
                if chunk.isComplete { break }
            }
            let reply = try await finishTransferKeepAlive()
            try requirePositiveCompletion(reply, operation: "RETR")
            if let expectedSize, prefixSize + transferred != expectedSize {
                throw FTPError.protocolViolation(description: "Resumed download size does not match SIZE response")
            }
            try Task.checkCancellation()
            if let modificationTime {
                try setFileModificationTime(modificationTime, descriptor: fd)
            }
            try file.close()
            guard renameat(directory, temporary, directory, name) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        } catch {
            diagnostic("error", "Transfer failed: \(error)")
            let keepAliveError = await abortTransferKeepAlive(dataConnection)
            resetConnection()
            if Task.isCancelled { throw CancellationError() }
            throw keepAliveError ?? error
        }
    }

    private func setFileModificationTime(_ date: Date, descriptor: Int32) throws {
        let value = date.timeIntervalSince1970
        guard value.isFinite, value >= -62_135_596_800, value <= 253_402_300_799 else {
            throw FTPError.invalidState(description: "Invalid file modification time")
        }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let seconds = floor(value)
        let nanoseconds = min(999_999_999, max(0, Int((value - seconds) * 1_000_000_000)))
        var times = [metadata.st_atimespec, timespec(tv_sec: Int(seconds), tv_nsec: nanoseconds)]
        guard futimens(descriptor, &times) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }

    /// Streams a local file in bounded chunks. Resume modifies the existing remote
    /// file in place: the caller must verify it is an exact prefix of the source.
    /// Progress counts bytes sent by this operation, not server acknowledgement.
    public func uploadFile(from source: URL, remotePath: String, append: Bool = false, resume: Bool = false, progress: (@Sendable (UInt64) -> Void)? = nil) async throws {
        try beginOperation()
        defer { operationInProgress = false; nextAllocationSize = 0 }
        beginTransferMetrics(.upload)
        var succeeded = false
        defer { finishTransferMetrics(.upload, succeeded: succeeded) }
        guard source.isFileURL else {
            throw FTPError.invalidState(description: "Source must be a file URL")
        }
        guard !(append && resume) else {
            throw FTPError.invalidState(description: "Append and resume cannot both be enabled")
        }
        guard !resume || transferType == .binary else { throw FTPError.invalidState(description: "Resume requires binary transfer mode") }
        let verifyCRC = try shouldVerifyUploadCRC(append: append)
        var crc = FTPCRC32()
        let file: FileHandle
        var sourceSize: UInt64?
        if resume {
            // O_NONBLOCK avoids hanging when a path names a FIFO or device.
            let fd = Darwin.open(source.path, O_RDONLY | O_CLOEXEC | O_NONBLOCK)
            guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            var info = stat()
            guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
                  let size = UInt64(exactly: info.st_size) else {
                _ = Darwin.close(fd)
                throw FTPError.invalidState(description: "Resume source must be a regular file")
            }
            file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            sourceSize = size
        } else {
            file = try FileHandle(forReadingFrom: source)
        }
        defer { try? file.close() }
        let restartOffset: UInt64?
        let expectedSize: UInt64?
        if resume {
            guard let size = sourceSize else { throw FTPError.invalidState(description: "Missing resume source size") }
            let offset = try await binaryFileSizeLocked(path: remotePath)
            guard offset <= size else {
                throw FTPError.invalidState(description: "Remote resume prefix exceeds local size")
            }
            if verifyCRC {
                var remaining = offset
                while remaining > 0 {
                    try Task.checkCancellation()
                    let length = Int(min(remaining, 65_536))
                    guard let chunk = try file.read(upToCount: length), !chunk.isEmpty else {
                        throw FTPError.invalidState(description: "Resume source changed while calculating CRC")
                    }
                    crc.update(chunk)
                    remaining -= UInt64(chunk.count)
                }
            } else {
                try file.seek(toOffset: offset)
            }
            restartOffset = offset
            expectedSize = size
        } else {
            restartOffset = nil
            expectedSize = nil
        }
        var sourceInfo = stat()
        if fstat(file.fileDescriptor, &sourceInfo) == 0, (sourceInfo.st_mode & S_IFMT) == S_IFREG,
           let size = UInt64(exactly: sourceInfo.st_size), size >= (restartOffset ?? 0) {
            uploadCounter.expectedBytes = size - (restartOffset ?? 0)
        }
        let verb = append ? "APPE" : "STOR"
        try await allocateUploadLocked()
        let dataConnection = try await beginFileTransfer(command: "\(verb) \(remotePath)", restartOffset: restartOffset)
        defer { dataConnection.cancel() }
        startTransferKeepAlive(dataConnection)
        do {
            var transferred: UInt64 = 0
            let start = ProcessInfo.processInfo.systemUptime
            let rate = configuration?.bandwidthThrottleUp ?? 0
            progress?(transferred)
            while true {
                try Task.checkCancellation()
                guard let chunk = try file.read(upToCount: 65_536), !chunk.isEmpty else { break }
                try await send(payload: chunk, connection: dataConnection)
                recordTransferBytes(chunk.count)
                if verifyCRC { crc.update(chunk) }
                transferred += UInt64(chunk.count)
                progress?(transferred)
                try await throttle(bytes: transferred, rate: rate, started: start)
            }
            try Task.checkCancellation()
            try await finishSending(payload: Data(), connection: dataConnection)
            let reply = try await finishTransferKeepAlive()
            try requirePositiveCompletion(reply, operation: verb)
            if let expectedSize {
                let remoteSize = try await binaryFileSizeLocked(path: remotePath)
                guard remoteSize == expectedSize else {
                    throw FTPError.protocolViolation(description: "Resumed upload size does not match local file")
                }
            }
        } catch {
            diagnostic("error", "Transfer failed: \(error)")
            let keepAliveError = await abortTransferKeepAlive(dataConnection)
            resetConnection()
            if Task.isCancelled { throw CancellationError() }
            throw keepAliveError ?? error
        }
        if verifyCRC { try await verifyUploadCRC(crc.value, path: remotePath) }
        succeeded = true
    }

    private func beginFileTransfer(command: String, restartOffset: UInt64? = nil) async throws -> FTPDataConnection {
        guard isConnected else { throw FTPError.invalidState(description: "Not connected") }
        try Task.checkCancellation()
        try await selectTransferTypeLocked()
        return try await startDataTransfer(command: command, restartOffset: restartOffset)
    }

    public func allocateNextUpload(_ size: UInt64) { nextAllocationSize = size }

    public func setAutomaticUploadCRC(_ enabled: Bool) throws {
        try beginOperation()
        defer { operationInProgress = false }
        guard configuration != nil else { throw FTPError.invalidState(description: "Not connected") }
        configuration?.automaticUploadCRC = enabled
    }

    private func shouldVerifyUploadCRC(append: Bool) throws -> Bool {
        guard configuration?.automaticUploadCRC == true, serverFeatures.contains("XCRC") else { return false }
        guard transferType == .binary, !append else {
            throw FTPError.invalidState(description: "Automatic XCRC requires a binary, non-append upload")
        }
        return true
    }

    private func verifyUploadCRC(_ expected: UInt32, path: String) async throws {
        let reply = try await sendCommandLocked("XCRC \(path)")
        guard reply.code == 250 else { throw FTPError.serverReply(code: reply.code, message: reply.message) }
        let fields = reply.message.split(whereSeparator: { $0.isWhitespace })
        guard fields.count == 2, fields[0] == "250" else {
            throw FTPError.protocolViolation(description: "Invalid XCRC response")
        }
        var text = String(fields[1])
        if text.lowercased().hasPrefix("0x") { text.removeFirst(2) }
        guard (1...8).contains(text.utf8.count), text.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }),
              let actual = UInt32(text, radix: 16) else {
            throw FTPError.protocolViolation(description: "Invalid XCRC response")
        }
        guard actual == expected else { throw FTPError.protocolViolation(description: "XCRC upload checksum mismatch") }
    }

    private func allocateUploadLocked() async throws {
        let size = nextAllocationSize
        nextAllocationSize = 0
        guard size > 0 else { return }
        let reply = try await sendCommandLocked("ALLO \(size)")
        try requirePositiveCompletion(reply, operation: "ALLO")
    }

    private func startDataTransfer(command: String, restartOffset: UInt64? = nil) async throws -> FTPDataConnection {
        diagnostic("info", "Starting data command: \(command); restartOffset=\(restartOffset ?? 0), protected=\(dataProtected), compressed=\(modeZEnabled)")
        guard let configuration else { throw FTPError.invalidState(description: "Not connected") }
        guard configuration.security == .none || isAuthenticated else {
            throw FTPError.invalidState(description: "FTPS data protection requires authentication")
        }
        if configuration.dataConnectionMode == .active {
            diagnostic("debug", "Opening active data listener; portRange=\(configuration.activePortRangeStart)...\(configuration.activePortRangeEnd)")
            return try await startActiveDataTransfer(command: command, restartOffset: restartOffset)
        }
        let endpoint = try await openPassiveDataConnection()
        diagnostic("debug", "Passive data endpoint: \(endpoint.host):\(endpoint.port)")
        let dataConnection = endpoint.connection
        let compressed = modeZEnabled
        let protectedData = dataProtected
        let identity = importedIdentity
        let peerID = tlsSessionPeerID
        let ready = Task {
                    do {
            try await waitForReady(connection: dataConnection)
            if let proxy = configuration.proxy, proxy.isTunnel {
                let prefetched = try await negotiateProxy(proxy, targetHost: endpoint.host, targetPort: endpoint.port, connection: dataConnection)
                if protectedData {
                    guard prefetched.data.isEmpty, !prefetched.isComplete else { throw FTPError.protocolViolation(description: "Unexpected bytes before data TLS handshake") }
                    let stream = try FTPExplicitTLSStream(connection: dataConnection, configuration: configuration, importedIdentity: identity, sessionPeerID: peerID)
                    try await stream.handshake()
                    return try FTPDataConnection(connection: dataConnection, tls: stream, compressed: compressed)
                }
                return try FTPDataConnection(connection: dataConnection, tls: nil, prefetched: prefetched.data,
                                             compressed: compressed, prefetchedComplete: prefetched.isComplete)
            }
            if protectedData, peerID != nil {
                let stream = try FTPExplicitTLSStream(connection: dataConnection, configuration: configuration, importedIdentity: identity, sessionPeerID: peerID)
                try await stream.handshake()
                return try FTPDataConnection(connection: dataConnection, tls: stream, compressed: compressed)
            }
            return try FTPDataConnection(connection: dataConnection, tls: nil, compressed: compressed, identityOwner: identity)
                    } catch {
                        dataConnection.cancel()
                        throw error
                    }
        }
        var started = false
        var restartAccepted = false
        do {
            if let restartOffset {
                let restart = try await sendCommandLocked("REST \(restartOffset)")
                guard restart.code == 350 else {
                    throw FTPError.serverReply(code: restart.code, message: restart.message)
                }
                restartAccepted = true
            }
            let transferReply = try await sendCommandLocked(command)
            guard transferReply.code == 125 || transferReply.code == 150 else {
                throw FTPError.serverReply(code: transferReply.code, message: transferReply.message)
            }
            started = true
            let readyConnection = try await withTaskCancellationHandler {
                try await ready.value
            } onCancel: {
                dataConnection.cancel()
                ready.cancel()
            }
            try Task.checkCancellation()
            return readyConnection
        } catch {
            dataConnection.cancel()
            ready.cancel()
            if started || restartAccepted { resetConnection() }
            if Task.isCancelled { throw CancellationError() }
            throw error
        }
    }

    private func startActiveDataTransfer(command: String, restartOffset: UInt64?) async throws -> FTPDataConnection {
        guard let configuration else { throw FTPError.invalidState(description: "Not connected") }
        if case .socks5 = configuration.proxy {
            return try await startSOCKS5ActiveDataTransfer(command: command, restartOffset: restartOffset, configuration: configuration)
        }
        if case .socks4 = configuration.proxy {
            return try await startSOCKS4ActiveDataTransfer(command: command, restartOffset: restartOffset, configuration: configuration)
        }
        guard let control = connection,
              case .hostPort(let localHost, _) = control.currentPath?.localEndpoint,
              case .hostPort(let peerHost, _) = control.currentPath?.remoteEndpoint else {
            throw FTPError.invalidState(description: "Active mode requires resolved control endpoints")
        }
        let family: Int
        var address: String
        var bindHost = localHost
        switch (localHost, peerHost) {
        case (.ipv4(let local), .ipv4): family = 1; address = String(describing: local)
        case (.ipv6(let local), .ipv6): family = 2; address = String(describing: local)
        default: throw FTPError.invalidState(description: "Unsupported active-mode address family")
        }
        guard !address.contains("%") else {
            throw FTPError.invalidState(description: "Scoped IPv6 addresses cannot be advertised with EPRT")
        }
        if let override = configuration.activeAdvertisedIPv4, !override.isEmpty {
            var value = in_addr()
            guard family == 1, inet_pton(AF_INET, override, &value) == 1 else {
                throw FTPError.invalidState(description: "Active advertised address must be numeric IPv4")
            }
            address = override
            if configuration.bindActiveAdvertisedIPv4 { bindHost = NWEndpoint.Host(override) }
        }
        let start = configuration.activePortRangeStart
        let end = start == 0 ? 0 : max(start, configuration.activePortRangeEnd)
        var selected: (FTPActiveDataListener, NWEndpoint.Port)?
        var lastFailure: Error = FTPError.connectionFailed(description: "No active port available")
        for value in start...end {
            try Task.checkCancellation()
            let port = value == 0 ? NWEndpoint.Port.any : NWEndpoint.Port(rawValue: UInt16(value))!
            do {
                let candidate = try FTPActiveDataListener(localHost: bindHost, expectedPeer: peerHost, timeout: configuration.connectTimeout, port: port)
                do {
                    selected = (candidate, try await candidate.start())
                } catch {
                    await candidate.cancel()
                    throw error
                }
                break
            } catch {
                if Task.isCancelled { throw CancellationError() }
                lastFailure = error
            }
        }
        guard let (listener, port) = selected else { throw lastFailure }
        var started = false
        var restartAccepted = false
        do {
            try await advertiseActiveEndpoint(family: family, address: address, port: port.rawValue)
            if let restartOffset {
                let reply = try await sendCommandLocked("REST \(restartOffset)")
                guard reply.code == 350 else { throw FTPError.serverReply(code: reply.code, message: reply.message) }
                restartAccepted = true
            }
            let compressed = modeZEnabled
            let protectedData = dataProtected
            let identity = importedIdentity
            let peerID = tlsSessionPeerID
            let ready = Task {
                let dataConnection = try await listener.takeConnection()
                do {
                    try await waitForReady(connection: dataConnection)
                    try Task.checkCancellation()
                    if protectedData {
                        // FTP clients use the TLS client role even when the server opened the TCP connection.
                        let stream = try FTPExplicitTLSStream(connection: dataConnection, configuration: configuration, importedIdentity: identity, sessionPeerID: peerID)
                        try await stream.handshake()
                        return try FTPDataConnection(connection: dataConnection, tls: stream, compressed: compressed)
                    }
                    return try FTPDataConnection(connection: dataConnection, tls: nil, compressed: compressed)
                } catch {
                    dataConnection.cancel()
                    throw error
                }
            }
            do {
                let transferReply = try await sendCommandLocked(command)
                guard transferReply.code == 125 || transferReply.code == 150 else {
                    throw FTPError.serverReply(code: transferReply.code, message: transferReply.message)
                }
                started = true
                let dataConnection = try await withTaskCancellationHandler {
                    try await ready.value
                } onCancel: {
                    ready.cancel()
                    Task { await listener.cancel() }
                }
                try Task.checkCancellation()
                return dataConnection
            } catch {
                ready.cancel()
                await listener.cancel()
                if let connection = try? await ready.value { connection.cancel() }
                throw error
            }
        } catch {
            await listener.cancel()
            if started || restartAccepted { resetConnection() }
            if Task.isCancelled { throw CancellationError() }
            throw error
        }
    }

    private func advertiseActiveEndpoint(family: Int, address: String, port: UInt16) async throws {
        let reply = try await sendCommandLocked("EPRT |\(family)|\(address)|\(port)|")
        if reply.code != 200 {
            guard family == 1, let code = reply.code, [500, 501, 502, 504, 522].contains(code) else {
                throw FTPError.serverReply(code: reply.code, message: reply.message)
            }
            let octets = address.split(separator: ".")
            guard octets.count == 4, octets.allSatisfy({ UInt8($0) != nil }) else {
                throw FTPError.invalidState(description: "Invalid active-mode IPv4 address")
            }
            let value = Int(port)
            let fallback = try await sendCommandLocked("PORT \(octets.joined(separator: ",")),\(value / 256),\(value % 256)")
            try requirePositiveCompletion(fallback, operation: "PORT")
        }
    }

    private func startSOCKS5ActiveDataTransfer(command: String, restartOffset: UInt64?, configuration: FTPClientConfiguration) async throws -> FTPDataConnection {
        try validateSOCKS5ActiveConfiguration(configuration)
        guard case .socks5(let proxyHost, let proxyPort, let username, let password) = configuration.proxy,
              let expected = numericAddress(configuration.host),
              let portValue = UInt16(exactly: proxyPort), let port = NWEndpoint.Port(rawValue: portValue) else {
            throw FTPError.invalidState(description: "Invalid SOCKS5 active configuration")
        }
        let parameters = NWParameters.tcp
        try configureLocalBinding(parameters, configuration: configuration)
        let dataConnection = NWConnection(host: NWEndpoint.Host(proxyHost), port: port, using: parameters)
        var handedOff = false
        var started = false
        var restartAccepted = false
        defer { if !handedOff { dataConnection.cancel() } }
        do {
            try await waitForReady(connection: dataConnection)
            var buffer = FTPProxyBuffer()
            try await authenticateSOCKS5(username: username, password: password, buffer: &buffer, connection: dataConnection)
            var request = Data([5, 2, 0, expected.0])
            request.append(expected.1)
            request.append(contentsOf: [0, 0]) // server data source port is not known
            try await send(payload: request, connection: dataConnection)
            let bound = try await readSOCKS5Endpoint(buffer: &buffer, connection: dataConnection)
            guard buffer.data.isEmpty, !buffer.isComplete, bound.port != 0,
                  case .hostPort(let proxyPeer, _) = dataConnection.currentPath?.remoteEndpoint,
                  let peerAddress = numericAddress(String(describing: proxyPeer)),
                  bound.family == peerAddress.0 else {
                throw FTPError.protocolViolation(description: "Invalid SOCKS5 BIND endpoint")
            }
            // A proxy can otherwise direct an FTP server to an arbitrary host.
            let unspecified = bound.address.allSatisfy { $0 == 0 }
            guard unspecified || bound.address == peerAddress.1 else {
                throw FTPError.protocolViolation(description: "SOCKS5 BIND address differs from proxy peer")
            }
            let address = unspecified ? String(describing: proxyPeer) : bound.text
            try await advertiseActiveEndpoint(family: bound.family == 1 ? 1 : 2, address: address, port: bound.port)
            if let restartOffset {
                let reply = try await sendCommandLocked("REST \(restartOffset)")
                guard reply.code == 350 else { throw FTPError.serverReply(code: reply.code, message: reply.message) }
                restartAccepted = true
            }
            let compressed = modeZEnabled
            let protectedData = dataProtected
            let identity = importedIdentity
            let peerID = tlsSessionPeerID
            let ready = Task {
                var buffered = FTPProxyBuffer()
                let peer = try await readSOCKS5Endpoint(buffer: &buffered, connection: dataConnection)
                guard peer.family == expected.0, peer.address == expected.1, peer.port != 0 else {
                    throw FTPError.connectionFailed(description: "SOCKS5 BIND peer does not match FTP server")
                }
                if protectedData {
                    guard buffered.data.isEmpty, !buffered.isComplete else { throw FTPError.protocolViolation(description: "Unexpected bytes before data TLS handshake") }
                    let stream = try FTPExplicitTLSStream(connection: dataConnection, configuration: configuration, importedIdentity: identity, sessionPeerID: peerID)
                    try await stream.handshake()
                    return try FTPDataConnection(connection: dataConnection, tls: stream, compressed: compressed)
                }
                return try FTPDataConnection(connection: dataConnection, tls: nil, prefetched: buffered.data,
                                             compressed: compressed, prefetchedComplete: buffered.isComplete)
            }
            do {
                let reply = try await sendCommandLocked(command)
                guard reply.code == 125 || reply.code == 150 else { throw FTPError.serverReply(code: reply.code, message: reply.message) }
                started = true
                let data = try await withTaskCancellationHandler {
                    try await ready.value
                } onCancel: {
                    ready.cancel()
                    dataConnection.cancel()
                }
                try Task.checkCancellation()
                handedOff = true
                return data
            } catch {
                ready.cancel()
                dataConnection.cancel()
                throw error
            }
        } catch {
            if started || restartAccepted { resetConnection() }
            if Task.isCancelled { throw CancellationError() }
            throw error
        }
    }

    private func startSOCKS4ActiveDataTransfer(command: String, restartOffset: UInt64?, configuration: FTPClientConfiguration) async throws -> FTPDataConnection {
        try validateSOCKS4ActiveConfiguration(configuration)
        guard case .socks4(let proxyHost, let proxyPort, let userID) = configuration.proxy,
              let expected = numericAddress(configuration.host), expected.0 == 1,
              let portValue = UInt16(exactly: proxyPort), let port = NWEndpoint.Port(rawValue: portValue),
              !userID.utf8.contains(0), userID.utf8.count <= 1024 else {
            throw FTPError.invalidState(description: "Invalid SOCKS4 active configuration")
        }
        let parameters = NWParameters.tcp
        try configureLocalBinding(parameters, configuration: configuration)
        let dataConnection = NWConnection(host: NWEndpoint.Host(proxyHost), port: port, using: parameters)
        var handedOff = false
        var started = false
        var restartAccepted = false
        defer { if !handedOff { dataConnection.cancel() } }
        do {
            try await waitForReady(connection: dataConnection)
            var request = Data([4, 2, 0, 0])
            request.append(expected.1)
            request.append(contentsOf: userID.utf8)
            request.append(0)
            try await send(payload: request, connection: dataConnection)
            var buffer = FTPProxyBuffer()
            let bound = try await readSOCKS4Endpoint(buffer: &buffer, connection: dataConnection)
            guard buffer.data.isEmpty, !buffer.isComplete, bound.port != 0,
                  case .hostPort(let proxyPeer, _) = dataConnection.currentPath?.remoteEndpoint,
                  let peerAddress = numericAddress(String(describing: proxyPeer)), peerAddress.0 == 1 else {
                throw FTPError.protocolViolation(description: "Invalid SOCKS4 BIND endpoint")
            }
            let unspecified = bound.address.allSatisfy { $0 == 0 }
            guard unspecified || bound.address == peerAddress.1 else {
                throw FTPError.protocolViolation(description: "SOCKS4 BIND address differs from proxy peer")
            }
            let address = unspecified ? String(describing: proxyPeer) : bound.text
            try await advertiseActiveEndpoint(family: 1, address: address, port: bound.port)
            if let restartOffset {
                let reply = try await sendCommandLocked("REST \(restartOffset)")
                guard reply.code == 350 else { throw FTPError.serverReply(code: reply.code, message: reply.message) }
                restartAccepted = true
            }
            let compressed = modeZEnabled
            let protectedData = dataProtected
            let identity = importedIdentity
            let peerID = tlsSessionPeerID
            let ready = Task {
                var buffered = FTPProxyBuffer()
                let peer = try await readSOCKS4Endpoint(buffer: &buffered, connection: dataConnection)
                guard peer.address == expected.1, peer.port != 0 else {
                    throw FTPError.connectionFailed(description: "SOCKS4 BIND peer does not match FTP server")
                }
                if protectedData {
                    guard buffered.data.isEmpty, !buffered.isComplete else { throw FTPError.protocolViolation(description: "Unexpected bytes before data TLS handshake") }
                    let stream = try FTPExplicitTLSStream(connection: dataConnection, configuration: configuration, importedIdentity: identity, sessionPeerID: peerID)
                    try await stream.handshake()
                    return try FTPDataConnection(connection: dataConnection, tls: stream, compressed: compressed)
                }
                return try FTPDataConnection(connection: dataConnection, tls: nil, prefetched: buffered.data,
                                             compressed: compressed, prefetchedComplete: buffered.isComplete)
            }
            do {
                let reply = try await sendCommandLocked(command)
                guard reply.code == 125 || reply.code == 150 else { throw FTPError.serverReply(code: reply.code, message: reply.message) }
                started = true
                let data = try await withTaskCancellationHandler {
                    try await ready.value
                } onCancel: {
                    ready.cancel()
                    dataConnection.cancel()
                }
                try Task.checkCancellation()
                handedOff = true
                return data
            } catch {
                ready.cancel()
                dataConnection.cancel()
                throw error
            }
        } catch {
            if started || restartAccepted { resetConnection() }
            if Task.isCancelled { throw CancellationError() }
            throw error
        }
    }

    public func disconnect() async {
        diagnostic("info", "Disconnect requested")
        if !operationInProgress && aggregatingUpload { endChunkedUploadMetrics(succeeded: false) }
        if !operationInProgress && isConnected {
            operationInProgress = true
            _ = try? await sendCommandLocked("QUIT")
            operationInProgress = false
        }
        resetConnection()
    }

    public func setLoggingEnabled(_ enabled: Bool) { diagnosticLoggingEnabled = enabled }

    public func setRedactSensitiveInformation(_ enabled: Bool) { redactSensitiveInformation = enabled }

    private func diagnostic(_ level: String, _ message: @autoclosure () -> String) {
        guard diagnosticLoggingEnabled else { return }
        let safe = FTPDiagnosticRedactor.redact(message(), secrets: diagnosticSecrets, enabled: redactSensitiveInformation)
        print("[FTPClient \(diagnosticID)] [\(Date().ISO8601Format())] [\(level.uppercased())] \(safe)")
    }

    public func setSessionLogging(_ enabled: Bool) { loggingEnabled = enabled }
    public func sessionLog() -> String { logLines.joined(separator: "\n") }
    public func clearSessionLog() { logLines.removeAll(); logBytes = 0 }

    /// Returns metadata for the active control TLS connection, or nil for a clear/disconnected session.
    public func tlsSessionInfo() async throws -> FTPTLSSessionInfo? {
        guard isConnected, let configuration, let connection, configuration.security != .none else { return nil }
        if let explicitTLSStream { return try await explicitTLSStream.sessionInfo() }
        guard let tls = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
            throw FTPError.invalidState(description: "TLS session metadata unavailable")
        }
        let metadata = tls.securityProtocolMetadata
        let version = sec_protocol_metadata_get_negotiated_tls_protocol_version(metadata).rawValue
        let cipher = sec_protocol_metadata_get_negotiated_tls_ciphersuite(metadata).rawValue
        let certificate = FirstCertificate()
        _ = sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate.record($0) }
        let name: String
        switch version {
        case 0x0303: name = "TLS 1.2"
        case 0x0304: name = "TLS 1.3"
        default: name = String(format: "0x%04X", version)
        }
        return FTPTLSSessionInfo(protocolVersion: name, cipherSuite: FTPTLSPolicy.cipherName(cipher),
                                 serverCertificateDER: certificate.read(), chainValidationRequired: configuration.requireServerCertificateValidation)
    }

    private func appendLog(_ line: String) {
        diagnostic("debug", line)
        guard loggingEnabled else { return }
        let line = FTPDiagnosticRedactor.redact(line, secrets: diagnosticSecrets, enabled: redactSensitiveInformation)
        let size = line.utf8.count + 1
        guard size <= maxLogBytes else { return }
        while logBytes + size > maxLogBytes, !logLines.isEmpty {
            logBytes -= logLines.removeFirst().utf8.count + 1
        }
        logLines.append(line)
        logBytes += size
    }

    private func beginOperation() throws {
        guard !operationInProgress, aggregateUploadOwner == nil || FTPChunkedUploadScope.identifier == aggregateUploadOwner else {
            diagnostic("warning", "Rejected concurrent operation on the control channel")
            throw FTPError.invalidState(description: "Another FTP operation is in progress")
        }
        operationInProgress = true
    }

    private func resetConnection() {
        diagnostic("info", "Resetting connection; connected=\(isConnected), authenticated=\(isAuthenticated)")
        connection?.cancel()
        connection = nil
        explicitTLSStream = nil
        importedIdentity = nil
        tlsSessionPeerID = nil
        configuration = nil
        isConnected = false
        isAuthenticated = false
        replyParser = FTPReplyParser()
        prefetchedControl.removeAll()
        serverFeatures.removeAll()
        serverSystem = nil
        modeZEnabled = false
        dataProtected = false
        dataProtectionConfigured = false
        nextAllocationSize = 0
    }

    private func recordTransportState(_ state: String) {
        diagnostic("debug", "Transport state: \(state)")
    }

    private func waitForReady(connection: NWConnection) async throws {
        diagnostic("debug", "Waiting for transport: \(connection.endpoint)")
        let timeout = configuration?.connectTimeout ?? 30
        try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let resumeGuard = ContinuationResumeGuard()

            connection.stateUpdateHandler = { [weak self] state in
                let description = String(describing: state)
                Task { await self?.recordTransportState(description) }
                switch state {
                case .ready:
                    guard resumeGuard.tryResume() else {
                        return
                    }
                    continuation.resume(returning: ())
                case .failed(let error):
                    guard resumeGuard.tryResume() else {
                        return
                    }
                    continuation.resume(throwing: FTPError.connectionFailed(description: error.localizedDescription))
                case .cancelled:
                    guard resumeGuard.tryResume() else {
                        return
                    }
                    continuation.resume(throwing: FTPError.connectionFailed(description: "Connection cancelled"))
                default:
                    break
                }
            }

            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) {
                guard resumeGuard.tryResume() else { return }
                connection.cancel()
                continuation.resume(throwing: FTPError.timeout(operation: "connect"))
            }
        }
        } onCancel: { connection.cancel() }
    }

    private func send(payload: Data, connection: NWConnection) async throws {
        let timeout = configuration?.readTimeout ?? 30
        try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let resumeGuard = ContinuationResumeGuard()
            connection.send(content: payload, completion: .contentProcessed { error in
                guard resumeGuard.tryResume() else { return }
                if let error {
                    continuation.resume(throwing: FTPError.connectionFailed(description: error.localizedDescription))
                    return
                }

                continuation.resume(returning: ())
            })
            queue.asyncAfter(deadline: .now() + timeout) {
                guard resumeGuard.tryResume() else { return }
                connection.cancel()
                continuation.resume(throwing: FTPError.timeout(operation: "send"))
            }
        }
        } onCancel: { connection.cancel() }
    }

    private func finishSending(payload: Data, connection: NWConnection) async throws {
        let timeout = configuration?.readTimeout ?? 30
        try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let resumeGuard = ContinuationResumeGuard()
            connection.send(content: payload, contentContext: .finalMessage, isComplete: true,
                            completion: .contentProcessed { error in
                guard resumeGuard.tryResume() else { return }
                if let error {
                    continuation.resume(throwing: FTPError.connectionFailed(description: error.localizedDescription))
                } else {
                    continuation.resume(returning: ())
                }
            })
            queue.asyncAfter(deadline: .now() + timeout) {
                guard resumeGuard.tryResume() else { return }
                connection.cancel()
                continuation.resume(throwing: FTPError.timeout(operation: "send"))
            }
        }
        } onCancel: { connection.cancel() }
    }

    private func send(payload: Data, connection: FTPDataConnection) async throws {
        if connection.encoder != nil && payload.count > FTPZlibStream.maximumInputBytes {
            for offset in stride(from: 0, to: payload.count, by: FTPZlibStream.maximumInputBytes) {
                try await send(payload: Data(payload.dropFirst(offset).prefix(FTPZlibStream.maximumInputBytes)), connection: connection)
            }
            return
        }
        let data = try connection.encoder?.process(payload, final: false) ?? payload
        guard !data.isEmpty else { return }
        if let tls = connection.tls { try await tls.send(data) }
        else { try await send(payload: data, connection: connection.connection) }
    }

    private func finishSending(payload: Data, connection: FTPDataConnection) async throws {
        let data: Data
        if let encoder = connection.encoder {
            if !payload.isEmpty { try await send(payload: payload, connection: connection) }
            data = try encoder.process(Data(), final: true)
        } else { data = payload }
        if let tls = connection.tls {
            if !data.isEmpty { try await tls.send(data) }
            try await tls.finishSending()
            try await finishSending(payload: Data(), connection: connection.connection)
        } else {
            try await finishSending(payload: data, connection: connection.connection)
        }
    }

    private struct FTPProxyBuffer {
        var data = Data()
        var isComplete = false
    }

    private func fillProxyBuffer(_ buffer: inout FTPProxyBuffer, connection: NWConnection) async throws {
        guard !buffer.isComplete else { throw FTPError.connectionFailed(description: "Proxy closed during negotiation") }
        let chunk = try await receiveNetworkChunkWithCompletion(connection: connection)
        buffer.data.append(chunk.data)
        buffer.isComplete = chunk.isComplete
    }

    private func readProxyBytes(_ count: Int, buffer: inout FTPProxyBuffer, connection: NWConnection) async throws -> Data {
        while buffer.data.count < count { try await fillProxyBuffer(&buffer, connection: connection) }
        let value = Data(buffer.data.prefix(count))
        buffer.data.removeFirst(count)
        return value
    }

    private struct SOCKS5Endpoint {
        let family: UInt8
        let address: Data
        let text: String
        let port: UInt16
    }

    private func readSOCKS4Endpoint(buffer: inout FTPProxyBuffer, connection: NWConnection) async throws -> SOCKS5Endpoint {
        let response = try await readProxyBytes(8, buffer: &buffer, connection: connection)
        guard response[0] == 0, response[1] == 90 else { throw FTPError.connectionFailed(description: "SOCKS4 BIND rejected") }
        let address = Data(response[4..<8])
        let text = address.map(String.init).joined(separator: ".")
        let port = UInt16(response[2]) << 8 | UInt16(response[3])
        return SOCKS5Endpoint(family: 1, address: address, text: text, port: port)
    }

    private func numericAddress(_ value: String) -> (UInt8, Data)? {
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET, value, &v4) == 1 { return (1, withUnsafeBytes(of: &v4) { Data($0) }) }
        if inet_pton(AF_INET6, value, &v6) == 1 { return (4, withUnsafeBytes(of: &v6) { Data($0) }) }
        return nil
    }

    private func validateSOCKS5ActiveConfiguration(_ configuration: FTPClientConfiguration) throws {
        guard numericAddress(configuration.host) != nil else {
            throw FTPError.invalidState(description: "SOCKS5 active mode requires a numeric FTP server address")
        }
        guard configuration.activePortRangeStart == 0, configuration.activeAdvertisedIPv4?.isEmpty != false,
              !configuration.bindActiveAdvertisedIPv4 else {
            throw FTPError.invalidState(description: "SOCKS5 BIND controls its own active address and port")
        }
    }

    private func validateSOCKS4ActiveConfiguration(_ configuration: FTPClientConfiguration) throws {
        guard let address = numericAddress(configuration.host), address.0 == 1 else {
            throw FTPError.invalidState(description: "SOCKS4 active mode requires a numeric IPv4 FTP server address")
        }
        guard configuration.activePortRangeStart == 0, configuration.activeAdvertisedIPv4?.isEmpty != false,
              !configuration.bindActiveAdvertisedIPv4 else {
            throw FTPError.invalidState(description: "SOCKS4 BIND controls its own active address and port")
        }
    }

    private func authenticateSOCKS5(username: String?, password: String?, buffer: inout FTPProxyBuffer, connection: NWConnection) async throws {
        guard (username == nil) == (password == nil) else { throw FTPError.invalidState(description: "SOCKS5 requires both username and password") }
        let methods: [UInt8] = username == nil ? [5, 1, 0] : [5, 1, 2]
        try await send(payload: Data(methods), connection: connection)
        let selection = try await readProxyBytes(2, buffer: &buffer, connection: connection)
        guard selection[0] == 5 else { throw FTPError.protocolViolation(description: "Malformed SOCKS5 greeting") }
        if selection[1] == 2, let username, let password {
            let user = Array(username.utf8), pass = Array(password.utf8)
            guard (1...255).contains(user.count), (1...255).contains(pass.count) else { throw FTPError.invalidState(description: "Invalid SOCKS5 credentials") }
            try await send(payload: Data([1, UInt8(user.count)] + user + [UInt8(pass.count)] + pass), connection: connection)
            let result = try await readProxyBytes(2, buffer: &buffer, connection: connection)
            guard result[0] == 1, result[1] == 0 else { throw FTPError.connectionFailed(description: "SOCKS5 authentication rejected") }
        } else if selection[1] != 0 || username != nil {
            throw FTPError.connectionFailed(description: "SOCKS5 authentication method rejected")
        }
    }

    private func readSOCKS5Endpoint(buffer: inout FTPProxyBuffer, connection: NWConnection) async throws -> SOCKS5Endpoint {
        let response = try await readProxyBytes(4, buffer: &buffer, connection: connection)
        guard response[0] == 5, response[2] == 0, response[1] == 0 else {
            throw FTPError.connectionFailed(description: "SOCKS5 request rejected")
        }
        let family = response[3]
        let length: Int
        switch family {
        case 1: length = 4
        case 4: length = 16
        case 3: length = Int(try await readProxyBytes(1, buffer: &buffer, connection: connection)[0])
        default: throw FTPError.protocolViolation(description: "Invalid SOCKS5 response address")
        }
        guard length > 0 else { throw FTPError.protocolViolation(description: "Empty SOCKS5 response address") }
        let address = try await readProxyBytes(length, buffer: &buffer, connection: connection)
        let portBytes = try await readProxyBytes(2, buffer: &buffer, connection: connection)
        let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])
        let text: String
        if family == 3 {
            guard let name = String(data: address, encoding: .utf8), !name.utf8.contains(0) else { throw FTPError.protocolViolation(description: "Invalid SOCKS5 response name") }
            text = name
        } else {
            var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let outputSize = socklen_t(output.count)
            let converted = address.withUnsafeBytes { inet_ntop(family == 1 ? AF_INET : AF_INET6, $0.baseAddress, &output, outputSize) }
            guard converted != nil else { throw FTPError.protocolViolation(description: "Invalid SOCKS5 response address") }
            text = String(decoding: output.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        }
        return SOCKS5Endpoint(family: family, address: address, text: text, port: port)
    }

    private struct HTTPProxyResponse {
        let status: Int
        let headers: [String: [String]]
    }

    private func readProxyResponse(buffer: inout FTPProxyBuffer, connection: NWConnection) async throws -> HTTPProxyResponse {
        let delimiter = Data([13, 10, 13, 10])
        while buffer.data.range(of: delimiter) == nil {
            guard buffer.data.count < 65_536 else { throw FTPError.protocolViolation(description: "HTTP proxy response too large") }
            try await fillProxyBuffer(&buffer, connection: connection)
        }
        guard let end = buffer.data.range(of: delimiter), end.upperBound - buffer.data.startIndex <= 65_536,
              let header = String(data: buffer.data[..<end.lowerBound], encoding: .isoLatin1) else {
            throw FTPError.protocolViolation(description: "Malformed HTTP proxy response")
        }
        buffer.data.removeSubrange(..<end.upperBound)
        let lines = header.components(separatedBy: "\r\n")
        guard let first = lines.first else { throw FTPError.protocolViolation(description: "Malformed HTTP proxy response") }
        let fields = first.split(separator: " ")
        guard fields.count >= 2, ["HTTP/1.0", "HTTP/1.1"].contains(String(fields[0])), fields[1].count == 3,
              fields[1].utf8.allSatisfy({ (48...57).contains($0) }), let code = Int(fields[1]) else {
            throw FTPError.protocolViolation(description: "Malformed HTTP proxy status")
        }
        var headers: [String: [String]] = [:]
        for line in lines.dropFirst() {
            guard !line.hasPrefix(" "), !line.hasPrefix("\t"), let separator = line.firstIndex(of: ":") else {
                throw FTPError.protocolViolation(description: "Malformed HTTP proxy header")
            }
            let name = String(line[..<separator]).lowercased()
            guard !name.isEmpty, name.utf8.allSatisfy({ (33...126).contains($0) && $0 != 58 }) else {
                throw FTPError.protocolViolation(description: "Malformed HTTP proxy header name")
            }
            let value = String(line[line.index(after: separator)...]).trimmingCharacters(in: .whitespaces)
            headers[name, default: []].append(value)
        }
        return HTTPProxyResponse(status: code, headers: headers)
    }

    private func readProxyChunkLine(buffer: inout FTPProxyBuffer, consumed: inout Int, connection: NWConnection) async throws -> Data {
        let delimiter = Data([13, 10])
        while buffer.data.range(of: delimiter) == nil {
            guard buffer.data.count <= 8_192, consumed + buffer.data.count <= 65_536 else {
                throw FTPError.protocolViolation(description: "HTTP proxy challenge body too large")
            }
            try await fillProxyBuffer(&buffer, connection: connection)
        }
        guard let end = buffer.data.range(of: delimiter), end.lowerBound - buffer.data.startIndex <= 8_192 else {
            throw FTPError.protocolViolation(description: "Malformed HTTP proxy chunk")
        }
        let result = Data(buffer.data[..<end.lowerBound])
        consumed += result.count + 2
        guard consumed <= 65_536 else { throw FTPError.protocolViolation(description: "HTTP proxy challenge body too large") }
        buffer.data.removeSubrange(..<end.upperBound)
        return result
    }

    private func discardProxyChallengeBody(_ response: HTTPProxyResponse, buffer: inout FTPProxyBuffer, connection: NWConnection) async throws {
        let closeTokens = ((response.headers["connection"] ?? []) + (response.headers["proxy-connection"] ?? []))
            .joined(separator: ",").lowercased().split(separator: ",")
        guard !closeTokens.contains(where: { $0.trimmingCharacters(in: .whitespaces) == "close" }) else {
            throw FTPError.protocolViolation(description: "Unsupported HTTP proxy challenge framing")
        }
        if let encodings = response.headers["transfer-encoding"] {
            guard response.headers["content-length"] == nil, encodings.count == 1,
                  encodings[0].trimmingCharacters(in: .whitespaces).lowercased() == "chunked" else {
                throw FTPError.protocolViolation(description: "Unsupported HTTP proxy challenge framing")
            }
            var consumed = 0
            while true {
                let sizeLine = try await readProxyChunkLine(buffer: &buffer, consumed: &consumed, connection: connection)
                let hex = sizeLine.prefix { $0 != 59 }
                guard !hex.isEmpty, hex.count <= 8, hex.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }),
                      let length = Int(String(decoding: hex, as: UTF8.self), radix: 16), length <= 65_536 - consumed else {
                    throw FTPError.protocolViolation(description: "Malformed HTTP proxy chunk size")
                }
                if length == 0 {
                    while true {
                        let trailer = try await readProxyChunkLine(buffer: &buffer, consumed: &consumed, connection: connection)
                        if trailer.isEmpty { break }
                        guard trailer.contains(58), trailer.first != 32, trailer.first != 9 else {
                            throw FTPError.protocolViolation(description: "Malformed HTTP proxy trailer")
                        }
                    }
                    break
                }
                guard length + 2 <= 65_536 - consumed else { throw FTPError.protocolViolation(description: "HTTP proxy challenge body too large") }
                _ = try await readProxyBytes(length, buffer: &buffer, connection: connection)
                let ending = try await readProxyBytes(2, buffer: &buffer, connection: connection)
                guard ending == Data([13, 10]) else { throw FTPError.protocolViolation(description: "Malformed HTTP proxy chunk terminator") }
                consumed += length + 2
            }
        } else {
            guard let lengths = response.headers["content-length"], lengths.count == 1,
                  !lengths[0].isEmpty, lengths[0].utf8.allSatisfy({ (48...57).contains($0) }),
                  let length = Int(lengths[0]), length <= 65_536 else {
                throw FTPError.protocolViolation(description: "Unsupported HTTP proxy challenge framing")
            }
            _ = try await readProxyBytes(length, buffer: &buffer, connection: connection)
        }
        guard buffer.data.isEmpty, !buffer.isComplete else { throw FTPError.protocolViolation(description: "Unexpected bytes or EOF after HTTP proxy challenge") }
    }

    /// Performs a proxy handshake and returns bytes already received after the tunnel response.
    private func negotiateProxy(_ proxy: FTPProxy, targetHost: String, targetPort: Int, connection: NWConnection) async throws -> FTPProxyBuffer {
        guard !targetHost.isEmpty, targetHost.utf8.allSatisfy({ $0 > 32 && $0 != 127 }),
              let port = UInt16(exactly: targetPort), port != 0 else {
            throw FTPError.invalidState(description: "Invalid proxy target")
        }
        var buffer = FTPProxyBuffer()
        switch proxy {
        case .httpConnect(_, _, let username, let password):
            guard (username == nil) == (password == nil), username?.contains(":") != true else {
                throw FTPError.invalidState(description: "HTTP proxy requires a valid username and password")
            }
            let authority = targetHost.contains(":") ? "[\(targetHost)]:\(port)" : "\(targetHost):\(port)"
            var request = "CONNECT \(authority) HTTP/1.1\r\nHost: \(authority)\r\n"
            if let username, let password {
                request += "Proxy-Authorization: Basic \(Data("\(username):\(password)".utf8).base64EncodedString())\r\n"
            }
            request += "\r\n"
            try await send(payload: Data(request.utf8), connection: connection)
            let reply = try await readProxyResponse(buffer: &buffer, connection: connection)
            guard (200..<300).contains(reply.status) else {
                throw FTPError.connectionFailed(description: "HTTP proxy CONNECT rejected")
            }
        case .httpNTLM(_, _, let configuredUsername, let password, let configuredDomain):
            var username = configuredUsername
            var domain = configuredDomain
            if let slash = username.firstIndex(of: "\\") {
                let embedded = String(username[..<slash])
                guard domain.isEmpty || domain.caseInsensitiveCompare(embedded) == .orderedSame else {
                    throw FTPError.invalidState(description: "Conflicting NTLM proxy domains")
                }
                domain = embedded
                username = String(username[username.index(after: slash)...])
            }
            guard !username.isEmpty, !username.utf16.contains(0), !domain.utf16.contains(0),
                  username.utf16.count <= 1024, domain.utf16.count <= 1024, password.utf16.count <= 4096 else {
                throw FTPError.invalidState(description: "Invalid NTLM proxy credentials")
            }
            let authority = targetHost.contains(":") ? "[\(targetHost)]:\(port)" : "\(targetHost):\(port)"
            let negotiate = FTPNTLMv2.negotiate()
            let request = "CONNECT \(authority) HTTP/1.1\r\nHost: \(authority)\r\nProxy-Authorization: NTLM \(negotiate.base64EncodedString())\r\n\r\n"
            try await send(payload: Data(request.utf8), connection: connection)
            let first = try await readProxyResponse(buffer: &buffer, connection: connection)
            guard first.status == 407 else { throw FTPError.connectionFailed(description: "NTLM proxy did not issue a challenge") }
            let challenges = (first.headers["proxy-authenticate"] ?? []).flatMap { $0.split(separator: ",") }.compactMap { value -> String? in
                let parts = value.trimmingCharacters(in: .whitespaces).split(whereSeparator: { $0 == " " || $0 == "\t" })
                guard parts.count == 2, parts[0].caseInsensitiveCompare("NTLM") == .orderedSame else { return nil }
                return String(parts[1])
            }
            guard challenges.count == 1, let challenge = Data(base64Encoded: challenges[0]) else {
                throw FTPError.protocolViolation(description: "Missing or ambiguous NTLM proxy challenge")
            }
            try await discardProxyChallengeBody(first, buffer: &buffer, connection: connection)
            let authenticate = try FTPNTLMv2.authenticate(challenge: challenge, negotiate: negotiate, username: username, password: password, domain: domain)
            let finalRequest = "CONNECT \(authority) HTTP/1.1\r\nHost: \(authority)\r\nProxy-Authorization: NTLM \(authenticate.base64EncodedString())\r\n\r\n"
            try await send(payload: Data(finalRequest.utf8), connection: connection)
            let final = try await readProxyResponse(buffer: &buffer, connection: connection)
            guard (200..<300).contains(final.status) else { throw FTPError.connectionFailed(description: "NTLM proxy authentication rejected") }
        case .socks5(_, _, let username, let password):
            try await authenticateSOCKS5(username: username, password: password, buffer: &buffer, connection: connection)
            var address = Data()
            var v4 = in_addr(), v6 = in6_addr()
            if inet_pton(AF_INET, targetHost, &v4) == 1 {
                address.append(1)
                withUnsafeBytes(of: &v4) { address.append(contentsOf: $0) }
            } else if inet_pton(AF_INET6, targetHost, &v6) == 1 {
                address.append(4)
                withUnsafeBytes(of: &v6) { address.append(contentsOf: $0) }
            } else {
                let name = Array(targetHost.utf8)
                guard (1...255).contains(name.count) else { throw FTPError.invalidState(description: "Invalid SOCKS5 target name") }
                address.append(contentsOf: [3, UInt8(name.count)] + name)
            }
            var request = Data([5, 1, 0])
            request.append(address)
            request.append(contentsOf: [UInt8(port >> 8), UInt8(port & 255)])
            try await send(payload: request, connection: connection)
            _ = try await readSOCKS5Endpoint(buffer: &buffer, connection: connection)
        case .socks4(_, _, let userID):
            guard !userID.utf8.contains(0), !targetHost.contains(":") else {
                throw FTPError.invalidState(description: "SOCKS4 does not support this target or user ID")
            }
            var v4 = in_addr()
            let numeric = inet_pton(AF_INET, targetHost, &v4) == 1
            var request = Data([4, 1, UInt8(port >> 8), UInt8(port & 255)])
            if numeric { withUnsafeBytes(of: &v4) { request.append(contentsOf: $0) } }
            else { request.append(contentsOf: [0, 0, 0, 1]) }
            request.append(contentsOf: userID.utf8)
            request.append(0)
            if !numeric { request.append(contentsOf: targetHost.utf8); request.append(0) }
            try await send(payload: request, connection: connection)
            let response = try await readProxyBytes(8, buffer: &buffer, connection: connection)
            guard response[0] == 0, response[1] == 90 else { throw FTPError.connectionFailed(description: "SOCKS4 CONNECT rejected") }
        case .traditional:
            throw FTPError.invalidState(description: "Traditional FTP proxy is not a socket tunnel")
        }
        return buffer
    }

    private func receiveChunk(connection: NWConnection) async throws -> Data {
        let timeout = configuration?.readTimeout ?? 30
        return try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            let resumeGuard = ContinuationResumeGuard()
            connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, isComplete, error in
                guard resumeGuard.tryResume() else { return }
                if let error {
                    continuation.resume(throwing: FTPError.connectionFailed(description: error.localizedDescription))
                    return
                }

                if let data, !data.isEmpty {
                    continuation.resume(returning: data)
                    return
                }

                if isComplete {
                    continuation.resume(throwing: FTPError.connectionFailed(description: "Remote peer closed the connection"))
                    return
                }

                continuation.resume(throwing: FTPError.protocolViolation(description: "Received empty FTP control payload"))
            }
            queue.asyncAfter(deadline: .now() + timeout) {
                guard resumeGuard.tryResume() else { return }
                connection.cancel()
                continuation.resume(throwing: FTPError.timeout(operation: "read"))
            }
        }
        } onCancel: { connection.cancel() }
    }

    private func receiveChunkWithCompletion(connection dataConnection: FTPDataConnection) async throws -> (data: Data, isComplete: Bool) {
        let chunk = try await receiveRawChunkWithCompletion(connection: dataConnection)
        if let decoder = dataConnection.decoder {
            return (try decoder.process(chunk.data, final: chunk.isComplete), chunk.isComplete)
        }
        return chunk
    }

    private func receiveRawChunkWithCompletion(connection dataConnection: FTPDataConnection) async throws -> (data: Data, isComplete: Bool) {
        if !dataConnection.prefetched.isEmpty {
            let data = dataConnection.prefetched
            dataConnection.prefetched.removeAll()
            let complete = dataConnection.prefetchedComplete
            dataConnection.prefetchedComplete = false
            return (data, complete)
        }
        if dataConnection.prefetchedComplete { dataConnection.prefetchedComplete = false; return (Data(), true) }
        if let tls = dataConnection.tls { return try await tls.receiveWithCompletion() }
        return try await receiveNetworkChunkWithCompletion(connection: dataConnection.connection)
    }

    private func receiveNetworkChunkWithCompletion(connection: NWConnection) async throws -> (data: Data, isComplete: Bool) {
        let timeout = configuration?.readTimeout ?? 30
        return try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<(data: Data, isComplete: Bool), Error>) in
            let resumeGuard = ContinuationResumeGuard()
            connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, isComplete, error in
                guard resumeGuard.tryResume() else { return }
                if let error {
                    continuation.resume(throwing: FTPError.connectionFailed(description: error.localizedDescription))
                    return
                }

                if let data, !data.isEmpty {
                    continuation.resume(returning: (data, isComplete))
                    return
                }

                if isComplete {
                    continuation.resume(returning: (Data(), true))
                    return
                }

                continuation.resume(throwing: FTPError.protocolViolation(description: "Received empty FTP data payload"))
            }
            queue.asyncAfter(deadline: .now() + timeout) {
                guard resumeGuard.tryResume() else { return }
                connection.cancel()
                continuation.resume(throwing: FTPError.timeout(operation: "read"))
            }
        }
        } onCancel: { connection.cancel() }
    }

    private var downloadLineEnding: FTPASCIILineEnding {
        transferType == .ascii ? (configuration?.asciiLineEnding ?? .unchanged) : .unchanged
    }

    /// Changes conversion for subsequent downloads on the current session.
    public func setASCIILineEnding(_ mode: FTPASCIILineEnding) throws {
        try beginOperation()
        defer { operationInProgress = false }
        guard configuration != nil else { throw FTPError.invalidState(description: "Not connected") }
        configuration?.asciiLineEnding = mode
    }

    private func receiveAllData(connection: FTPDataConnection, throttleRate: UInt64 = 0, lineEnding: FTPASCIILineEnding = .unchanged, trackDownload: Bool = false) async throws -> Data {
        var result = Data()
        var converter = FTPASCIINewlineConverter(lineEnding)
        var received: UInt64 = 0
        let start = ProcessInfo.processInfo.systemUptime

        while true {
            try Task.checkCancellation()
            let chunk = try await receiveChunkWithCompletion(connection: connection)
            let converted = converter.convert(chunk.data, final: chunk.isComplete)
            if trackDownload { recordTransferBytes(converted.count) }
            if !converted.isEmpty {
                guard converted.count <= (configuration?.maximumBufferedBytes ?? 268_435_456) - result.count else {
                    throw FTPError.invalidState(description: "Buffered FTP response exceeds configured limit")
                }
                result.append(converted)
            }
            if !chunk.data.isEmpty {
                received += UInt64(chunk.data.count)
                try await throttle(bytes: received, rate: throttleRate, started: start)
            }
            if chunk.isComplete {
                return result
            }
        }
    }

    private func throttle(bytes: UInt64, rate: UInt64, started: TimeInterval) async throws {
        guard rate > 0 else { return }
        let target = Double(bytes) / Double(rate)
        while true {
            try Task.checkCancellation()
            let remaining = target - (ProcessInfo.processInfo.systemUptime - started)
            guard remaining > 0 else { return }
            try await Task.sleep(nanoseconds: UInt64(min(remaining, 3600) * 1_000_000_000))
        }
    }

    private func readPendingReply() async throws -> FTPReply {
        guard let connection else {
            throw FTPError.invalidState(description: "No active connection")
        }

        let reply = try await readReply(using: connection)
        lastReply = reply
        appendLog("< \(reply.message)")
        return reply
    }

    private func startTransferKeepAlive(_ data: FTPDataConnection) {
        transferKeepAliveStopped = false
        transferKeepAliveInFlight = false
        transferKeepAliveReply = nil
        transferKeepAliveError = nil
        guard let interval = configuration?.transferKeepAliveInterval, let control = connection else { return }
        transferKeepAliveTask = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000)) }
                catch { return }
                guard let self, await self.transferKeepAliveTick(control: control, data: data) else { return }
            }
        }
    }

    private func transferKeepAliveTick(control: NWConnection, data: FTPDataConnection) async -> Bool {
        guard !transferKeepAliveStopped, self.connection === control else { return false }
        transferKeepAliveInFlight = true
        defer { transferKeepAliveInFlight = false }
        do {
            appendLog("> NOOP")
            if let stream = explicitTLSStream { try await stream.send(Data("NOOP\r\n".utf8)) }
            else { try await send(payload: Data("NOOP\r\n".utf8), connection: control) }
            while true {
                let reply = try await readPendingReply()
                if reply.code == 200 { break }
                if reply.code == 226 || reply.code == 250 {
                    guard transferKeepAliveReply == nil else { throw FTPError.protocolViolation(description: "Multiple transfer completion replies") }
                    transferKeepAliveReply = reply
                    continue
                }
                throw FTPError.serverReply(code: reply.code, message: reply.message)
            }
            return !transferKeepAliveStopped && transferKeepAliveReply == nil
        } catch {
            transferKeepAliveError = error
            transferKeepAliveStopped = true
            data.cancel()
            resetConnection()
            return false
        }
    }

    private func finishTransferKeepAlive() async throws -> FTPReply {
        transferKeepAliveStopped = true
        let task = transferKeepAliveTask
        let control = connection
        if !transferKeepAliveInFlight { task?.cancel() }
        await withTaskCancellationHandler {
            await task?.value
        } onCancel: {
            task?.cancel()
            control?.cancel()
        }
        transferKeepAliveTask = nil
        try Task.checkCancellation()
        if let error = transferKeepAliveError { transferKeepAliveError = nil; throw error }
        if let reply = transferKeepAliveReply {
            transferKeepAliveReply = nil
            lastReply = reply
            return reply
        }
        return try await readPendingReply()
    }

    private func abortTransferKeepAlive(_ data: FTPDataConnection) async -> Error? {
        transferKeepAliveStopped = true
        let task = transferKeepAliveTask
        if transferKeepAliveInFlight {
            data.cancel()
            connection?.cancel()
        } else { task?.cancel() }
        await task?.value
        transferKeepAliveTask = nil
        let error = transferKeepAliveError
        transferKeepAliveError = nil
        transferKeepAliveReply = nil
        return error
    }

    private func openPassiveDataConnection() async throws -> (connection: NWConnection, host: String, port: Int) {
        guard let configuration, let connection else {
            throw FTPError.invalidState(description: "Not connected")
        }
        var host: NWEndpoint.Host
        if configuration.proxy?.isTunnel == true {
            host = NWEndpoint.Host(configuration.host)
        } else if case .hostPort(let peerHost, _) = connection.currentPath?.remoteEndpoint {
            host = peerHost
        } else {
            // Some path implementations do not expose the selected endpoint.
            host = NWEndpoint.Host(configuration.host)
        }

        let reply: FTPReply
        if configuration.preferEPSV || { if case .ipv6 = host { return true }; return false }() {
            reply = try await sendCommandLocked("EPSV")
        } else {
            reply = FTPReply(code: 502, message: "EPSV disabled")
        }
        let port: Int
        if reply.code == 229 {
            port = try FTPPassiveEndpointParser.parseExtendedPort(from: reply)
        } else if let code = reply.code, [500, 501, 502, 504, 522].contains(code) {
            if case .ipv6 = host {
                throw FTPError.serverReply(code: reply.code, message: reply.message)
            }
            let pasv = try await sendCommandLocked("PASV")
            guard pasv.code == 227 else {
                throw FTPError.serverReply(code: pasv.code, message: pasv.message)
            }
            let endpoint = try FTPPassiveEndpointParser.parse(from: pasv)
            port = endpoint.port
            if configuration.usePASVAdvertisedAddress { host = NWEndpoint.Host(endpoint.host) }
        } else {
            throw FTPError.serverReply(code: reply.code, message: reply.message)
        }
        let destination = configuration.proxy?.isTunnel == true ? configuration.proxy?.endpoint : nil
        let dataConnection = try await openDataConnection(host: destination.map { NWEndpoint.Host($0.host) } ?? host, port: destination?.port ?? port)
        return (dataConnection, String(describing: host), port)
    }

    private func openDataConnection(host: NWEndpoint.Host, port: Int) async throws -> NWConnection {
        guard let number = UInt16(exactly: port), let endpointPort = NWEndpoint.Port(rawValue: number) else {
            throw FTPError.invalidState(description: "Invalid passive data port: \(port)")
        }

        guard let configuration else { throw FTPError.invalidState(description: "Not connected") }
        let parameters = configuration.proxy?.isTunnel == true || !dataProtected || tlsSessionPeerID != nil ? .tcp : try connectionParameters(configuration: configuration, importedIdentity: importedIdentity)
        try configureLocalBinding(parameters, configuration: configuration)
        return NWConnection(host: host, port: endpointPort, using: parameters)
    }

    private func readReply(using connection: NWConnection) async throws -> FTPReply {
        if let reply = try replyParser.append(Data()) {
            return reply
        }
        if !prefetchedControl.isEmpty {
            let bytes = prefetchedControl
            prefetchedControl.removeAll()
            if let reply = try replyParser.append(bytes) { return reply }
        }
        while true {
            let chunk: Data
            if let explicitTLSStream {
                chunk = try await explicitTLSStream.receive()
            } else {
                chunk = try await receiveChunk(connection: connection)
            }
            if let reply = try replyParser.append(chunk) {
                return reply
            }
        }
    }

    private func isPositivePreliminaryOrCompletion(_ reply: FTPReply) -> Bool {
        guard let code = reply.code else {
            return false
        }

        return (100..<400).contains(code)
    }

    private func requirePositiveCompletion(_ reply: FTPReply, operation: String) throws {
        guard let code = reply.code else {
            throw FTPError.protocolViolation(description: "Missing FTP status code for \(operation)")
        }

        guard (200..<300).contains(code) else {
            throw FTPError.serverReply(code: code, message: reply.message)
        }
    }

    private func parseListingNames(from data: Data) throws -> [String] {
        let encoding = try FTPCharset.encoding(named: configuration?.directoryListingCharset ?? "utf-8")
        guard let text = String(data: data, encoding: encoding) else {
            throw FTPError.invalidResponseEncoding
        }

        return text
            .components(separatedBy: "\r\n")
            .filter { !$0.isEmpty }
    }
}
