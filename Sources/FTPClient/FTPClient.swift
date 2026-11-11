import Foundation
import FTPClientCore
import FTPClientSecurity
import FTPClientSync
import FTPClientFacade

public actor FTPClient {
    public let configuration: FTPClientConfiguration
    public let securityPolicy: FTPSecurityPolicy

    private let facade: FTPClientFacade

    public init(
        configuration: FTPClientConfiguration,
        securityPolicy: FTPSecurityPolicy? = nil
    ) {
        let securityPolicy = securityPolicy ?? FTPSecurityPolicy(
            requireServerCertificateValidation: configuration.requireServerCertificateValidation
        )
        self.configuration = configuration
        self.securityPolicy = securityPolicy

        let facade = FTPClientFacade()
        // The idiomatic configuration selects transport explicitly, regardless of port.
        facade.loggingEnabled = configuration.loggingEnabled
        facade.redactSensitiveInformation = configuration.redactSensitiveInformation
        facade.autoFix = false
        facade.hostname = configuration.host
        facade.port = configuration.port
        facade.username = configuration.username
        facade.password = configuration.password
        facade.account = configuration.account
        facade.authTls = configuration.security == .explicitTLS
        facade.authSsl = configuration.security == .explicitSSL
        facade.implicitTls = configuration.security == .implicitTLS
        facade.passive = configuration.dataConnectionMode == .passive
        switch configuration.dataProtection {
        case .matchControl: facade.dataProtection = "control"
        case .privateData: facade.dataProtection = "private"
        case .clear: facade.dataProtection = "clear"
        }
        facade.enableTLSSessionResumption = configuration.enableTLSSessionResumption
        facade.connectTimeout = configuration.connectTimeout
        facade.readTimeout = configuration.readTimeout
        facade.requireSslCertVerify = securityPolicy.requireServerCertificateValidation
        facade.trustedRootCertificates = securityPolicy.trustedRootCertificates.isEmpty ? configuration.trustedRootCertificates : securityPolicy.trustedRootCertificates
        facade.clientIdentity = configuration.clientIdentity
        facade.pinnedPublicKeyHashes = securityPolicy.pinnedPublicKeyHashes.isEmpty ? configuration.pinnedPublicKeyHashes : securityPolicy.pinnedPublicKeyHashes
        facade.certificateRequirements = configuration.certificateRequirements
        facade.proxy = configuration.proxy
        switch securityPolicy.minimumTLSVersion?.lowercased() {
        case "tls 1.3", "tls 1.3 or higher": facade.minimumTLSVersion = .tls13
        case "tls 1.2", "tls 1.2 or higher": facade.minimumTLSVersion = .tls12
        default: facade.minimumTLSVersion = configuration.minimumTLSVersion
        }
        facade.maximumTLSVersion = configuration.maximumTLSVersion
        facade.allowedCipherSuites = securityPolicy.allowedCipherSuites.isEmpty ? configuration.allowedCipherSuites : securityPolicy.allowedCipherSuites
        facade.bandwidthThrottleUp = configuration.bandwidthThrottleUp
        facade.bandwidthThrottleDown = configuration.bandwidthThrottleDown
        facade.transferKeepAliveInterval = configuration.transferKeepAliveInterval
        facade.activePortRangeStart = configuration.activePortRangeStart
        facade.activePortRangeEnd = configuration.activePortRangeEnd
        if let address = configuration.activeAdvertisedIPv4 {
            facade.forcePortIpAddress = configuration.bindActiveAdvertisedIPv4 ? "bind-\(address)" : address
        }
        facade.transferType = configuration.transferType
        facade.crlfMode = configuration.asciiLineEnding.rawValue
        facade.commandCharset = configuration.commandCharset
        facade.replyCharset = configuration.replyCharset
        facade.dirListingCharset = configuration.directoryListingCharset
        facade.autoSyst = configuration.autoSyst
        facade.autoFeat = configuration.autoFeat
        facade.autoXcrc = configuration.automaticUploadCRC
        facade.autoOptsUtf8 = configuration.autoOptsUtf8
        facade.useEpsv = configuration.preferEPSV
        facade.passiveUseHostAddr = !configuration.usePASVAdvertisedAddress
        facade.clientIpAddress = configuration.localIPAddress ?? ""
        facade.legacyListingTimeZoneIdentifier = configuration.legacyListingTimeZoneIdentifier
        facade.maximumBufferedBytes = configuration.maximumBufferedBytes
        facade.preserveDownloadModificationTime = configuration.preserveDownloadModificationTime
        self.facade = facade
    }

    public func connect() async throws {
        try await connectOnly()
        do {
            try await facade.loginAfterConnectOnly()
        } catch {
            await facade.disconnect()
            throw error
        }
    }

    public func connectOnly() async throws {
        try FTPSecurityEvaluator().evaluate(policy: securityPolicy, for: configuration)
        try await facade.connectOnly()
    }

    public func login() async throws { try await facade.loginAfterConnectOnly() }

    public func sendRawCommand(_ command: String) async throws -> String {
        try await facade.quote(command)
    }

    public func convertToTLS() async throws { try await facade.convertToTls() }

    public func serverFeatures() async throws -> String {
        try await facade.feat()
    }

    public func serverSystem() async throws -> String {
        try await facade.syst()
    }

    public func currentDirectory() async throws -> String {
        try await facade.getCurrentRemoteDir()
    }

    public func changeDirectory(_ path: String) async throws {
        try await facade.changeRemoteDir(path)
    }

    public func keepAlive() async throws {
        try await facade.noop()
    }

    public func listNames(path: String? = nil) async throws -> [String] {
        try await facade.nlst(path)
    }

    public func listDetails(path: String? = nil) async throws -> [String] {
        try await facade.list(path)
    }

    public func listEntries(path: String? = nil) async throws -> [FTPDirectoryEntry] {
        try await facade.mlsd(path)
    }

    public func fileSize(_ path: String) async throws -> UInt64 {
        try await facade.getSize(path)
    }

    public func modificationTime(_ path: String) async throws -> Date {
        try await facade.getLastModified(path)
    }

    public func setModificationTime(_ date: Date, path: String) async throws {
        try await facade.setRemoteFileDate(date, remoteFilename: path)
    }

    public func site(_ command: String) async throws { try await facade.site(command) }
    public func setTransferType(_ type: FTPTransferType) async throws {
        if type == .ascii { try await facade.setTypeAscii() }
        else { try await facade.setTypeBinary() }
    }
    public func setCompression(_ enabled: Bool) async throws {
        if enabled { try await facade.setModeZ() } else { try await facade.setModeStream() }
    }
    public func serverStatus() async throws -> String { try await facade.stat() }

    public func downloadData(remotePath: String) async throws -> Data {
        try await facade.getRemoteFileBinaryData(remotePath)
    }

    public func uploadData(_ data: Data, remotePath: String, append: Bool = false) async throws {
        if append { try await facade.appendFile(fromBinaryData: remotePath, binaryData: data) }
        else { try await facade.putFile(fromBinaryData: remotePath, binaryData: data) }
    }

    public func downloadStream(remotePath: String, progress: (@Sendable (UInt64) -> Void)? = nil, sink: @escaping @Sendable (Data) async throws -> Void) async throws {
        try await facade.getFileToStream(remoteFilename: remotePath, progress: progress, sink: sink)
    }

    public func uploadStream(remotePath: String, source: AsyncThrowingStream<Data, Error>, append: Bool = false, progress: (@Sendable (UInt64) -> Void)? = nil) async throws {
        try await facade.putFileFromStream(remoteFilename: remotePath, source: source, append: append, progress: progress)
    }

    public func downloadText(remotePath: String, encoding: String.Encoding = .utf8) async throws -> String {
        try await facade.getRemoteFileText(remotePath, encoding: encoding)
    }

    public func uploadText(_ text: String, remotePath: String, encoding: String.Encoding = .utf8, append: Bool = false) async throws {
        try await facade.putFile(fromTextData: remotePath, textData: text, encoding: encoding, append: append)
    }

    public func createDirectory(_ path: String) async throws {
        try await facade.createRemoteDir(path)
    }

    public func removeDirectory(_ path: String) async throws {
        try await facade.removeRemoteDir(path)
    }

    public func deleteFile(_ path: String) async throws {
        try await facade.deleteRemoteFile(path)
    }

    public func renameFile(from oldPath: String, to newPath: String) async throws {
        try await facade.renameRemoteFile(existingPath: oldPath, newPath: newPath)
    }

    public func downloadFile(remotePath: String, localPath: String, resume: Bool = false, querySizeForProgress: Bool = false,
                             progress: (@Sendable (UInt64) -> Void)? = nil) async throws {
        try await facade.getFile(remoteFilename: remotePath, localPath: localPath, resume: resume,
                                 querySizeForProgress: querySizeForProgress, progress: progress)
    }

    public func uploadFile(localPath: String, remotePath: String, resume: Bool = false, progress: (@Sendable (UInt64) -> Void)? = nil) async throws {
        try await facade.putFile(localPath: localPath, remoteFilename: remotePath, resume: resume, progress: progress)
    }

    public func appendFile(localPath: String, remotePath: String, progress: (@Sendable (UInt64) -> Void)? = nil) async throws {
        try await facade.appendFile(localPath: localPath, remoteFilename: remotePath, progress: progress)
    }

    public func uploadInChunks(localPath: String, remotePath: String, chunkSize: Int, progress: (@Sendable (UInt64) -> Void)? = nil) async throws {
        try await facade.largeFileUpload(localPath: localPath, remotePath: remotePath, chunkSize: chunkSize, progress: progress)
    }

    public func sync(_ plan: FTPSyncPlan) async throws {
        _ = try await facade.runSync(plan: plan)
    }

    public func previewSync(_ plan: FTPSyncPlan) async throws -> [FTPSyncOperation] {
        try await facade.previewSync(plan: plan)
    }

    @discardableResult
    public func runSync(_ plan: FTPSyncPlan) async throws -> [FTPSyncOperation] {
        try await facade.runSync(plan: plan)
    }

    public func uploadTree(localRoot: String) async throws { try await facade.putTree(localDir: localRoot) }
    public func downloadTree(localRoot: String) async throws { try await facade.downloadTree(localRoot: localRoot) }
    /// Irreversibly deletes files and subdirectories beneath the current remote directory.
    public func deleteRemoteTree() async throws { try await facade.deleteTree() }

    @discardableResult
    public func uploadMatching(localPattern: String) async throws -> Int { try await facade.mPutFiles(pattern: localPattern) }
    @discardableResult
    public func downloadMatching(remotePattern: String, localDirectory: String) async throws -> Int {
        try await facade.mGetFiles(remotePattern: remotePattern, localDir: localDirectory)
    }
    @discardableResult
    public func deleteMatching(_ remotePattern: String) async throws -> Int { try await facade.delete(matching: remotePattern) }

    public func disconnect() async {
        await facade.disconnect()
    }

    /// Enable or disable verbose console diagnostics, independently of the retained session log.
    public func setLoggingEnabled(_ enabled: Bool) async { await facade.setLoggingEnabled(enabled) }

    /// Applies to future console output and retained session log entries.
    public func setRedactSensitiveInformation(_ enabled: Bool) async { await facade.setRedactSensitiveInformation(enabled) }

    public func setSessionLogging(_ enabled: Bool) async { await facade.setSessionLogging(enabled) }
    public func sessionLog() async -> String { await facade.sessionLog() }
    public func clearSessionLog() async { await facade.clearSessionLog() }
    public func transferMetrics() async -> FTPTransferMetrics { await facade.transferMetrics() }
    public func isConnected() async -> Bool { await facade.checkConnection() }
    public func isAuthenticated() async -> Bool { await facade.isLoggedIn() }
    public func serverCapabilities() async -> Set<String> { await facade.serverCapabilities() }
    public func tlsSessionInfo() async throws -> FTPTLSSessionInfo? { try await facade.tlsSessionInfo() }
}
