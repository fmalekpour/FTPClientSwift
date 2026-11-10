import Foundation
import FTPClientCore
import FTPClientSecurity

/// The authentication selector used by the legacy FTP export screen.
public enum FTPExportAuthentication: Int, Sendable, Equatable {
    case plain = 0
    case explicitTLS = 1
    case explicitSSL = 2
    /// Preserves the legacy behavior where both explicit flags were enabled.
    /// AUTH TLS takes precedence in this package.
    case explicitTLSAndSSL = 3
}

/// Configuration for a single-file upload with connection lifecycle management.
public struct FTPExportOptions: Sendable, Equatable {
    public var username: String
    public var password: String
    public var host: String
    public var port: Int
    public var authentication: FTPExportAuthentication
    public var implicitTLS: Bool
    public var remoteDirectory: String
    public var passive: Bool
    /// Matches the legacy exporter, which disabled chain verification.
    /// Keep this false only for compatibility with the old application.
    public var requireServerCertificateValidation: Bool
    public var connectTimeout: TimeInterval
    public var readTimeout: TimeInterval

    public init(
        username: String,
        password: String,
        host: String,
        port: Int = 21,
        authentication: FTPExportAuthentication = .plain,
        implicitTLS: Bool = false,
        remoteDirectory: String = "",
        passive: Bool = true,
        requireServerCertificateValidation: Bool = false,
        connectTimeout: TimeInterval = 30,
        readTimeout: TimeInterval = 60
    ) {
        self.username = username
        self.password = password
        self.host = host
        self.port = port
        self.authentication = authentication
        self.implicitTLS = implicitTLS
        self.remoteDirectory = remoteDirectory
        self.passive = passive
        self.requireServerCertificateValidation = requireServerCertificateValidation
        self.connectTimeout = connectTimeout
        self.readTimeout = readTimeout
    }
}

/// Result of a completed FTP export.
public struct FTPExportResult: Sendable, Equatable {
    public let remotePath: String
    public let sentBytes: UInt64
    public let uploadRate: UInt64

    public init(remotePath: String, sentBytes: UInt64, uploadRate: UInt64) {
        self.remotePath = remotePath
        self.sentBytes = sentBytes
        self.uploadRate = uploadRate
    }
}

/// Uploads a single file and disconnects after success or failure.
public enum FTPExport {
    public static func upload(
        file: URL,
        remoteFilename: String,
        options: FTPExportOptions,
        progress: (@Sendable (_ totalBytes: UInt64, _ processedBytes: UInt64) -> Void)? = nil
    ) async throws -> FTPExportResult {
        guard file.isFileURL else { throw FTPError.invalidState(description: "Export source must be a file URL") }
        guard !remoteFilename.isEmpty, remoteFilename != ".", remoteFilename != "..",
              !remoteFilename.contains("/"), !remoteFilename.utf8.contains(where: { $0 == 0 || $0 == 10 || $0 == 13 }) else {
            throw FTPError.invalidState(description: "Invalid FTP export filename")
        }
        let source = try FileHandle(forReadingFrom: file)
        defer { try? source.close() }
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        guard let fileSize = (attributes[.size] as? NSNumber)?.uint64Value else {
            throw FTPError.invalidState(description: "Unable to determine export file size")
        }

        let host = normalizeHost(options.host)
        guard !host.isEmpty else { throw FTPError.invalidState(description: "FTP export host must not be empty") }
        let security: FTPTransportSecurity
        if options.implicitTLS {
            security = .implicitTLS
        } else {
            switch options.authentication {
            case .plain: security = .none
            case .explicitTLS, .explicitTLSAndSSL: security = .explicitTLS
            case .explicitSSL: security = .explicitSSL
            }
        }
        let configuration = FTPClientConfiguration(
            host: host,
            port: options.port,
            username: options.username,
            password: options.password,
            security: security,
            dataConnectionMode: options.passive ? .passive : .active,
            dataProtection: security == .none ? .matchControl : .privateData,
            connectTimeout: options.connectTimeout,
            readTimeout: options.readTimeout,
            requireServerCertificateValidation: options.requireServerCertificateValidation,
            transferType: .binary
        )
        let client = FTPClient(configuration: configuration)
        do {
            try await client.connect()
            if !options.remoteDirectory.isEmpty {
                try await client.changeDirectory(options.remoteDirectory)
            }
            let remotePath = remoteFilename
            try await client.uploadStream(remotePath: remotePath, source: stream(from: source), progress: { processed in
                progress?(fileSize, processed)
            })
            let metrics = await client.transferMetrics()
            await client.disconnect()
            return FTPExportResult(remotePath: remotePath, sentBytes: metrics.sentBytes, uploadRate: metrics.uploadBytesPerSecond)
        } catch {
            await client.disconnect()
            throw error
        }
    }

    private static func stream(from file: FileHandle) -> AsyncThrowingStream<Data, Error> {
        AsyncThrowingStream(unfolding: {
            try Task.checkCancellation()
            guard let data = try file.read(upToCount: 65_536), !data.isEmpty else { return nil }
            return data
        })
    }

    private static func normalizeHost(_ value: String) -> String {
        var host = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if host.lowercased().hasPrefix("ftp://") { host.removeFirst(6) }
        if let slash = host.firstIndex(of: "/") { host = String(host[..<slash]) }
        return host
    }
}
