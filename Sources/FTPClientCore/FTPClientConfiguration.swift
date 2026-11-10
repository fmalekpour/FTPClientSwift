import Foundation

public enum FTPTransportSecurity: Sendable, Equatable {
    case none
    case explicitTLS
    case explicitSSL
    case implicitTLS
}

public enum FTPDataConnectionMode: Sendable, Equatable {
    case passive
    case active
}

public enum FTPTransferType: Sendable, Equatable {
    case binary
    case ascii
}

/// Optional normalization applied only to ASCII-mode file downloads.
public enum FTPASCIILineEnding: Int, Sendable, Equatable {
    case unchanged = 0
    case crlf = 1
    case lf = 2
    case cr = 3
}

/// Data protection is private by default for FTPS. Clear data must be explicitly requested.
public enum FTPDataProtection: Sendable, Equatable {
    case matchControl
    case privateData
    case clear
}

public enum FTPListingPreference: Sendable, Equatable {
    case machineReadable
    case legacyDetails
    case namesOnly
}

public enum FTPTLSMinimumVersion: Sendable, Equatable {
    case tls12
    case tls13
}

public struct FTPCertificateRequirement: Sendable, Equatable {
    public enum Field: String, Sendable, Equatable {
        case subjectDN, subjectCN, issuerDN, issuerCN, subjectAlternativeName
    }
    public var field: Field
    /// Case-sensitive shell-style pattern applied in addition to normal TLS verification.
    public var pattern: String
    public init(field: Field, pattern: String) {
        self.field = field
        self.pattern = pattern
    }
}

/// A client certificate and private key represented by PKCS#12 or PEM data.
public struct FTPClientIdentity: Sendable, Equatable {
    public var pkcs12Data: Data
    public var passphrase: String
    /// When present, PEM data takes precedence over PKCS#12 data.
    public var pemData: Data?
    public init(pkcs12Data: Data, passphrase: String) {
        self.pkcs12Data = pkcs12Data
        self.passphrase = passphrase
        self.pemData = nil
    }

    /// Validates a PEM identity immediately; private keys remain in memory.
    public init(pemData: Data, passphrase: String = "") throws {
        self.pkcs12Data = Data()
        self.passphrase = passphrase
        self.pemData = pemData
        _ = try FTPImportedIdentity.load(self)
    }
}

/// A proxy used for both control and passive data connections.
public enum FTPProxy: Sendable, Equatable {
    case httpConnect(host: String, port: Int, username: String? = nil, password: String? = nil)
    case httpNTLM(host: String, port: Int, username: String, password: String, domain: String = "")
    case socks5(host: String, port: Int, username: String? = nil, password: String? = nil)
    case socks4(host: String, port: Int, userID: String = "")
    case traditional(host: String, port: Int, method: Int, username: String = "", password: String = "")

    var endpoint: (host: String, port: Int) {
        switch self {
        case .httpConnect(let host, let port, _, _), .httpNTLM(let host, let port, _, _, _), .socks5(let host, let port, _, _), .socks4(let host, let port, _), .traditional(let host, let port, _, _, _):
            return (host, port)
        }
    }

    var isTunnel: Bool {
        if case .traditional = self { return false }
        return true
    }
}

public struct FTPClientConfiguration: Sendable, Equatable {
    public var host: String
    public var port: Int
    public var username: String
    public var password: String
    public var account: String?
    public var security: FTPTransportSecurity
    public var dataConnectionMode: FTPDataConnectionMode
    public var dataProtection: FTPDataProtection
    /// Attempt TLS session reuse between one FTPS control session and its data sockets.
    public var enableTLSSessionResumption: Bool
    public var connectTimeout: TimeInterval
    public var readTimeout: TimeInterval
    /// DER-encoded root certificates. When non-empty, these replace system trust roots.
    public var trustedRootCertificates: [Data]
    public var clientIdentity: FTPClientIdentity?
    public var requireServerCertificateValidation: Bool
    /// SHA-256 SPKI pins, encoded as `sha256/<base64>` or base64 digests.
    public var pinnedPublicKeyHashes: [String]
    public var certificateRequirements: [FTPCertificateRequirement]
    public var proxy: FTPProxy?
    public var minimumTLSVersion: FTPTLSMinimumVersion
    public var maximumTLSVersion: FTPTLSMinimumVersion?
    public var allowedCipherSuites: [String]
    public var bandwidthThrottleUp: UInt64
    public var bandwidthThrottleDown: UInt64
    /// Seconds between transfer NOOP commands; nil disables keepalives.
    public var transferKeepAliveInterval: TimeInterval?
    public var activePortRangeStart: Int
    public var activePortRangeEnd: Int
    public var activeAdvertisedIPv4: String?
    public var bindActiveAdvertisedIPv4: Bool
    public var transferType: FTPTransferType
    public var asciiLineEnding: FTPASCIILineEnding
    public var commandCharset: String
    public var replyCharset: String
    public var directoryListingCharset: String
    public var autoSyst: Bool
    public var autoFeat: Bool
    /// Verify uploaded bytes with XCRC when the server advertises that extension.
    public var automaticUploadCRC: Bool
    public var autoOptsUtf8: Bool
    public var preferEPSV: Bool
    public var usePASVAdvertisedAddress: Bool
    public var localIPAddress: String?
    public var legacyListingTimeZoneIdentifier: String?
    public var maximumBufferedBytes: Int
    public var preserveDownloadModificationTime: Bool

    public init(
        host: String,
        port: Int = 21,
        username: String,
        password: String,
        account: String? = nil,
        security: FTPTransportSecurity = .none,
        dataConnectionMode: FTPDataConnectionMode = .passive,
        dataProtection: FTPDataProtection = .matchControl,
        enableTLSSessionResumption: Bool = false,
        connectTimeout: TimeInterval = 30,
        readTimeout: TimeInterval = 30,
        trustedRootCertificates: [Data] = [],
        clientIdentity: FTPClientIdentity? = nil,
        requireServerCertificateValidation: Bool = true,
        pinnedPublicKeyHashes: [String] = [],
        certificateRequirements: [FTPCertificateRequirement] = [],
        proxy: FTPProxy? = nil,
        minimumTLSVersion: FTPTLSMinimumVersion = .tls12,
        maximumTLSVersion: FTPTLSMinimumVersion? = nil,
        allowedCipherSuites: [String] = [],
        bandwidthThrottleUp: UInt64 = 0,
        bandwidthThrottleDown: UInt64 = 0,
        transferKeepAliveInterval: TimeInterval? = nil,
        activePortRangeStart: Int = 0,
        activePortRangeEnd: Int = 0,
        activeAdvertisedIPv4: String? = nil,
        bindActiveAdvertisedIPv4: Bool = false,
        transferType: FTPTransferType = .binary,
        asciiLineEnding: FTPASCIILineEnding = .unchanged,
        commandCharset: String = "utf-8",
        replyCharset: String = "utf-8",
        directoryListingCharset: String = "utf-8",
        autoSyst: Bool = false,
        autoFeat: Bool = false,
        automaticUploadCRC: Bool = false,
        autoOptsUtf8: Bool = true,
        preferEPSV: Bool = true,
        usePASVAdvertisedAddress: Bool = false,
        localIPAddress: String? = nil,
        legacyListingTimeZoneIdentifier: String? = nil,
        maximumBufferedBytes: Int = 268_435_456,
        preserveDownloadModificationTime: Bool = false
    ) {
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.account = account
        self.security = security
        self.dataConnectionMode = dataConnectionMode
        self.dataProtection = dataProtection
        self.enableTLSSessionResumption = enableTLSSessionResumption
        self.connectTimeout = connectTimeout
        self.readTimeout = readTimeout
        self.trustedRootCertificates = trustedRootCertificates
        self.clientIdentity = clientIdentity
        self.requireServerCertificateValidation = requireServerCertificateValidation
        self.pinnedPublicKeyHashes = pinnedPublicKeyHashes
        self.certificateRequirements = certificateRequirements
        self.proxy = proxy
        self.minimumTLSVersion = minimumTLSVersion
        self.maximumTLSVersion = maximumTLSVersion
        self.allowedCipherSuites = allowedCipherSuites
        self.bandwidthThrottleUp = bandwidthThrottleUp
        self.bandwidthThrottleDown = bandwidthThrottleDown
        self.transferKeepAliveInterval = transferKeepAliveInterval
        self.activePortRangeStart = activePortRangeStart
        self.activePortRangeEnd = activePortRangeEnd
        self.activeAdvertisedIPv4 = activeAdvertisedIPv4
        self.bindActiveAdvertisedIPv4 = bindActiveAdvertisedIPv4
        self.transferType = transferType
        self.asciiLineEnding = asciiLineEnding
        self.commandCharset = commandCharset
        self.replyCharset = replyCharset
        self.directoryListingCharset = directoryListingCharset
        self.autoSyst = autoSyst
        self.autoFeat = autoFeat
        self.automaticUploadCRC = automaticUploadCRC
        self.autoOptsUtf8 = autoOptsUtf8
        self.preferEPSV = preferEPSV
        self.usePASVAdvertisedAddress = usePASVAdvertisedAddress
        self.localIPAddress = localIPAddress
        self.legacyListingTimeZoneIdentifier = legacyListingTimeZoneIdentifier
        self.maximumBufferedBytes = maximumBufferedBytes
        self.preserveDownloadModificationTime = preserveDownloadModificationTime
    }
}
