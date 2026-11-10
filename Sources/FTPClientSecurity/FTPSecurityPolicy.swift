import Foundation
import FTPClientCore

public struct FTPSecurityPolicy: Sendable, Equatable {
    public var requireServerCertificateValidation: Bool
    public var pinnedPublicKeyHashes: [String]
    public var minimumTLSVersion: String?
    public var allowedCipherSuites: [String]
    /// DER-encoded roots replacing system roots when non-empty.
    public var trustedRootCertificates: [Data]

    public init(
        requireServerCertificateValidation: Bool = true,
        pinnedPublicKeyHashes: [String] = [],
        minimumTLSVersion: String? = nil,
        allowedCipherSuites: [String] = [],
        trustedRootCertificates: [Data] = []
    ) {
        self.requireServerCertificateValidation = requireServerCertificateValidation
        self.pinnedPublicKeyHashes = pinnedPublicKeyHashes
        self.minimumTLSVersion = minimumTLSVersion
        self.allowedCipherSuites = allowedCipherSuites
        self.trustedRootCertificates = trustedRootCertificates
    }
}

public struct FTPSecurityEvaluator: Sendable {
    public init() {}

    public func evaluate(policy: FTPSecurityPolicy, for configuration: FTPClientConfiguration) throws {
        if let version = policy.minimumTLSVersion,
           !["tls 1.2", "tls 1.2 or higher", "tls 1.3", "tls 1.3 or higher", "default"].contains(version.lowercased()) {
            throw FTPError.invalidState(description: "Unsupported minimum TLS version: \(version)")
        }
    }
}
