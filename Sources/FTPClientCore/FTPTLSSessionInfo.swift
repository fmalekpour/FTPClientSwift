import Foundation

/// Negotiated parameters and DER-encoded peer certificate for the active control TLS session.
public struct FTPTLSSessionInfo: Sendable, Equatable {
    public let protocolVersion: String
    public let cipherSuite: String
    public let serverCertificateDER: Data?
    /// False when normal chain verification was explicitly disabled, not an assessment of trust.
    public let chainValidationRequired: Bool

    public init(protocolVersion: String, cipherSuite: String, serverCertificateDER: Data?, chainValidationRequired: Bool) {
        self.protocolVersion = protocolVersion
        self.cipherSuite = cipherSuite
        self.serverCertificateDER = serverCertificateDER
        self.chainValidationRequired = chainValidationRequired
    }
}