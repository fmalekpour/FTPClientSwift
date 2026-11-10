import Testing
@testable import FTPClient
import FTPClientCore
import FTPClientSecurity

@Test func configurationDefaults() {
    let configuration = FTPClientConfiguration(
        host: "example.com",
        username: "demo",
        password: "secret"
    )

    #expect(configuration.port == 21)
    #expect(configuration.security == .none)
    #expect(configuration.dataConnectionMode == .passive)
}

@Test func defaultSecurityPolicyAllowsPlainFTP() throws {
    let configuration = FTPClientConfiguration(
        host: "example.com",
        username: "demo",
        password: "secret",
        security: .none
    )

    let policy = FTPSecurityPolicy(requireServerCertificateValidation: true)

    try FTPSecurityEvaluator().evaluate(policy: policy, for: configuration)
}

@Test func securityEvaluatorAllowsPinning() throws {
    let configuration = FTPClientConfiguration(host: "example.com", username: "demo", password: "secret")
    let policy = FTPSecurityPolicy(pinnedPublicKeyHashes: ["sha256/test"])
    try FTPSecurityEvaluator().evaluate(policy: policy, for: configuration)
}

@Test func invalidPinFailsBeforeConnecting() async {
    let configuration = FTPClientConfiguration(host: "localhost", username: "demo", password: "secret", security: .explicitTLS, pinnedPublicKeyHashes: ["sha256/invalid"])
    let channel = FTPControlChannel()
    await #expect(throws: FTPError.invalidState(description: "Invalid SHA-256 SPKI pin")) { try await channel.connect(configuration: configuration) }
}

@Test func securityEvaluatorAllowsExplicitlyDisablingFTPSChainValidation() throws {
    let configuration = FTPClientConfiguration(host: "example.com", username: "demo", password: "secret", security: .implicitTLS)
    let policy = FTPSecurityPolicy(requireServerCertificateValidation: false)
    try FTPSecurityEvaluator().evaluate(policy: policy, for: configuration)
}

