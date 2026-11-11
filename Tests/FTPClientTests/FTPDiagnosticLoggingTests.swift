import Testing
import FTPClient
@testable import FTPClientCore

@Test func diagnosticLoggingDefaultsToOff() async {
    let configuration = FTPClientConfiguration(host: "localhost", username: "user", password: "secret")
    #expect(!configuration.loggingEnabled)
    #expect(configuration.redactSensitiveInformation)
    let client = FTPClient(configuration: configuration)
    await client.setLoggingEnabled(true)
    await client.setLoggingEnabled(false)
    await client.setRedactSensitiveInformation(false)
    await client.setRedactSensitiveInformation(true)
    #expect(await client.sessionLog().isEmpty)
}

@Test func diagnosticRedactionCoversCredentialsAndControlCharacters() {
    let configuration = FTPClientConfiguration(
        host: "localhost", username: "alice", password: "long-secret", account: "account-value",
        clientIdentity: FTPClientIdentity(pkcs12Data: .init(), passphrase: "key-secret"),
        proxy: .httpNTLM(host: "proxy", port: 8080, username: "proxy-user", password: "proxy-secret", domain: "domain-value")
    )
    let secrets = FTPDiagnosticRedactor.secrets(in: configuration)
    let output = FTPDiagnosticRedactor.redact(
        "alice long-secret account-value key-secret proxy-user proxy-secret domain-value\r\n\u{1B}[31m", secrets: secrets)
    for secret in secrets { #expect(!output.contains(secret)) }
    #expect(!output.contains("\n"))
    #expect(!output.contains("\u{1B}"))
    #expect(output.contains("[redacted]"))
}

@Test func diagnosticRedactionPreservesNonSensitiveDetails() {
    #expect(FTPDiagnosticRedactor.redact("< 226 Transfer complete; bytes=1024", secrets: []) == "< 226 Transfer complete; bytes=1024")
}

@Test func diagnosticRedactionCanBeDisabled() {
    let message = "> PASS long-secret"
    #expect(FTPDiagnosticRedactor.redact(message, secrets: ["long-secret"], enabled: false) == message)
    #expect(FTPDiagnosticRedactor.redact(message, secrets: ["long-secret"], enabled: true) == "> PASS [redacted]")
    let configuration = FTPClientConfiguration(host: "localhost", username: "user", password: "secret", redactSensitiveInformation: false)
    #expect(!configuration.redactSensitiveInformation)
}
