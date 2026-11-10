#if os(macOS)
import Foundation
import Testing
import FTPClientCore
import FTPClientFacade

@Test(.enabled(if: nodeExecutable != nil)) func implicitFTPSSupportsResumedUpload() async throws {
    let payload = Data((0..<100_123).map { UInt8(truncatingIfNeeded: $0) })
    let server = try ExplicitFTPTestServer(implicitTLS: true, initialRemoteData: Data(payload.prefix(50_000)), expectedUploadByteCount: payload.count - 50_000)
    defer { server.stop() }
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .implicitTLS, connectTimeout: 10, readTimeout: 10, trustedRootCertificates: [server.root])
    try await channel.connect(configuration: config)
    try await channel.login()
    let source = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: source) }
    try payload.write(to: source)
    try await channel.uploadFile(from: source, remotePath: "sample", resume: true)
    #expect(try await channel.retrieveFileData(remotePath: "sample") == payload)
    await channel.disconnect()
}

@Test(.enabled(if: nodeExecutable != nil)) func implicitFTPSAuthenticatesTrustedServer() async throws {
    let server = try ExplicitFTPTestServer(implicitTLS: true)
    defer { server.stop() }
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .implicitTLS, connectTimeout: 10, readTimeout: 10, trustedRootCertificates: [server.root])
    try await channel.connect(configuration: config)
    try await channel.login()
    #expect(await channel.isAuthenticated)
    let session = try #require(try await channel.tlsSessionInfo())
    #expect(["TLS 1.2", "TLS 1.3"].contains(session.protocolVersion))
    #expect(!session.cipherSuite.isEmpty)
    #expect(session.serverCertificateDER == server.root)
    #expect(session.chainValidationRequired)
    #expect(try await channel.listNames() == ["encrypted-file"])
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    let destination = folder.appendingPathComponent("download")
    try await channel.downloadFile(remotePath: "sample", to: destination)
    #expect(try Data(contentsOf: destination) == Data([0, 10, 13, 255, 65, 66]))
    let payload = Data((0..<100_123).map { UInt8(truncatingIfNeeded: $0) })
    let source = folder.appendingPathComponent("upload")
    try payload.write(to: source)
    try await channel.uploadFile(from: source, remotePath: "sample")
    #expect(try await channel.retrieveFileData(remotePath: "sample") == payload)
    try await channel.noop()
    await channel.disconnect()
}

@Test(.enabled(if: nodeExecutable != nil)) func implicitFTPSRejectsWrongDataChannelHostname() async throws {
    let server = try ExplicitFTPTestServer(badDataCertificate: true, implicitTLS: true)
    defer { server.stop() }
    let channel = FTPControlChannel()
    let otherRoot = try #require(server.dataRoot)
    let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .implicitTLS, connectTimeout: 3, readTimeout: 3, trustedRootCertificates: [server.root, otherRoot])
    try await channel.connect(configuration: config)
    try await channel.login()
    await #expect(throws: FTPError.self) { try await channel.listNames() }
    #expect(await channel.isConnected == false)
}

@Test(.enabled(if: nodeExecutable != nil)) func implicitFTPSRejectsUntrustedDataChannel() async throws {
    let server = try ExplicitFTPTestServer(badDataCertificate: true, implicitTLS: true)
    defer { server.stop() }
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .implicitTLS, connectTimeout: 3, readTimeout: 3, trustedRootCertificates: [server.root])
    try await channel.connect(configuration: config)
    try await channel.login()
    await #expect(throws: FTPError.self) { try await channel.listNames() }
    #expect(await channel.isConnected == false)
}

@Test(.enabled(if: nodeExecutable != nil)) func implicitFTPSRejectsUntrustedServer() async throws {
    let server = try ExplicitFTPTestServer(implicitTLS: true)
    defer { server.stop() }
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .implicitTLS, connectTimeout: 3, readTimeout: 3)
    await #expect(throws: FTPError.self) { try await channel.connect(configuration: config) }
    #expect(await channel.isConnected == false)
}

@Test(.enabled(if: nodeExecutable != nil)) func implicitFTPSRejectsWrongHostname() async throws {
    let server = try ExplicitFTPTestServer(implicitTLS: true)
    defer { server.stop() }
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", security: .implicitTLS, connectTimeout: 3, readTimeout: 3, trustedRootCertificates: [server.root])
    await #expect(throws: FTPError.self) { try await channel.connect(configuration: config) }
    #expect(await channel.isConnected == false)
}

@Test(.enabled(if: nodeExecutable != nil)) func implicitFTPSClosesWhenProtectionRejected() async throws {
    let server = try ExplicitFTPTestServer(rejectProtection: true, implicitTLS: true)
    defer { server.stop() }
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .implicitTLS, connectTimeout: 3, readTimeout: 3, trustedRootCertificates: [server.root])
    await #expect(throws: FTPError.serverReply(code: 534, message: "534 Rejected")) { try await channel.connect(configuration: config) }
    #expect(await channel.isConnected == false)
}

@Test(.enabled(if: nodeExecutable != nil)) func facadeUsesImplicitFTPSAndCustomTrust() async throws {
    let server = try ExplicitFTPTestServer(implicitTLS: true)
    defer { server.stop() }
    let facade = FTPClientFacade()
    facade.hostname = "localhost"
    facade.port = server.port
    facade.username = "demo"
    facade.password = "secret"
    facade.implicitTls = true
    facade.trustedRootCertificates = [server.root]
    facade.connectTimeout = 10
    facade.readTimeout = 10
    try await facade.connect()
    try await facade.loginAfterConnectOnly()
    #expect(try await facade.nlst() == ["encrypted-file"])
    await facade.disconnect()
}
#endif