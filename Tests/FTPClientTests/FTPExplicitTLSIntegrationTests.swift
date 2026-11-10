#if os(macOS)
import Darwin
import Foundation
import CryptoKit
import Testing
@testable import FTPClientCore
import FTPClient
import FTPClientSecurity
import FTPClientFacade
import Security

let nodeExecutable = ["/opt/homebrew/bin/node", "/usr/local/bin/node", "/usr/bin/node"].first {
    FileManager.default.isExecutableFile(atPath: $0)
}

/// Node and OpenSSL are used only by integration tests; the package has no runtime dependencies.
final class ExplicitFTPTestServer {
    let root: Data
    let dataRoot: Data?
    let publicKeyPin: String
    let clientIdentity: FTPClientIdentity?
    let legacyClientIdentity: FTPClientIdentity?
    let clientPrivatePEM: Data?
    let clientCertificatePEM: Data?
    let encryptedClientPrivatePEM: Data?
    let traditionalClientPrivatePEM: Data?
    let extraEncryptedClientKeys: [Data]
    let port: Int
    private let folder: URL
    private let process = Process()
    private let exited = DispatchSemaphore(value: 0)

    init(rejectAuth: Bool = false, rejectProtection: Bool = false, badDataCertificate: Bool = false, dataCertificateSameSAN: Bool = false, stallHandshake: Bool = false, trickleHandshake: Bool = false, implicitTLS: Bool = false, initialRemoteData: Data? = nil, expectedUploadByteCount: Int = 100_123, requireClientCertificate: Bool = false, clientCurve: String? = nil, extraPEMVariants: Bool = false, preliminaryAfterTLS: Bool = false, rejectClearProtection: Bool = false, requireSessionReuse: Bool = false, protectionOrder: Int = 0, includeIPSan: Bool = false, includeLegacyP12: Bool = false, transferDelayMS: Int = 0, noopDelayMS: Int = 0, rejectNoop: Bool = false, distinctDataTickets: Bool = false, reuseTLS13: Bool = false, failFirstTransfer: Bool = false) throws {
        guard let nodeExecutable else { throw POSIXError(.ENOENT) }
        guard let openssl = ["/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl"].first(where: {
            FileManager.default.isExecutableFile(atPath: $0)
        }) else { throw POSIXError(.ENOENT) }
        let temporaryFolder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        folder = temporaryFolder
        try FileManager.default.createDirectory(at: temporaryFolder, withIntermediateDirectories: true)
        var initialized = false
        defer { if !initialized { try? FileManager.default.removeItem(at: temporaryFolder) } }
        let key = folder.appendingPathComponent("key.pem").path
        let cert = folder.appendingPathComponent("cert.pem").path
        let der = folder.appendingPathComponent("cert.der").path
        func run(_ arguments: [String]) throws {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: openssl)
            p.arguments = arguments
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            let exited = DispatchSemaphore(value: 0)
            p.terminationHandler = { _ in exited.signal() }
            try p.run()
            if exited.wait(timeout: .now() + 10) == .timedOut {
              if p.isRunning { p.terminate() }
              if exited.wait(timeout: .now() + 2) == .timedOut { _ = kill(p.processIdentifier, SIGKILL) }
              throw POSIXError(.ETIMEDOUT)
            }
            guard p.terminationStatus == 0 else { throw POSIXError(.EIO) }
        }
        try run(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", key, "-out", cert, "-subj", "/CN=localhost", "-addext", includeIPSan ? "subjectAltName=DNS:localhost,IP:127.0.0.1" : "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "extendedKeyUsage=serverAuth"])
        try run(["x509", "-in", cert, "-outform", "DER", "-out", der])
        root = try Data(contentsOf: URL(fileURLWithPath: der))
        let publicPEM = folder.appendingPathComponent("public.pem").path
        let publicDER = folder.appendingPathComponent("public.der").path
        try run(["x509", "-in", cert, "-pubkey", "-noout", "-out", publicPEM])
        try run(["pkey", "-pubin", "-in", publicPEM, "-outform", "DER", "-out", publicDER])
        publicKeyPin = "sha256/" + Data(SHA256.hash(data: try Data(contentsOf: URL(fileURLWithPath: publicDER)))).base64EncodedString()
        let clientKey = folder.appendingPathComponent("client-key.pem").path
        let clientCert = folder.appendingPathComponent("client-cert.pem").path
        let clientP12 = folder.appendingPathComponent("client.p12").path
        if requireClientCertificate {
          var keyArguments = ["req", "-x509", "-newkey", clientCurve == nil ? "rsa:2048" : "ec"]
          if let clientCurve { keyArguments += ["-pkeyopt", "ec_paramgen_curve:\(clientCurve)"] }
          keyArguments += ["-nodes", "-days", "1", "-keyout", clientKey, "-out", clientCert, "-subj", "/CN=ftp-client", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "extendedKeyUsage=clientAuth"]
          try run(keyArguments)
          try run(["pkcs12", "-export", "-in", clientCert, "-inkey", clientKey, "-out", clientP12, "-passout", "pass:testing"])
          clientIdentity = FTPClientIdentity(pkcs12Data: try Data(contentsOf: URL(fileURLWithPath: clientP12)), passphrase: "testing")
          if includeLegacyP12 {
            let legacyPath = folder.appendingPathComponent("client-sha1.p12").path
            try run(["pkcs12", "-export", "-legacy", "-in", clientCert, "-inkey", clientKey, "-out", legacyPath, "-passout", "pass:testing", "-macalg", "sha1"])
            legacyClientIdentity = FTPClientIdentity(pkcs12Data: try Data(contentsOf: URL(fileURLWithPath: legacyPath)), passphrase: "testing")
          } else { legacyClientIdentity = nil }
          let encryptedKey = folder.appendingPathComponent("client-encrypted.pem").path
          let traditionalKey = folder.appendingPathComponent("client-traditional.pem").path
          try run(["pkcs8", "-topk8", "-in", clientKey, "-out", encryptedKey, "-v2", "aes-256-cbc", "-iter", "10000", "-passout", "pass:testing"])
          try run(["pkey", "-in", clientKey, "-traditional", "-out", traditionalKey])
          clientPrivatePEM = try Data(contentsOf: URL(fileURLWithPath: clientKey))
          clientCertificatePEM = try Data(contentsOf: URL(fileURLWithPath: clientCert))
          encryptedClientPrivatePEM = try Data(contentsOf: URL(fileURLWithPath: encryptedKey))
          traditionalClientPrivatePEM = try Data(contentsOf: URL(fileURLWithPath: traditionalKey))
          var variants: [Data] = []
          if extraPEMVariants {
            let passwordFile = folder.appendingPathComponent("pem-test-password")
            try Data("päss🔐".utf8).write(to: passwordFile)
            for (index, variant) in [("aes-128-cbc", "hmacWithSHA1"), ("aes-192-cbc", "hmacWithSHA384"), ("aes-256-cbc", "hmacWithSHA512")].enumerated() {
              let path = folder.appendingPathComponent("client-variant-\(index).pem").path
              try run(["pkcs8", "-topk8", "-in", clientKey, "-out", path, "-v2", variant.0, "-v2prf", variant.1, "-iter", "10000", "-passout", "file:\(passwordFile.path)"])
              variants.append(try Data(contentsOf: URL(fileURLWithPath: path)))
            }
          }
          extraEncryptedClientKeys = variants
        } else {
          clientIdentity = nil
          legacyClientIdentity = nil
          clientPrivatePEM = nil
          clientCertificatePEM = nil
          encryptedClientPrivatePEM = nil
          traditionalClientPrivatePEM = nil
          extraEncryptedClientKeys = []
        }
        let dataKey = folder.appendingPathComponent("data-key.pem").path
        let dataCert = folder.appendingPathComponent("data-cert.pem").path
        let dataDER = folder.appendingPathComponent("data-cert.der").path
        if badDataCertificate {
          let dnsName = dataCertificateSameSAN ? "localhost" : "other.invalid"
          try run(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", dataKey, "-out", dataCert, "-subj", "/CN=other.invalid", "-addext", "subjectAltName=DNS:\(dnsName)", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "extendedKeyUsage=serverAuth"])
          try run(["x509", "-in", dataCert, "-outform", "DER", "-out", dataDER])
          dataRoot = try Data(contentsOf: URL(fileURLWithPath: dataDER))
        } else {
          dataRoot = nil
        }
        let script = #"""
        const net = require('net'), tls = require('tls'), fs = require('fs'), zlib = require('zlib');
        const key = fs.readFileSync(process.argv[1]), cert = fs.readFileSync(process.argv[2]);
        const rejectAuth = process.argv[3] === '1', rejectProtection = process.argv[4] === '1';
        const dataKey = fs.readFileSync(process.argv[5]), dataCert = fs.readFileSync(process.argv[6]);
        const stallHandshake = process.argv[7] === '1';
        const trickleHandshake = process.argv[8] === '1';
        const implicitTLS = process.argv[9] === '1';
        const initialData = process.argv[10] === '-' ? null : Buffer.from(process.argv[10], 'base64');
        const expectedUploadBytes = Number(process.argv[11]);
        const clientCA = process.argv[12] === '-' ? undefined : fs.readFileSync(process.argv[12]);
        const delayedPreliminary = process.argv[13] === '1';
        const rejectClearProtection = process.argv[14] === '1';
        const requireSessionReuse = process.argv[15] === '1';
        const protectionOrder = Number(process.argv[16]);
        const transferDelay = Number(process.argv[17]), noopDelay = Number(process.argv[18]), rejectNoop = process.argv[19] === '1';
        const distinctDataTickets = process.argv[20] === '1';
        const reuseTLS13 = process.argv[21] === '1';
        const failFirstTransfer = process.argv[22] === '1';
        const ticketKeys = require('crypto').randomBytes(48);
        const dataTicketKeys = distinctDataTickets ? require('crypto').randomBytes(48) : ticketKeys;
        const tlsVersions = requireSessionReuse ? {minVersion:reuseTLS13 ? 'TLSv1.3' : 'TLSv1.2', maxVersion:reuseTLS13 ? 'TLSv1.3' : 'TLSv1.2', sessionIdContext:'ftp-test-session'} : {};
        const context = tls.createSecureContext({key, cert, ca:clientCA, ticketKeys, ...tlsVersions});
        const dataContext = tls.createSecureContext({key:dataKey, cert:dataCert, ca:clientCA, ticketKeys:dataTicketKeys, ...tlsVersions});
        let connectionCount = 0;
        const server = net.createServer(raw => {
          const connectionNumber = ++connectionCount;
          let stream = raw, input = '', secure = false, loggedIn = false, protectionSet = false, dataServer = null, dataSocket = null, pending = null, pendingSend = null, sawNoop = false, uploaded = initialData, chunks = [], restartOffset = 0, active = null, compressed = false, privateData = true;
          raw.on('error', () => {});
          function send(line) { stream.write(line + '\r\n'); }
          function sendData() {
            if (dataSocket && Buffer.isBuffer(pending)) { const content = compressed ? zlib.deflateSync(pending) : pending; pending = null; const deliver = () => dataSocket.end(content, () => send(failFirstTransfer && connectionNumber === 1 ? '451 Transfer failed' : '226 Complete')); if (transferDelay < 0 && !sawNoop) pendingSend = deliver; else setTimeout(deliver, Math.max(0,transferDelay)); }
          }
          function setupDataSocket(socket) {
            if (requireSessionReuse && !socket.isSessionReused()) { socket.destroy(); send('522 TLS session reuse required'); return; }
            dataSocket = socket; socket.on('error', () => {});
            socket.on('data', chunk => {
              chunks.push(chunk);
              if (compressed && pending === 'upload') {
                try {
                  const decoded = zlib.inflateSync(Buffer.concat(chunks));
                  uploaded = Buffer.concat([(uploaded || Buffer.alloc(0)).subarray(0, restartOffset), decoded]); restartOffset = 0; pending = null; socket.end(); send('226 Complete');
                } catch (error) { if (error.code !== 'Z_BUF_ERROR') { pending = null; send('426 Invalid compression'); } }
              } else {
                if (pending === 'upload' && chunks.reduce((n, c) => n + c.length, 0) === expectedUploadBytes) {
                  uploaded = Buffer.concat([(uploaded || Buffer.alloc(0)).subarray(0, restartOffset), ...chunks]); restartOffset = 0; pending = null; socket.end(); send('226 Complete');
                }
              }
            });
            socket.on('end', () => { if (pending === 'upload') { uploaded = Buffer.concat(chunks); pending = null; send('226 Complete'); } });
            sendData();
          }
          function beginActive() {
            if (!active) return;
            const endpoint = active; active = null;
            const peer = net.createConnection(endpoint.port, endpoint.host);
            peer.on('error', () => {});
            if (!privateData) {
              peer.on('connect', () => { if (delayedPreliminary) send('150 Opening'); setupDataSocket(peer); });
              return;
            }
            const socket = new tls.TLSSocket(peer, {isServer:true, secureContext:dataContext, requestCert:!!clientCA, rejectUnauthorized:!!clientCA});
            socket.on('error', () => {});
            socket.on('secure', () => { if (delayedPreliminary) send('150 Opening'); setupDataSocket(socket); });
          }
          function onData(chunk) {
            input += chunk.toString('utf8');
            while (input.includes('\r\n')) {
              const end = input.indexOf('\r\n'); let cmd = input.slice(0, end); input = input.slice(end + 2);
              if (cmd === 'RETR /sample') cmd = 'RETR sample';
              if (!secure) {
                if (cmd !== 'AUTH TLS' && cmd !== 'AUTH SSL') { send('530 TLS required'); continue; }
                if (rejectAuth) { send('502 Unsupported'); continue; }
                send('234 Proceed'); raw.removeListener('data', onData);
                if (stallHandshake) { raw.on('data', () => {}); return; }
                if (trickleHandshake) {
                  raw.once('data', () => {
                    raw.write(Buffer.from([0x16, 0x03, 0x03, 0x00, 0xff]));
                    const timer = setInterval(() => raw.write(Buffer.from([0])), 30);
                    raw.on('close', () => clearInterval(timer));
                  });
                  return;
                }
                stream = new tls.TLSSocket(raw, {isServer:true, secureContext:context, requestCert:!!clientCA, rejectUnauthorized:!!clientCA});
                stream.on('error', () => {}); stream.on('secure', () => { secure = true; });
                stream.on('data', onData); return;
              }
              if (cmd === 'USER demo') send(protectionOrder === 2 && !protectionSet ? '503 Protection required first' : '331 Password required');
              else if (cmd === 'PASS secret') { loggedIn = true; send('230 Logged in'); }
              else if (cmd === 'PBSZ 0') send(protectionOrder === 1 && !loggedIn ? '530 Login first' : '200 PBSZ');
              else if (cmd === 'PROT P') { if ((protectionOrder === 1 || protectionOrder === 3 || protectionOrder === 4) && !loggedIn) { send('530 Login first'); } else { if (!rejectProtection) { privateData = true; protectionSet = true; } send(rejectProtection ? '534 Rejected' : '200 Protected'); } }
              else if (cmd === 'PROT C') { if ((protectionOrder === 1 || protectionOrder === 3) && !loggedIn) { send('530 Login first'); } else { if (!rejectClearProtection) { privateData = false; protectionSet = true; } send(rejectClearProtection ? '534 Clear rejected' : '200 Clear'); } }
              else if (cmd === 'NOOP') { sawNoop = true; if (pendingSend) { const deliver = pendingSend; pendingSend = null; deliver(); } setTimeout(() => send(rejectNoop ? '500 NOOP rejected' : '200 OK'), noopDelay); }
              else if (cmd === 'TYPE I') send('200 Binary');
              else if (cmd === 'TYPE A') send('200 ASCII');
              else if (cmd === 'MODE Z') { compressed = true; send('200 Compressed'); }
              else if (cmd === 'MODE S') { compressed = false; send('200 Stream'); }
              else if (cmd === 'SIZE sample') send('213 ' + (uploaded || Buffer.from([0,10,13,255,65,66])).length);
              else if (cmd.startsWith('REST ')) { restartOffset = Number(cmd.slice(5)); send('350 Restart accepted'); }
              else if (cmd.startsWith('EPRT ')) { const parts = cmd.slice(5).split('|'); dataSocket = null; active = {host:parts[2], port:Number(parts[3])}; send('200 Active'); }
              else if (cmd === 'EPSV') {
                dataSocket = null;
                dataServer = privateData ? tls.createServer({key:dataKey, cert:dataCert, ca:clientCA, ticketKeys:dataTicketKeys, ...tlsVersions, requestCert:!!clientCA, rejectUnauthorized:!!clientCA}, setupDataSocket) : net.createServer(setupDataSocket);
                dataServer.on('error', () => {});
                dataServer.listen(0, '127.0.0.1', () => send('229 Extended (|||' + dataServer.address().port + '|)'));
              } else if (cmd === 'NLST' || cmd === 'RETR sample') {
                sawNoop = false;
                pending = cmd === 'NLST' ? Buffer.from(implicitTLS ? 'encrypted-file\r\n' : 'protected-file\r\n') : (uploaded || Buffer.from([0,10,13,255,65,66]));
                if (!active || !delayedPreliminary) send('150 Opening');
                if (active) beginActive(); else sendData();
              } else if (cmd === 'STOR sample') {
                chunks = []; pending = 'upload';
                if (!active || !delayedPreliminary) send('150 Opening');
                if (active) beginActive();
              } else send('500 Unknown');
            }
          }
          if (implicitTLS) {
            stream = new tls.TLSSocket(raw, {isServer:true, secureContext:context, requestCert:!!clientCA, rejectUnauthorized:!!clientCA});
            stream.on('error', () => {}); stream.on('secure', () => { secure = true; send('220 Ready'); });
            stream.on('data', onData);
          } else { raw.on('data', onData); send('220 Ready'); }
          raw.on('close', () => { if (dataServer) dataServer.close(); if (!failFirstTransfer || connectionNumber >= 2) server.close(); });
        });
        server.listen(0, '127.0.0.1', () => console.log(server.address().port));
        """#
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: nodeExecutable)
        process.arguments = ["-e", script, key, cert, rejectAuth ? "1" : "0", rejectProtection ? "1" : "0", badDataCertificate ? dataKey : key, badDataCertificate ? dataCert : cert, stallHandshake ? "1" : "0", trickleHandshake ? "1" : "0", implicitTLS ? "1" : "0", initialRemoteData?.base64EncodedString() ?? "-", String(expectedUploadByteCount), requireClientCertificate ? clientCert : "-", preliminaryAfterTLS ? "1" : "0", rejectClearProtection ? "1" : "0", requireSessionReuse ? "1" : "0", String(protectionOrder), String(transferDelayMS), String(noopDelayMS), rejectNoop ? "1" : "0", distinctDataTickets ? "1" : "0", reuseTLS13 ? "1" : "0", failFirstTransfer ? "1" : "0"]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        let exited = self.exited
        process.terminationHandler = { _ in exited.signal() }
        try process.run()
        var pollDescriptor = pollfd(fd: output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
        guard poll(&pollDescriptor, 1, 10_000) > 0 else {
            if process.isRunning { process.terminate() }
          if exited.wait(timeout: .now() + 2) == .timedOut { _ = kill(process.processIdentifier, SIGKILL) }
          try? FileManager.default.removeItem(at: folder)
          throw POSIXError(.ETIMEDOUT)
        }
        let first = output.fileHandleForReading.availableData
        guard let number = Int(String(decoding: first, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) else {
          if process.isRunning { process.terminate() }
          if exited.wait(timeout: .now() + 2) == .timedOut { _ = kill(process.processIdentifier, SIGKILL) }
          try? FileManager.default.removeItem(at: folder)
            throw POSIXError(.EIO)
        }
        port = number
        initialized = true
    }

    func stop() {
        if process.isRunning { process.terminate() }
      if exited.wait(timeout: .now() + 2) == .timedOut {
        _ = kill(process.processIdentifier, SIGKILL)
        if exited.wait(timeout: .now() + 2) == .timedOut {
          Issue.record("Explicit FTPS test server did not exit")
        }
      }
        try? FileManager.default.removeItem(at: folder)
    }

}

private actor FTPSProgressGate {
  private var continuation: CheckedContinuation<Void, Never>?
  private var released = false
  func wait() async {
    if released { return }
    await withCheckedContinuation { continuation = $0 }
  }
  func release() {
    released = true
    continuation?.resume()
    continuation = nil
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func transferMetricsCanBeReadDuringStreamingOperations() async throws {
  let server = try ExplicitFTPTestServer()
  defer { server.stop() }
  let channel = FTPControlChannel()
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS,
    connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root])
  try await channel.connect(configuration: config)
  try await channel.login()
  let payload = Data((0..<100_123).map { UInt8(truncatingIfNeeded: $0) })
  let (stream, producer) = AsyncThrowingStream<Data, Error>.makeStream()
  let upload = Task { try await channel.uploadStream(remotePath: "sample", source: stream) }
  producer.yield(Data(payload.prefix(1024)))
  let deadline = ContinuousClock.now.advanced(by: .seconds(5))
  while (await channel.transferMetrics()).sentBytes < 1024 && ContinuousClock.now < deadline {
    try await Task.sleep(nanoseconds: 10_000_000)
  }
  let uploading = await channel.transferMetrics()
  #expect(uploading.activeDirection == .upload)
  #expect(uploading.sentBytes == 1024 && uploading.lastUploadSucceeded == nil)
  producer.yield(Data(payload.dropFirst(1024)))
  producer.finish()
  try await upload.value
  let uploaded = await channel.transferMetrics()
  #expect(uploaded.activeDirection == nil && uploaded.sentBytes == UInt64(payload.count))
  #expect(uploaded.lastUploadSucceeded == true)
  let gate = FTPSProgressGate()
  let (events, signal) = AsyncStream<Void>.makeStream()
  let download = Task {
    try await channel.downloadStream(remotePath: "sample") { _ in
      signal.yield(())
      await gate.wait()
    }
  }
  let observed = await withTaskGroup(of: Bool.self, returning: Bool.self) { group in
    group.addTask { var iterator = events.makeAsyncIterator(); return await iterator.next() != nil }
    group.addTask { try? await Task.sleep(nanoseconds: 5_000_000_000); return false }
    let first = await group.next() ?? false
    group.cancelAll()
    return first
  }
  guard observed else {
    download.cancel()
    await gate.release()
    _ = try? await download.value
    Issue.record("Download produced no data within the deadline")
    return
  }
  let downloading = await channel.transferMetrics()
  #expect(downloading.activeDirection == .download)
  #expect(downloading.receivedBytes > 0 && downloading.lastDownloadSucceeded == nil)
  #expect(downloading.sentBytes == UInt64(payload.count) && downloading.lastUploadSucceeded == true)
  await gate.release()
  try await download.value
  let completed = await channel.transferMetrics()
  #expect(completed.receivedBytes == UInt64(payload.count) && completed.lastDownloadSucceeded == true)
  #expect(completed.activeDirection == nil)
  signal.finish()
  await channel.disconnect()
}

@Test(.enabled(if: nodeExecutable != nil)) func explicitFTPSUpgradesAndProtectsData() async throws {
    let server = try ExplicitFTPTestServer()
    defer { server.stop() }
    let channel = FTPControlChannel()
    let configuration = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root])
    try await channel.connect(configuration: configuration)
    try await channel.login()
    #expect(await channel.isAuthenticated)
    let session = try #require(try await channel.tlsSessionInfo())
    #expect(["TLS 1.2", "TLS 1.3"].contains(session.protocolVersion))
    #expect(!session.cipherSuite.isEmpty)
    #expect(session.serverCertificateDER == server.root)
    #expect(session.chainValidationRequired)
    #expect(try await channel.listNames() == ["protected-file"])
    #expect(try await channel.retrieveFileData(remotePath: "sample") == Data([0,10,13,255,65,66]))
    let payload = Data((0..<100_123).map { UInt8(truncatingIfNeeded: $0) })
    do { try await channel.storeFileData(payload, remotePath: "sample") }
    catch { Issue.record("Explicit FTPS upload failed: \(error)"); throw error }
    do { #expect(try await channel.retrieveFileData(remotePath: "sample") == payload) }
    catch { Issue.record("Explicit FTPS re-download failed: \(error)"); throw error }
    try await channel.noop()
    await channel.disconnect()
    #expect(try await channel.tlsSessionInfo() == nil)
}

@Test(.enabled(if: nodeExecutable != nil)) func retriedFTPSDownloadsReestablishProtectedSessions() async throws {
  for (implicit, active) in [(false, false), (true, true)] {
    let server = try ExplicitFTPTestServer(implicitTLS: implicit, requireSessionReuse: true, failFirstTransfer: true)
    defer { server.stop() }
    let target = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: target) }
    try Data("existing".utf8).write(to: target)
    let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret",
      security: implicit ? .implicitTLS : .explicitTLS, dataConnectionMode: active ? .active : .passive,
      enableTLSSessionResumption: true, connectTimeout: 10, readTimeout: 10,
      trustedRootCertificates: [server.root], pinnedPublicKeyHashes: [server.publicKeyPin], maximumTLSVersion: .tls12)
    try await FTPDownloadRetry.download(configuration: config, remotePath: "/sample", destination: target,
      retryPolicy: FTPRetryPolicy(maximumAttempts: 2, initialDelay: 0, maximumDelay: 0))
    #expect(try Data(contentsOf: target) == Data([0,10,13,255,65,66]))
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func transferKeepAliveHandlesConcurrentCompletionAndNOOPReplies() async throws {
  for (implicit, noopDelay) in [(false, 0), (true, 0), (false, 350)] {
    let server = try ExplicitFTPTestServer(implicitTLS: implicit, transferDelayMS: -1, noopDelayMS: noopDelay)
    defer { server.stop() }
    let channel = FTPControlChannel()
    await channel.setSessionLogging(true)
    let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret",
      security: implicit ? .implicitTLS : .explicitTLS, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root],
      transferKeepAliveInterval: 0.05)
    try await channel.connect(configuration: config)
    try await channel.login()
    #expect(try await channel.retrieveFileData(remotePath: "sample") == Data([0,10,13,255,65,66]))
    #expect(await channel.lastReply?.code == 226)
    let log = await channel.sessionLog()
    #expect(log.contains("> NOOP"))
    if noopDelay > 0 {
      let completion = try #require(log.range(of: "< 226 Complete"))
      let noop = try #require(log.range(of: "< 200 OK", options: .backwards))
      #expect(completion.lowerBound < noop.lowerBound)
    }
    try await channel.noop()
    await channel.disconnect()
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func cancellingTransferStopsKeepAlive() async throws {
  let server = try ExplicitFTPTestServer(transferDelayMS: 3000, noopDelayMS: 1000)
  defer { server.stop() }
  let channel = FTPControlChannel()
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS,
    connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root], transferKeepAliveInterval: 0.05)
  try await channel.connect(configuration: config)
  try await channel.login()
  let task = Task { try await channel.retrieveFileData(remotePath: "sample") }
  try await Task.sleep(nanoseconds: 200_000_000)
  task.cancel()
  await #expect(throws: CancellationError.self) { try await task.value }
  #expect(!(await channel.isConnected))
}

@Test(.enabled(if: nodeExecutable != nil)) func cancellingTransferWhileKeepAliveReplyPending() async throws {
  let server = try ExplicitFTPTestServer(transferDelayMS: -1, noopDelayMS: 4000)
  defer { server.stop() }
  let channel = FTPControlChannel()
  await channel.setSessionLogging(true)
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS,
    connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root], transferKeepAliveInterval: 0.05)
  try await channel.connect(configuration: config)
  try await channel.login()
  let task = Task { try await channel.retrieveFileData(remotePath: "sample") }
  let deadline = ContinuousClock.now.advanced(by: .seconds(3))
  while !(await channel.sessionLog()).contains("< 226 Complete") && ContinuousClock.now < deadline {
    try await Task.sleep(nanoseconds: 20_000_000)
  }
  #expect((await channel.sessionLog()).contains("< 226 Complete"))
  let start = ContinuousClock.now
  task.cancel()
  await #expect(throws: CancellationError.self) { try await task.value }
  #expect(start.duration(to: .now) < .seconds(2))
  #expect(!(await channel.isConnected))
}

@Test(.enabled(if: nodeExecutable != nil)) func transferKeepAliveFailureClosesConnection() async throws {
  let server = try ExplicitFTPTestServer(transferDelayMS: 500, rejectNoop: true)
  defer { server.stop() }
  let channel = FTPControlChannel()
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS,
    connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root], transferKeepAliveInterval: 0.05)
  try await channel.connect(configuration: config)
  try await channel.login()
  await #expect(throws: FTPError.serverReply(code: 500, message: "500 NOOP rejected")) { try await channel.retrieveFileData(remotePath: "sample") }
  #expect(!(await channel.isConnected))
}

@Test(.enabled(if: nodeExecutable != nil)) func transferKeepAliveIsDisabledByDefault() async throws {
  let server = try ExplicitFTPTestServer(transferDelayMS: 150)
  defer { server.stop() }
  let channel = FTPControlChannel()
  await channel.setSessionLogging(true)
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS,
    connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root])
  try await channel.connect(configuration: config)
  try await channel.login()
  _ = try await channel.retrieveFileData(remotePath: "sample")
  #expect(!(await channel.sessionLog()).contains("> NOOP"))
  await channel.disconnect()
}

@Test(.enabled(if: nodeExecutable != nil)) func transferKeepAliveCoversStreamAndFileTransfers() async throws {
  let server = try ExplicitFTPTestServer(transferDelayMS: 200)
  defer { server.stop() }
  let channel = FTPControlChannel()
  await channel.setSessionLogging(true)
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS,
    connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root], bandwidthThrottleUp: 250_000, transferKeepAliveInterval: 0.05)
  try await channel.connect(configuration: config)
  try await channel.login()
  let payload = Data((0..<100_123).map { UInt8(truncatingIfNeeded: $0) })
  let stream = AsyncThrowingStream<Data, Error> { continuation in
    Task {
      do {
        try await Task.sleep(nanoseconds: 200_000_000)
        continuation.yield(payload)
        continuation.finish()
      } catch { continuation.finish(throwing: error) }
    }
  }
  try await channel.uploadStream(remotePath: "sample", source: stream)
  #expect(await channel.lastReply?.code == 226)
  let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: folder) }
  let source = folder.appendingPathComponent("source")
  let destination = folder.appendingPathComponent("destination")
  try payload.write(to: source)
  try await channel.uploadFile(from: source, remotePath: "sample")
  try await channel.downloadFile(remotePath: "sample", to: destination)
  #expect(try Data(contentsOf: destination) == payload)
  #expect((await channel.sessionLog()).components(separatedBy: "> NOOP").count > 3)
  try await channel.noop()
  await channel.disconnect()
}

@Test(.enabled(if: nodeExecutable != nil)) func strictFTPSServerRejectsFreshDataSession() async throws {
  let server = try ExplicitFTPTestServer(requireSessionReuse: true)
  defer { server.stop() }
  let channel = FTPControlChannel()
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 2, readTimeout: 2, trustedRootCertificates: [server.root], maximumTLSVersion: .tls12)
  try await channel.connect(configuration: config)
  try await channel.login()
  await #expect(throws: FTPError.self) { try await channel.listNames() }
}

@Test(.enabled(if: nodeExecutable != nil)) func strictFTPSSessionReuse() async throws {
  for (implicit, active) in [(false, false), (false, true), (true, false), (true, true)] {
    let server = try ExplicitFTPTestServer(implicitTLS: implicit, requireSessionReuse: true)
    defer { server.stop() }
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: implicit ? .implicitTLS : .explicitTLS,
      dataConnectionMode: active ? .active : .passive, enableTLSSessionResumption: true,
      connectTimeout: 3, readTimeout: 3, trustedRootCertificates: [server.root], maximumTLSVersion: .tls12)
    do {
      try await channel.connect(configuration: config)
      try await channel.login()
      #expect(try await channel.listNames() == [implicit ? "encrypted-file" : "protected-file"])
      #expect(try await channel.retrieveFileData(remotePath: "sample") == Data([0,10,13,255,65,66]))
      await channel.disconnect()
    } catch {
      Issue.record("Session reuse failed implicit=\(implicit), active=\(active): \(error)")
      throw error
    }
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func strictFTPSResumptionSupportsStagedUpgradeAndMutualTLS() async throws {
  let server = try ExplicitFTPTestServer(requireClientCertificate: true, requireSessionReuse: true)
  defer { server.stop() }
  let channel = FTPControlChannel()
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret",
    enableTLSSessionResumption: true, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root],
    clientIdentity: server.clientIdentity, pinnedPublicKeyHashes: [server.publicKeyPin],
    certificateRequirements: [.init(field: .subjectCN, pattern: "localhost")], maximumTLSVersion: .tls12)
  try await channel.connect(configuration: config)
  try await channel.convertToTLS()
  try await channel.login()
  #expect(try await channel.listNames() == ["protected-file"])
  #expect(try await channel.retrieveFileData(remotePath: "sample") == Data([0,10,13,255,65,66]))
  await channel.disconnect()
}

@Test(.enabled(if: nodeExecutable != nil)) func strictFTPSResumptionTLS13() async throws {
  let server = try ExplicitFTPTestServer(requireSessionReuse: true, reuseTLS13: true)
  defer { server.stop() }
  let channel = FTPControlChannel()
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS,
    enableTLSSessionResumption: true, connectTimeout: 3, readTimeout: 3, trustedRootCertificates: [server.root],
    minimumTLSVersion: .tls13, maximumTLSVersion: .tls13)
  await #expect(throws: FTPError.notImplemented(feature: "TLS 1.3 with FTPS session reuse")) {
    try await channel.connect(configuration: config)
  }
  #expect(!(await channel.isConnected))
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpsResumptionStillRejectsInvalidFreshDataCertificate() async throws {
  let server = try ExplicitFTPTestServer(badDataCertificate: true, distinctDataTickets: true)
  defer { server.stop() }
  let channel = FTPControlChannel()
  let otherRoot = try #require(server.dataRoot)
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS,
    enableTLSSessionResumption: true, connectTimeout: 3, readTimeout: 3, trustedRootCertificates: [server.root, otherRoot],
    maximumTLSVersion: .tls12)
  try await channel.connect(configuration: config)
  try await channel.login()
  await #expect(throws: FTPError.self) { try await channel.listNames() }
  #expect(!(await channel.isConnected))
}

@Test(.enabled(if: nodeExecutable != nil)) func strictFTPSFixtureAcceptsRealResumption() throws {
    let node = try #require(nodeExecutable)
    let server = try ExplicitFTPTestServer(implicitTLS: true, requireSessionReuse: true)
    defer { server.stop() }
    let script = #"""
    const tls = require('tls');
    const port = Number(process.argv[1]), cert = Buffer.from(process.argv[2], 'base64').toString('base64').match(/.{1,64}/g).join('\n');
    const ca = '-----BEGIN CERTIFICATE-----\n' + cert + '\n-----END CERTIFICATE-----\n';
    const opts = {host:'127.0.0.1', servername:'localhost', ca, minVersion:'TLSv1.2', maxVersion:'TLSv1.2'};
    const control = tls.connect({...opts,port}); let input='', stage=0, data, payload='';
    const fail = err => { console.error(String(err)); process.exit(1); };
    control.on('error', fail);
    control.on('data', chunk => {
      input += chunk.toString();
      while (input.includes('\r\n')) {
        const end=input.indexOf('\r\n'), line=input.slice(0,end); input=input.slice(end+2);
        if (stage===0 && line.startsWith('220 ')) { stage++; control.write('PBSZ 0\r\n'); }
        else if (stage===1 && line.startsWith('200 ')) { stage++; control.write('PROT P\r\n'); }
        else if (stage===2 && line.startsWith('200 ')) { stage++; control.write('USER demo\r\n'); }
        else if (stage===3 && line.startsWith('331 ')) { stage++; control.write('PASS secret\r\n'); }
        else if (stage===4 && line.startsWith('230 ')) { stage++; control.write('EPSV\r\n'); }
        else if (stage===5 && line.startsWith('229 ')) {
          const match=line.match(/\(\|\|\|(\d+)\|\)/); if(!match) return fail('bad EPSV');
          const session=control.getSession(); if(!session) return fail('missing TLS session');
          data=tls.connect({...opts,port:Number(match[1]),session}, () => { if(!data.isSessionReused()) fail('not resumed'); });
          data.on('error',fail); data.on('data',chunk=>payload+=chunk.toString());
          stage++; control.write('NLST\r\n');
        } else if (stage===6 && line.startsWith('150 ')) { stage++; }
        else if (stage===7 && line.startsWith('226 ')) { if(payload!=='encrypted-file\r\n') return fail('incorrect data'); console.log('resumed'); control.destroy(); }
        else if (/^[45]/.test(line)) return fail(line);
      }
    });
    setTimeout(() => fail('timeout'), 5000).unref();
    """#
    let process = Process(), output = Pipe(), errors = Pipe(), exited = DispatchSemaphore(value: 0)
    process.executableURL = URL(fileURLWithPath: node)
    process.arguments = ["-e", script, String(server.port), server.root.base64EncodedString()]
    process.standardOutput = output
    process.standardError = errors
    process.terminationHandler = { _ in exited.signal() }
    try process.run()
    if exited.wait(timeout: .now() + 10) == .timedOut {
        process.terminate()
        throw POSIXError(.ETIMEDOUT)
    }
    let diagnostic = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    #expect(process.terminationStatus == 0, "Node TLS resumption test: \(diagnostic)")
    #expect(String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self).contains("resumed"))
}

@Test(.enabled(if: nodeExecutable != nil)) func explicitFTPSRejectsBadCertificatesAndAuth() async throws {
    for mode in 0..<3 {
        let server = try ExplicitFTPTestServer(rejectAuth: mode == 2)
        defer { server.stop() }
        let channel = FTPControlChannel()
        let configuration = FTPClientConfiguration(host: mode == 1 ? "127.0.0.1" : "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: mode == 0 ? [] : [server.root])
        await #expect(throws: FTPError.self) { try await channel.connect(configuration: configuration) }
        #expect(await channel.isConnected == false)
    }
}

@Test(.enabled(if: nodeExecutable != nil)) func explicitFTPSRejectsUnprotectedData() async throws {
    let server = try ExplicitFTPTestServer(rejectProtection: true)
    defer { server.stop() }
    let channel = FTPControlChannel()
    let configuration = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root])
    await #expect(throws: FTPError.serverReply(code: 534, message: "534 Rejected")) { try await channel.connect(configuration: configuration) }
    #expect(await channel.isConnected == false)
}

@Test(.enabled(if: nodeExecutable != nil)) func explicitFTPSRejectsWrongDataIdentity() async throws {
  let server = try ExplicitFTPTestServer(badDataCertificate: true)
  defer { server.stop() }
  let channel = FTPControlChannel()
  let root = try #require(server.dataRoot)
  let configuration = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 1, readTimeout: 3, trustedRootCertificates: [server.root, root])
  try await channel.connect(configuration: configuration)
  try await channel.login()
  await #expect(throws: FTPError.self) { try await channel.listNames() }
  #expect(await channel.isConnected == false)
}

@Test(.enabled(if: nodeExecutable != nil)) func explicitFTPSHandshakeTimeoutClosesSession() async throws {
  let server = try ExplicitFTPTestServer(stallHandshake: true)
  defer { server.stop() }
  let channel = FTPControlChannel()
  let configuration = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 3, readTimeout: 0.3, trustedRootCertificates: [server.root])
  await #expect(throws: FTPError.timeout(operation: "TLS read")) { try await channel.connect(configuration: configuration) }
  #expect(await channel.isConnected == false)
}

@Test(.enabled(if: nodeExecutable != nil)) func explicitFTPSHandshakeDeadlineRejectsSlowPeer() async throws {
  let server = try ExplicitFTPTestServer(trickleHandshake: true)
  defer { server.stop() }
  let channel = FTPControlChannel()
  let configuration = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 3, readTimeout: 0.3, trustedRootCertificates: [server.root])
  let clock = ContinuousClock()
  let start = clock.now
  await #expect(throws: FTPError.timeout(operation: "TLS read")) { try await channel.connect(configuration: configuration) }
  // The full suite starts many TLS fixtures in parallel; the deadline itself
  // remains 0.3 seconds, but scheduling and TCP setup can take longer.
  #expect(start.duration(to: clock.now) < .seconds(5))
  #expect(await channel.isConnected == false)
}

@Test(.enabled(if: nodeExecutable != nil)) func explicitFTPSHandshakeCancellationClosesSession() async throws {
  let server = try ExplicitFTPTestServer(stallHandshake: true)
  defer { server.stop() }
  let channel = FTPControlChannel()
  let configuration = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 10, readTimeout: 10, trustedRootCertificates: [server.root])
  let task = Task { try await channel.connect(configuration: configuration) }
  try await Task.sleep(for: .milliseconds(200))
  #expect(await channel.isConnected == false)
  let clock = ContinuousClock()
  let start = clock.now
  task.cancel()
  await #expect(throws: CancellationError.self) { try await task.value }
  #expect(start.duration(to: clock.now) < .seconds(3))
  #expect(await channel.isConnected == false)
}

@Test(.enabled(if: nodeExecutable != nil)) func activeFTPSProtectsBothTransferDirections() async throws {
  for implicit in [false, true] {
    let server = try ExplicitFTPTestServer(implicitTLS: implicit, preliminaryAfterTLS: true)
    defer { server.stop() }
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: implicit ? .implicitTLS : .explicitTLS, dataConnectionMode: .active, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root])
    try await channel.connect(configuration: config)
    try await channel.login()
    #expect(try await channel.listNames() == [implicit ? "encrypted-file" : "protected-file"])
    let payload = Data((0..<100_123).map { UInt8(truncatingIfNeeded: $0) })
    try await channel.storeFileData(payload, remotePath: "sample")
    #expect(try await channel.retrieveFileData(remotePath: "sample") == payload)
    await channel.disconnect()
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func activeFTPSRejectsWrongDataCertificate() async throws {
  let server = try ExplicitFTPTestServer(badDataCertificate: true)
  defer { server.stop() }
  let channel = FTPControlChannel()
  let otherRoot = try #require(server.dataRoot)
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, dataConnectionMode: .active, connectTimeout: 2, readTimeout: 2, trustedRootCertificates: [server.root, otherRoot])
  try await channel.connect(configuration: config)
  try await channel.login()
  await #expect(throws: FTPError.self) { try await channel.listNames() }
  #expect(await channel.isConnected == false)
}

@Test(.enabled(if: nodeExecutable != nil)) func explicitFTPSDataProtectionNegotiation() async throws {
  for (rejectClear, active) in [(false, false), (false, true), (true, false)] {
    let server = try ExplicitFTPTestServer(preliminaryAfterTLS: active, rejectClearProtection: rejectClear)
    defer { server.stop() }
    let channel = FTPControlChannel()
    await channel.setSessionLogging(true)
    let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, dataConnectionMode: active ? .active : .passive, dataProtection: .clear, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root])
    try await channel.connect(configuration: config)
    await #expect(throws: FTPError.invalidState(description: "FTPS data protection requires authentication")) { try await channel.listNames() }
    try await channel.login()
    #expect(try await channel.listNames() == ["protected-file"])
    let log = await channel.sessionLog()
    #expect(log.contains("> PROT C"))
    #expect(log.contains("> PROT P") == rejectClear)
    await channel.disconnect()
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpsNegotiatesProtectionBeforeOrAfterLogin() async throws {
  for implicit in [false, true] {
    for order in [1, 2, 3, 4] {
      let server = try ExplicitFTPTestServer(implicitTLS: implicit, rejectClearProtection: order == 4, protectionOrder: order)
      defer { server.stop() }
      let channel = FTPControlChannel()
      await channel.setSessionLogging(true)
      let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: implicit ? .implicitTLS : .explicitTLS, dataProtection: order == 4 ? .clear : .privateData, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root])
      try await channel.connect(configuration: config)
      let beforeLogin = await channel.sessionLog()
      #expect(beforeLogin.contains("> PBSZ 0"))
      #expect(!beforeLogin.contains("> USER"))
      if order == 2 { #expect(beforeLogin.contains("> PROT P")) }
      if order == 1 { #expect(!beforeLogin.contains("> PROT P")) }
      await #expect(throws: FTPError.invalidState(description: "FTPS data protection requires authentication")) { try await channel.listNames() }
      try await channel.login()
      #expect(try await channel.listNames() == [implicit ? "encrypted-file" : "protected-file"])
      let log = await channel.sessionLog()
      #expect(log.components(separatedBy: "> PBSZ 0").count == (order == 2 ? 2 : 3))
      if order == 4 { #expect(log.components(separatedBy: "> PROT P").count == 3) }
      await channel.disconnect()
    }
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpsFailsWhenDeferredProtectionIsRejected() async throws {
  let server = try ExplicitFTPTestServer(rejectProtection: true, protectionOrder: 1)
  defer { server.stop() }
  let channel = FTPControlChannel()
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root])
  try await channel.connect(configuration: config)
  await #expect(throws: FTPError.serverReply(code: 534, message: "534 Rejected")) { try await channel.login() }
  #expect(!(await channel.isConnected))
  #expect(!(await channel.isAuthenticated))
}

@Test(.enabled(if: nodeExecutable != nil)) func stagedTLSUpgradeDefersProtectionUntilLogin() async throws {
  let server = try ExplicitFTPTestServer(protectionOrder: 3)
  defer { server.stop() }
  let channel = FTPControlChannel()
  await channel.setSessionLogging(true)
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root])
  try await channel.connect(configuration: config)
  try await channel.convertToTLS()
  #expect((await channel.sessionLog()).contains("> PROT P"))
  try await channel.login()
  #expect(try await channel.listNames() == ["protected-file"])
  #expect((await channel.sessionLog()).components(separatedBy: "> PBSZ 0").count == 3)
  await channel.disconnect()
}

@Test(.enabled(if: nodeExecutable != nil)) func explicitFTPSFailsWhenBothProtectionModesAreRejected() async throws {
  let server = try ExplicitFTPTestServer(rejectProtection: true, rejectClearProtection: true)
  defer { server.stop() }
  let channel = FTPControlChannel()
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, dataProtection: .clear, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root])
  await #expect(throws: FTPError.serverReply(code: 534, message: "534 Rejected")) { try await channel.connect(configuration: config) }
  #expect(await channel.isConnected == false)
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpsEnforcesSPKIPinsAndHostnameWithoutChainValidation() async throws {
  for mode in 0..<4 {
    let server = try ExplicitFTPTestServer()
    defer { server.stop() }
    let channel = FTPControlChannel()
    let pins = mode == 1 ? ["sha256/" + Data(repeating: 0, count: 32).base64EncodedString()] : [server.publicKeyPin]
    let config = FTPClientConfiguration(host: mode == 3 ? "127.0.0.1" : "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: mode < 2 ? [server.root] : [], requireServerCertificateValidation: mode < 2, pinnedPublicKeyHashes: pins)
    if mode == 0 || mode == 2 {
      try await channel.connect(configuration: config)
      try await channel.login()
      #expect(try await channel.listNames() == ["protected-file"])
      await channel.disconnect()
    } else {
      await #expect(throws: FTPError.self) { try await channel.connect(configuration: config) }
      #expect(await channel.isConnected == false)
    }
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpsChecksControlCertificateRequirements() async throws {
  let all: [FTPCertificateRequirement] = [
    .init(field: .subjectCN, pattern: "local*"),
    .init(field: .issuerCN, pattern: "localhost"),
    .init(field: .subjectDN, pattern: "*CN=localhost*"),
    .init(field: .issuerDN, pattern: "*CN=localhost*"),
    .init(field: .subjectAlternativeName, pattern: "localhost"),
  ]
  for implicit in [false, true] {
    let server = try ExplicitFTPTestServer(badDataCertificate: true, dataCertificateSameSAN: true, implicitTLS: implicit)
    defer { server.stop() }
    let channel = FTPControlChannel()
    let otherRoot = try #require(server.dataRoot)
    let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: implicit ? .implicitTLS : .explicitTLS, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root, otherRoot], certificateRequirements: all)
    try await channel.connect(configuration: config)
    try await channel.login()
    // The data certificate has a different subject CN but a valid localhost SAN.
    #expect(try await channel.listNames() == [implicit ? "encrypted-file" : "protected-file"])
    await channel.disconnect()
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpsRejectsMismatchedCertificateRequirementsBeforeLogin() async throws {
  for implicit in [false, true] {
    for field in [FTPCertificateRequirement.Field.subjectCN, .issuerCN, .subjectDN, .issuerDN, .subjectAlternativeName] {
      let server = try ExplicitFTPTestServer(implicitTLS: implicit)
      defer { server.stop() }
      let channel = FTPControlChannel()
      await channel.setSessionLogging(true)
      let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: implicit ? .implicitTLS : .explicitTLS, connectTimeout: 1, readTimeout: 5, trustedRootCertificates: [server.root], certificateRequirements: [.init(field: .subjectCN, pattern: "localhost"), .init(field: field, pattern: "LOCALHOST")])
      await #expect(throws: FTPError.self) {
        try await channel.connect(configuration: config)
      }
      #expect(await channel.isConnected == false)
      #expect(!(await channel.sessionLog()).contains("> USER"))
    }
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpsUsesPKCS12ClientIdentity() async throws {
  let server = try ExplicitFTPTestServer(requireClientCertificate: true)
  defer { server.stop() }
  let channel = FTPControlChannel()
  let identity = try #require(server.clientIdentity)
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root], clientIdentity: identity)
  try await channel.connect(configuration: config)
  try await channel.login()
  #expect(try await channel.listNames() == ["protected-file"])
  await channel.disconnect()
}

@Test(.enabled(if: nodeExecutable != nil)) func pkcs12ImportsWithoutPersistentKeychainWrites() async throws {
  let server = try ExplicitFTPTestServer(requireClientCertificate: true, includeLegacyP12: true)
  defer { server.stop() }
  let source = try #require(server.clientIdentity)
  let legacySource = try #require(server.legacyClientIdentity)
  for identitySource in [source, legacySource] {
    let directory: URL
    do {
      let legacy = try FTPImportedIdentity.loadLegacyMacOSIdentity(identitySource)
      directory = try #require(legacy.temporaryKeychainDirectory)
      #expect(FileManager.default.fileExists(atPath: directory.path))
      var certificate: SecCertificate?
      var key: SecKey?
      #expect(SecIdentityCopyCertificate(legacy.identity, &certificate) == errSecSuccess)
      #expect(SecIdentityCopyPrivateKey(legacy.identity, &key) == errSecSuccess)
      #expect(certificate != nil && key != nil)
      let privateKey = try #require(key)
      let publicKey = try #require(SecKeyCopyPublicKey(privateKey))
      let message = Data("temporary identity verification".utf8)
      var signingError: Unmanaged<CFError>?
      let signature = try #require(SecKeyCreateSignature(privateKey, .rsaSignatureMessagePKCS1v15SHA256, message as CFData, &signingError))
      #expect(SecKeyVerifySignature(publicKey, .rsaSignatureMessagePKCS1v15SHA256, message as CFData, signature, nil))
      withExtendedLifetime(legacy) {}
    }
    #expect(!FileManager.default.fileExists(atPath: directory.path))
  }
  var wrong = legacySource
  wrong.passphrase = "incorrect"
  #expect(throws: FTPError.self) { try FTPImportedIdentity.loadLegacyMacOSIdentity(wrong) }
  #expect(throws: FTPError.self) { try FTPImportedIdentity.load(wrong) }
  let successes = await withTaskGroup(of: Bool.self, returning: Int.self) { group in
    for _ in 0..<8 { group.addTask { (try? FTPImportedIdentity.load(source)) != nil } }
    var count = 0
    for await success in group where success { count += 1 }
    return count
  }
  #expect(successes == 8)
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpsUsesPEMClientIdentities() async throws {
  let cases: [(curve: String?, format: Int, implicit: Bool, active: Bool)] = [
    (nil, 0, false, false), (nil, 1, true, false), (nil, 2, false, true),
    ("prime256v1", 0, false, false), ("prime256v1", 1, true, false),
    ("secp384r1", 2, false, true), ("secp521r1", 1, false, true), ("secp521r1", 1, true, false)
  ]
  for item in cases {
    let server = try ExplicitFTPTestServer(implicitTLS: item.implicit, requireClientCertificate: true, clientCurve: item.curve)
    defer { server.stop() }
    let certificate = try #require(server.clientCertificatePEM)
    let key = try #require(item.format == 0 ? server.clientPrivatePEM : (item.format == 1 ? server.encryptedClientPrivatePEM : server.traditionalClientPrivatePEM))
    let pem = certificate + key
    let password = item.format == 1 ? "testing" : ""
    let facade = FTPClientFacade()
    facade.hostname = "localhost"
    facade.port = server.port
    facade.username = "demo"
    facade.password = "secret"
    facade.authTls = !item.implicit
    facade.implicitTls = item.implicit
    if item.curve == "secp521r1" && item.implicit { facade.maximumTLSVersion = .tls12 }
    facade.passive = !item.active
    facade.trustedRootCertificates = [server.root]
    do {
      if item.format == 2 {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: file) }
        try pem.write(to: file)
        try facade.setSslClientCertPem(pemDataOrFilename: file.path, pemPassword: password)
      } else {
        try facade.setSslClientCertPem(pemDataOrFilename: try #require(String(data: pem, encoding: .utf8)), pemPassword: password)
      }
      try await facade.connect()
      #expect(try await facade.nlst() == [item.implicit ? "encrypted-file" : "protected-file"])
      await facade.disconnect()
    } catch {
      Issue.record("PEM case curve=\(item.curve ?? "RSA"), format=\(item.format), implicit=\(item.implicit), active=\(item.active): \(error)")
      throw error
    }
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func pemIdentityRejectsWrongPasswordAndMismatchedCertificates() throws {
  let server = try ExplicitFTPTestServer(requireClientCertificate: true)
  defer { server.stop() }
  let certificate = try #require(server.clientCertificatePEM)
  let key = try #require(server.clientPrivatePEM)
  let encrypted = try #require(server.encryptedClientPrivatePEM)
  #expect(throws: FTPError.self) { try FTPClientIdentity(pemData: certificate + encrypted, passphrase: "incorrect") }
  let otherCertificate = Data("-----BEGIN CERTIFICATE-----\n\(server.root.base64EncodedString())\n-----END CERTIFICATE-----\n".utf8)
  #expect(throws: FTPError.self) { try FTPClientIdentity(pemData: otherCertificate + key) }
  #expect(throws: FTPError.self) { try FTPClientIdentity(pemData: certificate) }
  #expect(throws: FTPError.self) { try FTPClientIdentity(pemData: certificate + key + key) }
  #expect(throws: FTPError.self) { try FTPClientIdentity(pemData: Data(repeating: 65, count: 8_388_609)) }
  let facade = FTPClientFacade()
  try facade.setSslClientCertPem(pemDataOrFilename: try #require(String(data: certificate + key, encoding: .utf8)), pemPassword: "")
  let original = facade.clientIdentity
  #expect(throws: FTPError.self) { try facade.setSslClientCertPem(pemDataOrFilename: "-----BEGIN PRIVATE KEY-----\n***\n-----END PRIVATE KEY-----", pemPassword: "") }
  #expect(facade.clientIdentity == original)
}

@Test(.enabled(if: nodeExecutable != nil)) func pemIdentitySupportsPBES2CipherAndPRFVariants() throws {
  let server = try ExplicitFTPTestServer(requireClientCertificate: true, extraPEMVariants: true)
  defer { server.stop() }
  let certificate = try #require(server.clientCertificatePEM)
  func der(_ pem: Data) throws -> Data {
    let text = try #require(String(data: pem, encoding: .utf8))
    let body = text.components(separatedBy: .newlines).filter { !$0.hasPrefix("-----") }.joined()
    return try #require(Data(base64Encoded: body))
  }
  let original = try der(#require(server.clientPrivatePEM))
  #expect(server.extraEncryptedClientKeys.count == 3)
  for (index, key) in server.extraEncryptedClientKeys.enumerated() {
    do {
      let plaintext = try FTPPEMIdentityLoader.decryptPKCS8(der(key), passphrase: "päss🔐")
      let same = plaintext == original
      #expect(same)
      let identity = try FTPClientIdentity(pemData: certificate + key, passphrase: "päss🔐")
      #expect(identity.pemData != nil)
      #expect(throws: FTPError.self) { try FTPClientIdentity(pemData: certificate + key, passphrase: "incorrect") }
    } catch {
      Issue.record("Encrypted PEM variant \(index) failed: \(error)")
      throw error
    }
  }
}


@Test(.enabled(if: nodeExecutable != nil)) func p521PKCS12MutualTLSBaseline() async throws {
  let server = try ExplicitFTPTestServer(implicitTLS: true, requireClientCertificate: true, clientCurve: "secp521r1")
  defer { server.stop() }
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .implicitTLS, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root], clientIdentity: server.clientIdentity, maximumTLSVersion: .tls12)
  let channel = FTPControlChannel()
  try await channel.connect(configuration: config)
  try await channel.login()
  #expect(try await channel.listNames() == ["encrypted-file"])
  await channel.disconnect()
}

@Test(.enabled(if: nodeExecutable != nil)) func idiomaticClientHonorsCertificateValidationConfiguration() async throws {
  for mode in 0..<3 {
    let server = try ExplicitFTPTestServer()
    defer { server.stop() }
    let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 5, readTimeout: 5, requireServerCertificateValidation: mode == 2)
    let client: FTPClient
    if mode == 1 {
      client = FTPClient(configuration: config, securityPolicy: FTPSecurityPolicy(requireServerCertificateValidation: true))
    } else if mode == 2 {
      client = FTPClient(configuration: config, securityPolicy: FTPSecurityPolicy(requireServerCertificateValidation: false))
    } else {
      client = FTPClient(configuration: config)
    }
    if mode == 1 {
      await #expect(throws: FTPError.self) { try await client.connect() }
    } else {
      try await client.connect()
      #expect(try await client.listNames() == ["protected-file"])
      await client.disconnect()
    }
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func defaultSecurityPolicyDoesNotLowerConfiguredTLSMinimum() async throws {
  let server = try ExplicitFTPTestServer(requireSessionReuse: true)
  defer { server.stop() }
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 3, readTimeout: 3, trustedRootCertificates: [server.root], minimumTLSVersion: .tls13)
  let client = FTPClient(configuration: config, securityPolicy: FTPSecurityPolicy(minimumTLSVersion: "default"))
  await #expect(throws: FTPError.self) { try await client.connect() }
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpsModeZTransfersCompressedData() async throws {
  let server = try ExplicitFTPTestServer()
  defer { server.stop() }
  let channel = FTPControlChannel()
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root])
  try await channel.connect(configuration: config)
  try await channel.login()
  try await channel.setModeZ(true)
  #expect(try await channel.listNames() == ["protected-file"])
  let payload = Data((0..<100_123).map { UInt8(truncatingIfNeeded: $0) })
  try await channel.storeFileData(payload, remotePath: "sample")
  #expect(try await channel.retrieveFileData(remotePath: "sample") == payload)
  try await channel.setModeZ(false)
  #expect(try await channel.listNames() == ["protected-file"])
  await channel.disconnect()
}

@Test(.enabled(if: nodeExecutable != nil)) func stagedAndLegacyExplicitTLSConnections() async throws {
  for staged in [false, true] {
    let server = try ExplicitFTPTestServer()
    defer { server.stop() }
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: staged ? .none : .explicitSSL, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root], minimumTLSVersion: .tls12, maximumTLSVersion: .tls12, allowedCipherSuites: ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"])
    try await channel.connect(configuration: config)
    if staged { try await channel.convertToTLS() }
    try await channel.login()
    #expect(try await channel.listNames() == ["protected-file"])
    await channel.disconnect()
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func dataChannelRejectsDifferentPinnedKey() async throws {
  let server = try ExplicitFTPTestServer(badDataCertificate: true)
  defer { server.stop() }
  let channel = FTPControlChannel()
  let dataRoot = try #require(server.dataRoot)
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 1, readTimeout: 3, trustedRootCertificates: [server.root, dataRoot], pinnedPublicKeyHashes: [server.publicKeyPin])
  try await channel.connect(configuration: config)
  try await channel.login()
  await #expect(throws: FTPError.self) { try await channel.listNames() }
  #expect(await channel.isConnected == false)
}
#endif