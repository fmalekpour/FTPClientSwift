#if os(macOS)
import Darwin
import Foundation
import Testing
import FTPClientCore
import FTPClientFacade

private func stopTestProcess(_ process: Process, exited: DispatchSemaphore) {
  if process.isRunning { process.terminate() }
  if exited.wait(timeout: .now() + 2) == .timedOut { _ = kill(process.processIdentifier, SIGKILL) }
}

final class LocalFTPProxy {
    let port: Int
    private let process = Process()
    private let exited = DispatchSemaphore(value: 0)

    init(mode: String) throws {
        guard let nodeExecutable else { throw POSIXError(.ENOENT) }
        let script = #"""
        const net = require('net'), crypto = require('crypto'); const mode = process.argv[1]; let connections = 0;
        const server = net.createServer(client => {
          const connectionNumber = ++connections;
          let data = Buffer.alloc(0), state = mode.startsWith('socks5') ? 'greeting' : (mode.startsWith('socks4') ? 'socks4' : (mode.startsWith('ntlm') ? 'ntlm' : mode));
          let ntlmNegotiate = null, ntlmChallenge = null, ntlmServerNonce = null;
          client.on('error', () => {});
          function tunnel(host, port, response) {
            client.removeListener('data', parse);
            const remote = net.createConnection(port, host === 'localhost' ? '127.0.0.1' : host);
            remote.on('error', () => client.destroy());
            remote.on('connect', () => {
              if (mode === 'socks5coalesce' && connectionNumber > 1) {
                const chunks = [];
                remote.on('data', chunk => chunks.push(chunk));
                remote.on('end', () => client.end(Buffer.concat([response, ...chunks])));
                return;
              }
              client.write(response);
              if (data.length) remote.write(data);
              client.pipe(remote); remote.pipe(client);
            });
            client.on('close', () => remote.destroy());
          }
          function parse(chunk) {
            data = Buffer.concat([data, chunk]);
            while (true) {
              if (state === 'http') {
                const end = data.indexOf('\r\n\r\n'); if (end < 0) return;
                const header = data.subarray(0, end).toString(); data = data.subarray(end + 4);
                if (!header.includes('Proxy-Authorization: Basic YWxpY2U6c2VjcmV0')) { client.end('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n'); return; }
                const target = header.split('\r\n')[0].split(' ')[1]; const i = target.lastIndexOf(':');
                tunnel(target.slice(0, i).replace(/^\[|\]$/g, ''), Number(target.slice(i + 1)), Buffer.from('HTTP/1.1 200 Connection Established\r\n\r\n')); return;
              }
              if (state === 'ntlm' || state === 'ntlm-auth') {
                const end = data.indexOf('\r\n\r\n'); if (end < 0) return;
                const header = data.subarray(0, end).toString(); data = data.subarray(end + 4);
                const match = header.match(/^Proxy-Authorization: NTLM ([A-Za-z0-9+/=]+)$/mi);
                if (!match) { client.end('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n'); return; }
                const token = Buffer.from(match[1], 'base64');
                if (token.length < 16 || token.subarray(0,8).toString('binary') !== 'NTLMSSP\0') { client.destroy(); return; }
                if (state === 'ntlm') {
                  if (token.readUInt32LE(8) !== 1) { client.destroy(); return; }
                  ntlmNegotiate = token; ntlmServerNonce = crypto.randomBytes(8);
                  const av = (id, value) => { const h = Buffer.alloc(4); h.writeUInt16LE(id,0); h.writeUInt16LE(value.length,2); return Buffer.concat([h,value]); };
                  const stamp = Buffer.alloc(8); stamp.writeBigUInt64LE(133801632000000000n);
                  const info = Buffer.concat([av(1,Buffer.from('PROXY','utf16le')),av(2,Buffer.from('Domain','utf16le')),...(mode === 'ntlm-notime' ? [] : [av(7,stamp)]),Buffer.alloc(4)]);
                  ntlmChallenge = Buffer.alloc(48); ntlmChallenge.write('NTLMSSP\0',0,'binary'); ntlmChallenge.writeUInt32LE(2,8);
                  ntlmChallenge.writeUInt32LE(0xa0888205,20); ntlmServerNonce.copy(ntlmChallenge,24);
                  ntlmChallenge.writeUInt16LE(info.length,40); ntlmChallenge.writeUInt16LE(info.length,42); ntlmChallenge.writeUInt32LE(48,44);
                  ntlmChallenge = Buffer.concat([ntlmChallenge,info]); state = 'ntlm-auth';
                  const framing = mode === 'ntlm-chunked' ? 'Transfer-Encoding: chunked\r\n\r\n3;foo=bar\r\nabc\r\n0\r\nX-Test: done\r\n\r\n' : mode === 'ntlm-badframing' ? 'Transfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n' : 'Content-Length: 3\r\n\r\nabc';
                  const response = 'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="proxy"\r\nProxy-Authenticate: NTLM ' + ntlmChallenge.toString('base64') + '\r\n' + framing;
                  client.write(response.slice(0, 37)); client.write(response.slice(37)); return;
                }
                try {
                  if (token.length < 64 || token.readUInt32LE(8) !== 3) throw Error('bad type');
                  const field = (at) => { const n=token.readUInt16LE(at), p=token.readUInt32LE(at+4); if (p+n>token.length) throw Error('bounds'); return token.subarray(p,p+n); };
                  const lm = field(12), nt = field(20), domain = field(28).toString('utf16le'), user = field(36).toString('utf16le');
                  if (user !== 'User' || domain !== 'Domain' || lm.length !== 24 || nt.length < 48) throw Error('identity');
                  const hmac = (k,b) => crypto.createHmac('md5',k).update(b).digest();
                  const responseKey = hmac(Buffer.from('a4f49c406510bdcab6824ee7c30fd852','hex'),Buffer.from('USERDomain','utf16le'));
                  const proof = hmac(responseKey,Buffer.concat([ntlmServerNonce,nt.subarray(16)]));
                  if (!crypto.timingSafeEqual(proof,nt.subarray(0,16))) throw Error('proof');
                  if (mode === 'ntlm-notime') {
                    const expectedLM = hmac(responseKey,Buffer.concat([ntlmServerNonce,lm.subarray(16)]));
                    if (!crypto.timingSafeEqual(expectedLM,lm.subarray(0,16))) throw Error('LMv2');
                  } else {
                    if (lm.some(v => v !== 0) || token.length < 88) throw Error('LM');
                    const key = hmac(responseKey,proof), receivedMIC = Buffer.from(token.subarray(72,88)), blank = Buffer.from(token); blank.fill(0,72,88);
                    const expectedMIC = hmac(key,Buffer.concat([ntlmNegotiate,ntlmChallenge,blank]));
                    if (!crypto.timingSafeEqual(receivedMIC,expectedMIC)) throw Error('MIC');
                  }
                } catch (_) { client.end('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n'); return; }
                const target = header.split('\r\n')[0].split(' ')[1], i = target.lastIndexOf(':');
                tunnel(target.slice(0,i).replace(/^\[|\]$/g,''),Number(target.slice(i+1)),Buffer.from('HTTP/1.1 200 Connection Established\r\n\r\n')); return;
              }
              if (state === 'socks4') {
                if (data.length < 9) return;
                const command = data[1];
                const userEnd = data.indexOf(0, 8); if (userEnd < 0) return;
                if (data.subarray(8, userEnd).toString() !== 'alice') { client.end(Buffer.from([0,91,0,0,0,0,0,0])); return; }
                let host = Array.from(data.subarray(4,8)).join('.'), end = userEnd + 1;
                if (host === '0.0.0.1') { const nameEnd = data.indexOf(0, end); if (nameEnd < 0) return; host = data.subarray(end,nameEnd).toString(); end = nameEnd + 1; }
                const port = data.readUInt16BE(2); data = data.subarray(end);
                if (command === 2) {
                  if (host !== '127.0.0.1' || port !== 0) { client.end(Buffer.from([0,91,0,0,0,0,0,0])); return; }
                  state = 'binding';
                  const listener = net.createServer(remote => {
                    remote.on('error', () => {}); listener.close();
                    client.removeListener('data', parse);
                    const remotePort = remote.remotePort;
                    const peer = mode === 'socks4badpeer' ? [127,0,0,2] : [127,0,0,1];
                    client.write(Buffer.from([0,90,remotePort >> 8,remotePort & 255,...peer]));
                    if (data.length) remote.write(data);
                    client.pipe(remote); remote.pipe(client);
                    client.on('close', () => remote.destroy());
                  });
                  listener.on('error', () => client.destroy());
                  client.on('close', () => { try { listener.close(); } catch (_) {} });
                  listener.listen(0, '127.0.0.1', () => {
                    const bound = listener.address().port;
                    const address = mode === 'socks4badbound' ? [127,0,0,2] : [127,0,0,1];
                    client.write(Buffer.from([0,90,bound >> 8,bound & 255,...address]));
                  });
                  return;
                }
                if (command !== 1) { client.end(Buffer.from([0,91,0,0,0,0,0,0])); return; }
                tunnel(host, port, Buffer.from([0,90,0,0,0,0,0,0])); return;
              }
              if (state === 'greeting') {
                if (data.length < 2 || data.length < 2 + data[1]) return;
                data = data.subarray(2 + data[1]); client.write(Buffer.from([5,2])); state = 'auth'; continue;
              }
              if (state === 'auth') {
                if (data.length < 2 || data.length < 2 + data[1] + 1) return;
                const n = data[1], p = data[2 + n]; if (data.length < 3 + n + p) return;
                const user = data.subarray(2,2+n).toString(), pass = data.subarray(3+n,3+n+p).toString(); data = data.subarray(3+n+p);
                if (user !== 'alice' || pass !== 'secret') { client.end(Buffer.from([1,1])); return; }
                client.write(Buffer.from([1,0])); state = 'request'; continue;
              }
              if (state === 'request') {
                if (data.length < 5) return;
                const command = data[1];
                let length, offset;
                if (data[3] === 1) { length = 4; offset = 4; }
                else if (data[3] === 3) { length = data[4]; offset = 5; }
                else { client.destroy(); return; }
                if (data.length < offset + length + 2) return;
                const host = data[3] === 1 ? Array.from(data.subarray(offset,offset+length)).join('.') : data.subarray(offset,offset+length).toString();
                const port = data.readUInt16BE(offset+length); data = data.subarray(offset+length+2);
                if (command === 2) {
                  if (host !== '127.0.0.1' || port !== 0) { client.end(Buffer.from([5,2,0,1,0,0,0,0,0,0])); return; }
                  state = 'binding';
                  const listener = net.createServer(remote => {
                    remote.on('error', () => {}); listener.close();
                    client.removeListener('data', parse);
                    const remotePort = remote.remotePort;
                    const peer = mode === 'socks5badpeer' ? [127,0,0,2] : [127,0,0,1];
                    client.write(Buffer.from([5,0,0,1,...peer,remotePort >> 8,remotePort & 255]));
                    if (data.length) remote.write(data);
                    client.pipe(remote); remote.pipe(client);
                    client.on('close', () => remote.destroy());
                  });
                  listener.on('error', () => client.destroy());
                  client.on('close', () => { try { listener.close(); } catch (_) {} });
                  listener.listen(0, '127.0.0.1', () => {
                    const bound = listener.address().port;
                    const address = mode === 'socks5badbound' ? [127,0,0,2] : [127,0,0,1];
                    client.write(Buffer.from([5,0,0,1,...address,bound >> 8,bound & 255]));
                  });
                  return;
                }
                if (command !== 1) { client.end(Buffer.from([5,7,0,1,0,0,0,0,0,0])); return; }
                tunnel(host, port, Buffer.from([5,0,0,1,127,0,0,1,0,0])); return;
              }
            }
          }
          client.on('data', parse);
        });
        server.listen(0, '127.0.0.1', () => console.log(server.address().port));
        """#
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: nodeExecutable)
        process.arguments = ["-e", script, mode]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        let exited = self.exited
        process.terminationHandler = { _ in exited.signal() }
        try process.run()
        var descriptor = pollfd(fd: output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
        guard poll(&descriptor, 1, 10_000) > 0,
              let value = Int(String(decoding: output.fileHandleForReading.availableData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) else {
            if process.isRunning { process.terminate() }
            throw POSIXError(.ETIMEDOUT)
        }
        port = value
    }

    func stop() {
        if process.isRunning { process.terminate() }
        if exited.wait(timeout: .now() + 2) == .timedOut { _ = kill(process.processIdentifier, SIGKILL) }
    }
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpProxiesTunnelProtectedControlAndData() async throws {
    for mode in ["http", "socks4", "socks5"] {
        let server = try ExplicitFTPTestServer()
        defer { server.stop() }
        let proxy = try LocalFTPProxy(mode: mode)
        defer { proxy.stop() }
        let configured: FTPProxy
        switch mode {
        case "http": configured = .httpConnect(host: "127.0.0.1", port: proxy.port, username: "alice", password: "secret")
        case "socks4": configured = .socks4(host: "127.0.0.1", port: proxy.port, userID: "alice")
        default: configured = .socks5(host: "127.0.0.1", port: proxy.port, username: "alice", password: "secret")
        }
        let channel = FTPControlChannel()
        let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root], proxy: configured)
        try await channel.connect(configuration: config)
        try await channel.login()
        #expect(try await channel.listNames() == ["protected-file"])
        #expect(try await channel.retrieveFileData(remotePath: "sample") == Data([0,10,13,255,65,66]))
        await channel.disconnect()
    }
}

@Test(.enabled(if: nodeExecutable != nil)) func socks5BindSupportsActiveFTPS() async throws {
  for (implicit, clear) in [(false, false), (true, false), (false, true)] {
    let server = try ExplicitFTPTestServer(implicitTLS: implicit, includeIPSan: true)
    defer { server.stop() }
    let proxy = try LocalFTPProxy(mode: "socks5")
    defer { proxy.stop() }
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret",
      security: implicit ? .implicitTLS : .explicitTLS, dataConnectionMode: .active, dataProtection: clear ? .clear : .privateData,
      connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root],
      proxy: .socks5(host: "127.0.0.1", port: proxy.port, username: "alice", password: "secret"))
    try await channel.connect(configuration: config)
    try await channel.login()
    #expect(try await channel.listNames() == [implicit ? "encrypted-file" : "protected-file"])
    let bytes = Data((0..<100_123).map { UInt8(truncatingIfNeeded: $0) })
    try await channel.storeFileData(bytes, remotePath: "sample")
    #expect(try await channel.retrieveFileData(remotePath: "sample") == bytes)
    await channel.disconnect()
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func socks5BindRejectsUnexpectedAddresses() async throws {
  for mode in ["socks5badbound", "socks5badpeer"] {
    let server = try ExplicitFTPTestServer(includeIPSan: true)
    defer { server.stop() }
    let proxy = try LocalFTPProxy(mode: mode)
    defer { proxy.stop() }
    let channel = FTPControlChannel()
    await channel.setSessionLogging(true)
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", security: .explicitTLS,
      dataConnectionMode: .active, connectTimeout: 4, readTimeout: 4, trustedRootCertificates: [server.root],
      proxy: .socks5(host: "127.0.0.1", port: proxy.port, username: "alice", password: "secret"))
    try await channel.connect(configuration: config)
    try await channel.login()
    if mode == "socks5badbound" {
      await #expect(throws: FTPError.protocolViolation(description: "SOCKS5 BIND address differs from proxy peer")) { try await channel.listNames() }
      #expect(!(await channel.sessionLog()).contains("> EPRT"))
    } else {
      await #expect(throws: FTPError.connectionFailed(description: "SOCKS5 BIND peer does not match FTP server")) { try await channel.listNames() }
      #expect(!(await channel.isConnected))
    }
    await channel.disconnect()
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func socks4BindSupportsActiveFTPS() async throws {
  for (implicit, clear) in [(false, false), (true, false), (false, true)] {
    let server = try ExplicitFTPTestServer(implicitTLS: implicit, includeIPSan: true)
    defer { server.stop() }
    let proxy = try LocalFTPProxy(mode: "socks4")
    defer { proxy.stop() }
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret",
      security: implicit ? .implicitTLS : .explicitTLS, dataConnectionMode: .active, dataProtection: clear ? .clear : .privateData,
      connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root],
      proxy: .socks4(host: "127.0.0.1", port: proxy.port, userID: "alice"))
    try await channel.connect(configuration: config)
    try await channel.login()
    #expect(try await channel.listNames() == [implicit ? "encrypted-file" : "protected-file"])
    let bytes = Data((0..<100_123).map { UInt8(truncatingIfNeeded: $0) })
    try await channel.storeFileData(bytes, remotePath: "sample")
    #expect(try await channel.retrieveFileData(remotePath: "sample") == bytes)
    await channel.disconnect()
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func strictFTPSResumptionThroughProxies() async throws {
  for mode in ["http", "socks4", "socks5"] {
    let server = try ExplicitFTPTestServer(requireSessionReuse: true, includeIPSan: true)
    defer { server.stop() }
    let proxy = try LocalFTPProxy(mode: mode)
    defer { proxy.stop() }
    let configured: FTPProxy
    switch mode {
    case "http": configured = .httpConnect(host: "127.0.0.1", port: proxy.port, username: "alice", password: "secret")
    case "socks4": configured = .socks4(host: "127.0.0.1", port: proxy.port, userID: "alice")
    default: configured = .socks5(host: "127.0.0.1", port: proxy.port, username: "alice", password: "secret")
    }
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", security: .explicitTLS,
      dataConnectionMode: mode == "http" ? .passive : .active, enableTLSSessionResumption: true,
      connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root], proxy: configured, maximumTLSVersion: .tls12)
    try await channel.connect(configuration: config)
    try await channel.login()
    #expect(try await channel.listNames() == ["protected-file"])
    #expect(try await channel.retrieveFileData(remotePath: "sample") == Data([0,10,13,255,65,66]))
    await channel.disconnect()
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func socks4BindRejectsUnexpectedAddresses() async throws {
  for mode in ["socks4badbound", "socks4badpeer"] {
    let server = try ExplicitFTPTestServer(includeIPSan: true)
    defer { server.stop() }
    let proxy = try LocalFTPProxy(mode: mode)
    defer { proxy.stop() }
    let channel = FTPControlChannel()
    await channel.setSessionLogging(true)
    let config = FTPClientConfiguration(host: "127.0.0.1", port: server.port, username: "demo", password: "secret", security: .explicitTLS,
      dataConnectionMode: .active, connectTimeout: 4, readTimeout: 4, trustedRootCertificates: [server.root],
      proxy: .socks4(host: "127.0.0.1", port: proxy.port, userID: "alice"))
    try await channel.connect(configuration: config)
    try await channel.login()
    if mode == "socks4badbound" {
      await #expect(throws: FTPError.protocolViolation(description: "SOCKS4 BIND address differs from proxy peer")) { try await channel.listNames() }
      #expect(!(await channel.sessionLog()).contains("> EPRT"))
    } else {
      await #expect(throws: FTPError.connectionFailed(description: "SOCKS4 BIND peer does not match FTP server")) { try await channel.listNames() }
      #expect(!(await channel.isConnected))
    }
    await channel.disconnect()
  }
}

@Test func socks4BindRejectsUnsafeConfigurationBeforeConnecting() async {
  let proxy = FTPProxy.socks4(host: "127.0.0.1", port: 1080)
  let channel = FTPControlChannel()
  let hostname = FTPClientConfiguration(host: "localhost", username: "demo", password: "secret", dataConnectionMode: .active, proxy: proxy)
  await #expect(throws: FTPError.invalidState(description: "SOCKS4 active mode requires a numeric IPv4 FTP server address")) { try await channel.connect(configuration: hostname) }
  let range = FTPClientConfiguration(host: "127.0.0.1", username: "demo", password: "secret", dataConnectionMode: .active, proxy: proxy, activePortRangeStart: 9000)
  await #expect(throws: FTPError.invalidState(description: "SOCKS4 BIND controls its own active address and port")) { try await channel.connect(configuration: range) }
}

@Test func socks5BindRejectsUnsafeConfigurationBeforeConnecting() async {
  let proxy = FTPProxy.socks5(host: "127.0.0.1", port: 1080)
  let channel = FTPControlChannel()
  let hostname = FTPClientConfiguration(host: "localhost", username: "demo", password: "secret", dataConnectionMode: .active, proxy: proxy)
  await #expect(throws: FTPError.invalidState(description: "SOCKS5 active mode requires a numeric FTP server address")) { try await channel.connect(configuration: hostname) }
  let range = FTPClientConfiguration(host: "127.0.0.1", username: "demo", password: "secret", dataConnectionMode: .active, proxy: proxy, activePortRangeStart: 9000)
  await #expect(throws: FTPError.invalidState(description: "SOCKS5 BIND controls its own active address and port")) { try await channel.connect(configuration: range) }
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpProxyRejectsInvalidCredentials() async throws {
    let proxy = try LocalFTPProxy(mode: "socks5")
    defer { proxy.stop() }
    let channel = FTPControlChannel()
    let config = FTPClientConfiguration(host: "localhost", username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3, proxy: .socks5(host: "127.0.0.1", port: proxy.port, username: "alice", password: "wrong"))
    await #expect(throws: FTPError.self) { try await channel.connect(configuration: config) }
    #expect(await channel.isConnected == false)
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpProxyNTLMv2AuthenticatesEachTLSConnection() async throws {
  for implicit in [false, true] {
    let server = try ExplicitFTPTestServer(implicitTLS: implicit)
    defer { server.stop() }
    let proxy = try LocalFTPProxy(mode: "ntlm")
    defer { proxy.stop() }
    let client = FTPClientFacade()
    client.hostname = "localhost"
    client.port = server.port
    client.username = "demo"
    client.password = "secret"
    client.authTls = !implicit
    client.implicitTls = implicit
    client.trustedRootCertificates = [server.root]
    client.httpProxyHostname = "127.0.0.1"
    client.httpProxyPort = proxy.port
    client.httpProxyUsername = "Domain\\User"
    client.httpProxyPassword = "Password"
    client.httpProxyAuthMethod = "NTLM"
    client.keepSessionLog = true
    try await client.connect()
    #expect(try await client.nlst() == [implicit ? "encrypted-file" : "protected-file"])
    #expect(try await client.getRemoteFileBinaryData("sample") == Data([0,10,13,255,65,66]))
    let log = await client.sessionLog()
    #expect(!log.contains("Password"))
    #expect(!log.contains("Proxy-Authorization"))
    await client.disconnect()
  }
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpProxyNTLMv2RejectsWrongPassword() async throws {
  let proxy = try LocalFTPProxy(mode: "ntlm")
  defer { proxy.stop() }
  let channel = FTPControlChannel()
  let config = FTPClientConfiguration(host: "localhost", username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3,
    proxy: .httpNTLM(host: "127.0.0.1", port: proxy.port, username: "User", password: "wrong", domain: "Domain"))
  await #expect(throws: FTPError.connectionFailed(description: "NTLM proxy authentication rejected")) { try await channel.connect(configuration: config) }
  #expect(await channel.isConnected == false)
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpProxyNTLMv2HandlesChallengeWithoutTimestamp() async throws {
  let server = try ExplicitFTPTestServer()
  defer { server.stop() }
  let proxy = try LocalFTPProxy(mode: "ntlm-notime")
  defer { proxy.stop() }
  let channel = FTPControlChannel()
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root],
    proxy: .httpNTLM(host: "127.0.0.1", port: proxy.port, username: "User", password: "Password", domain: "Domain"))
  try await channel.connect(configuration: config)
  try await channel.login()
  #expect(try await channel.listNames() == ["protected-file"])
  await channel.disconnect()
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpProxyNTLMv2HandlesChunkedChallenge() async throws {
  let server = try ExplicitFTPTestServer()
  defer { server.stop() }
  let proxy = try LocalFTPProxy(mode: "ntlm-chunked")
  defer { proxy.stop() }
  let channel = FTPControlChannel()
  let config = FTPClientConfiguration(host: "localhost", port: server.port, username: "demo", password: "secret", security: .explicitTLS, connectTimeout: 5, readTimeout: 5, trustedRootCertificates: [server.root],
    proxy: .httpNTLM(host: "127.0.0.1", port: proxy.port, username: "User", password: "Password", domain: "Domain"))
  try await channel.connect(configuration: config)
  try await channel.login()
  #expect(try await channel.listNames() == ["protected-file"])
  await channel.disconnect()
}

@Test(.enabled(if: nodeExecutable != nil)) func ftpProxyNTLMv2RejectsUnsupportedFraming() async throws {
  let proxy = try LocalFTPProxy(mode: "ntlm-badframing")
  defer { proxy.stop() }
  let channel = FTPControlChannel()
  let config = FTPClientConfiguration(host: "localhost", username: "demo", password: "secret", connectTimeout: 3, readTimeout: 3,
    proxy: .httpNTLM(host: "127.0.0.1", port: proxy.port, username: "User", password: "Password", domain: "Domain"))
  await #expect(throws: FTPError.protocolViolation(description: "Unsupported HTTP proxy challenge framing")) { try await channel.connect(configuration: config) }
  #expect(await channel.isConnected == false)
}

@Test(.enabled(if: nodeExecutable != nil)) func failedDownloadCanBeRetriedAfterExplicitReconnect() async throws {
    guard let nodeExecutable else { return }
    let script = #"""
    const net = require('net'); let sessions = 0;
    const server = net.createServer(control => {
      const session = ++sessions; let input = '', dataServer = null, dataSocket = null, pending = false, cwd = session === 1;
      control.on('error', () => {});
      function reply(line) { control.write(line + '\r\n'); }
      function transfer() {
        if (!pending || !dataSocket) return; pending = false;
        if (session === 1) { dataSocket.write('partial'); dataSocket.destroy(); control.destroy(); }
        else dataSocket.end('complete', () => reply('226 Complete'));
      }
      control.on('data', chunk => {
        input += chunk.toString();
        while (input.includes('\r\n')) {
          const end = input.indexOf('\r\n'), cmd = input.slice(0,end); input = input.slice(end+2);
          if (cmd === 'USER demo') reply('331 Password');
          else if (cmd === 'PASS secret') reply('230 Logged in');
          else if (cmd === 'PWD') reply('257 "/remote"');
          else if (cmd === 'CWD /remote') { cwd = true; reply('250 Changed'); }
          else if (cmd === 'TYPE I') reply('200 Binary');
          else if (cmd === 'EPSV') {
            dataServer = net.createServer(socket => { dataSocket = socket; socket.on('error', () => {}); transfer(); });
            dataServer.listen(0, '127.0.0.1', () => reply('229 Extended (|||' + dataServer.address().port + '|)'));
          } else if (cmd === 'RETR sample') {
            if (!cwd) { reply('550 Wrong directory'); continue; }
            pending = true; reply('150 Opening'); transfer();
          } else if (cmd === 'QUIT') { reply('221 Bye'); control.end(); }
          else reply('500 Unknown');
        }
      });
      control.on('close', () => { if (dataServer) dataServer.close(); });
      reply('220 Ready');
    });
    server.listen(0, '127.0.0.1', () => console.log(server.address().port));
    """#
    let process = Process(), output = Pipe(), exited = DispatchSemaphore(value: 0)
    process.executableURL = URL(fileURLWithPath: nodeExecutable)
    process.arguments = ["-e", script]
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    process.terminationHandler = { _ in exited.signal() }
    try process.run()
    defer { stopTestProcess(process, exited: exited) }
    var descriptor = pollfd(fd: output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
    guard poll(&descriptor, 1, 10_000) > 0,
          let port = Int(String(decoding: output.fileHandleForReading.availableData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) else { throw POSIXError(.ETIMEDOUT) }
    let client = FTPClientFacade()
    client.hostname = "127.0.0.1"
    client.port = port
    client.username = "demo"
    client.password = "secret"
    client.connectTimeout = 3
    client.readTimeout = 3
    try await client.connect()
    try await client.loginAfterConnectOnly()
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    let destination = folder.appendingPathComponent("download")
    try Data("old".utf8).write(to: destination)
    await #expect(throws: FTPError.self) { try await client.getFile(remoteFilename: "sample", localPath: destination.path) }
    #expect(try Data(contentsOf: destination) == Data("old".utf8))
    await client.disconnect()
    try await client.connect()
    try await client.loginAfterConnectOnly()
    try await client.changeRemoteDir("/remote")
    try await client.getFile(remoteFilename: "sample", localPath: destination.path)
    #expect(try Data(contentsOf: destination) == Data("complete".utf8))
    await client.disconnect()
}
#endif