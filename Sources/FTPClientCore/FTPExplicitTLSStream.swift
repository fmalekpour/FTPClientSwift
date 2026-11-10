import Foundation
import Network
import Security
import Security.SecureTransport

/// SecureTransport is deprecated, but provides the in-place TLS primitive not
/// exposed by NWConnection. All SSL calls run serially off the network queue.
final class FTPExplicitTLSStream: @unchecked Sendable {
    private let connection: NWConnection
    private let worker = DispatchQueue(label: "FTPClientSwift.explicitTLS")
    private let timeout: TimeInterval
    private let hostname: String
    private let roots: [SecCertificate]
    private let clientIdentity: FTPImportedIdentity?
    private let requireChainValidation: Bool
    private let pins: [Data]
    private let certificateRequirements: [FTPCertificateRequirement]
    private let sessionPeerID: Data?
    private let minimumTLSVersion: FTPTLSMinimumVersion
    private let maximumTLSVersion: FTPTLSMinimumVersion?
    private let cipherCodes: [UInt16]
    private var context: SSLContext?
    private var ioError: Error?
    private var peerCertificateDER: Data?
    private var deadline: DispatchTime = .distantFuture

    private func checkDeadline(operation: String) throws {
        if let ioError { throw ioError }
        guard DispatchTime.now() < deadline else {
            connection.cancel()
            throw FTPError.timeout(operation: operation)
        }
    }

        init(connection: NWConnection, configuration: FTPClientConfiguration, controlChannel: Bool = false,
                importedIdentity: FTPImportedIdentity? = nil, sessionPeerID: Data? = nil) throws {
        self.connection = connection
        self.timeout = configuration.readTimeout
        self.hostname = configuration.host
        self.requireChainValidation = configuration.requireServerCertificateValidation
        self.pins = try FTPTrustEvaluator.parsePins(configuration.pinnedPublicKeyHashes)
        self.certificateRequirements = controlChannel ? configuration.certificateRequirements : []
        self.sessionPeerID = sessionPeerID
        self.minimumTLSVersion = configuration.minimumTLSVersion
        self.maximumTLSVersion = configuration.maximumTLSVersion
        self.cipherCodes = try FTPTLSPolicy.cipherCodes(configuration.allowedCipherSuites)
        if let importedIdentity { self.clientIdentity = importedIdentity }
        else { self.clientIdentity = try configuration.clientIdentity.map(FTPImportedIdentity.load) }
        self.roots = try configuration.trustedRootCertificates.map { data in
            guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else {
                throw FTPError.invalidState(description: "Invalid DER-encoded trust anchor")
            }
            return certificate
        }
    }

    private final class ResultBox<T>: @unchecked Sendable {
        private let lock = NSLock()
        private var value: T?
        func set(_ value: T) { lock.lock(); defer { lock.unlock() }; self.value = value }
        func get() -> T? { lock.lock(); defer { lock.unlock() }; return value }
    }

    private final class Completion<T: Sendable>: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<T, Error>?
        private var result: Result<T, Error>?

        func install(_ continuation: CheckedContinuation<T, Error>) {
            lock.lock()
            if let result {
                lock.unlock()
                continuation.resume(with: result)
            } else {
                self.continuation = continuation
                lock.unlock()
            }
        }

        @discardableResult
        func resolve(_ result: Result<T, Error>) -> Bool {
            lock.lock()
            guard self.result == nil else { lock.unlock(); return false }
            self.result = result
            let continuation = self.continuation
            self.continuation = nil
            lock.unlock()
            continuation?.resume(with: result)
            return true
        }

        var isResolved: Bool {
            lock.lock(); defer { lock.unlock() }
            return result != nil
        }
    }

    private func receive(_ buffer: UnsafeMutableRawPointer, length: UnsafeMutablePointer<Int>) -> OSStatus {
        let requested = length.pointee
        if requested == 0 { return noErr }
        let semaphore = DispatchSemaphore(value: 0)
        let result = ResultBox<(Data?, Bool, NWError?)>()
        connection.receive(minimumIncompleteLength: 1, maximumLength: requested) { data, _, complete, error in
            result.set((data, complete, error))
            semaphore.signal()
        }
        guard semaphore.wait(timeout: deadline) == .success, let (data, complete, error) = result.get() else {
            ioError = FTPError.timeout(operation: "TLS read")
            connection.cancel()
            length.pointee = 0
            return errSSLClosedAbort
        }
        if let error {
            ioError = FTPError.connectionFailed(description: error.localizedDescription)
            length.pointee = 0
            return errSSLClosedAbort
        }
        let bytes = data ?? Data()
        bytes.copyBytes(to: buffer.assumingMemoryBound(to: UInt8.self), count: bytes.count)
        length.pointee = bytes.count
        if bytes.count == requested { return noErr }
        if complete && bytes.isEmpty { return errSSLClosedGraceful }
        return errSSLWouldBlock
    }

    private func write(_ buffer: UnsafeRawPointer, length: UnsafeMutablePointer<Int>) -> OSStatus {
        let data = Data(bytes: buffer, count: length.pointee)
        let semaphore = DispatchSemaphore(value: 0)
        let result = ResultBox<Result<Void, NWError>>()
        connection.send(content: data, completion: .contentProcessed { error in
            result.set(error.map { .failure($0) } ?? .success(()))
            semaphore.signal()
        })
        guard semaphore.wait(timeout: deadline) == .success, let outcome = result.get() else {
            ioError = FTPError.timeout(operation: "TLS send")
            connection.cancel()
            length.pointee = 0
            return errSSLClosedAbort
        }
        if case .failure(let error) = outcome {
            ioError = FTPError.connectionFailed(description: error.localizedDescription)
            length.pointee = 0
            return errSSLClosedAbort
        }
        return noErr
    }

    private func check(_ status: OSStatus, operation: String) throws {
        guard status == noErr else {
            throw ioError ?? FTPError.connectionFailed(description: "\(operation) failed (TLS status \(status))")
        }
    }

    private func verifyPeer(_ context: SSLContext) throws {
        var trust: SecTrust?
        try check(SSLCopyPeerTrust(context, &trust), operation: "TLS peer trust")
        guard let trust else { throw FTPError.connectionFailed(description: "Missing TLS peer trust") }
        guard FTPTrustEvaluator.evaluate(trust, hostname: hostname, roots: roots, requireChainValidation: requireChainValidation, pins: pins) else {
            throw FTPError.connectionFailed(description: "TLS certificate verification failed")
        }
        if let certificate = SecTrustGetCertificateAtIndex(trust, 0) {
            peerCertificateDER = SecCertificateCopyData(certificate) as Data
        }
        if !certificateRequirements.isEmpty {
            guard let certificate = peerCertificateDER,
                  FTPCertificateFields.satisfies(certificateRequirements, certificate: certificate) else {
                throw FTPError.connectionFailed(description: "TLS certificate requirement not satisfied")
            }
        }
    }

    private func perform<T: Sendable>(operation: String, _ body: @escaping @Sendable () throws -> T) async throws -> T {
        try Task.checkCancellation()
        let completion = Completion<T>()
        let value = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                completion.install(continuation)
                worker.async {
                    guard !completion.isResolved else { return }
                    do {
                        self.ioError = nil
                        self.deadline = .now() + self.timeout
                        completion.resolve(.success(try body()))
                    }
                    catch { completion.resolve(.failure(error)) }
                }
                DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak self] in
                    if completion.resolve(.failure(FTPError.timeout(operation: operation))) {
                        self?.connection.cancel()
                    }
                }
            }
        } onCancel: {
            if completion.resolve(.failure(CancellationError())) { self.connection.cancel() }
        }
        try Task.checkCancellation()
        return value
    }

    func handshake() async throws {
        try await perform(operation: "TLS read") {
            guard let context = SSLCreateContext(nil, .clientSide, .streamType) else {
                throw FTPError.connectionFailed(description: "Cannot create TLS context")
            }
            self.context = context
            try self.check(SSLSetIOFuncs(context, { ref, buffer, length in
                return Unmanaged<FTPExplicitTLSStream>.fromOpaque(ref).takeUnretainedValue().receive(buffer, length: length)
            }, { ref, buffer, length in
                return Unmanaged<FTPExplicitTLSStream>.fromOpaque(ref).takeUnretainedValue().write(buffer, length: length)
            }), operation: "TLS I/O configuration")
            try self.check(SSLSetConnection(context, Unmanaged.passUnretained(self).toOpaque()), operation: "TLS connection")
            try self.check(SSLSetProtocolVersionMin(context, self.minimumTLSVersion == .tls13 ? .tlsProtocol13 : .tlsProtocol12), operation: "TLS minimum version")
            if let maximum = self.maximumTLSVersion {
                try self.check(SSLSetProtocolVersionMax(context, maximum == .tls13 ? .tlsProtocol13 : .tlsProtocol12), operation: "TLS maximum version")
            }
            if !self.cipherCodes.isEmpty {
                let suites = self.cipherCodes.map { SSLCipherSuite($0) }
                try self.check(suites.withUnsafeBufferPointer { SSLSetEnabledCiphers(context, $0.baseAddress!, $0.count) }, operation: "TLS cipher suites")
            }
            if let identity = self.clientIdentity {
                let chain: [Any] = [identity.identity] + identity.certificates
                try self.check(SSLSetCertificate(context, chain as CFArray), operation: "TLS client identity")
            }
            try self.check(self.hostname.withCString { SSLSetPeerDomainName(context, $0, self.hostname.utf8.count) }, operation: "TLS server name")
            if let peerID = self.sessionPeerID {
                try self.check(peerID.withUnsafeBytes { SSLSetPeerID(context, $0.baseAddress, $0.count) }, operation: "TLS session peer ID")
                try self.check(SSLSetSessionTicketsEnabled(context, true), operation: "TLS session tickets")
            }
            try self.check(SSLSetSessionOption(context, .breakOnServerAuth, true), operation: "TLS trust configuration")
            var verified = false
            while true {
                try self.checkDeadline(operation: "TLS read")
                let result = SSLHandshake(context)
                if let error = self.ioError { throw error }
                if result == errSSLWouldBlock { continue }
                if result == errSSLPeerAuthCompleted {
                    try self.verifyPeer(context)
                    verified = true
                    continue
                }
                try self.check(result, operation: "TLS handshake")
                if !verified, self.sessionPeerID != nil {
                    // Resumption may omit the certificate callback; re-evaluate
                    // the cached peer trust under the current FTP session policy.
                    try self.verifyPeer(context)
                    verified = true
                }
                guard verified else { throw FTPError.connectionFailed(description: "TLS peer was not verified") }
                return
            }
        }
    }

    func send(_ data: Data) async throws {
        try await perform(operation: "TLS send") {
            guard let context = self.context else { throw FTPError.invalidState(description: "TLS not initialized") }
            try data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    try self.checkDeadline(operation: "TLS send")
                    var processed = 0
                    let result = SSLWrite(context, bytes.baseAddress!.advanced(by: offset), bytes.count - offset, &processed)
                    if let error = self.ioError { throw error }
                    offset += processed
                    if result != errSSLWouldBlock { try self.check(result, operation: "TLS write") }
                }
            }
        }
    }

    func sessionInfo() async throws -> FTPTLSSessionInfo {
        try await perform(operation: "TLS metadata") {
            guard let context = self.context else { throw FTPError.invalidState(description: "TLS not initialized") }
            var version = SSLProtocol(rawValue: 0)!
            var cipher: SSLCipherSuite = 0
            try self.check(SSLGetNegotiatedProtocolVersion(context, &version), operation: "TLS protocol metadata")
            try self.check(SSLGetNegotiatedCipher(context, &cipher), operation: "TLS cipher metadata")
            let versionName: String
            switch version.rawValue {
            case 8: versionName = "TLS 1.2"
            case 10: versionName = "TLS 1.3"
            default: versionName = "Unknown (\(version.rawValue))"
            }
            return FTPTLSSessionInfo(protocolVersion: versionName, cipherSuite: FTPTLSPolicy.cipherName(cipher),
                                     serverCertificateDER: self.peerCertificateDER, chainValidationRequired: self.requireChainValidation)
        }
    }

    func receive() async throws -> Data {
        let chunk = try await receiveWithCompletion()
        guard !chunk.data.isEmpty else {
            throw FTPError.connectionFailed(description: "TLS peer closed connection")
        }
        return chunk.data
    }

    func receiveWithCompletion() async throws -> (data: Data, isComplete: Bool) {
        try await perform(operation: "TLS read") {
            guard let context = self.context else { throw FTPError.invalidState(description: "TLS not initialized") }
            var bytes = [UInt8](repeating: 0, count: 8192)
            while true {
                try self.checkDeadline(operation: "TLS read")
                var processed = 0
                let result = SSLRead(context, &bytes, bytes.count, &processed)
                if let error = self.ioError { throw error }
                if result == errSSLClosedGraceful { return (Data(bytes.prefix(processed)), true) }
                if result != noErr && result != errSSLWouldBlock { try self.check(result, operation: "TLS read") }
                if processed > 0 { return (Data(bytes.prefix(processed)), false) }
                if result == errSSLWouldBlock { continue }
                throw FTPError.connectionFailed(description: "TLS peer closed connection")
            }
        }
    }

    func finishSending() async throws {
        try await perform(operation: "TLS send") {
            guard let context = self.context else { throw FTPError.invalidState(description: "TLS not initialized") }
            while true {
                try self.checkDeadline(operation: "TLS send")
                let result = SSLClose(context)
                if let error = self.ioError { throw error }
                if result == errSSLWouldBlock { continue }
                try self.check(result, operation: "TLS close")
                return
            }
        }
    }
}