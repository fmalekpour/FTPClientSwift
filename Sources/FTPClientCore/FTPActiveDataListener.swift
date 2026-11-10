import Foundation
import Network

/// A single-use active FTP listener. Events and continuations are serialized by the actor.
actor FTPActiveDataListener {
    private let listener: NWListener
    private let expectedPeer: NWEndpoint.Host
    private let queue = DispatchQueue(label: "FTPClientSwift.activeListener")
    private let timeout: TimeInterval
    private var port: NWEndpoint.Port?
    private var incoming: NWConnection?
    private var failure: Error?
    private var isFinished = false
    private var readyWaiter: CheckedContinuation<NWEndpoint.Port, Error>?
    private var acceptWaiter: CheckedContinuation<NWConnection, Error>?

    init(localHost: NWEndpoint.Host, expectedPeer: NWEndpoint.Host, timeout: TimeInterval, port: NWEndpoint.Port = .any) throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: localHost, port: port)
        self.listener = try NWListener(using: parameters)
        self.expectedPeer = expectedPeer
        self.timeout = timeout
    }

    func start() async throws -> NWEndpoint.Port {
        listener.stateUpdateHandler = { [weak self] state in
            Task { await self?.stateChanged(state) }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { connection.cancel(); return }
            Task { await self.received(connection) }
        }
        listener.start(queue: queue)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                if let failure { continuation.resume(throwing: failure) }
                else if let port { continuation.resume(returning: port) }
                else { readyWaiter = continuation }
                queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
                    Task { await self?.expireReady() }
                }
            }
        } onCancel: { Task { await self.cancel() } }
    }

    func takeConnection() async throws -> NWConnection {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                if let failure { continuation.resume(throwing: failure) }
                else if let incoming {
                    self.incoming = nil
                    isFinished = true
                    listener.cancel()
                    continuation.resume(returning: incoming)
                } else { acceptWaiter = continuation }
                queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
                    Task { await self?.expireAccept() }
                }
            }
        } onCancel: { Task { await self.cancel() } }
    }

    func cancel() {
        fail(CancellationError())
    }

    private func expireReady() {
        if readyWaiter != nil { fail(FTPError.timeout(operation: "active listener")) }
    }

    private func expireAccept() {
        if acceptWaiter != nil { fail(FTPError.timeout(operation: "active data connection")) }
    }

    private func stateChanged(_ state: NWListener.State) {
        switch state {
        case .ready:
            guard failure == nil, let port = listener.port else { return }
            self.port = port
            readyWaiter?.resume(returning: port)
            readyWaiter = nil
        case .failed(let error):
            fail(FTPError.connectionFailed(description: error.localizedDescription))
        default: break
        }
    }

    private func received(_ connection: NWConnection) {
        guard failure == nil, !isFinished, case .hostPort(let host, _) = connection.endpoint, host == expectedPeer else {
            connection.cancel()
            return
        }
        if let waiter = acceptWaiter {
            acceptWaiter = nil
            isFinished = true
            listener.cancel()
            waiter.resume(returning: connection)
        } else if incoming == nil {
            incoming = connection
        } else {
            connection.cancel()
        }
    }

    private func fail(_ error: Error) {
        guard failure == nil else { return }
        failure = error
        listener.cancel()
        incoming?.cancel()
        incoming = nil
        readyWaiter?.resume(throwing: error)
        readyWaiter = nil
        acceptWaiter?.resume(throwing: error)
        acceptWaiter = nil
    }
}