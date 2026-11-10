import Foundation
import FTPClientCore
import FTPClientSecurity

/// Bounded exponential backoff for explicitly retried downloads.
public struct FTPRetryPolicy: Sendable, Equatable {
    /// Includes the initial attempt; must be between 1 and 10.
    public var maximumAttempts: Int
    public var initialDelay: TimeInterval
    public var maximumDelay: TimeInterval

    public init(maximumAttempts: Int = 3, initialDelay: TimeInterval = 0.25, maximumDelay: TimeInterval = 10) {
        self.maximumAttempts = maximumAttempts
        self.initialDelay = initialDelay
        self.maximumDelay = maximumDelay
    }
}

/// Opt-in retry for a download. Each attempt starts a new session and downloads
/// from the beginning into a temporary sibling of the destination.
public enum FTPDownloadRetry {
    public static func download(
        configuration: FTPClientConfiguration,
        securityPolicy: FTPSecurityPolicy? = nil,
        remotePath: String,
        destination: URL,
        retryPolicy: FTPRetryPolicy = FTPRetryPolicy(),
        progress: (@Sendable (UInt64) -> Void)? = nil,
        onRetry: (@Sendable (_ nextAttempt: Int, _ error: FTPError) -> Void)? = nil
    ) async throws {
        guard (1...10).contains(retryPolicy.maximumAttempts), retryPolicy.initialDelay.isFinite,
              retryPolicy.maximumDelay.isFinite, retryPolicy.initialDelay >= 0,
              retryPolicy.maximumDelay >= retryPolicy.initialDelay, retryPolicy.maximumDelay <= 300 else {
            throw FTPError.invalidState(description: "Invalid download retry policy")
        }
        guard destination.isFileURL else { throw FTPError.invalidState(description: "Destination must be a file URL") }
        guard remotePath.hasPrefix("/"), !remotePath.utf8.contains(where: { $0 == 0 || $0 == 10 || $0 == 13 }) else {
            throw FTPError.invalidState(description: "Retried download requires an absolute remote path")
        }

        var delay = retryPolicy.initialDelay
        for attempt in 1...retryPolicy.maximumAttempts {
            try Task.checkCancellation()
            let client = FTPClient(configuration: configuration, securityPolicy: securityPolicy)
            do {
                try await client.connect()
                try await client.downloadFile(remotePath: remotePath, localPath: destination.path, progress: progress)
                await client.disconnect()
                return
            } catch {
                await client.disconnect()
                if Task.isCancelled { throw CancellationError() }
                guard attempt < retryPolicy.maximumAttempts, let ftpError = error as? FTPError,
                      isRetryable(ftpError) else { throw error }
                onRetry?(attempt + 1, ftpError)
                try Task.checkCancellation()
                if delay > 0 { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
                delay = min(retryPolicy.maximumDelay, delay * 2)
            }
        }
    }

    private static func isRetryable(_ error: FTPError) -> Bool {
        switch error {
        case .timeout, .connectionFailed: return true
        case .serverReply(let code, _): return code.map { [421, 425, 426, 450, 451, 452].contains($0) } ?? false
        default: return false
        }
    }
}