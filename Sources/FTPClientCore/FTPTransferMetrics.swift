import Foundation

/// Internal coordination for a multi-command upload; callers should use the facade API.
public enum FTPChunkedUploadScope {
    @TaskLocal public static var identifier: UUID?
}

/// A point-in-time view of the current or most recent file transfers.
public struct FTPTransferMetrics: Sendable, Equatable {
    public enum Direction: Sendable, Equatable { case upload, download }
    public let receivedBytes: UInt64
    public let sentBytes: UInt64
    public let downloadBytesPerSecond: UInt64
    public let uploadBytesPerSecond: UInt64
    public let activeDirection: Direction?
    public let lastDownloadSucceeded: Bool?
    public let lastUploadSucceeded: Bool?
    /// Expected logical bytes for this operation, excluding an existing resume prefix.
    public let expectedDownloadBytes: UInt64?
    public let expectedUploadBytes: UInt64?

    /// Fraction of expected bytes processed, not a guarantee of server acceptance.
    public var downloadFractionCompleted: Double? { fraction(receivedBytes, expectedDownloadBytes, lastDownloadSucceeded) }
    public var uploadFractionCompleted: Double? { fraction(sentBytes, expectedUploadBytes, lastUploadSucceeded) }

    /// True when a failed download received fewer than the expected number of bytes.
    /// Nil means the transfer is unfinished or its completeness cannot be determined.
    public var partialDownload: Bool? {
        guard let succeeded = lastDownloadSucceeded else { return nil }
        if succeeded || receivedBytes == 0 { return false }
        guard let expectedDownloadBytes else { return nil }
        return receivedBytes < expectedDownloadBytes
    }

    private func fraction(_ bytes: UInt64, _ total: UInt64?, _ succeeded: Bool?) -> Double? {
        guard let total else { return nil }
        if total == 0 { return succeeded == true ? 1 : 0 }
        return min(1, Double(bytes) / Double(total))
    }

    public init(receivedBytes: UInt64, sentBytes: UInt64, downloadBytesPerSecond: UInt64,
                uploadBytesPerSecond: UInt64, activeDirection: Direction?, lastDownloadSucceeded: Bool?, lastUploadSucceeded: Bool?,
                expectedDownloadBytes: UInt64? = nil, expectedUploadBytes: UInt64? = nil) {
        self.receivedBytes = receivedBytes
        self.sentBytes = sentBytes
        self.downloadBytesPerSecond = downloadBytesPerSecond
        self.uploadBytesPerSecond = uploadBytesPerSecond
        self.activeDirection = activeDirection
        self.lastDownloadSucceeded = lastDownloadSucceeded
        self.lastUploadSucceeded = lastUploadSucceeded
        self.expectedDownloadBytes = expectedDownloadBytes
        self.expectedUploadBytes = expectedUploadBytes
    }
}