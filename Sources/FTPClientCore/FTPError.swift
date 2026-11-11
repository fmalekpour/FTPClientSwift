import Foundation

public enum FTPError: Error, Sendable, Equatable {
    case notImplemented(feature: String)
    case invalidState(description: String)
    case serverReply(code: Int?, message: String)
    case connectionFailed(description: String)
    case timeout(operation: String)
    case protocolViolation(description: String)
    case invalidResponseEncoding
}

extension FTPError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notImplemented(let feature):
            return "This FTP feature is not supported: \(feature)."
        case .invalidState(let description):
            return "The FTP operation could not be performed: \(description)"
        case .serverReply(let code, let message):
            let detail = message.trimmingCharacters(in: .whitespacesAndNewlines)
            if let code {
                return detail.isEmpty ? "The FTP server returned error \(code)." : "The FTP server returned an error (\(code)): \(detail)"
            }
            return detail.isEmpty ? "The FTP server returned an error." : "The FTP server returned an error: \(detail)"
        case .connectionFailed(let description):
            return "The FTP connection failed: \(description)"
        case .timeout(let operation):
            return "The FTP operation timed out while performing \(operation)."
        case .protocolViolation(let description):
            return "An FTP protocol error occurred: \(description)"
        case .invalidResponseEncoding:
            return "The FTP server's response could not be decoded using the configured character encoding."
        }
    }
}
