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
