import Foundation

public struct FTPReplyParser: Sendable {
    private var buffer = Data()
    private var multilineCode: Int?
    private var lines: [String] = []
    private var replyBytes = 0
    private static let maximumReplyBytes = 1_048_576
    private let encoding: String.Encoding

    public init(encoding: String.Encoding = .utf8) { self.encoding = encoding }

    /// An upgrade must not discard plaintext bytes buffered after a reply.
    var hasBufferedBytes: Bool { !buffer.isEmpty || multilineCode != nil }

    /// Call with empty data to drain replies already received in a single packet.
    public mutating func append(_ data: Data) throws -> FTPReply? {
        buffer.append(data)
        let delimiter = Data([13, 10])
        while let range = buffer.range(of: delimiter) {
            let lineData = Data(buffer[..<range.lowerBound])
            buffer.removeSubrange(..<range.upperBound)
            replyBytes += lineData.count + 2
            guard replyBytes <= Self.maximumReplyBytes else {
                throw FTPError.protocolViolation(description: "FTP reply exceeds size limit")
            }
            guard let line = String(data: lineData, encoding: encoding) else {
                throw FTPError.invalidResponseEncoding
            }
            if let code = multilineCode {
                lines.append(line)
                if line.hasPrefix("\(code) ") {
                    let reply = FTPReply(code: code, message: lines.joined(separator: "\n"))
                    multilineCode = nil
                    lines.removeAll()
                    replyBytes = 0
                    return reply
                }
                continue
            }
            let bytes = Array(lineData)
            guard bytes.count >= 4, bytes[0...2].allSatisfy({ (48...57).contains($0) }),
                  bytes[3] == 32 || bytes[3] == 45,
                  let code = Int(String(decoding: bytes[0...2], as: UTF8.self)),
                  (100...599).contains(code) else {
                throw FTPError.protocolViolation(description: "Malformed FTP reply: \(line)")
            }
            if bytes[3] == 45 {
                multilineCode = code
                lines = [line]
            } else {
                replyBytes = 0
                return FTPReply(code: code, message: line)
            }
        }
        guard buffer.count + replyBytes <= Self.maximumReplyBytes else {
            throw FTPError.protocolViolation(description: "FTP reply exceeds size limit")
        }
        return nil
    }
}
