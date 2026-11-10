import Foundation

public struct FTPPassiveEndpoint: Sendable, Equatable {
    public let host: String
    public let port: Int

    public init(host: String, port: Int) {
        self.host = host
        self.port = port
    }
}

public enum FTPPassiveEndpointParser {
    /// Parse the RFC 2428 (delimiter, delimiter, delimiter, port, delimiter) tuple.
    public static func parseExtendedPort(from reply: FTPReply) throws -> Int {
                let bytes = Array(reply.message.utf8)
                guard reply.code == 229, let open = bytes.firstIndex(of: 40), open + 6 < bytes.count else {
            throw FTPError.protocolViolation(description: "Malformed EPSV reply")
        }
                let delimiter = bytes[open + 1]
                guard (33...126).contains(delimiter), bytes[open + 2] == delimiter,
                            bytes[open + 3] == delimiter else {
            throw FTPError.protocolViolation(description: "Malformed EPSV tuple")
        }
                let start = open + 4
                guard let end = (start..<(bytes.count - 1)).first(where: { bytes[$0] == delimiter && bytes[$0 + 1] == 41 }),
                            end > start else {
                        throw FTPError.protocolViolation(description: "Malformed EPSV tuple")
                }
                let digits = bytes[start..<end]
                guard digits.allSatisfy({ (48...57).contains($0) }),
              let port = UInt16(String(decoding: digits, as: UTF8.self)), port != 0 else {
            throw FTPError.protocolViolation(description: "Invalid EPSV port")
        }
        return Int(port)
    }

    public static func parse(from reply: FTPReply) throws -> FTPPassiveEndpoint {
        guard let open = reply.message.firstIndex(of: "("),
              let close = reply.message[open...].firstIndex(of: ")") else {
            throw FTPError.protocolViolation(description: "PASV reply missing endpoint tuple")
        }

        let payload = reply.message[reply.message.index(after: open)..<close]
        let segments = payload
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }

        guard segments.count == 6 else {
            throw FTPError.protocolViolation(description: "PASV reply must include 6 numbers")
        }

        let values = try segments.map { segment -> Int in
            guard let value = Int(segment), (0...255).contains(value) else {
                throw FTPError.protocolViolation(description: "PASV reply contains invalid octet: \(segment)")
            }
            return value
        }

        let host = "\(values[0]).\(values[1]).\(values[2]).\(values[3])"
        let port = (values[4] * 256) + values[5]
        guard port > 0 else {
            throw FTPError.protocolViolation(description: "Invalid PASV port")
        }
        return FTPPassiveEndpoint(host: host, port: port)
    }
}
