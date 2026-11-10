import Foundation

public struct FTPDirectoryEntry: Sendable, Equatable {
    public enum Kind: Sendable, Equatable {
        case file, directory, currentDirectory, parentDirectory
        case other(String)
    }

    public let name: String
    public let kind: Kind
    public let size: UInt64?
    public let modifiedAt: Date?
    /// Original MLSD facts keyed by lowercase fact name.
    public let facts: [String: String]
}

/// Parses RFC 3659 MLSD records. Names and unknown facts are preserved.
public enum FTPMLSDParser {
    public static func parse(_ data: Data, encoding: String.Encoding = .utf8) throws -> [FTPDirectoryEntry] {
        guard let text = String(data: data, encoding: encoding) else {
            throw FTPError.invalidResponseEncoding
        }
        return try text.components(separatedBy: "\r\n")
            .filter { !$0.isEmpty }
            .map(parseLine)
    }

    private static func parseLine(_ line: String) throws -> FTPDirectoryEntry {
        guard let separator = line.firstIndex(of: " "), separator != line.startIndex else {
            throw FTPError.protocolViolation(description: "Malformed MLSD record")
        }
        let factsText = line[..<separator]
        let name = String(line[line.index(after: separator)...])
        guard factsText.last == ";", !name.isEmpty else {
            throw FTPError.protocolViolation(description: "Malformed MLSD record")
        }
        var facts: [String: String] = [:]
        for fact in factsText.split(separator: ";", omittingEmptySubsequences: true) {
            guard let equal = fact.firstIndex(of: "="), equal != fact.startIndex else {
                throw FTPError.protocolViolation(description: "Malformed MLSD fact")
            }
            let key = fact[..<equal].lowercased()
            guard facts[key] == nil else {
                throw FTPError.protocolViolation(description: "Duplicate MLSD fact: \(key)")
            }
            facts[key] = String(fact[fact.index(after: equal)...])
        }
        let type = facts["type"] ?? ""
        let kind: FTPDirectoryEntry.Kind
        switch type.lowercased() {
        case "file": kind = .file
        case "dir": kind = .directory
        case "cdir": kind = .currentDirectory
        case "pdir": kind = .parentDirectory
        default: kind = .other(type)
        }
        var size: UInt64?
        if let value = facts["size"] {
            guard !value.isEmpty, value.utf8.allSatisfy({ (48...57).contains($0) }),
                  let parsed = UInt64(value) else {
                throw FTPError.protocolViolation(description: "Invalid MLSD size")
            }
            size = parsed
        }
        let modified = try facts["modify"].map(parseTimestamp)
        return FTPDirectoryEntry(name: name, kind: kind, size: size, modifiedAt: modified, facts: facts)
    }

    /// Parses an RFC 3659 UTC timestamp, including optional fractional seconds.
    public static func parseTimestamp(_ value: String) throws -> Date {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count), parts[0].utf8.count == 14,
              parts[0].utf8.allSatisfy({ (48...57).contains($0) }),
              parts.count == 1 || (!parts[1].isEmpty && parts[1].utf8.allSatisfy({ (48...57).contains($0) })) else {
            throw FTPError.protocolViolation(description: "Invalid FTP timestamp")
        }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = TimeZone(secondsFromGMT: 0)!
        formatter.dateFormat = "yyyyMMddHHmmss"
        formatter.isLenient = false
        guard let date = formatter.date(from: String(parts[0])), formatter.string(from: date) == parts[0] else {
            throw FTPError.protocolViolation(description: "Invalid FTP timestamp")
        }
        if parts.count == 2, let fraction = Double("0." + parts[1]) {
            return date.addingTimeInterval(fraction)
        }
        return date
    }
}
