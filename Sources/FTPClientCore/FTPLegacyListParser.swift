import Foundation

/// Parses common UNIX and Windows LIST formats. Ambiguous dates remain unavailable.
public enum FTPLegacyListParser {
    public static func parse(_ data: Data, encoding: String.Encoding = .utf8, assumedTimeZone: TimeZone? = nil, now: Date = Date()) throws -> [FTPDirectoryEntry] {
        guard let text = String(data: data, encoding: encoding) else { throw FTPError.invalidResponseEncoding }
        let unix = try NSRegularExpression(pattern: #"^([bcdlps-][rwxStTs-]{9}[+@.]?)\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{4}|\d{1,2}:\d{2})\s+(.+)$"#)
        let windows = try NSRegularExpression(pattern: #"^(\d{2}-\d{2}-\d{2,4})\s+(\d{1,2}:\d{2}(?:AM|PM))\s+(<DIR>|\d+)\s+(.+)$"#, options: .caseInsensitive)
        var result: [FTPDirectoryEntry] = []
        for line in text.components(separatedBy: "\r\n") where !line.isEmpty {
            if line.hasPrefix("total ") { continue }
            let range = NSRange(line.startIndex..<line.endIndex, in: line)
            if let match = unix.firstMatch(in: line, range: range) {
                func group(_ index: Int) -> String { Range(match.range(at: index), in: line).map { String(line[$0]) } ?? "" }
                let mode = group(1), owner = group(2), groupName = group(3)
                guard let size = UInt64(group(4)) else { throw FTPError.protocolViolation(description: "Invalid LIST size") }
                var name = group(8)
                let kind: FTPDirectoryEntry.Kind
                switch mode.first {
                case "-": kind = .file
                case "d": kind = .directory
                case "l":
                    kind = .other("symlink")
                    if let arrow = name.range(of: " -> ") { name = String(name[..<arrow.lowerBound]) }
                default: kind = .other("special")
                }
                guard !name.isEmpty else { throw FTPError.protocolViolation(description: "Invalid LIST filename") }
                let modified = assumedTimeZone.flatMap { parseUnixDate(month: group(5), day: group(6), yearOrTime: group(7), zone: $0, now: now) }
                result.append(FTPDirectoryEntry(name: name, kind: kind, size: size, modifiedAt: modified,
                                                facts: ["unix.mode": mode, "unix.owner": owner, "unix.group": groupName]))
            } else if let match = windows.firstMatch(in: line, range: range) {
                func group(_ index: Int) -> String { Range(match.range(at: index), in: line).map { String(line[$0]) } ?? "" }
                let sizeOrDirectory = group(3), name = group(4)
                let directory = sizeOrDirectory.uppercased() == "<DIR>"
                guard !name.isEmpty, directory || UInt64(sizeOrDirectory) != nil else {
                    throw FTPError.protocolViolation(description: "Invalid LIST record")
                }
                let modified = assumedTimeZone.flatMap { parseWindowsDate(date: group(1), time: group(2), zone: $0) }
                result.append(FTPDirectoryEntry(name: name, kind: directory ? .directory : .file,
                                                size: directory ? nil : UInt64(sizeOrDirectory), modifiedAt: modified, facts: [:]))
            } else {
                throw FTPError.protocolViolation(description: "Unsupported LIST record")
            }
        }
        return result
    }

    private static func formatter(_ format: String, zone: TimeZone) -> DateFormatter {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = zone
        formatter.dateFormat = format
        formatter.isLenient = false
        return formatter
    }

    private static func parseUnixDate(month: String, day: String, yearOrTime: String, zone: TimeZone, now: Date) -> Date? {
        guard yearOrTime.contains(":") else {
            return formatter("MMM d yyyy", zone: zone).date(from: "\(month) \(day) \(yearOrTime)")
        }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = zone
        let year = calendar.component(.year, from: now)
        let parser = formatter("MMM d yyyy HH:mm", zone: zone)
        guard let value = parser.date(from: "\(month) \(day) \(year) \(yearOrTime)") else { return nil }
        if value.timeIntervalSince(now) > 24 * 60 * 60 { return calendar.date(byAdding: .year, value: -1, to: value) }
        return value
    }

    private static func parseWindowsDate(date: String, time: String, zone: TimeZone) -> Date? {
        let yearDigits = date.split(separator: "-").last?.count ?? 0
        let format = yearDigits == 4 ? "MM-dd-yyyy h:mma" : "MM-dd-yy h:mma"
        return formatter(format, zone: zone).date(from: "\(date) \(time.uppercased())")
    }
}