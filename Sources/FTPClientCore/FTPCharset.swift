import Foundation
import CoreFoundation

public enum FTPCharset {
    public static func encoding(named name: String, asciiCompatible: Bool = false) throws -> String.Encoding {
        if name.caseInsensitiveCompare("ANSI") == .orderedSame { return .utf8 }
        let value = CFStringConvertIANACharSetNameToEncoding(name as CFString)
        guard value != kCFStringEncodingInvalidId else {
            throw FTPError.invalidState(description: "Unsupported character set: \(name)")
        }
        let encoding = String.Encoding(rawValue: CFStringConvertEncodingToNSStringEncoding(value))
        guard !asciiCompatible || "FTP 123".data(using: encoding) == Data("FTP 123".utf8) else {
            throw FTPError.invalidState(description: "FTP character set must preserve ASCII bytes: \(name)")
        }
        return encoding
    }
}