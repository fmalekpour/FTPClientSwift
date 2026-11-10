import Foundation
import Testing
import FTPClientCore

@Test func parsesUnixAndWindowsLegacyListings() throws {
    let listing = "total 2\r\n-rw-r--r-- 1 alice staff 12 Jan 02 2024 file with spaces.txt\r\ndrwxr-xr-x 2 alice staff 0 Jan 03 12:34 folder\r\nlrwxrwxrwx 1 alice staff 4 Jan 03 2024 link -> dest\r\n01-02-2024  03:04PM       <DIR>          win folder\r\n01-02-2024  03:04PM             23      win.txt\r\n"
    let zone = try #require(TimeZone(secondsFromGMT: 0))
    let entries = try FTPLegacyListParser.parse(Data(listing.utf8), assumedTimeZone: zone, now: Date(timeIntervalSince1970: 1_704_164_645))
    #expect(entries.map(\.name) == ["file with spaces.txt", "folder", "link", "win folder", "win.txt"])
    #expect(entries.map(\.kind) == [.file, .directory, .other("symlink"), .directory, .file])
    #expect(entries[0].size == 12)
    #expect(entries[0].facts["unix.owner"] == "alice")
    #expect(entries[0].modifiedAt != nil)
    #expect(entries[3].modifiedAt != nil)
    #expect(try FTPLegacyListParser.parse(Data(listing.utf8))[0].modifiedAt == nil)
}

@Test func rejectsUnrecognizedLegacyListing() {
    #expect(throws: FTPError.self) { try FTPLegacyListParser.parse(Data("unrecognized entry\r\n".utf8)) }
}

@Test func parsesLegacyReplyCharsetAndRejectsUnsafeProtocolEncodings() throws {
    let encoding = try FTPCharset.encoding(named: "iso-8859-1", asciiCompatible: true)
    var parser = FTPReplyParser(encoding: encoding)
    let reply = try #require("220 café\r\n".data(using: encoding))
    #expect(try parser.append(reply)?.message == "220 café")
    #expect(throws: FTPError.self) { try FTPCharset.encoding(named: "utf-16", asciiCompatible: true) }
}