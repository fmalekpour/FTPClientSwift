import Foundation
import Testing
@testable import FTPClientCore

@Test func parsesSingleLineReply() throws {
    var parser = FTPReplyParser()
    let data = Data("220 Service ready\r\n".utf8)

    let reply = try parser.append(data)

    #expect(reply?.code == 220)
    #expect(reply?.message == "220 Service ready")
}

@Test func parsesMultilineReply() throws {
    var parser = FTPReplyParser()
    let chunk1 = Data("211-Features\r\n SIZE\r\n".utf8)
    let chunk2 = Data(" UTF8\r\n211 End\r\n".utf8)

    let first = try parser.append(chunk1)
    #expect(first == nil)

    let second = try parser.append(chunk2)
    #expect(second?.code == 211)
    #expect(second?.message == "211-Features\n SIZE\n UTF8\n211 End")
}

@Test func failsOnInvalidEncoding() {
    var parser = FTPReplyParser()
    let invalidData = Data([0x32, 0x32, 0x30, 0x20, 0xFF, 0x0D, 0x0A])

    #expect(throws: FTPError.self) {
        _ = try parser.append(invalidData)
    }
}

@Test func drainsMultipleRepliesFromOnePacket() throws {
    var parser = FTPReplyParser()
    let first = try parser.append(Data("150 Opening\r\n226 Complete\r\n".utf8))
    let second = try parser.append(Data())
    #expect(first?.code == 150)
    #expect(second?.code == 226)
}

@Test func parsesUTF8SplitAcrossPackets() throws {
    var parser = FTPReplyParser()
    let bytes = Array("220 café\r\n".utf8)
    let split = bytes.firstIndex(of: 0xc3)!
    #expect(try parser.append(Data(bytes[...split])) == nil)
    let reply = try parser.append(Data(bytes[(split + 1)...]))
    #expect(reply?.message == "220 café")
}

@Test func rejectsMalformedReplyAndExcessiveLength() {
    var parser = FTPReplyParser()
    #expect(throws: FTPError.self) { try parser.append(Data("garbage\r\n".utf8)) }
    var oversized = FTPReplyParser()
    #expect(throws: FTPError.self) { try oversized.append(Data(repeating: 65, count: 1_048_577)) }
}

@Test func parsesQuotedWorkingDirectory() throws {
    let reply = FTPReply(code: 257, message: "257 \"/a\"\"b\" is the current directory")
    #expect(try reply.workingDirectoryPath() == "/a\"b")
    #expect(throws: FTPError.self) {
        try FTPReply(code: 257, message: "257 \"/unfinished").workingDirectoryPath()
    }
}
