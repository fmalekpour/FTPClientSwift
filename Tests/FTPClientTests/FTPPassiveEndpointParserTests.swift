import Testing
@testable import FTPClientCore

@Test func parsesExtendedPassivePort() throws {
    #expect(try FTPPassiveEndpointParser.parseExtendedPort(from: FTPReply(code: 229, message: "229 Extended (|||50000|)")) == 50000)
    #expect(try FTPPassiveEndpointParser.parseExtendedPort(from: FTPReply(code: 229, message: "229 Extended (!!!21!)")) == 21)
    #expect(try FTPPassiveEndpointParser.parseExtendedPort(from: FTPReply(code: 229, message: "229 Extended (1112341)")) == 234)
    #expect(try FTPPassiveEndpointParser.parseExtendedPort(from: FTPReply(code: 229, message: "229 Extended ()))21))")) == 21)
    for tuple in ["(|||0|)", "(|||65536|)", "(|||12x|)", "(|!|123|)", "(||||)"] {
        #expect(throws: FTPError.self) {
            try FTPPassiveEndpointParser.parseExtendedPort(from: FTPReply(code: 229, message: "229 \(tuple)"))
        }
    }
}

@Test func parsesValidPasvReply() throws {
    let reply = FTPReply(code: 227, message: "227 Entering Passive Mode (192,168,1,5,195,80)")

    let endpoint = try FTPPassiveEndpointParser.parse(from: reply)

    #expect(endpoint.host == "192.168.1.5")
    #expect(endpoint.port == 50000)
}

@Test func rejectsPasvReplyWithWrongSegmentCount() {
    let reply = FTPReply(code: 227, message: "227 Entering Passive Mode (192,168,1,5,195)")

    #expect(throws: FTPError.self) {
        _ = try FTPPassiveEndpointParser.parse(from: reply)
    }
}

@Test func rejectsPasvReplyWithOutOfRangeValue() {
    let reply = FTPReply(code: 227, message: "227 Entering Passive Mode (10,0,0,1,300,10)")

    #expect(throws: FTPError.self) {
        _ = try FTPPassiveEndpointParser.parse(from: reply)
    }
}
