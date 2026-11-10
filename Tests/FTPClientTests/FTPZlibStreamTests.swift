import Foundation
import Testing
@testable import FTPClientCore

@Test func modeZDecodesKnownZlibStreamOneByteAtATime() throws {
    let encoded = Data([0x78,0x9c,0xcb,0x48,0xcd,0xc9,0xc9,0x07,0x00,0x06,0x2c,0x02,0x15])
    let decoder = try FTPZlibStream(encoding: false)
    var output = Data()
    for (index, byte) in encoded.enumerated() {
        output.append(try decoder.process(Data([byte]), final: index == encoded.count - 1))
    }
    #expect(output == Data("hello".utf8))
}

@Test func modeZRoundTripsFragmentedBinaryData() throws {
    let input = Data((0..<250_123).map { UInt8(truncatingIfNeeded: $0) })
    let encoder = try FTPZlibStream(encoding: true)
    var encoded = Data()
    for offset in stride(from: 0, to: input.count, by: 4093) {
        encoded.append(try encoder.process(Data(input.dropFirst(offset).prefix(4093)), final: false))
    }
    encoded.append(try encoder.process(Data(), final: true))
    let decoder = try FTPZlibStream(encoding: false)
    var output = Data()
    for offset in stride(from: 0, to: encoded.count, by: 17) {
        let chunk = Data(encoded.dropFirst(offset).prefix(17))
        output.append(try decoder.process(chunk, final: offset + chunk.count == encoded.count))
    }
    #expect(output == input)
}

@Test func modeZRejectsInvalidOrTruncatedStreams() throws {
    let corrupt = Data([0x78,0x9c,0xcb,0x48,0xcd,0xc9,0xc9,0x07,0x00,0x06,0x2c,0x02,0x16])
    let decoder = try FTPZlibStream(encoding: false)
    #expect(throws: FTPError.self) { try decoder.process(corrupt, final: true) }
    let truncated = try FTPZlibStream(encoding: false)
    #expect(throws: FTPError.self) { try truncated.process(Data([0x78,0x9c,0x01]), final: true) }
}