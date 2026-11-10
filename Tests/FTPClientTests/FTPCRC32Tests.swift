import Foundation
import Testing
@testable import FTPClientCore

@Test func crc32MatchesStandardVectorsAndChunking() {
    var crc = FTPCRC32()
    #expect(crc.value == 0)
    for chunk in ["123", "456", "789"] { crc.update(Data(chunk.utf8)) }
    #expect(crc.value == 0xcbf43926)
    var second = FTPCRC32()
    second.update(Data("abc".utf8))
    #expect(second.value == 0x352441c2)
}