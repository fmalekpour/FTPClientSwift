import Foundation

/// IEEE CRC-32, used as an accidental-corruption check, not authentication.
struct FTPCRC32 {
    private static let table: [UInt32] = (0..<256).map { index in
        var value = UInt32(index)
        for _ in 0..<8 {
            value = (value & 1 == 1) ? (value >> 1) ^ 0xedb88320 : value >> 1
        }
        return value
    }
    private var state: UInt32 = 0xffffffff

    mutating func update(_ data: Data) {
        for byte in data {
            state = Self.table[Int((state ^ UInt32(byte)) & 0xff)] ^ (state >> 8)
        }
    }

    var value: UInt32 { state ^ 0xffffffff }
}