import Foundation
import Compression

/// FTP MODE Z uses RFC 1950 zlib framing, while Apple's Compression API emits raw RFC 1951 DEFLATE.
final class FTPZlibStream {
    static let maximumInputBytes = 1_048_576
    static let maximumOutputPerChunk = 16_777_216
    private var stream = unsafeBitCast((UInt(0), UInt(0), UInt(0), UInt(0), UInt(0)), to: compression_stream.self)
    private let encode: Bool
    private var initialized = false
    private var ended = false
    private var finished = false
    private var headerProcessed = false
    private var pending = Data()
    private var rawPending = Data()
    private var adlerA: UInt32 = 1
    private var adlerB: UInt32 = 0

    init(encoding: Bool) throws {
        encode = encoding
        let operation = encoding ? COMPRESSION_STREAM_ENCODE : COMPRESSION_STREAM_DECODE
        guard compression_stream_init(&stream, operation, COMPRESSION_ZLIB) == COMPRESSION_STATUS_OK else {
            throw FTPError.invalidState(description: "Unable to initialize MODE Z compression")
        }
        initialized = true
    }

    deinit { if initialized { compression_stream_destroy(&stream) } }

    private func updateChecksum(_ data: Data) {
        for byte in data {
            adlerA = (adlerA + UInt32(byte)) % 65521
            adlerB = (adlerB + adlerA) % 65521
        }
    }

    func process(_ data: Data, final: Bool) throws -> Data {
        guard !finished else { throw FTPError.protocolViolation(description: "MODE Z stream already ended") }
        if encode {
            updateChecksum(data)
            var output = Data()
            if !headerProcessed { output.append(contentsOf: [0x78, 0x9c]); headerProcessed = true }
            output.append(try processRaw(data, final: final))
            if final {
                guard ended else { throw FTPError.protocolViolation(description: "Incomplete MODE Z compression") }
                let checksum = (adlerB << 16) | adlerA
                output.append(contentsOf: [UInt8((checksum >> 24) & 255), UInt8((checksum >> 16) & 255), UInt8((checksum >> 8) & 255), UInt8(checksum & 255)])
                finished = true
            }
            return output
        }

        pending.append(data)
        if !headerProcessed {
            guard pending.count >= 2 else {
                if final { throw FTPError.protocolViolation(description: "Incomplete MODE Z header") }
                return Data()
            }
            let header = Array(pending.prefix(2))
            guard header[0] & 15 == 8, header[0] >> 4 <= 7,
                  (Int(header[0]) * 256 + Int(header[1])) % 31 == 0, header[1] & 0x20 == 0 else {
                throw FTPError.protocolViolation(description: "Invalid MODE Z header")
            }
            pending.removeFirst(2)
            headerProcessed = true
        }
        if final && pending.count < 4 { throw FTPError.protocolViolation(description: "Incomplete MODE Z checksum") }
        let bodyCount = max(0, pending.count - 4)
        guard !ended || bodyCount == 0 else { throw FTPError.protocolViolation(description: "Extra data after MODE Z stream") }
        if bodyCount > 0 {
            rawPending.append(pending.prefix(bodyCount))
            pending.removeFirst(bodyCount)
        }
        let result = ended ? Data() : try processRaw(rawPending, final: final)
        updateChecksum(result)
        if final {
            guard ended, pending.count == 4 else { throw FTPError.protocolViolation(description: "Incomplete MODE Z stream") }
            let bytes = Array(pending)
            let received = UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
            guard received == ((adlerB << 16) | adlerA) else { throw FTPError.protocolViolation(description: "MODE Z checksum mismatch") }
            finished = true
        }
        return result
    }

    private func processRaw(_ data: Data, final: Bool) throws -> Data {
        let storage = data.isEmpty ? Data([0]) : data
        var result = Data()
        var consumed = 0
        try storage.withUnsafeBytes { source in
            stream.src_ptr = source.bindMemory(to: UInt8.self).baseAddress!
            stream.src_size = data.count
            while true {
                let before = stream.src_size
                var output = [UInt8](repeating: 0, count: 65_536)
                let status = output.withUnsafeMutableBufferPointer { target in
                    stream.dst_ptr = target.baseAddress!
                    stream.dst_size = target.count
                    return compression_stream_process(&stream, final ? Int32(COMPRESSION_STREAM_FINALIZE.rawValue) : 0)
                }
                let produced = output.count - stream.dst_size
                guard result.count + produced <= Self.maximumOutputPerChunk else {
                    throw FTPError.protocolViolation(description: "MODE Z decompressed chunk exceeds limit")
                }
                result.append(contentsOf: output.prefix(produced))
                guard status != COMPRESSION_STATUS_ERROR else { throw FTPError.protocolViolation(description: "Invalid MODE Z stream") }
                if status == COMPRESSION_STATUS_END {
                    guard stream.src_size == 0 else { throw FTPError.protocolViolation(description: "Extra data after MODE Z stream") }
                    ended = true
                    break
                }
                if stream.src_size == 0 && !final { break }
                if before == stream.src_size && produced == 0 {
                    if final { throw FTPError.protocolViolation(description: "Truncated MODE Z stream") }
                    break
                }
            }
            consumed = data.count - stream.src_size
        }
        if !encode { rawPending.removeFirst(consumed) }
        else if consumed != data.count { throw FTPError.protocolViolation(description: "Unable to compress complete MODE Z input") }
        return result
    }
}