import Foundation
import CommonCrypto
import Security

/// NTLMv2 is used only for legacy HTTP proxy authentication. It does not
/// authenticate or encrypt the proxy connection and is susceptible to relay.
enum FTPNTLMv2 {
    private static let signature = Array("NTLMSSP\0".utf8)
    private static let flags: UInt32 = 0xa0888205 // Unicode, NTLM, ESS, target-info, 128/56-bit

    static func negotiate() -> Data {
        var result = Data(signature)
        append32(1, to: &result)
        append32(flags, to: &result)
        result.append(contentsOf: repeatElement(0, count: 16))
        return result
    }

    static func authenticate(challenge: Data, negotiate: Data, username: String, password: String, domain: String,
                             nonce: Data? = nil, timestamp: UInt64? = nil) throws -> Data {
        guard !username.isEmpty, !username.utf16.contains(0), !domain.utf16.contains(0),
              challenge.count >= 48, challenge.count <= 16_384 else { throw invalidChallenge() }
        let bytes = Array(challenge)
        guard Array(bytes[0..<8]) == signature, read32(bytes, 8) == 2 else { throw invalidChallenge() }
        let serverFlags = read32(bytes, 20)
        let required: UInt32 = 0x00880201 // target info, extended session security, NTLM, Unicode
        guard serverFlags & required == required else { throw FTPError.connectionFailed(description: "Proxy does not support NTLMv2") }
        _ = try field(bytes, at: 12)
        let information = try field(bytes, at: 40)
        guard !information.isEmpty else { throw invalidChallenge() }
        var pairs: [(UInt16, Data)] = []
        var offset = 0
        var seen = Set<UInt16>()
        var serverTime: UInt64?
        var avFlags: UInt32 = 0
        var terminated = false
        let info = Array(information)
        while offset + 4 <= info.count {
            let id = read16(info, offset), length = Int(read16(info, offset + 2))
            offset += 4
            guard length <= info.count - offset else { throw invalidChallenge() }
            if id == 0 {
                guard length == 0, offset == info.count else { throw invalidChallenge() }
                terminated = true
                break
            }
            guard seen.insert(id).inserted else { throw invalidChallenge() }
            let value = Data(info[offset..<(offset + length)])
            if id == 7 {
                guard length == 8 else { throw invalidChallenge() }
                serverTime = read64(Array(value), 0)
            } else if id == 6 {
                guard length == 4 else { throw invalidChallenge() }
                avFlags = read32(Array(value), 0)
            } else if id == 10 {
                // There is no authenticated TLS channel to the HTTP proxy.
                guard length == 16, value.allSatisfy({ $0 == 0 }) else {
                    throw FTPError.notImplemented(feature: "NTLM proxy TLS channel binding")
                }
            }
            pairs.append((id, value))
            offset += length
        }
        guard terminated else { throw invalidChallenge() }
        let includeMIC = serverTime != nil || avFlags & 2 != 0
        if includeMIC {
            if let index = pairs.firstIndex(where: { $0.0 == 6 }) {
                var value = Data(); append32(avFlags | 2, to: &value); pairs[index].1 = value
            } else {
                var value = Data(); append32(2, to: &value); pairs.append((6, value))
            }
        }
        var targetInfo = Data()
        for (id, value) in pairs {
            guard let length = UInt16(exactly: value.count) else { throw invalidChallenge() }
            append16(id, to: &targetInfo); append16(length, to: &targetInfo); targetInfo.append(value)
        }
        append32(0, to: &targetInfo)

        let clientNonce: Data
        if let nonce {
            guard nonce.count == 8 else { throw invalidChallenge() }
            clientNonce = nonce
        } else {
            var random = [UInt8](repeating: 0, count: 8)
            guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else {
                throw FTPError.connectionFailed(description: "Unable to generate NTLM nonce")
            }
            clientNonce = Data(random)
        }
        let now = Date().timeIntervalSince1970 + 11_644_473_600
        guard now.isFinite, now >= 0, now < Double(UInt64.max) / 10_000_000 else { throw invalidChallenge() }
        let time = serverTime ?? timestamp ?? UInt64(now * 10_000_000)
        var blob = Data([1, 1, 0, 0, 0, 0, 0, 0])
        append64(time, to: &blob)
        blob.append(clientNonce)
        append32(0, to: &blob)
        blob.append(targetInfo)
        append32(0, to: &blob)
        var passwordBytes = utf16(password)
        defer { passwordBytes.resetBytes(in: 0..<passwordBytes.count) }
        var ntHash = md4(passwordBytes)
        defer { ntHash.resetBytes(in: 0..<ntHash.count) }
        var responseKey = hmac(ntHash, utf16(username.uppercased() + domain))
        defer { responseKey.resetBytes(in: 0..<responseKey.count) }
        let serverNonce = Data(bytes[24..<32])
        let proof = hmac(responseKey, serverNonce + blob)
        let ntResponse = proof + blob
        let lmResponse = serverTime != nil ? Data(repeating: 0, count: 24) : hmac(responseKey, serverNonce + clientNonce) + clientNonce
        let names = [lmResponse, ntResponse, utf16(domain), utf16(username), Data(), Data()]
        let headerSize = includeMIC ? 88 : 64
        var message = Data(signature)
        append32(3, to: &message)
        var payloadOffset = headerSize
        for value in names {
            guard let length = UInt16(exactly: value.count), let position = UInt32(exactly: payloadOffset) else { throw invalidChallenge() }
            append16(length, to: &message); append16(length, to: &message); append32(position, to: &message)
            payloadOffset += value.count
        }
        append32(serverFlags & flags, to: &message)
        if includeMIC { message.append(Data(repeating: 0, count: 24)) } // empty VERSION, zeroed MIC
        for value in names { message.append(value) }
        if includeMIC {
            var sessionKey = hmac(responseKey, proof)
            defer { sessionKey.resetBytes(in: 0..<sessionKey.count) }
            let mic = hmac(sessionKey, negotiate + challenge + message)
            message.replaceSubrange(72..<88, with: mic)
        }
        return message
    }

    private static func field(_ bytes: [UInt8], at offset: Int) throws -> Data {
        let length = Int(read16(bytes, offset)), maximum = Int(read16(bytes, offset + 2)), start = Int(read32(bytes, offset + 4))
        guard length <= maximum, start <= bytes.count, length <= bytes.count - start,
              length == 0 || start >= 48 else { throw invalidChallenge() }
        return Data(bytes[start..<(start + length)])
    }

    private static func utf16(_ text: String) -> Data {
        var result = Data()
        for unit in text.utf16 { append16(unit, to: &result) }
        return result
    }
    private static func md4(_ data: Data) -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD4_DIGEST_LENGTH))
        data.withUnsafeBytes { _ = CC_MD4($0.baseAddress, CC_LONG($0.count), &digest) }
        return Data(digest)
    }
    private static func hmac(_ key: Data, _ data: Data) -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        key.withUnsafeBytes { k in data.withUnsafeBytes { d in
            CCHmac(CCHmacAlgorithm(kCCHmacAlgMD5), k.baseAddress, k.count, d.baseAddress, d.count, &digest)
        } }
        return Data(digest)
    }
    private static func append16(_ value: UInt16, to data: inout Data) { data.append(UInt8(value & 255)); data.append(UInt8(value >> 8)) }
    private static func append32(_ value: UInt32, to data: inout Data) { for shift in stride(from: 0, through: 24, by: 8) { data.append(UInt8((value >> shift) & 255)) } }
    private static func append64(_ value: UInt64, to data: inout Data) { for shift in stride(from: 0, through: 56, by: 8) { data.append(UInt8((value >> shift) & 255)) } }
    private static func read16(_ data: [UInt8], _ offset: Int) -> UInt16 { UInt16(data[offset]) | (UInt16(data[offset + 1]) << 8) }
    private static func read32(_ data: [UInt8], _ offset: Int) -> UInt32 { (0..<4).reduce(0) { $0 | (UInt32(data[offset + $1]) << (8 * $1)) } }
    private static func read64(_ data: [UInt8], _ offset: Int) -> UInt64 { (0..<8).reduce(0) { $0 | (UInt64(data[offset + $1]) << (8 * $1)) } }
    private static func invalidChallenge() -> FTPError { .protocolViolation(description: "Malformed NTLM proxy challenge") }
}