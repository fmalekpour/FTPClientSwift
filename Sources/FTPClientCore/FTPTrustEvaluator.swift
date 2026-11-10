import Foundation
import Security
import CryptoKit

enum FTPTrustEvaluator {
    static func parsePins(_ pins: [String]) throws -> [Data] {
        try pins.map { value in
            let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
            let encoded: String
            if text.lowercased().hasPrefix("sha256/") { encoded = String(text.dropFirst(7)) }
            else { encoded = text }
            guard let digest = Data(base64Encoded: encoded), digest.count == 32 else {
                throw FTPError.invalidState(description: "Invalid SHA-256 SPKI pin")
            }
            return digest
        }
    }

    static func evaluate(_ trust: SecTrust, hostname: String, roots: [SecCertificate], requireChainValidation: Bool, pins: [Data]) -> Bool {
        guard SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, hostname as CFString)) == errSecSuccess else { return false }
        if !requireChainValidation {
            // Treat the presented leaf as an anchor but keep SSL hostname and certificate-policy checks.
            // This deliberately allows an attacker-controlled certificate for the expected hostname.
            guard let leaf = SecTrustGetCertificateAtIndex(trust, 0),
                  SecTrustSetAnchorCertificates(trust, [leaf] as CFArray) == errSecSuccess,
                  SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess else { return false }
        } else if !roots.isEmpty {
            guard SecTrustSetAnchorCertificates(trust, roots as CFArray) == errSecSuccess,
                  SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess else { return false }
        }
        guard SecTrustEvaluateWithError(trust, nil) else { return false }
        guard !pins.isEmpty else { return true }
        guard let certificate = SecTrustGetCertificateAtIndex(trust, 0),
              let key = SecCertificateCopyKey(certificate),
              let spki = subjectPublicKeyInfo(key) else { return false }
        let digest = Data(SHA256.hash(data: spki))
        return pins.contains(digest)
    }

    private static func der(_ tag: UInt8, _ body: Data) -> Data {
        var result = Data([tag])
        if body.count < 128 {
            result.append(UInt8(body.count))
        } else {
            var value = body.count
            var bytes: [UInt8] = []
            while value > 0 { bytes.insert(UInt8(value & 255), at: 0); value >>= 8 }
            result.append(0x80 | UInt8(bytes.count))
            result.append(contentsOf: bytes)
        }
        result.append(body)
        return result
    }

    private static func subjectPublicKeyInfo(_ key: SecKey) -> Data? {
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              let type = attributes[kSecAttrKeyType as String] as? String,
              let raw = SecKeyCopyExternalRepresentation(key, nil) as Data? else { return nil }
        let algorithm: Data
        if type == kSecAttrKeyTypeRSA as String {
            algorithm = Data([0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00])
        } else if type == kSecAttrKeyTypeECSECPrimeRandom as String,
                  let bits = attributes[kSecAttrKeySizeInBits as String] as? Int {
            switch bits {
            case 256: algorithm = Data([0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07])
            case 384: algorithm = Data([0x30,0x10,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x05,0x2b,0x81,0x04,0x00,0x22])
            case 521: algorithm = Data([0x30,0x10,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x05,0x2b,0x81,0x04,0x00,0x23])
            default: return nil
            }
        } else { return nil }
        var bitString = Data([0])
        bitString.append(raw)
        return der(0x30, algorithm + der(0x03, bitString))
    }
}