import Foundation

enum FTPTLSPolicy {
    static func cipherName(_ code: UInt16) -> String {
        switch code {
        case 0x1301: return "TLS_AES_128_GCM_SHA256"
        case 0x1302: return "TLS_AES_256_GCM_SHA384"
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256"
        case 0xc02f: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        case 0xc030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        case 0xc02b: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        case 0xc02c: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        case 0xcca8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        case 0xcca9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        default: return String(format: "0x%04X", code)
        }
    }

    static func cipherCodes(_ names: [String]) throws -> [UInt16] {
        let supported: [String: UInt16] = [
            "TLS_AES_128_GCM_SHA256": 0x1301,
            "TLS_AES_256_GCM_SHA384": 0x1302,
            "TLS_CHACHA20_POLY1305_SHA256": 0x1303,
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": 0xc02f,
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": 0xc030,
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 0xc02b,
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 0xc02c,
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 0xcca8,
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 0xcca9,
        ]
        return try names.map { name in
            guard let code = supported[name.uppercased()] else {
                throw FTPError.invalidState(description: "Unsupported TLS cipher suite: \(name)")
            }
            return code
        }
    }
}