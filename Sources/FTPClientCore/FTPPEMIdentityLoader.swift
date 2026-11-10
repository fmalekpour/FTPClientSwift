import Foundation
import Security
import CryptoKit
import CommonCrypto

/// PEM parsing and PBES2 decryption are deliberately bounded. SecIdentityCreate
/// checks that the private key corresponds to the selected certificate.
enum FTPPEMIdentityLoader {
    private static let maximumBytes = 8_388_608
    private static let rsaOID: [UInt8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]
    private static let ecOID: [UInt8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]
    private static let p256OID: [UInt8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
    private static let p384OID: [UInt8] = [0x2b, 0x81, 0x04, 0x00, 0x22]
    private static let p521OID: [UInt8] = [0x2b, 0x81, 0x04, 0x00, 0x23]
    private static let pbes2OID: [UInt8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d]
    private static let pbkdf2OID: [UInt8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c]
    private static let hmacPrefix: [UInt8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02]
    private static let aesPrefix: [UInt8] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01]

    private struct Block {
        let label: String
        let data: Data
    }

    static func load(_ pem: Data, passphrase: String) throws -> FTPImportedIdentity {
        let blocks = try parsePEM(pem)
        var certificates: [SecCertificate] = []
        var keyBlock: Block?
        for block in blocks {
            if block.label == "CERTIFICATE" {
                guard certificates.count < 32,
                      let certificate = SecCertificateCreateWithData(nil, block.data as CFData) else {
                    throw FTPError.invalidState(description: "Invalid PEM certificate chain")
                }
                certificates.append(certificate)
            } else {
                guard keyBlock == nil else { throw FTPError.invalidState(description: "PEM contains multiple private keys") }
                keyBlock = block
            }
        }
        guard !certificates.isEmpty, let keyBlock else {
            throw FTPError.invalidState(description: "PEM must contain a certificate and private key")
        }
        let key: SecKey
        switch keyBlock.label {
        case "RSA PRIVATE KEY": key = try rsaKey(keyBlock.data)
        case "EC PRIVATE KEY": key = try ecKey(keyBlock.data, curve: nil)
        case "PRIVATE KEY": key = try pkcs8Key(keyBlock.data)
        case "ENCRYPTED PRIVATE KEY":
            var plaintext = try decryptPKCS8(keyBlock.data, passphrase: passphrase)
            defer { plaintext.resetBytes(in: 0..<plaintext.count) }
            do { key = try pkcs8Key(plaintext) }
            catch { throw FTPError.invalidState(description: "Decrypted PKCS#8 private key is invalid: \(error)") }
        default: throw FTPError.invalidState(description: "Unsupported PEM private key")
        }
        for (index, certificate) in certificates.enumerated() {
            if let identity = SecIdentityCreate(nil, certificate, key) {
                var chain = certificates
                chain.remove(at: index)
                return FTPImportedIdentity(identity: identity, certificates: chain)
            }
        }
        throw FTPError.invalidState(description: "PEM certificate does not match the private key")
    }

    private static func parsePEM(_ data: Data) throws -> [Block] {
        guard !data.isEmpty, data.count <= maximumBytes, let text = String(data: data, encoding: .utf8) else {
            throw FTPError.invalidState(description: "Invalid or oversized PEM data")
        }
        let allowed: Set<String> = ["CERTIFICATE", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"]
        var label: String?
        var body = ""
        var blocks: [Block] = []
        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if let current = label {
                if line == "-----END \(current)-----" {
                    guard !body.isEmpty, let decoded = Data(base64Encoded: body), !decoded.isEmpty else {
                        throw FTPError.invalidState(description: "Invalid PEM base64")
                    }
                    blocks.append(Block(label: current, data: decoded))
                    guard blocks.count <= 33 else { throw FTPError.invalidState(description: "Too many PEM blocks") }
                    label = nil
                    body = ""
                } else {
                    guard !line.contains(":"), !line.hasPrefix("-----"), line.utf8.allSatisfy({
                        (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 43 || $0 == 47 || $0 == 61
                    }) else {
                        throw FTPError.invalidState(description: "Unsupported or malformed PEM block; legacy PEM encryption is not supported")
                    }
                    body += line
                }
            } else if line.hasPrefix("-----BEGIN ") && line.hasSuffix("-----") {
                let name = String(line.dropFirst(11).dropLast(5))
                guard allowed.contains(name) else { throw FTPError.invalidState(description: "Unsupported PEM block: \(name)") }
                label = name
            } else if line.hasPrefix("-----") {
                throw FTPError.invalidState(description: "Malformed PEM boundary")
            }
        }
        guard label == nil else { throw FTPError.invalidState(description: "Unterminated PEM block") }
        return blocks
    }

    private static func pkcs8Key(_ data: Data) throws -> SecKey {
        var outer = FTPDERReader(bytes: Array(data))
        var info = try outer.require(0x30).reader()
        guard outer.isAtEnd else { throw invalidKey() }
        let version = try positiveInteger(info.require(0x02).bytes)
        guard version == 0 || version == 1 else { throw invalidKey() }
        var algorithm = try info.require(0x30).reader()
        let oid = try algorithm.require(0x06).bytes
        let parameter = algorithm.isAtEnd ? nil : try algorithm.read()
        guard algorithm.isAtEnd else { throw invalidKey() }
        let privateBytes = Data(try info.require(0x04).bytes)
        while !info.isAtEnd {
            let extra = try info.read()
            guard extra.tag == 0xa0 || extra.tag == 0x81 else { throw invalidKey() }
        }
        if oid == rsaOID {
            guard parameter == nil || (parameter?.tag == 0x05 && parameter?.bytes.isEmpty == true) else { throw invalidKey() }
            return try rsaKey(privateBytes)
        }
        if oid == ecOID, let parameter, parameter.tag == 0x06 {
            return try ecKey(privateBytes, curve: parameter.bytes)
        }
        throw FTPError.invalidState(description: "Unsupported PKCS#8 private key algorithm")
    }

    private static func rsaKey(_ data: Data) throws -> SecKey {
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                         kSecAttrKeyClass as String: kSecAttrKeyClassPrivate]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else { throw invalidKey() }
        return key
    }

    private static func ecKey(_ data: Data, curve suppliedCurve: [UInt8]?) throws -> SecKey {
        var outer = FTPDERReader(bytes: Array(data))
        var info = try outer.require(0x30).reader()
        guard outer.isAtEnd, try positiveInteger(info.require(0x02).bytes) == 1 else { throw invalidKey() }
        let scalar = Data(try info.require(0x04).bytes)
        var curve = suppliedCurve
        var seenParameters = false
        var seenPublic = false
        while !info.isAtEnd {
            let extra = try info.read()
            if extra.tag == 0xa0 {
                guard !seenParameters else { throw invalidKey() }
                seenParameters = true
                var parameter = extra.reader()
                let embedded = try parameter.require(0x06).bytes
                guard parameter.isAtEnd, curve == nil || curve == embedded else { throw invalidKey() }
                curve = embedded
            } else if extra.tag == 0xa1 {
                guard !seenPublic else { throw invalidKey() }
                seenPublic = true
            } else { throw invalidKey() }
        }
        let external: Data
        do {
            switch curve {
            case p256OID: external = try P256.Signing.PrivateKey(rawRepresentation: scalar).x963Representation
            case p384OID: external = try P384.Signing.PrivateKey(rawRepresentation: scalar).x963Representation
            case p521OID: external = try P521.Signing.PrivateKey(rawRepresentation: scalar).x963Representation
            default: throw FTPError.invalidState(description: "Unsupported PEM EC curve")
            }
        } catch { throw invalidKey() }
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                         kSecAttrKeyClass as String: kSecAttrKeyClassPrivate]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(external as CFData, attributes as CFDictionary, &error) else { throw invalidKey() }
        return key
    }

    static func decryptPKCS8(_ encrypted: Data, passphrase: String) throws -> Data {
        var outer = FTPDERReader(bytes: Array(encrypted))
        var info = try outer.require(0x30).reader()
        guard outer.isAtEnd else { throw invalidKey() }
        var algorithm = try info.require(0x30).reader()
        guard try algorithm.require(0x06).bytes == pbes2OID else {
            throw FTPError.invalidState(description: "Only PBES2-encrypted PKCS#8 keys are supported")
        }
        var parameters = try algorithm.require(0x30).reader()
        guard algorithm.isAtEnd else { throw invalidKey() }
        var kdf = try parameters.require(0x30).reader()
        guard try kdf.require(0x06).bytes == pbkdf2OID else { throw invalidKey() }
        var kdfParameters = try kdf.require(0x30).reader()
        guard kdf.isAtEnd else { throw invalidKey() }
        let salt = Data(try kdfParameters.require(0x04).bytes)
        let iterations = try positiveInteger(kdfParameters.require(0x02).bytes)
        guard (8...1024).contains(salt.count), (1...2_000_000).contains(iterations) else { throw invalidKey() }
        var requestedKeySize: Int?
        var prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        if !kdfParameters.isAtEnd {
            var next = try kdfParameters.read()
            if next.tag == 0x02 {
                requestedKeySize = try positiveInteger(next.bytes)
                if !kdfParameters.isAtEnd { next = try kdfParameters.read() }
                else { next = FTPDERReader.Element(tag: 0, bytes: []) }
            }
            if next.tag != 0 {
                guard next.tag == 0x30 else { throw invalidKey() }
                var prfAlgorithm = next.reader()
                let oid = try prfAlgorithm.require(0x06).bytes
                guard oid.count == hmacPrefix.count + 1, oid.starts(with: hmacPrefix) else { throw invalidKey() }
                switch oid.last {
                case 7: prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
                case 9: prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
                case 10: prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
                case 11: prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
                default: throw FTPError.invalidState(description: "Unsupported PBKDF2 PRF")
                }
                if !prfAlgorithm.isAtEnd {
                    let null = try prfAlgorithm.require(0x05)
                    guard null.bytes.isEmpty else { throw invalidKey() }
                }
                guard prfAlgorithm.isAtEnd else { throw invalidKey() }
            }
            guard kdfParameters.isAtEnd else { throw invalidKey() }
        }
        var encryption = try parameters.require(0x30).reader()
        let oid = try encryption.require(0x06).bytes
        guard oid.count == aesPrefix.count + 1, oid.starts(with: aesPrefix) else {
            throw FTPError.invalidState(description: "Only AES-CBC encrypted PKCS#8 keys are supported")
        }
        let keySize: Int
        switch oid.last {
        case 2: keySize = 16
        case 22: keySize = 24
        case 42: keySize = 32
        default: throw FTPError.invalidState(description: "Unsupported PKCS#8 cipher")
        }
        let iv = Data(try encryption.require(0x04).bytes)
        let ciphertext = Data(try info.require(0x04).bytes)
        guard encryption.isAtEnd, parameters.isAtEnd, info.isAtEnd, iv.count == 16,
              !ciphertext.isEmpty, ciphertext.count % 16 == 0,
              requestedKeySize == nil || requestedKeySize == keySize else { throw invalidKey() }
        var key = Data(count: keySize)
        var password = Data(passphrase.utf8)
        defer {
            key.resetBytes(in: 0..<key.count)
            password.resetBytes(in: 0..<password.count)
        }
        let derivation = password.withUnsafeBytes { passBytes in
            salt.withUnsafeBytes { saltBytes in
                key.withUnsafeMutableBytes { keyBytes in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), passBytes.bindMemory(to: Int8.self).baseAddress, password.count,
                                        saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count, prf,
                                        UInt32(iterations), keyBytes.bindMemory(to: UInt8.self).baseAddress, keySize)
                }
            }
        }
        guard derivation == kCCSuccess else { throw invalidKey() }
        var result = Data(count: ciphertext.count)
        var written = 0
        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                ciphertext.withUnsafeBytes { encryptedBytes in
                    result.withUnsafeMutableBytes { output in
                        CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(0),
                                keyBytes.baseAddress, keySize, ivBytes.baseAddress, encryptedBytes.baseAddress,
                                ciphertext.count, output.baseAddress, output.count, &written)
                    }
                }
            }
        }
        guard status == kCCSuccess, written == ciphertext.count, let last = result.last, (1...16).contains(last) else {
            throw FTPError.invalidState(description: "Unable to decrypt PKCS#8 private key")
        }
        let padding = Int(last)
        var mismatch: UInt8 = 0
        for offset in 1...16 {
            let byte = result[result.count - offset]
            if offset <= padding { mismatch |= byte ^ last }
        }
        guard mismatch == 0 else { throw FTPError.invalidState(description: "Unable to decrypt PKCS#8 private key") }
        result.removeLast(padding)
        return result
    }

    private static func positiveInteger(_ bytes: [UInt8]) throws -> Int {
        guard !bytes.isEmpty, bytes.count <= 5, bytes[0] & 0x80 == 0,
              bytes.count == 1 || bytes[0] != 0 || bytes[1] & 0x80 != 0 else { throw invalidKey() }
        var value = 0
        for byte in bytes { value = (value << 8) | Int(byte) }
        return value
    }

    private static func invalidKey() -> FTPError {
        .invalidState(description: "Invalid or unsupported PEM private key")
    }
}