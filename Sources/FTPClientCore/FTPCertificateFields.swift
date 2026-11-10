import Foundation
import Darwin

/// A bounded DER reader used only for additional checks after system TLS trust validation.
struct FTPDERReader {
    struct Element {
        let tag: UInt8
        let bytes: [UInt8]
        func reader() -> FTPDERReader { FTPDERReader(bytes: bytes) }
    }

    let bytes: [UInt8]
    private(set) var offset = 0
    var isAtEnd: Bool { offset == bytes.count }

    init(bytes: [UInt8]) { self.bytes = bytes }

    mutating func read() throws -> Element {
        guard offset < bytes.count else { throw FTPError.protocolViolation(description: "Truncated certificate DER") }
        let tag = bytes[offset]
        offset += 1
        guard tag & 0x1f != 0x1f, offset < bytes.count else { throw FTPError.protocolViolation(description: "Unsupported certificate DER tag") }
        let first = bytes[offset]
        offset += 1
        let length: Int
        if first < 0x80 {
            length = Int(first)
        } else {
            let count = Int(first & 0x7f)
            guard count > 0, count <= 4, count <= bytes.count - offset, bytes[offset] != 0 else {
                throw FTPError.protocolViolation(description: "Invalid certificate DER length")
            }
            var value = 0
            for byte in bytes[offset..<(offset + count)] { value = (value << 8) | Int(byte) }
            offset += count
            guard value >= 128 else { throw FTPError.protocolViolation(description: "Noncanonical certificate DER length") }
            length = value
        }
        guard length <= bytes.count - offset else { throw FTPError.protocolViolation(description: "Truncated certificate DER value") }
        let value = Array(bytes[offset..<(offset + length)])
        offset += length
        return Element(tag: tag, bytes: value)
    }

    mutating func require(_ tag: UInt8) throws -> Element {
        let element = try read()
        guard element.tag == tag else { throw FTPError.protocolViolation(description: "Unexpected certificate DER field") }
        return element
    }
}

enum FTPCertificateFields {
    private struct Name {
        let distinguished: String
        let commonNames: [String]
    }

    static func satisfies(_ requirements: [FTPCertificateRequirement], certificate: Data) -> Bool {
        guard !requirements.isEmpty else { return true }
        guard certificate.count <= 1_048_576, requirements.allSatisfy({ !$0.pattern.utf8.contains(0) }) else { return false }
        do {
            var certificateReader = FTPDERReader(bytes: Array(certificate))
            var outer = try certificateReader.require(0x30).reader()
            guard certificateReader.isAtEnd else { return false }
            var tbs = try outer.require(0x30).reader()
            _ = try outer.require(0x30) // outer signature algorithm
            _ = try outer.require(0x03) // signature value
            guard outer.isAtEnd else { return false }
            var first = try tbs.read()
            if first.tag == 0xa0 { first = try tbs.read() }
            guard first.tag == 0x02 else { return false }
            _ = try tbs.require(0x30) // signature algorithm
            let issuer = try parseName(tbs.require(0x30))
            _ = try tbs.require(0x30) // validity
            let subject = try parseName(tbs.require(0x30))
            _ = try tbs.require(0x30) // subject public key
            var alternativeNames: [String] = []
            var sawExtensions = false
            while !tbs.isAtEnd {
                let element = try tbs.read()
                switch element.tag {
                case 0x81, 0x82: break // optional issuer/subject unique identifiers
                case 0xa3:
                    guard !sawExtensions else { return false }
                    sawExtensions = true
                    alternativeNames = try parseExtensions(element)
                default: return false
                }
            }
            return requirements.allSatisfy { requirement in
                let values: [String]
                switch requirement.field {
                case .subjectDN: values = [subject.distinguished]
                case .subjectCN: values = subject.commonNames
                case .issuerDN: values = [issuer.distinguished]
                case .issuerCN: values = issuer.commonNames
                case .subjectAlternativeName: values = alternativeNames
                }
                return requirement.pattern.withCString { pattern in
                    values.contains { value in value.withCString { fnmatch(pattern, $0, FNM_NOESCAPE) == 0 } }
                }
            }
        } catch { return false }
    }

    private static func parseName(_ element: FTPDERReader.Element) throws -> Name {
        var sequence = element.reader()
        var rdns: [[String]] = []
        var commonNames: [String] = []
        while !sequence.isAtEnd {
            var set = try sequence.require(0x31).reader()
            var attributes: [String] = []
            while !set.isAtEnd {
                var attribute = try set.require(0x30).reader()
                let oid = try parseOID(attribute.require(0x06).bytes)
                let value = try parseString(attribute.read())
                guard attribute.isAtEnd, !value.utf8.contains(0) else { throw FTPError.protocolViolation(description: "Invalid certificate name") }
                if oid == "2.5.4.3" { commonNames.append(value) }
                let shortName: String
                switch oid {
                case "2.5.4.3": shortName = "CN"
                case "2.5.4.6": shortName = "C"
                case "2.5.4.7": shortName = "L"
                case "2.5.4.8": shortName = "ST"
                case "2.5.4.9": shortName = "STREET"
                case "2.5.4.10": shortName = "O"
                case "2.5.4.11": shortName = "OU"
                case "2.5.4.5": shortName = "SERIALNUMBER"
                case "1.2.840.113549.1.9.1": shortName = "E"
                case "0.9.2342.19200300.100.1.25": shortName = "DC"
                case "0.9.2342.19200300.100.1.1": shortName = "UID"
                default: shortName = oid
                }
                attributes.append("\(shortName)=\(escapeDN(value))")
            }
            guard !attributes.isEmpty else { throw FTPError.protocolViolation(description: "Empty certificate RDN") }
            rdns.append(attributes)
        }
        return Name(distinguished: rdns.reversed().map { $0.joined(separator: "+") }.joined(separator: ","), commonNames: commonNames)
    }

    private static func parseString(_ element: FTPDERReader.Element) throws -> String {
        let data = Data(element.bytes)
        let value: String?
        switch element.tag {
        case 0x0c: value = String(data: data, encoding: .utf8)
        case 0x13, 0x16: value = String(data: data, encoding: .ascii)
        case 0x14: value = String(data: data, encoding: .isoLatin1)
        case 0x1e: value = String(data: data, encoding: .utf16BigEndian)
        default: value = nil
        }
        guard let value else { throw FTPError.protocolViolation(description: "Unsupported certificate name encoding") }
        return value
    }

    private static func parseOID(_ bytes: [UInt8]) throws -> String {
        guard !bytes.isEmpty else { throw FTPError.protocolViolation(description: "Empty certificate OID") }
        var numbers: [UInt64] = []
        var value: UInt64 = 0
        var inComponent = false
        for byte in bytes {
            guard value <= (UInt64.max >> 7), !(byte == 0x80 && !inComponent) else {
                throw FTPError.protocolViolation(description: "Invalid certificate OID")
            }
            value = (value << 7) | UInt64(byte & 0x7f)
            inComponent = true
            if byte & 0x80 == 0 { numbers.append(value); value = 0; inComponent = false }
        }
        guard !inComponent, let first = numbers.first else { throw FTPError.protocolViolation(description: "Truncated certificate OID") }
        let head: [UInt64] = first < 40 ? [0, first] : first < 80 ? [1, first - 40] : [2, first - 80]
        return (head + numbers.dropFirst()).map(String.init).joined(separator: ".")
    }

    private static func escapeDN(_ value: String) -> String {
        let characters = Array(value)
        return characters.enumerated().map { index, character in
            let reserved = ",+\"\\<>;=".contains(character)
            let edge = (index == 0 && (character == " " || character == "#")) || (index == characters.count - 1 && character == " ")
            return reserved || edge ? "\\\(character)" : String(character)
        }.joined()
    }

    private static func parseExtensions(_ element: FTPDERReader.Element) throws -> [String] {
        var explicit = element.reader()
        var extensions = try explicit.require(0x30).reader()
        guard explicit.isAtEnd else { throw FTPError.protocolViolation(description: "Invalid certificate extensions") }
        var names: [String] = []
        var sawSAN = false
        while !extensions.isAtEnd {
            var extensionReader = try extensions.require(0x30).reader()
            let oid = try parseOID(extensionReader.require(0x06).bytes)
            var value = try extensionReader.read()
            if value.tag == 0x01 { value = try extensionReader.read() }
            guard value.tag == 0x04, extensionReader.isAtEnd else { throw FTPError.protocolViolation(description: "Invalid certificate extension") }
            guard oid == "2.5.29.17" else { continue }
            guard !sawSAN else { throw FTPError.protocolViolation(description: "Duplicate subject alternative name extension") }
            sawSAN = true
            var wrapper = value.reader()
            var alternatives = try wrapper.require(0x30).reader()
            guard wrapper.isAtEnd else { throw FTPError.protocolViolation(description: "Invalid subject alternative names") }
            while !alternatives.isAtEnd {
                let name = try alternatives.read()
                switch name.tag {
                case 0x81, 0x82, 0x86:
                    guard let text = String(bytes: name.bytes, encoding: .ascii), !text.utf8.contains(0) else {
                        throw FTPError.protocolViolation(description: "Invalid subject alternative name")
                    }
                    names.append(text)
                case 0x87:
                    let family = name.bytes.count == 4 ? AF_INET : (name.bytes.count == 16 ? AF_INET6 : 0)
                    guard family != 0 else { throw FTPError.protocolViolation(description: "Invalid certificate IP address") }
                    var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    let bufferSize = socklen_t(buffer.count)
                    let converted = name.bytes.withUnsafeBytes { inet_ntop(family, $0.baseAddress, &buffer, bufferSize) }
                    guard converted != nil else { throw FTPError.protocolViolation(description: "Invalid certificate IP address") }
                    names.append(String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self))
                default: continue
                }
            }
        }
        return names
    }
}