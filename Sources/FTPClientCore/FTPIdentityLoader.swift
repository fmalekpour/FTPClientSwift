import Foundation
import Security

struct FTPImportedIdentity: @unchecked Sendable {
    let identity: SecIdentity
    let certificates: [SecCertificate]
    private let owner: AnyObject?

    init(identity: SecIdentity, certificates: [SecCertificate], owner: AnyObject? = nil) {
        self.identity = identity
        self.certificates = certificates
        self.owner = owner
    }

    static func load(_ source: FTPClientIdentity) throws -> FTPImportedIdentity {
        if let pem = source.pemData {
            return try FTPPEMIdentityLoader.load(pem, passphrase: source.passphrase)
        }
        #if os(macOS)
        if #unavailable(macOS 15) {
            return try loadLegacyMacOSIdentity(source)
        }
        #endif
        var options: [String: Any] = [kSecImportExportPassphrase as String: source.passphrase]
        if #available(macOS 15, iOS 18, tvOS 18, watchOS 11, *) {
            options[kSecImportToMemoryOnly as String] = true
        }
        return try importPKCS12(source, options: options)
    }

    private static func importPKCS12(_ source: FTPClientIdentity, options: [String: Any], owner: AnyObject? = nil) throws -> FTPImportedIdentity {
        var result: CFArray?
        let status = SecPKCS12Import(source.pkcs12Data as CFData, options as CFDictionary, &result)
        guard status == errSecSuccess,
              let entries = result as? [[String: Any]], let first = entries.first,
              let value = first[kSecImportItemIdentity as String],
              CFGetTypeID(value as CFTypeRef) == SecIdentityGetTypeID() else {
            throw FTPError.invalidState(description: "Unable to import PKCS#12 client identity (status \(status))")
        }
        let identity = value as! SecIdentity
        let chain = first[kSecImportItemCertChain as String] as? [SecCertificate] ?? []
        return FTPImportedIdentity(identity: identity, certificates: Array(chain.dropFirst()), owner: owner)
    }

    #if os(macOS)
    var temporaryKeychainDirectory: URL? { (owner as? FTPEphemeralKeychain)?.directory }

    /// macOS 14 has no kSecImportToMemoryOnly. Import into an isolated,
    /// randomly password-protected temporary keychain, never the default one.
    static func loadLegacyMacOSIdentity(_ source: FTPClientIdentity) throws -> FTPImportedIdentity {
        let owner = try FTPEphemeralKeychain()
        var access: SecAccess?
        let accessStatus = SecAccessCreate("FTPClientSwift temporary identity" as CFString, nil, &access)
        guard accessStatus == errSecSuccess, let access else {
            throw FTPError.invalidState(description: "Unable to configure temporary identity access (status \(accessStatus))")
        }
        let options: [String: Any] = [kSecImportExportPassphrase as String: source.passphrase,
                                      kSecImportExportKeychain as String: owner.keychain,
                                      kSecImportExportAccess as String: access]
        return try importPKCS12(source, options: options, owner: owner)
    }
    #endif
}

#if os(macOS)
private final class FTPEphemeralKeychain {
    let keychain: SecKeychain
    let directory: URL

    init() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("ftp-identity-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        var initialized = false
        defer { if !initialized { try? FileManager.default.removeItem(at: directory) } }
        var password = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, password.count, &password) == errSecSuccess else {
            throw FTPError.invalidState(description: "Unable to generate temporary Keychain password")
        }
        defer { password.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        var keychain: SecKeychain?
        let path = directory.appendingPathComponent("identity.keychain").path
        let result = password.withUnsafeBytes { bytes in
            path.withCString { SecKeychainCreate($0, UInt32(bytes.count), bytes.baseAddress, false, nil, &keychain) }
        }
        guard result == errSecSuccess, let keychain else {
            throw FTPError.invalidState(description: "Unable to create isolated client identity Keychain (status \(result))")
        }
        self.keychain = keychain
        self.directory = directory
        initialized = true
    }

    deinit {
        SecKeychainDelete(keychain)
        try? FileManager.default.removeItem(at: directory)
    }
}
#endif