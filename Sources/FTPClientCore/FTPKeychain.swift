import Foundation
import Security

public enum FTPKeychain {
    /// Reads a generic-password item accessible to the current process or access group.
    public static func password(service: String, account: String, accessGroup: String? = nil) throws -> String {
        guard !service.isEmpty, !account.isEmpty else { throw FTPError.invalidState(description: "Keychain service and account are required") }
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let accessGroup, !accessGroup.isEmpty { query[kSecAttrAccessGroup as String] = accessGroup }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let bytes = result as? Data,
              let value = String(data: bytes, encoding: .utf8) else {
            throw FTPError.invalidState(description: "Unable to read UTF-8 Keychain password (status \(status))")
        }
        return value
    }
}