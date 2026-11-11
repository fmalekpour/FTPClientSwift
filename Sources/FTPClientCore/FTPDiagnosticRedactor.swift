import Foundation

/// Shared sanitization for console diagnostics and the retained protocol transcript.
enum FTPDiagnosticRedactor {
    static func secrets(in configuration: FTPClientConfiguration) -> [String] {
        var values = [configuration.username, configuration.password]
        if let account = configuration.account { values.append(account) }
        if let identity = configuration.clientIdentity { values.append(identity.passphrase) }
        switch configuration.proxy {
        case .httpConnect(_, _, let user, let password), .socks5(_, _, let user, let password):
            values += [user ?? "", password ?? ""]
        case .httpNTLM(_, _, let user, let password, let domain):
            values += [user, password, domain]
        case .socks4(_, _, let user):
            values.append(user)
        case .traditional(_, _, _, let user, let password):
            values += [user, password]
        case nil:
            break
        }
        return Array(Set(values.filter { !$0.isEmpty })).sorted { $0.count > $1.count }
    }

    static func redact(_ message: String, secrets: [String], enabled: Bool = true) -> String {
        var result = message
        for secret in secrets where enabled && !secret.isEmpty {
            result = result.replacingOccurrences(of: secret, with: "[redacted]")
        }
        // Keep server-controlled text on one line and prevent terminal escape sequences.
        return result.unicodeScalars.map { scalar in
            if scalar.value < 32 || (127...159).contains(scalar.value) {
                return String(format: "\\u{%04X}", scalar.value)
            }
            return String(scalar)
        }.joined()
    }
}
