import Foundation
import Testing
@testable import FTPClientCore

@Test func ntlmRejectsMalformedChallengeBuffers() {
    let negotiate = FTPNTLMv2.negotiate()
    for size in 0..<48 {
        #expect(throws: FTPError.self) {
            try FTPNTLMv2.authenticate(challenge: Data(repeating: 0, count: size), negotiate: negotiate,
                                       username: "User", password: "Password", domain: "Domain")
        }
    }
    var challenge = Data("NTLMSSP\0".utf8) + Data(repeating: 0, count: 40)
    challenge[8] = 2
    challenge[20] = 1; challenge[21] = 2; challenge[22] = 0x88
    challenge[40] = 16; challenge[42] = 16; challenge[44] = 0xff; challenge[45] = 0xff
    #expect(throws: FTPError.self) {
        try FTPNTLMv2.authenticate(challenge: challenge, negotiate: negotiate,
                                   username: "User", password: "Password", domain: "Domain")
    }
}