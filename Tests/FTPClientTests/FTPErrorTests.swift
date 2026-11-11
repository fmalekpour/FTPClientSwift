import Foundation
import Testing
import FTPClientCore

@Test func ftpErrorsExposeReadableLocalizedDescriptions() {
    let cases: [(FTPError, String)] = [
        (.notImplemented(feature: "example"), "This FTP feature is not supported: example."),
        (.invalidState(description: "Not connected"), "The FTP operation could not be performed: Not connected"),
        (.serverReply(code: 530, message: "Login incorrect"), "The FTP server returned an error (530): Login incorrect"),
        (.serverReply(code: 500, message: " \n"), "The FTP server returned error 500."),
        (.serverReply(code: nil, message: "Unavailable"), "The FTP server returned an error: Unavailable"),
        (.serverReply(code: nil, message: ""), "The FTP server returned an error."),
        (.connectionFailed(description: "Connection refused"), "The FTP connection failed: Connection refused"),
        (.timeout(operation: "read"), "The FTP operation timed out while performing read."),
        (.protocolViolation(description: "Unexpected reply"), "An FTP protocol error occurred: Unexpected reply"),
        (.invalidResponseEncoding, "The FTP server's response could not be decoded using the configured character encoding.")
    ]
    for (ftpError, expected) in cases {
        let error: any Error = ftpError
        #expect(error.localizedDescription == expected)
        #expect((error as NSError).localizedDescription == expected)
    }
}
