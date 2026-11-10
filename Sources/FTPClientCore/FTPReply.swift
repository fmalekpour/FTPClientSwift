import Foundation

public struct FTPReply: Sendable, Equatable {
    public var code: Int?
    public var message: String

    public init(code: Int? = nil, message: String) {
        self.code = code
        self.message = message
    }

    /// Decode the quoted pathname in a 257 PWD reply; doubled quotes are literal.
    public func workingDirectoryPath() throws -> String {
        guard code == 257, let opening = message.firstIndex(of: "\"") else {
            throw FTPError.protocolViolation(description: "Malformed PWD reply")
        }
        var index = message.index(after: opening)
        var path = ""
        while index < message.endIndex {
            let character = message[index]
            index = message.index(after: index)
            if character == "\"" {
                if index < message.endIndex && message[index] == "\"" {
                    path.append("\"")
                    index = message.index(after: index)
                } else {
                    return path
                }
            } else {
                path.append(character)
            }
        }
        throw FTPError.protocolViolation(description: "Unterminated PWD pathname")
    }
}
