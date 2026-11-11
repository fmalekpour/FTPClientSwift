import Testing
@testable import FTPClientCore

@Test func anonymousUsernameFallbackResolvesAtLoginTime() {
    var configuration = FTPClientConfiguration(host: "localhost", username: "", password: "")
    #expect(configuration.loginUsername == "anonymous")
    #expect(configuration.password.isEmpty)
    configuration.username = "named-user"
    configuration.password = "supplied-password"
    #expect(configuration.loginUsername == "named-user")
    configuration.username = ""
    #expect(configuration.loginUsername == "anonymous")
    #expect(configuration.password == "supplied-password")
    configuration.username = " user with spaces "
    #expect(configuration.loginUsername == " user with spaces ")
}
