import Foundation
import Testing
@testable import FTPClientCore
import FTPClientFacade

@Test func certificateRequirementsRejectMalformedDER() {
    let requirements = [FTPCertificateRequirement(field: .subjectCN, pattern: "*")]
    for bytes: [UInt8] in [[], [0x30], [0x30, 0x80], [0x30, 0x81, 0x01, 0x00], [0x30, 0x82, 0xff, 0xff]] {
        #expect(!FTPCertificateFields.satisfies(requirements, certificate: Data(bytes)))
    }
    #expect(!FTPCertificateFields.satisfies(requirements, certificate: Data(repeating: 0, count: 1_048_577)))
    #expect(FTPCertificateFields.satisfies([], certificate: Data()))
}

@Test func facadeRejectsInvalidCertificateRequirements() throws {
    let config = FTPCertificateRequirement(field: .subjectCN, pattern: "bad\0name")
    #expect(!FTPCertificateFields.satisfies([config], certificate: Data([0x30, 0x00])))
    let facade = FTPClientFacade()
    try facade.setSslCertRequirement(name: "SubjectCN", value: "local*")
    try facade.setSslCertRequirement(name: "san", value: "localhost")
    #expect(facade.certificateRequirements == [
        .init(field: .subjectCN, pattern: "local*"),
        .init(field: .subjectAlternativeName, pattern: "localhost")
    ])
    #expect(throws: FTPError.self) { try facade.setSslCertRequirement(name: "unknown", value: "*") }
    #expect(throws: FTPError.self) { try facade.setSslCertRequirement(name: "SAN", value: "bad\0name") }
    #expect(facade.certificateRequirements.count == 2)
}