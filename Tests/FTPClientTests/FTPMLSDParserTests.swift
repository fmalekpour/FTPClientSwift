import Foundation
import Testing
import FTPClientCore

@Test func parsesMLSDFactsAndPreservesNames() throws {
    let input = "TyPe=file;Size=123;Modify=20240102030405.125;UNIX.mode=0644;  name.txt \r\ntype=dir; folder\r\n"
    let entries = try FTPMLSDParser.parse(Data(input.utf8))
    #expect(entries.count == 2)
    #expect(entries[0].name == " name.txt ")
    #expect(entries[0].kind == .file)
    #expect(entries[0].size == 123)
    #expect(entries[0].facts["unix.mode"] == "0644")
    #expect(entries[0].modifiedAt?.timeIntervalSince1970 == 1_704_164_645.125)
    #expect(entries[1].kind == .directory)
}

@Test func rejectsInvalidMLSDRecords() {
    for input in ["type=file;size=-1; x\r\n", "type=file;modify=20241302030405; x\r\n", "type=file;TYPE=dir; x\r\n", "type=file x\r\n"] {
        #expect(throws: FTPError.self) { try FTPMLSDParser.parse(Data(input.utf8)) }
    }
}
