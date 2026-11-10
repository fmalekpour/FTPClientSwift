import Foundation
import Testing
@testable import FTPClientSync

@Test func destructiveSyncRejectsReplacedDirectorySymlink() throws {
    let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let root = base.appendingPathComponent("root")
    let outside = base.appendingPathComponent("outside")
    let original = root.appendingPathComponent("nested")
    defer { try? FileManager.default.removeItem(at: base) }
    try FileManager.default.createDirectory(at: original, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    let protectedFile = outside.appendingPathComponent("file.txt")
    try Data("protected".utf8).write(to: protectedFile)
    let tree = try FTPSafeLocalTree(root: root)
    try FileManager.default.removeItem(at: original)
    try FileManager.default.createSymbolicLink(at: original, withDestinationURL: outside)
    #expect(throws: Error.self) { try tree.deleteRegularFile("nested/file.txt") }
    #expect(throws: Error.self) { try tree.containsEntry("nested/file.txt") }
    #expect(try Data(contentsOf: protectedFile) == Data("protected".utf8))
}

@Test func destructiveSyncChecksSourceAndFinalSymlinks() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let tree = try FTPSafeLocalTree(root: root)
    #expect(try !tree.containsEntry("missing/file"))
    let file = root.appendingPathComponent("file")
    try Data("source".utf8).write(to: file)
    #expect(try tree.containsEntry("file"))
    try tree.deleteRegularFile("file")
    #expect(try !tree.containsEntry("file"))
    try FileManager.default.createSymbolicLink(at: file, withDestinationURL: URL(fileURLWithPath: "/tmp"))
    #expect(throws: Error.self) { try tree.containsEntry("file") }
    #expect(throws: Error.self) { try tree.deleteRegularFile("file") }
    #expect(throws: Error.self) { try tree.deleteRegularFile("../file") }
}

@Test func syncTransferPathsRejectReplacedSymlinks() throws {
    let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let root = base.appendingPathComponent("root")
    let nested = root.appendingPathComponent("nested")
    let moved = root.appendingPathComponent("moved")
    let outside = base.appendingPathComponent("outside")
    defer { try? FileManager.default.removeItem(at: base) }
    try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    try Data("safe".utf8).write(to: nested.appendingPathComponent("file"))
    try Data("secret".utf8).write(to: outside.appendingPathComponent("file"))
    let tree = try FTPSafeLocalTree(root: root)
    let source = try tree.openRegularFile("nested/file")
    defer { try? source.close() }
    try FileManager.default.moveItem(at: nested, to: moved)
    try FileManager.default.createSymbolicLink(at: nested, withDestinationURL: outside)
    #expect(try source.readToEnd() == Data("safe".utf8))
    #expect(throws: Error.self) { try tree.openRegularFile("nested/file") }
    #expect(throws: Error.self) { try tree.openParentForTransfer("nested/file") }
    #expect(throws: Error.self) { try tree.createDirectory("nested/new") }
    #expect(!FileManager.default.fileExists(atPath: outside.appendingPathComponent("new").path))
    #expect(try Data(contentsOf: outside.appendingPathComponent("file")) == Data("secret".utf8))
}

@Test func syncUploadRejectsFinalSymlinkAndNonRegularFiles() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("link"), withDestinationURL: URL(fileURLWithPath: "/etc/passwd"))
    try FileManager.default.createDirectory(at: root.appendingPathComponent("directory"), withIntermediateDirectories: false)
    let tree = try FTPSafeLocalTree(root: root)
    #expect(throws: Error.self) { try tree.openRegularFile("link") }
    #expect(throws: Error.self) { try tree.openRegularFile("directory") }
    #expect(throws: Error.self) { try tree.openRegularFile("../file") }
}

@Test func syncSnapshotsRemainAnchoredWhenRootPathChanges() throws {
    let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let root = base.appendingPathComponent("root")
    let moved = base.appendingPathComponent("moved")
    let outside = base.appendingPathComponent("outside")
    defer { try? FileManager.default.removeItem(at: base) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    try Data("safe".utf8).write(to: root.appendingPathComponent("inside"))
    try Data("secret".utf8).write(to: outside.appendingPathComponent("outside"))
    let tree = try FTPSafeLocalTree(root: root)
    #expect(try tree.snapshotDirectory("").map(\.name) == ["inside"])
    try FileManager.default.moveItem(at: root, to: moved)
    try FileManager.default.createSymbolicLink(at: root, withDestinationURL: outside)
    #expect(try tree.snapshotDirectory("").map(\.name) == ["inside"])
    #expect(try tree.snapshotDirectory("").map(\.name) == ["inside"])
    #expect(throws: Error.self) { try tree.openRegularFile("outside") }
}