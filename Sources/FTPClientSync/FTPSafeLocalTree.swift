import Foundation
import Darwin
import FTPClientCore

/// Anchors sync operations to an opened root rather than resolving paths through symlinks.
final class FTPSafeLocalTree: @unchecked Sendable {
    private let root: Int32

    struct SnapshotEntry {
        let name: String
        let mode: mode_t
        let size: off_t
        let modificationTime: Date
    }

    init(root: URL) throws {
        let descriptor = Darwin.open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw posixError() }
        self.root = descriptor
    }

    deinit { Darwin.close(root) }

    /// Reads one directory without following substituted path components.
    func snapshotDirectory(_ path: String) throws -> [SnapshotEntry] {
        let descriptor: Int32
        if path.isEmpty {
            descriptor = openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else { throw posixError() }
        } else {
            let (parent, name) = try openParentForTransfer(path)
            defer { Darwin.close(parent) }
            descriptor = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else { throw posixError() }
        }
        guard let directory = fdopendir(descriptor) else {
            let error = posixError()
            Darwin.close(descriptor)
            throw error
        }
        defer { closedir(directory) }
        var result: [SnapshotEntry] = []
        while true {
            errno = 0
            guard let entry = readdir(directory) else {
                if errno != 0 { throw posixError() }
                return result
            }
            let length = Int(entry.pointee.d_namlen)
            guard length > 0 else { throw FTPError.protocolViolation(description: "Invalid local sync entry name") }
            let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
                pointer.withMemoryRebound(to: UInt8.self, capacity: length) {
                    String(bytes: UnsafeBufferPointer(start: $0, count: length), encoding: .utf8)
                }
            }
            guard let name else { throw FTPError.invalidState(description: "Local sync entry is not valid UTF-8") }
            if name == "." || name == ".." { continue }
            var metadata = stat()
            guard fstatat(descriptor, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0 else { throw posixError() }
            let seconds = TimeInterval(metadata.st_mtimespec.tv_sec)
            let fraction = TimeInterval(metadata.st_mtimespec.tv_nsec) / 1_000_000_000
            result.append(SnapshotEntry(name: name, mode: metadata.st_mode, size: metadata.st_size,
                                        modificationTime: Date(timeIntervalSince1970: seconds + fraction)))
            guard result.count <= 100_000 else { throw FTPError.invalidState(description: "Local tree exceeds entry limit") }
        }
    }

    /// Returns an owned descriptor for the parent and the final filename.
    func openParentForTransfer(_ path: String) throws -> (Int32, String) {
        guard let parent = try openParent(path, allowMissing: false) else {
            throw FTPError.invalidState(description: "Missing sync parent: \(path)")
        }
        return parent
    }

    func createDirectory(_ path: String) throws {
        let (parent, name) = try openParentForTransfer(path)
        defer { Darwin.close(parent) }
        guard mkdirat(parent, name, 0o777) == 0 else { throw posixError() }
    }

    /// Opens a regular file without following a final or intermediate symlink.
    func openRegularFile(_ path: String) throws -> FileHandle {
        let (parent, name) = try openParentForTransfer(path)
        defer { Darwin.close(parent) }
        let descriptor = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { throw posixError() }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0, (metadata.st_mode & S_IFMT) == S_IFREG else {
            Darwin.close(descriptor)
            throw FTPError.invalidState(description: "Local sync source is not a regular file: \(path)")
        }
        return FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    /// Returns false if an ancestor or the final entry is missing. Symlinks fail closed.
    func containsEntry(_ path: String) throws -> Bool {
        guard let (parent, name) = try openParent(path, allowMissing: true) else { return false }
        defer { Darwin.close(parent) }
        var metadata = stat()
        guard fstatat(parent, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0 else {
            if errno == ENOENT { return false }
            throw posixError()
        }
        guard (metadata.st_mode & S_IFMT) != S_IFLNK else {
            throw FTPError.invalidState(description: "Symbolic link in sync path: \(path)")
        }
        return true
    }

    func deleteRegularFile(_ path: String) throws {
        guard let (parent, name) = try openParent(path, allowMissing: false) else {
            throw FTPError.invalidState(description: "Missing sync deletion parent: \(path)")
        }
        defer { Darwin.close(parent) }
        var metadata = stat()
        guard fstatat(parent, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0 else { throw posixError() }
        guard (metadata.st_mode & S_IFMT) == S_IFREG else {
            throw FTPError.invalidState(description: "Local deletion target is not a regular file: \(path)")
        }
        // unlinkat removes the directory entry itself and never follows a final symlink.
        guard unlinkat(parent, name, 0) == 0 else { throw posixError() }
    }

    private func openParent(_ path: String, allowMissing: Bool) throws -> (Int32, String)? {
        let components = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !components.isEmpty, components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.utf8.contains(0) }) else {
            throw FTPError.invalidState(description: "Invalid local sync path")
        }
        var descriptor = dup(root)
        guard descriptor >= 0 else { throw posixError() }
        for component in components.dropLast() {
            let next = openat(descriptor, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            if next < 0 {
                let error = errno
                Darwin.close(descriptor)
                if allowMissing && error == ENOENT { return nil }
                throw POSIXError(POSIXErrorCode(rawValue: error) ?? .EIO)
            }
            Darwin.close(descriptor)
            descriptor = next
        }
        return (descriptor, components.last!)
    }
}

private func posixError() -> POSIXError {
    POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
}