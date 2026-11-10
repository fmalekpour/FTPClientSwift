import Foundation
import Darwin
import FTPClientCore

/// A proposed operation. Paths are relative to the configured sync roots.
public struct FTPSyncOperation: Sendable, Equatable {
    public enum Action: Sendable, Equatable {
        case createLocalDirectory, createRemoteDirectory, upload, download, deleteLocalFile, deleteRemoteFile
    }
    public let action: Action
    public let relativePath: String
    public let sourceModificationTime: Date?

    public init(action: Action, relativePath: String, sourceModificationTime: Date? = nil) {
        self.action = action
        self.relativePath = relativePath
        self.sourceModificationTime = sourceModificationTime
    }
}

/// One-way synchronization. Mirror mode deletes selected destination files absent from the source.
public struct FTPSyncEngine: Sendable {
    private let channel: FTPControlChannel
    public init(channel: FTPControlChannel) { self.channel = channel }

    private struct Entry {
        let isDirectory: Bool
        let size: UInt64?
        let modified: Date?
    }

    /// Examines both trees without changing either one.
    public func preview(_ plan: FTPSyncPlan) async throws -> [FTPSyncOperation] {
        guard !plan.localRootPath.isEmpty, !plan.remoteRootPath.isEmpty else {
            throw FTPError.invalidState(description: "Both synchronization roots must be specified")
        }
        let tree = try FTPSafeLocalTree(root: URL(fileURLWithPath: plan.localRootPath, isDirectory: true))
        return try await preview(plan, localTree: tree)
    }

    private func preview(_ plan: FTPSyncPlan, localTree: FTPSafeLocalTree) async throws -> [FTPSyncOperation] {
        let local = try localSnapshot(tree: localTree, filter: plan.filter, descend: plan.descend)
        let remote = try await remoteSnapshot(root: plan.remoteRootPath, filter: plan.filter, descend: plan.descend)
        // Server and local case/normalization behavior can differ. Reject any
        // ambiguous names before uploads, downloads, or deletes. Iterate both
        // snapshots directly: Swift Set/String equality would otherwise merge
        // canonically equivalent names before the byte comparison.
        var canonical: [String: String] = [:]
        for path in Array(local.keys) + Array(remote.keys) {
            let normalized = path.precomposedStringWithCanonicalMapping.lowercased()
            if let existing = canonical[normalized], !existing.utf8.elementsEqual(path.utf8) {
                throw FTPError.invalidState(description: "Ambiguous case-insensitive sync paths: \(existing), \(path)")
            }
            canonical[normalized] = path
        }
        let source = plan.direction == .localToRemote ? local : remote
        let destination = plan.direction == .localToRemote ? remote : local
        var result: [FTPSyncOperation] = []
        var requiredDirectories: Set<String> = []
        for path in source.keys {
            if let sourceEntry = source[path], let destinationEntry = destination[path],
               sourceEntry.isDirectory != destinationEntry.isDirectory {
                throw FTPError.invalidState(description: "File/directory conflict: \(path)")
            }
        }
        for path in source.keys.sorted() {
            if plan.mode == .deleteDestinationOnly { continue }
            guard let item = source[path] else { continue }
            if item.isDirectory {
                if let other = destination[path], !other.isDirectory {
                    throw FTPError.invalidState(description: "File/directory conflict: \(path)")
                }
                if plan.includeEmptyDirectories && destination[path] == nil { requiredDirectories.insert(path) }
                continue
            }
            guard plan.filter.includesFile(path) else { continue }
            if let oldest = plan.oldestSourceModification {
                guard let modified = item.modified else { throw FTPError.invalidState(description: "Sync requires source modification times") }
                if modified < oldest { continue }
            }
            if let other = destination[path] {
                guard !other.isDirectory else { throw FTPError.invalidState(description: "File/directory conflict: \(path)") }
                if try !needsTransfer(source: item, destination: other, mode: plan.mode) { continue }
            } else if plan.mode == .existingNewer {
                continue
            }
            if plan.preserveModificationTimes && item.modified == nil {
                throw FTPError.invalidState(description: "Sync requires source modification times: \(path)")
            }
            let components = path.split(separator: "/")
            if components.count > 1 {
                for index in 1..<components.count {
                    let parent = components.prefix(index).joined(separator: "/")
                    if let other = destination[parent] {
                        guard other.isDirectory else { throw FTPError.invalidState(description: "File/directory conflict: \(parent)") }
                    } else {
                        requiredDirectories.insert(parent)
                    }
                }
            }
            result.append(FTPSyncOperation(action: plan.direction == .localToRemote ? .upload : .download,
                                           relativePath: path, sourceModificationTime: plan.preserveModificationTimes ? item.modified : nil))
        }
        let directories = requiredDirectories.sorted {
            let a = $0.split(separator: "/").count
            let b = $1.split(separator: "/").count
            return a == b ? $0 < $1 : a < b
        }.map { FTPSyncOperation(action: plan.direction == .localToRemote ? .createRemoteDirectory : .createLocalDirectory, relativePath: $0) }
        let deletions: [FTPSyncOperation]
        if plan.mode == .mirrorWithDelete || plan.mode == .deleteDestinationOnly {
            deletions = destination.keys.sorted().compactMap { path in
                guard let entry = destination[path], !entry.isDirectory, source[path] == nil,
                      plan.filter.includesFile(path) else { return nil }
                return FTPSyncOperation(action: plan.direction == .localToRemote ? .deleteRemoteFile : .deleteLocalFile, relativePath: path)
            }
        } else {
            deletions = []
        }
        return directories + result + deletions
    }

    /// Recomputes the plan, then executes it unless dryRun is set. Returns the plan.
    @discardableResult
    public func run(_ plan: FTPSyncPlan) async throws -> [FTPSyncOperation] {
        guard !plan.localRootPath.isEmpty, !plan.remoteRootPath.isEmpty else {
            throw FTPError.invalidState(description: "Both synchronization roots must be specified")
        }
        let safeLocalTree = try FTPSafeLocalTree(root: URL(fileURLWithPath: plan.localRootPath, isDirectory: true))
        let operations = try await preview(plan, localTree: safeLocalTree)
        guard !plan.dryRun else { return operations }
        for operation in operations {
            try Task.checkCancellation()
            let remote = remotePath(plan.remoteRootPath, operation.relativePath)
            switch operation.action {
            case .createLocalDirectory:
                try safeLocalTree.createDirectory(operation.relativePath)
            case .createRemoteDirectory:
                try await channel.makeDirectory(path: remote)
            case .download:
                let (parent, name) = try safeLocalTree.openParentForTransfer(operation.relativePath)
                defer { Darwin.close(parent) }
                try await channel.downloadFile(remotePath: remote, directoryDescriptor: parent, filename: name, modificationTime: operation.sourceModificationTime)
            case .upload:
                let source = try safeLocalTree.openRegularFile(operation.relativePath)
                defer { try? source.close() }
                let stream = AsyncThrowingStream<Data, Error>(unfolding: {
                    try Task.checkCancellation()
                    guard let chunk = try source.read(upToCount: 65_536), !chunk.isEmpty else { return nil }
                    return chunk
                })
                // Upload to a unique sibling first, never exposing a partial target.
                let components = operation.relativePath.split(separator: "/")
                let prefix = components.dropLast().joined(separator: "/")
                let temporaryName = ".ftp-sync-\(UUID().uuidString).part"
                let temp = remotePath(plan.remoteRootPath, prefix.isEmpty ? temporaryName : "\(prefix)/\(temporaryName)")
                do {
                    try await channel.uploadStream(remotePath: temp, source: stream)
                    if let modificationTime = operation.sourceModificationTime {
                        try await channel.setModificationTime(modificationTime, path: temp)
                    }
                    try await channel.renameFile(from: temp, to: remote)
                } catch {
                    try? await channel.deleteFile(path: temp)
                    throw error
                }
            case .deleteRemoteFile:
                guard try !safeLocalTree.containsEntry(operation.relativePath) else {
                    throw FTPError.invalidState(description: "Sync source changed before deletion: \(operation.relativePath)")
                }
                try await channel.deleteFile(path: remote)
            case .deleteLocalFile:
                let components = operation.relativePath.split(separator: "/")
                let name = String(components.last!)
                let parent = components.dropLast().joined(separator: "/")
                let remoteParent = parent.isEmpty ? plan.remoteRootPath : remotePath(plan.remoteRootPath, parent)
                let currentEntries = try await channel.listEntries(path: remoteParent)
                if currentEntries.contains(where: { $0.name == name }) {
                    throw FTPError.invalidState(description: "Sync source changed before deletion: \(operation.relativePath)")
                }
                try safeLocalTree.deleteRegularFile(operation.relativePath)
            }
        }
        return operations
    }

    private func localSnapshot(tree: FTPSafeLocalTree, filter: FTPSyncFilter, descend: Bool) throws -> [String: Entry] {
        var entries: [String: Entry] = [:]
        var pending: [(String, Int)] = [("", 0)]
        while let (prefix, depth) = pending.popLast() {
            guard depth <= 128 else { throw FTPError.invalidState(description: "Local tree exceeds depth limit") }
            for child in try tree.snapshotDirectory(prefix) {
                let name = child.name
                try validateName(name)
                let path = prefix.isEmpty ? name : "\(prefix)/\(name)"
                let type = child.mode & S_IFMT
                guard type == S_IFDIR || type == S_IFREG else {
                    throw FTPError.invalidState(description: "Unsupported local entry: \(path)")
                }
                let isDirectory = type == S_IFDIR
                if isDirectory && (!descend || !filter.includesDirectory(path)) { continue }
                guard entries[path] == nil else { throw FTPError.invalidState(description: "Ambiguous local sync entry: \(path)") }
                entries[path] = Entry(isDirectory: isDirectory, size: UInt64(exactly: child.size), modified: child.modificationTime)
                guard entries.count <= 100_000 else { throw FTPError.invalidState(description: "Local tree exceeds entry limit") }
                if isDirectory { pending.append((path, depth + 1)) }
            }
        }
        return entries
    }

    private func remoteSnapshot(root: String, filter: FTPSyncFilter, descend: Bool) async throws -> [String: Entry] {
        var entries: [String: Entry] = [:]
        var seen: Set<String> = []
        var pending: [(String, Int)] = [("", 0)]
        while let (prefix, depth) = pending.popLast() {
            guard depth <= 128 else { throw FTPError.invalidState(description: "Remote tree exceeds depth limit") }
            let listing = try await channel.listEntries(path: prefix.isEmpty ? root : remotePath(root, prefix))
            for item in listing {
                if item.kind == .currentDirectory || item.kind == .parentDirectory { continue }
                try validateName(item.name)
                let path = prefix.isEmpty ? item.name : "\(prefix)/\(item.name)"
                guard seen.insert(path).inserted else { throw FTPError.protocolViolation(description: "Duplicate remote entry: \(path)") }
                let isDirectory: Bool
                switch item.kind {
                case .file: isDirectory = false
                case .directory: isDirectory = true
                default: throw FTPError.invalidState(description: "Unsupported remote entry: \(path)")
                }
                if isDirectory && (!descend || !filter.includesDirectory(path)) { continue }
                entries[path] = Entry(isDirectory: isDirectory, size: item.size, modified: item.modifiedAt)
                guard entries.count <= 100_000 else { throw FTPError.invalidState(description: "Remote tree exceeds entry limit") }
                if isDirectory { pending.append((path, depth + 1)) }
            }
        }
        return entries
    }

    private func needsTransfer(source: Entry, destination: Entry, mode: FTPSyncMode) throws -> Bool {
        switch mode {
        case .deleteDestinationOnly: return false
        case .all: return true
        case .missingOnly: return false
        case .existingNewer:
            guard let a = source.modified, let b = destination.modified else { throw FTPError.invalidState(description: "Sync requires modification times") }
            return a > b
        case .sizeOnly:
            guard let a = source.size, let b = destination.size else { throw FTPError.invalidState(description: "Sync requires file sizes") }
            return a != b
        case .newerOnly:
            guard let a = source.modified, let b = destination.modified else { throw FTPError.invalidState(description: "Sync requires modification times") }
            return a > b
        case .sizeAndNewer:
            guard let aSize = source.size, let bSize = destination.size, let a = source.modified, let b = destination.modified else {
                throw FTPError.invalidState(description: "Sync requires file sizes and modification times")
            }
            return aSize != bSize && a > b
        case .sizeOrNewer, .mirrorWithDelete:
            guard let aSize = source.size, let bSize = destination.size, let a = source.modified, let b = destination.modified else {
                throw FTPError.invalidState(description: "Sync requires file sizes and modification times")
            }
            return aSize != bSize || a > b
        }
    }

    private func validateName(_ name: String) throws {
        guard !name.isEmpty, name != ".", name != "..", !name.utf8.contains(where: { $0 == 47 || $0 == 0 || $0 == 10 || $0 == 13 }) else {
            throw FTPError.protocolViolation(description: "Unsafe sync entry name")
        }
    }

    private func remotePath(_ root: String, _ relative: String) -> String {
        (root.hasSuffix("/") ? root : root + "/") + relative
    }
}
