import Foundation
import Darwin

public enum FTPSyncDirection: Sendable, Equatable {
    case localToRemote
    case remoteToLocal
}

public enum FTPSyncMode: Sendable, Equatable {
    case all
    case missingOnly
    case existingNewer
    case newerOnly
    case sizeOnly
    case sizeAndNewer
    case sizeOrNewer
    case mirrorWithDelete
    case deleteDestinationOnly
}

public struct FTPSyncFilter: Sendable, Equatable {
    public var includePatterns: [String]
    public var excludePatterns: [String]
    public var includeDirectoryPatterns: [String]
    public var excludeDirectoryPatterns: [String]
    public var caseSensitive: Bool
    public var matchBasenameOnly: Bool

    public init(includePatterns: [String] = ["*"], excludePatterns: [String] = [], includeDirectoryPatterns: [String] = ["*"], excludeDirectoryPatterns: [String] = [], caseSensitive: Bool = true, matchBasenameOnly: Bool = false) {
        self.includePatterns = includePatterns
        self.excludePatterns = excludePatterns
        self.includeDirectoryPatterns = includeDirectoryPatterns
        self.excludeDirectoryPatterns = excludeDirectoryPatterns
        self.caseSensitive = caseSensitive
        self.matchBasenameOnly = matchBasenameOnly
    }

    public func includesFile(_ path: String) -> Bool {
        matches(path, include: includePatterns, exclude: excludePatterns)
    }

    public func includesDirectory(_ path: String) -> Bool {
        matches(path, include: includeDirectoryPatterns, exclude: excludeDirectoryPatterns)
    }

    private func matches(_ value: String, include: [String], exclude: [String]) -> Bool {
        let path = caseSensitive ? value : value.lowercased()
        let filename = String(path.split(separator: "/").last ?? "")
        func match(_ pattern: String) -> Bool {
            (caseSensitive ? pattern : pattern.lowercased()).withCString { pattern in
                (!matchBasenameOnly && path.withCString { fnmatch(pattern, $0, FNM_PATHNAME) == 0 })
                || filename.withCString { fnmatch(pattern, $0, FNM_PATHNAME) == 0 }
            }
        }
        return include.contains(where: match) && !exclude.contains(where: match)
    }
}

public struct FTPSyncPlan: Sendable, Equatable {
    public var direction: FTPSyncDirection
    public var mode: FTPSyncMode
    public var localRootPath: String
    public var remoteRootPath: String
    public var filter: FTPSyncFilter
    public var dryRun: Bool
    public var descend: Bool
    public var includeEmptyDirectories: Bool
    public var oldestSourceModification: Date?
    /// Preserve source timestamps; uploads require server MFMT support.
    public var preserveModificationTimes: Bool

    public init(
        direction: FTPSyncDirection,
        mode: FTPSyncMode,
        localRootPath: String,
        remoteRootPath: String,
        filter: FTPSyncFilter = FTPSyncFilter(),
        dryRun: Bool = false,
        descend: Bool = true,
        includeEmptyDirectories: Bool = false,
        oldestSourceModification: Date? = nil,
        preserveModificationTimes: Bool = false
    ) {
        self.direction = direction
        self.mode = mode
        self.localRootPath = localRootPath
        self.remoteRootPath = remoteRootPath
        self.filter = filter
        self.dryRun = dryRun
        self.descend = descend
        self.includeEmptyDirectories = includeEmptyDirectories
        self.oldestSourceModification = oldestSourceModification
        self.preserveModificationTimes = preserveModificationTimes
    }
}
