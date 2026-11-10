# Facade Migration Guide

This guide maps legacy FTP usage to the new package.

## API Layers

- `FTPClientFacade`: migration-friendly layer with familiar naming.
- `FTPClient`: idiomatic Swift async/await layer.

## Operation Mapping

| Legacy concept | Current replacement | Status |
| --- | --- | --- |
| Hostname/Port/Username/Password | `FTPClientFacade` properties | Available |
| Connect/Login | `connect()` authenticates; `connectOnly()` + `loginAfterConnectOnly()` separates the steps | Available |
| Quote/SendCommand | `quote(_:)` / `sendCommand(_:)` | both throw on a negative reply |
| Noop | `noop()` | Available |
| Feat/Syst | `feat()` / `syst()` | Available |
| Pwd/Cwd | `getCurrentRemoteDir()` / `changeRemoteDir(_:)` | Available |
| Nlst | `nlst(_:)` | Available |
| List | `list(_:)` | raw server-specific lines only |
| Size/LastModified | `getSize(_:)` / `getLastModified(_:)` | SIZE and MDTM |
| Create/Remove remote dir | `createRemoteDir(_:)` / `removeRemoteDir(_:)` | Available |
| Delete/Rename remote file | `deleteRemoteFile(_:)` / `renameRemoteFile(existingPath:newPath:)` | Available |
| GetFile/PutFile | `getFile` / `putFile` | Available |
| Resume download | `getFile(..., resume: true)` | caller must verify local prefix, SIZE/REST required |
| Resume upload | `putFile(..., resume: true)` | caller must verify remote prefix, in-place and potentially destructive |
| Retry a download | `FTPDownloadRetry.download(...)` | opt-in, fresh sessions and full atomic re-downloads only; remote state is not snapshotted |
| Single-file upload | `FTPExport.upload(file:remoteFilename:options:progress:)` | plain/explicit/implicit FTP(S), remote directory, binary upload, cancellation and progress |
| Binary/text wrapper transfers | `getFileBd`, `putFileBd`, `appendFileBd`, `getFileSb`, `putFileSb`, `appendFileSb` | native `Data` and `String`; explicit BOM support for UTF encodings |
| Transfer progress | `transferMetrics()` and optional file/stream callbacks | byte counts are not acknowledgement; size hints can be inaccurate |
| SyncRemoteTree | `syncRemoteTree(plan:)` | supports optional deletion; mode semantics differ |

## Compatibility Notes

- Passive and active data transfers, binary/text and streaming APIs, and MLSD/common LIST listing are implemented; data-based transfers and listings buffer results.
- Explicit and implicit FTPS use certificate validation by default; active FTPS and explicit control upgrades use deprecated SecureTransport. Disabling chain validation is insecure.
- `setSslCertRequirement(name:value:)` throws on unsupported fields and adds a case-sensitive control-certificate check for the next connection. DN formatting and SAN types are documented in [the behavior reference](reference.md).
- Sync supports optional destructive file deletion, empty directories, and opt-in timestamp preservation, but is not transactional or snapshot-isolated. Preview and back up before use.
- The idiomatic `FTPClient` delegates to the facade.
