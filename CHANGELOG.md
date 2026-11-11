# Changelog

## 1.0.2

- Fix the anonymous-login integration test by allowing the test server to accept explicitly configured credentials.
- Update release documentation. No library runtime behavior changes from 1.0.1.

## 1.0.1

- Add opt-in console diagnostics for connections, FTP commands and replies, and transfers.
- Add configurable sensitive-information redaction for console and session logs.
- Use `anonymous` when the configured username is empty, preserving the supplied password.
- Provide readable `LocalizedError` descriptions, including when bridged to `NSError`.

## 1.0.0

Initial release, prepared for publication.

- Async/await FTP and FTPS client for Apple platforms.
- Passive and active data connections, directory listings, and remote file management.
- File, memory, text, and streaming transfers with resume, progress, and opt-in download retries.
- TLS validation, public-key pinning, client identities, and proxy support.
- One-way synchronization, previews, filtering, and opt-in destination-file deletion.
- Compatibility facade and single-file upload helper.

See [behavior and compatibility](docs/reference.md) for implementation limits. Release versions are established by Git tags; `Package.swift` declares the Swift tools version separately.
