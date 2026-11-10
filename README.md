# FTPClientSwift

An FTP and FTPS client for Apple platforms, written in Swift with an async/await API and no third-party runtime dependencies.

## Features

- Plain FTP, explicit FTPS (`AUTH TLS` / `AUTH SSL`), and implicit FTPS.
- Passive and active connections, directory listings, and remote file management.
- File, data, text, and streaming transfers with cancellation and progress metrics.
- Resumable transfers, optional download retries, bandwidth limits, and MODE Z compression.
- Certificate validation, public-key pinning, and client certificates.
- One-way directory synchronization with previews and configurable filters.
- HTTP CONNECT and SOCKS proxies, plus a compatibility facade for existing integrations.

FTPS is FTP over TLS. This package does **not** implement SFTP (SSH File Transfer Protocol).

## Requirements

- Swift 6.4 or later.
- iOS 15+, macOS 14+, tvOS 17+, or watchOS 10+.

These are the deployment targets declared in `Package.swift`. Runtime validation on every platform and minimum OS version is not yet complete.

## Installation

In Xcode, choose **File → Add Package Dependencies**, enter:

```text
https://github.com/fmalekpour/FTPClientSwift.git
```

Select **Up to Next Major Version** starting at **1.0.0**, then add the **FTPClientSwift** product to your target. Its Swift module is named **FTPClient**.

For a Swift package, add the dependency and product to `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/fmalekpour/FTPClientSwift.git", from: "1.0.0")
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: [
            .product(name: "FTPClientSwift", package: "FTPClientSwift")
        ]
    )
]
```

Version-based installation becomes available when the `1.0.0` Git tag is pushed.

## Quick start

Download a file over explicit FTPS. Supply credentials from your application's secure storage and a destination whose parent directory already exists.

```swift
import Foundation
import FTPClient
import FTPClientCore

func downloadReport(
    host: String,
    username: String,
    password: String,
    destination: URL
) async throws {
    let configuration = FTPClientConfiguration(
        host: host,
        username: username,
        password: password,
        security: .explicitTLS,
        dataProtection: .privateData,
        requireServerCertificateValidation: true
    )
    let client = FTPClient(configuration: configuration)

    do {
        try await client.connect()
        try await client.downloadFile(
            remotePath: "reports/today.csv",
            localPath: destination.path
        )
        await client.disconnect()
    } catch {
        await client.disconnect()
        throw error
    }
}
```

Use one operation at a time per connection. For parallel transfers, create separate clients.

## Products

| Product | Import | Purpose |
| --- | --- | --- |
| `FTPClientSwift` | `FTPClient` | Async client, download retries, and single-file upload helper |
| `FTPClientCore` | `FTPClientCore` | Configuration, protocol types, and transfer metrics |
| `FTPClientSecurity` | `FTPClientSecurity` | TLS policy configuration |
| `FTPClientSync` | `FTPClientSync` | Synchronization plans and filters |
| `FTPClientFacade` | `FTPClientFacade` | Mutable compatibility API for existing integrations |

## Security and compatibility

Prefer FTPS with certificate validation and private data channels. The configuration defaults to plain FTP unless you explicitly choose a TLS mode. Plain FTP exposes credentials and file contents.

Explicit FTPS and active FTPS rely on Apple's deprecated SecureTransport API. TLS 1.2 session reuse is optional; TLS 1.3 is not supported with that option. Server interoperability varies. Uploads and synchronization can leave partial changes after failure; review synchronization previews before enabling deletion.

See the [security guide](docs/security.md) and [behavior reference](docs/reference.md) for certificate, proxy, resume, and synchronization limits.

## Documentation

- [Usage guide](docs/usage.md)
- [Facade migration guide](docs/migration-guide.md)
- [Behavior and compatibility reference](docs/reference.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Build and test

```sh
swift build
swift test
```

Run tests on macOS with Swift 6.4 or later. Some integration fixtures require Node.js and OpenSSL; Node-dependent tests are skipped when Node.js is unavailable. These tools are not runtime dependencies.

## License

[MIT](LICENSE) © 2026 Farhad Malekpour and contributors.
