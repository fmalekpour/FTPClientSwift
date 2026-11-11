# Usage Guide

## Add the package

In Xcode, choose **File → Add Package Dependencies** and enter the repository URL. The package supports iOS 15+, macOS 14+, tvOS 17+, and watchOS 10+ as declared in `Package.swift`.

For Swift Package Manager:

```swift
.package(url: "https://github.com/fmalekpour/FTPClientSwift.git", from: "1.0.1")
```

The primary product is `FTPClientSwift`, imported as `FTPClient`.

## Connect securely

```swift
import FTPClient
import FTPClientCore

let configuration = FTPClientConfiguration(
    host: "ftp.example.com",
    port: 21,
    username: "username",
    password: "password",
    security: .explicitTLS,
    dataProtection: .privateData,
    requireServerCertificateValidation: true
)

let client = FTPClient(configuration: configuration)
try await client.connect()
// Perform operations inside a do/catch and await disconnect() on both paths.
// See the complete connection lifecycle example in README.md.
```

For production applications, do not embed credentials in source code. Load them from an application-managed secret store.

## Download and upload files

```swift
try await client.downloadFile(
    remotePath: "reports/today.csv",
    localPath: destination.path
)

try await client.uploadFile(
    localPath: source.path,
    remotePath: "incoming/today.csv",
    progress: { bytes in
        print("uploaded: \(bytes) bytes")
    }
)
```

Downloads are written to a temporary sibling and replace the destination only after successful server completion. Uploads are not transactional.

## Stream large files

```swift
let source = AsyncThrowingStream<Data, Error> { continuation in
    continuation.yield(Data("Example payload".utf8))
    continuation.finish()
}

try await client.uploadStream(
    remotePath: "incoming/archive.bin",
    source: source,
    progress: { bytes in
        print("sent: \(bytes)")
    }
)

try await client.downloadStream(remotePath: "archive.bin", progress: { bytes in
    print("received: \(bytes)")
}) { chunk in
    try await sink.write(chunk)
}
```

Stream callbacks report logical bytes processed. They do not mean the server has acknowledged the complete transfer until the method returns successfully.

## Resume and retry

Resume is opt-in and requires the existing local or remote content to be an exact prefix of the current file. Use binary mode and verify the prefix when correctness matters.

```swift
try await client.downloadFile(
    remotePath: "large.bin",
    localPath: destination.path,
    resume: true
)
```

For a complete fresh retry, use `FTPDownloadRetry`. Each attempt uses a new session and starts from the beginning:

```swift
try await FTPDownloadRetry.download(
    configuration: configuration,
    remotePath: "/large.bin",
    destination: destination,
    retryPolicy: FTPRetryPolicy(maximumAttempts: 3)
)
```

## Listings and remote directories

```swift
let entries = try await client.listEntries(path: "reports")
for entry in entries {
    print(entry.name, entry.kind, entry.size as Any)
}

try await client.createDirectory("incoming")
try await client.changeDirectory("incoming")
try await client.deleteFile("old.txt")
```

## Progress metrics

```swift
let metrics = await client.transferMetrics()
print(metrics.receivedBytes)
print(metrics.sentBytes)
print(metrics.downloadBytesPerSecond)
print(metrics.uploadFractionCompleted as Any)
```

Metrics are snapshots and are safe to read while a transfer is active. Counters are retained independently for uploads and downloads.

## Migration facade

Use `FTPClientFacade` when porting an existing callback-oriented integration or when mutable configuration properties are useful:

```swift
import FTPClientFacade

let facade = FTPClientFacade()
facade.hostname = "ftp.example.com"
facade.username = "username"
facade.password = "password"
facade.authTls = true
facade.autoFix = false

try await facade.connect()
try await facade.putFile(localPath: source.path, remoteFilename: "upload.bin")
await facade.disconnect()
```

The facade is not safe for concurrent property mutation. Serialize its operations.

## Single-file upload helper

```swift
let options = FTPExportOptions(
    username: username,
    password: password,
    host: host,
    port: port,
    authentication: .explicitTLS,
    remoteDirectory: directory,
    passive: true,
    requireServerCertificateValidation: true
)

let result = try await FTPExport.upload(
    file: recordingURL,
    remoteFilename: "recording.m4a",
    options: options,
    progress: { total, processed in
        print("\(processed)/\(total)")
    }
)
print(result.remotePath)
```

`FTPExportOptions` preserves a legacy default of disabled certificate validation. Explicitly set `requireServerCertificateValidation: true`, as above.
