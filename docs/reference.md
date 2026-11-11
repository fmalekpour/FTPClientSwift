# Behavior and Compatibility Reference

Detailed transfer semantics and implementation limits for version 1.0.1. See the [usage guide](usage.md) for examples.

## TLS and certificates

For implicit FTPS, set transport security to `implicitTLS` and use the server's implicit FTPS port (typically 990). System trust and hostname verification are enabled by default; optional DER roots replace system roots. Client PKCS#12 identities, SHA-256 SPKI pins, TLS 1.2/1.3 minimums and a limited set of named cipher suites are configurable. Pins supplement the configured trust policy and apply to data and control channels. Disabling chain verification explicitly trusts the presented leaf and **allows interception by an attacker with a certificate for the expected hostname**; do not use that option in production. Data channels use `PBSZ 0` and `PROT P` by default.

For servers requiring control/data TLS session reuse, enable `enableTLSSessionResumption` before connecting. This opts into deprecated SecureTransport for both channels and uses a unique cache identity per FTP session; cached peer trust and pins are re-evaluated. Direct and proxied active/passive TLS 1.2 reuse has been tested against a local strict server. Resumption is attempted, not guaranteed; a server requiring it can still reject the transfer. TLS 1.3 with this option is not supported and is rejected rather than silently downgraded. Runtime behavior on iOS, tvOS, and watchOS remains unverified.

Client identities can also be loaded from PEM data or a local PEM file, with matching RSA or P-256/P-384/P-521 certificates and private keys. Unencrypted PKCS#8, traditional RSA/EC, and PBES2/PBKDF2 AES-CBC encrypted PKCS#8 are supported. Other encrypted PEM formats fail rather than being downgraded. The password, PEM contents and decrypted key exist in process memory; use appropriate secret-handling precautions.

PKCS#12 identities are never intentionally added to the user's default Keychain. On macOS 15 and later the package requests memory-only import. On macOS 14 it imports into a randomly password-protected temporary Keychain that is retained for the session and deleted afterward; a crash may leave that encrypted temporary file behind. Other platforms use their Security-framework import behavior.

In local macOS/Node interoperability testing, P-521 client identities failed with Network.framework TLS 1.3 both from PEM and PKCS#12, while TLS 1.2 succeeded. No automatic downgrade is performed; configure the TLS maximum explicitly if the target server has this interoperability problem.

The idiomatic client uses the configuration's certificate-verification setting unless an explicit security policy is supplied; an explicit policy overrides that setting.

For a single-file upload workflow, use `FTPExport.upload(file:remoteFilename:options:progress:)`. It normalizes an optional `ftp://` prefix, supports plain FTP, explicit `AUTH TLS`, explicit `AUTH SSL`, implicit TLS, passive or active data mode, remote-directory selection, binary transfer, cancellation, and cumulative `(totalBytes, processedBytes)` progress. It always disconnects on success or failure. The legacy exporter disabled certificate verification; `FTPExportOptions` preserves that default for migration, but production callers should set `requireServerCertificateValidation` to `true` and provide appropriate trust configuration through the idiomatic API when needed.

For explicit FTPS, select `explicitTLS` (typically port 21). The control connection is upgraded in place after `AUTH TLS` and validated before credentials are sent. The client negotiates `PBSZ` and `PROT` before login, or retries after login if the server responds `530`. The configured read timeout bounds each complete control-channel TLS read or handshake, including partial records; the send timeout uses the same setting. The implementation uses Apple's deprecated SecureTransport API for the control-channel upgrade; Apple describes that API as no longer supported, so future SDK compatibility is not guaranteed. Data channels are private by default. Broader FTPS interoperability and runtime behavior on iOS, tvOS, and watchOS remain unverified. The local FTPS tests require Node.js and OpenSSL; they are test-only tools, not package dependencies. FTPS tests are skipped if Node.js is unavailable.

Setting `dataProtection` to `clear` explicitly requests `PROT C`: **file contents and listings then travel without encryption or data-channel authentication**, even though the control channel is encrypted. If the server refuses `PROT C`, the client attempts `PROT P` instead. Do not select clear protection on untrusted networks.

`tlsSessionInfo()` reports the active control channel's negotiated TLS version, cipher and server certificate in DER form. The chain-validation flag reports whether verification was required; it does not claim that a certificate was independently trusted when verification was disabled.

Optional `certificateRequirements` add case-sensitive wildcard checks against the control-channel leaf certificate during TLS verification and before FTP credentials are sent. Multiple requirements are ANDed; DNS, email, URI and IP subject-alternative names are matched individually. Distinguished names use RFC 4514-style reverse RDN order, comma-separated attributes and escaping; unknown attribute OIDs are rendered numerically. Unsupported name encodings or malformed certificates fail closed. These checks do not replace chain, hostname, or pin verification, and they are not applied to data-channel certificates.

## Transfers and cancellation

File transfers stream in chunks; downloads replace the destination only after a successful server completion reply. Streaming upload, append and download accept an optional synchronous, `@Sendable` progress callback reporting cumulative bytes transferred by that operation, starting at zero after the data connection opens. A callback reports bytes processed, not server acceptance or successful completion; wait for the method to return successfully. Empty files report zero. Callbacks should return promptly and must not mutate the facade concurrently. Cancellation interrupts pending network waits by cancelling the affected connection and closes the control session if synchronization may have been lost. A cancelled upload can leave a partial remote file; a cancelled download preserves the existing local destination. Local file I/O and callback execution are not interruptible. In-memory transfers and listings have a configurable buffer limit; streaming APIs avoid buffering the entire file. LIST fallback supports common UNIX/Windows formats and requires an explicit server time zone for legacy timestamps. Concurrent operations on a control channel are rejected. Passive connections use the resolved control peer when available, falling back to the configured host, rather than trusting a PASV-provided address by default. Local IPv4 and IPv6 integration tests have run on macOS. Simulator runtime tests and minimum-OS behavior remain unverified.

Streaming download callbacks count logical bytes after successful delivery to the sink. The live metrics snapshot counts received logical bytes before the sink returns, so its count can be higher if the sink throws. Streaming upload callbacks count bytes handed to the data connection. In either direction, callback progress does not guarantee completion.

## Text and binary data

The facade accepts native `Data` and `String` in its `getFileBd`, `putFileBd`, `appendFileBd`, `getFileSb`, `putFileSb`, and `appendFileSb` methods without object-wrapper types. `putFileSb` can include a UTF-8, UTF-16, or UTF-32 byte-order mark; for other encodings the option has no effect. Text append does not add a byte-order mark. Text downloads reject invalid byte sequences instead of replacing them. Text resume uses the encoded length of the existing string as the byte offset; the caller must ensure it exactly represents the remote prefix, including any byte-order mark, and should use binary data for byte-exact resumes. The `ANSI` charset maps to UTF-8 in this package.

## Progress metrics

`transferMetrics()` and the facade's asynchronous byte/rate properties can be read during a transfer. Upload and download counters are retained independently, represent logical bytes processed (not compressed wire bytes or server acknowledgement), and count only newly transferred bytes on resume. Chunked uploads report the whole operation. Rates are averages since that direction's operation began; a failed transfer retains its count and reports failure in the typed snapshot. Listing transfers do not reset these file-transfer counters.

The metrics snapshot also contains optional expected byte counts and fractional progress. Regular-file and in-memory uploads have a known source size; resumed transfers count the remaining bytes only. File downloads can opt in to a `SIZE` query with `querySizeForProgress` or the facade's `autoGetSizeForProgress`; replies 500, 501, 502 and 504 fall back to an unknown fraction, while other query failures fail the operation. The facade's one-shot `progressMonSize64` (or `progressMonSize`) supplies an expected logical byte count for the next file download without that query. It is consumed even if the operation fails. Resumed downloads use the server's `SIZE` result instead of a supplied hint. Automatic size queries are not used in ASCII mode because line-ending conversion changes the output length. An expected size is only a hint: the file may change, and a fraction of 1 does not mean that the server acknowledged the transfer or that integrity was verified. Check the operation result and success flag; inaccurate hints are clamped to a maximum fraction of 1.

`partialDownload` in the snapshot and the facade's async `partialTransfer` are optional booleans. They report false after success or a failure before any bytes; after a failure with bytes, they compare the count with the expected size when known, and return nil otherwise. Nil also means a download has not finished. A caller-provided size or an outdated server size can make the result inaccurate, and a server's positive completion reply is not proof of content integrity.

## Active mode

Active mode listens on the control connection's local address, advertises it with EPRT, and falls back to PORT when an IPv4 server does not support EPRT. Incoming data connections must originate from the control peer's IP address; plain FTP has no cryptographic peer authentication. Active FTPS uses TLS client mode on the accepted socket. Firewalls, NAT, scoped IPv6 addresses, and servers using a different data host may prevent active mode from working. Explicit port ranges and an advertised IPv4 override are available.

## Resuming transfers

Download `resume: true` requires an existing regular, non-symlink local file and server support for binary `SIZE` and `REST`. The existing file is copied to a temporary sibling; the result replaces it only after the final reply and a size check succeed. Progress counts only newly downloaded bytes. **The caller must ensure the local file is an exact prefix of the current remote file:** size checks do not verify contents, remote changes of the same size, or concurrent changes to the local file. No checksum or snapshot isolation is provided, and copying the prefix requires extra disk space.

Upload `resume: true` requires an existing remote file, a regular local file, and server support for binary `SIZE` and `REST` with `STOR`. It seeks to the remote size and checks the final remote size after a successful completion reply. **The caller must verify that the remote file is an exact prefix of the unchanged local file.** The upload modifies the remote file in place: a server that ignores `REST`, a failed or cancelled transfer, or a concurrent change can truncate or corrupt it even when an error is reported. The size check cannot prove content integrity. Progress reports only newly sent bytes; append and resume cannot be combined.

## Synchronization

Sync requires existing local and remote roots and a parseable MLSD or common UNIX/Windows LIST. Unsupported entry types and symbolic links are rejected. Directory traversal, empty-directory creation, case sensitivity, basename/path matching and filters are configurable. Sync conservatively rejects paths that differ only by case or Unicode normalization, even on case-sensitive filesystems, to avoid overwriting differently named files on a less-sensitive destination. Sync opens the local root once and performs directory creation, file reads, staged downloads and deletion relative to opened directory descriptors without following path symlinks. The `mirrorWithDelete` and `deleteDestinationOnly` modes **delete selected destination files absent from the source**; they leave extra directories in place. Deletion rechecks source absence. Uploads use a temporary remote file followed by rename, which may fail on servers that do not replace existing files. Synchronization is not snapshot-isolated or transactional: local files or directories can be moved or changed while open, and remote changes can race the operation. Review previews and back up data before destructive operations.

Modification-time preservation is opt-in. Set `preserveDownloadModificationTime` to fetch `MDTM` before a file download, or set `preserveModificationTimes` on a sync plan. Downloads set the time on the temporary file before replacing the destination. Sync uploads set the time on the staged remote file with `MFMT` before renaming; unsupported `MFMT` or unavailable timestamps cause the operation to fail. The server may apply different timestamp precision.

## Proxies

HTTP CONNECT with Basic or NTLMv2, SOCKS4a, SOCKS5 and traditional FTP firewall proxies are configurable. SOCKS4 and SOCKS5 support active transfers via BIND when the FTP server is configured by numeric IP address (IPv4 only for SOCKS4). The reported incoming peer must match that IP; the proxy's bound address must match the proxy connection's peer or be unspecified. BIND uses a proxy-selected address and port, so custom active address and port-range overrides are rejected. Active mode through other proxies and FTPS through traditional FTP firewalls remain unsupported. The proxy connection is unencrypted: Basic and SOCKS credentials are exposed; NTLMv2 responses are vulnerable to relay and offline password guessing and do not authenticate the proxy. Use only a trusted network and proxy. NTLMv2 requires a persistent HTTP/1.x connection and bounded Content-Length or chunked challenge bodies; NTLMv1 and proxy TLS channel binding are unsupported. Choosing the server-advertised PASV host instead of the default control peer can expose FTP bounce attacks and should be enabled only for trusted servers.

## Download retries

Ordinary transfers do not automatically retry. The opt-in `FTPDownloadRetry.download` API retries atomic file downloads from the beginning with a fresh connection for each attempt, bounded exponential backoff and an optional retry callback. It accepts only slash-prefixed remote paths because each fresh login may have a different current directory; the server must interpret that path as absolute. Timeout and connection failures and replies 421, 425, 426, 450, 451 and 452 are retryable; other errors are returned immediately. The retry policy permits at most 10 attempts and a maximum delay of 300 seconds. Progress resets to zero on each attempt. The destination is replaced only after one successful completion; cancellation interrupts retry waits. Remote files may change between attempts, and no content checksum or snapshot guarantee is implied. Credentials are sent again on each connection. Retrying uploads, appends, synchronization or in-place resumes is not automatic because they can modify remote state.

## Compression and logging

MODE Z uses zlib framing and imposes a per-chunk decompression expansion limit. Session logs redact common credential commands, but raw commands and server messages may still contain secrets or sensitive file names. Upload plans and completion logs use a package-specific format.

## Upload plans

Upload-plan execution opens the local source root once and resolves child directories and regular files without following symlinks. The completion log must be a regular, non-symlink file; it is bounded to 16 MiB, locked cooperatively while the plan runs, and rejects incomplete records. Advisory locks do not prevent unrelated processes from ignoring the lock. A crash can leave a truncated log or a remote operation completed but not recorded; inspect and repair the log and remote state before resuming. Plan execution is not transactional, does not snapshot local file contents, and cannot prevent concurrent changes to already-open files or directories.

## Wildcard operations

Wildcard downloads hold an open destination directory throughout listing and transfer, and reject case-folding or Unicode-normalization filename collisions before writing. Wildcard deletions validate all selected names before deleting anything. These bulk operations are not transactional: later network or server failures can still leave earlier files transferred or deleted, and a directory moved after opening remains the operation's destination.

## Transfer keepalives

For servers that accept `NOOP` during transfers, enable the facade's `largeFileMeasures` for a 60-second interval, or set `transferKeepAliveInterval` explicitly. The client serializes control replies, including a transfer completion arriving before the NOOP reply. A rejected or ambiguous NOOP fails the transfer and closes the session; server support varies. Keepalives do not make a transfer transactional or guarantee that firewalls will preserve a session.

## Listings

The facade can select MLSD, legacy LIST, or names-only NLST for cached listings. NLST does not identify entry types, so type queries fail rather than guessing. Legacy LIST dates remain unavailable unless a server time zone is configured.

`dirTreeXml()` applies the facade's file and directory sync filters during recursive traversal and reports available file sizes and modification times. XML listing methods escape markup and reject filenames containing characters forbidden by XML 1.0.

## ASCII conversion

ASCII file downloads can optionally normalize CRLF, bare CR and bare LF using `asciiLineEnding` or the facade's `crlfMode`; the default leaves bytes unchanged. Conversion handles line endings split across network chunks and preserves NVT CR-NUL sequences. It is not applied to binary transfers or listings. Progress for converted file downloads counts bytes written locally; bandwidth throttling uses bytes received from the network. Use binary mode for byte-exact or multibyte-encoded files.

## Upload checksums

Optional `automaticUploadCRC` / `autoXcrc` checks an IEEE CRC-32 after uploading when processed `FEAT` data advertises `XCRC`. It accepts a `250` reply containing one hexadecimal checksum, optionally prefixed by `0x`; other server-specific reply formats fail closed. Append, chunked append, and ASCII uploads are rejected before transfer when this check is active, because the resulting remote bytes cannot be verified from the supplied data. If `XCRC` was not advertised, no check is attempted. A failed verification can leave the remote upload in place. CRC detects accidental corruption, not malicious tampering.

## Facade concurrency

The mutable `FTPClientFacade` is not safe for simultaneous access from multiple tasks; serialize access and do not change its properties during an operation. 

Facade changes to command and listing charsets, passive/active mode, EPSV/PASV selection, active-port settings, bandwidth throttles and the buffer limit apply to subsequent operations on an existing session. Connection and TLS identity settings are captured when connecting.

