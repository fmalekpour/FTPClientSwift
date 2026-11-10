# Security Guide

## Recommended defaults

- Prefer explicit or implicit FTPS over plain FTP.
- Keep `requireServerCertificateValidation` enabled.
- Use hostname-based TLS connections so hostname verification and SNI work correctly.
- Use `dataProtection: .privateData` for protected FTPS data channels.
- Keep `usePASVAdvertisedAddress` disabled unless the server environment requires it and is trusted.
- Store credentials in an application-controlled secret store.
- Set a finite `connectTimeout` and `readTimeout`.
- Review session logs before shipping; logs are bounded and redact common credential commands, but raw commands can still contain sensitive paths.

## Plain FTP

Plain FTP sends credentials, commands, listings, and file contents without encryption. Use it only on a trusted network or with a protected tunnel.

## Certificate validation

Certificate-chain validation and hostname validation are enabled by default for the idiomatic client. Pins and certificate-field requirements add checks; they do not replace normal validation.

Disabling chain validation is an explicit trust decision that can permit interception by a certificate issued for the expected hostname. Do not disable it in production unless an independently authenticated network makes that decision acceptable.

## Data-channel protection

FTPS control and data channels are separate. A protected control channel does not automatically make data private unless `PBSZ 0` and `PROT P` succeed. `dataProtection: .clear` explicitly permits unencrypted data and should be treated as insecure.

## Resume and retries

Resume modifies an existing remote file in place for uploads and assumes the existing bytes are an exact prefix. A failed upload can leave a partial or corrupted remote file.

`FTPDownloadRetry` starts each attempt from the beginning and atomically replaces the local destination only after successful completion. It does not snapshot the remote file; the remote content can change between attempts.

## Proxies

Proxy credentials and traffic may be exposed to the proxy operator. SOCKS and HTTP proxy connections are not automatically protected by the FTP server's TLS layer. NTLMv2 proxy authentication does not authenticate the proxy and does not provide TLS channel binding.

Active-mode proxy support is intentionally restricted to validated SOCKS BIND configurations.

## Client identities

Private keys and passphrases are processed in memory. PKCS#12 and supported PEM identities are retained only for the lifetime required by the session. Protect identity files and avoid logging their contents.

## Reporting a vulnerability

Follow the [security policy](../SECURITY.md).
