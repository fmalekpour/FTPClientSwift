# Contributing

## Before opening an issue

Search existing issues and confirm the behavior against the latest `main` branch. Include:

- Platform and OS version.
- Swift/Xcode version.
- Server type and FTP/FTPS mode.
- Proxy and TLS settings, excluding credentials and private keys.
- A minimal reproduction.
- Relevant session-log excerpts with secrets removed.

## Development setup

1. Clone the repository.
2. Open it in Xcode or run `swift package resolve`.
3. Run `swift test`.
4. For platform checks, build the package for the declared Apple platforms.

The integration tests use local loopback fixtures. FTPS integration tests may use Node.js and OpenSSL when available; these are test-only tools and are not runtime dependencies.

## Code guidelines

- Keep the package dependency-free at runtime.
- Preserve the declared platform support unless a change is intentional and documented.
- Prefer small, focused changes.
- Keep public APIs `Sendable` where appropriate.
- Do not log passwords, private keys, tokens, or complete secret-bearing commands.
- Add regression tests for protocol, cancellation, security, and filesystem-safety changes.
- Update `README.md` and the relevant document under `docs/` when public behavior changes.

## Pull requests

A pull request should include:

- A concise description of the behavior changed.
- Tests added or updated.
- Validation commands and results.
- Security or compatibility implications.
- Documentation updates where needed.

Do not include credentials, certificates with private keys, customer data, or server logs containing sensitive information.
