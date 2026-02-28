# Changelog

## [0.0.9] - 2026-02-28

### <!-- 1 -->🐛 Bug Fixes

- Improve client I/O and window resizing

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Update libfast dependency

## [0.0.8] - 2026-02-25

### <!-- 0 -->⛰️  Features

- Implement keepalive probing for dead client detection
- Gracefully terminate shell sessions

### <!-- 1 -->🐛 Bug Fixes

- Improve session termination and error handling

## [0.0.7] - 2026-02-24

### <!-- 3 -->📚 Documentation

- Add comprehensive documentation for CLI, library, and protocol

## [0.0.6] - 2026-02-24

### <!-- 1 -->🐛 Bug Fixes

- Use standard known_hosts file path

## [0.0.5] - 2026-02-24

### <!-- 0 -->⛰️  Features

- Implement server forking for concurrent clients

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Update SSH-QUIC draft reference

## [0.0.4] - 2026-02-22

### <!-- 0 -->⛰️  Features

- Update channel protocol and KEX H calculation

### <!-- 3 -->📚 Documentation

- Refactor README for clarity and conciseness

## [0.0.3] - 2026-02-22

### <!-- 0 -->⛰️  Features

- Improve channel session and PTY handling
- Refactor authentication to exclusively use public keys
- Add host endpoint formatting and known-hosts path-scoped helpers
- Add strict and accept-new host trust policy options
- Add known-hosts trust workflow for client connections
- Add library user identity primitives and apply privilege drop

### <!-- 1 -->🐛 Bug Fixes

- Unblock release build in session channel acceptance
- Harden server-side session channel acceptance

### <!-- 2 -->🚜 Refactor

- Rename project to liblink
- Share server-ready checks across network e2e
- Share channel request string decode helper
- Share network channel request wait helper
- Standardize network e2e constants and seeds
- Share authenticated server thread startup helper
- Share network server thread context primitives
- Share authenticated network client helper
- Centralize network e2e server bootstrap flow
- Share env gating and readiness helpers for e2e
- Deduplicate network e2e test scaffolding
- Share network session-channel test helper
- Move exec output collection into channels workflow
- Move endpoint parsing into reusable network module
- Move high-level sftp file operations into library workflow
- Move client auth fallback flow into library module
- Move daemon pid lifecycle helpers into library
- Move server session runtime from sl binary into library

### <!-- 6 -->🧪 Testing

- Add packet-level coverage for exec output workflow
- Add deterministic network exec e2e assertions

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Rename runquic to libfast in package

## [0.0.2] - 2026-02-17

### <!-- 0 -->⛰️  Features

- Add -i identity auth support across shell exec and sftp
- Bind authenticated username into session and auth flow
- Implement public-key auth pk-ok and multi-step retries
- Enforce trusted host fingerprint checks in client kex
- Improve exec channel stderr and exit-status handling
- Harden daemon startup and graceful shutdown handling
- Support SFTP statvfs and fsync extensions
- Add SFTP posix-rename extended request support
- Add daemon start stop and status lifecycle
- Implement exec sessions and wire negotiated connection IDs
- Integrate runquic library for QUIC transport
- Remove password authentication
- Implement system-level authentication with PAM
- Improve PTY session handling and interactive shell
- Implement interactive shell and TTY modes
- Implement PTY request handling in session
- Implement PTY I/O bridging for shell sessions
- Implement basic session management and PTY spawning
- Implement custom minimal QUIC transport
- Add server and SSHFS client commands
- Implement SFTP server and enhance core features
- Implement interactive shell and SFTP command loops
- Implement proper Ed25519 signature verification using std.crypto
- Add SSH public key authentication support
- Implement secure password input and fix SSHFS installation
- Complete SSHFS implementation with full Zig 0.15.2 compatibility
- Implement basic SSH/QUIC client and server
- Implement SSH user authentication protocol
- Complete SSH/QUIC network stack with UDP transport
- Wire up UDP networking for SSH/QUIC key exchange
- Integrate zquic with SSH/QUIC and add UDP transport
- Implement connection orchestrator and complete SSH/QUIC integration
- Implement high-level SSH key exchange orchestrator
- Implement QUIC secret derivation from SSH
- Implement QUIC transport with SSH secret injection
- Use forked zquic with SSH secret injection support
- Implement CLI entry point with command structure
- Implement SFTP client with file operations
- Implement SFTP file attributes
- Implement SFTP protocol messages
- Implement public key authentication method
- Implement password authentication method
- Implement SSH authentication protocol messages
- Implement SSH_MSG_EXT_INFO extension info
- Implement SSH channel structure
- Add QUIC stream mapping and validation
- Implement SSH/QUIC packet format
- Implement SSH/QUIC key derivation
- Implement curve25519-sha256 key exchange method
- Implement SSH_QUIC_CANCEL message structure
- Implement SSH_QUIC_REPLY message structure
- Implement SSH_QUIC_INIT message structure
- Implement obfuscated envelope encryption and decryption
- Implement obfuscation keyword processing
- Add KDF wrappers for HMAC-SHA256 and HKDF-SHA256
- Add SHA-256 hash wrapper
- Add Ed25519 signature wrapper placeholder
- Add X25519 ECDH wrapper for key exchange
- Implement AES-256-GCM AEAD wrapper
- Add zcrypto integration facade and module structure
- Implement Random Name in Private and Anonymous forms
- Add Random Name generation in Assigned form
- Implement Random Bytes generation with proper distribution
- Add string and short-str encoding
- Implement mpint encoding with sign handling
- Implement byte and boolean encoding
- Add SSH message type constants and disconnect reason codes
- Define core error types for protocol, crypto, and connection

### <!-- 1 -->🐛 Bug Fixes

- Harden daemon pid file path and ownership checks
- Tighten SFTP error mapping and implement fsync sync
- Harden auth client handling for fragmented and banner responses
- Improve QUIC stream closing and error handling
- Refactor shell command and interactive mode
- Update const variable names from voidbox to syslink
- Replace broken SFTP client test with request ID test
- Update CLI and library for Zig 0.15.2 compatibility
- Update zquic to version with zcrypto Zig 0.15.2 fixes
- Use bresilla/zcrypto fork for Zig 0.15.2 compat

### <!-- 2 -->🚜 Refactor

- Wrap runquic transport behind stable local adapter
- Remove deprecated ServerConnection.accept API
- Introduce local quic transport adapter boundary
- Remove SSHFS to streamline the codebase
- Rename library from voidbox to syslink
- Improve CLI command structure and help system
- Rename CLI tool from vb to sl
- Rename src/ to lib/ and cli/ to bin/ for better clarity

### <!-- 3 -->📚 Documentation

- Add comprehensive implementation plan

### <!-- 6 -->🧪 Testing

- Replace placeholder integration checks with behavior tests
- Add opt-in network sftp subsystem e2e flow
- Add opt-in network auth e2e and robust auth request reads
- Add SSH/QUIC packet and streaming integration tests
- Add comprehensive obfuscation test vectors
- Add tests for random element generation
- Add edge case tests for wire encoding (empty, max values)
- Add comprehensive round-trip tests for mpint and strings
- Add comprehensive round-trip tests for all wire types

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Update runquic dependency version
- Remove old test binaries
- Complete Phase 1 - foundation with wire encoding and random generation
- Add zquic and zcrypto dependencies
- Initial project setup with build configuration and specification

### Add

- SSH/QUIC connection test example

### Build

- Add release automation and project metadata
- Create directory structure for all modules

