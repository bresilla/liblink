# liblink

SSH/QUIC protocol implementation in Zig. Secure remote access and file transfer over QUIC transport.

## Build

```bash
zig build
zig build test
```

## Usage

```bash
# Start server
sl server start
sl server start -p 2222 --daemon

# Remote shell
sl shell user@host:2222

# Execute command
sl exec user@host "ls -la"

# SFTP session
sl sftp user@host
```

## Library

```zig
const std = @import("std");
const liblink = @import("liblink");

// Connect
var conn = try liblink.connection.connectClient(allocator, "host", 2222, random);
defer conn.deinit();

// Execute
var session = try conn.requestExec("uptime");
defer session.close() catch {};

// SFTP
var sftp_channel = try conn.openSftp();
var sftp = try liblink.sftp.SftpClient.init(allocator, sftp_channel);
```

## Project Structure

```
lib/
  liblink.zig        Entry point
  connection.zig     Connection management
  auth/              Authentication
  channels/          SSH channels
  crypto/            Cryptographic primitives
  kex/               Key exchange
  network/           Networking (UDP)
  protocol/          Protocol messages
  sftp/              SFTP implementation
bin/
  sl.zig             CLI tool
examples/
  client_demo.zig
  server_demo.zig
```

## Protocol

Implements [draft-bider-ssh-quic](https://datatracker.ietf.org/doc/draft-bider-ssh-quic/) with:

- Ed25519 signatures, X25519 key exchange, HKDF-SHA256
- QUIC stream multiplexing (SSH channels map to QUIC streams)
- SSH authentication (public key)
- SFTP v3 client and server
- Session channels (shell, exec, subsystem)

## References

- [draft-bider-ssh-quic](https://datatracker.ietf.org/doc/draft-bider-ssh-quic/)
- [SSH Protocol (RFC 4251-4254)](https://www.rfc-editor.org/rfc/rfc4251.html)
- [SFTP Protocol](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02)
- [QUIC (RFC 9000)](https://www.rfc-editor.org/rfc/rfc9000.html)
