# SysLink User Guide

This guide covers SysLink usage for SSH/QUIC connections and SFTP file transfer.

## Table of Contents

- Getting Started
- Client Usage
- Server Setup
- SFTP File Transfer
- Troubleshooting

## Getting Started

Build the project:

```bash
zig build
```

Run tests:

```bash
zig build test
```

## Client Usage

Open shell session:

```bash
./zig-out/bin/sl shell user@host:2222
```

Run one command:

```bash
./zig-out/bin/sl exec user@host "uname -a"
```

Start interactive SFTP prompt:

```bash
./zig-out/bin/sl sftp user@host:2222
```

## Server Setup

Start server daemon:

```bash
./zig-out/bin/sl server start -p 2222
```

## SFTP File Transfer

In the `sftp>` prompt you can use:

- `ls [path]`
- `cd <path>`
- `pwd`
- `get <remote> [local]`
- `put <local> [remote]`
- `mkdir <path>`
- `rm <path>`
- `help`
- `exit`

## Troubleshooting

- If auth fails, verify username/password or identity key.
- If directory listings fail, verify server permissions and path.
- If transfers fail, retry with smaller files and inspect server logs.
