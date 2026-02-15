# Authentication in Syslink

Syslink supports both password and public key authentication, validated against the system's user database.

## Authentication Methods

### 1. Password Authentication

Password authentication uses **PAM (Pluggable Authentication Modules)** as the primary method, with fallback to direct shadow file checking if PAM is unavailable.

#### Setup

1. **Install PAM Configuration**

   Copy the PAM configuration file to your system:

   ```bash
   sudo cp pam.d/syslink /etc/pam.d/syslink
   ```

2. **Required Permissions**

   - PAM authentication: Can run as any user
   - Shadow file fallback: Requires root privileges

3. **Running the Server**

   ```bash
   # With PAM (recommended - runs as any user)
   ./zig-out/bin/sl server start

   # With shadow file access (requires root)
   sudo ./zig-out/bin/sl server start
   ```

#### How It Works

The library (`lib/auth/system.zig`) provides:

- `validatePassword(username, password)` - Validates user credentials
- `authenticateWithPam()` - PAM-based authentication
- `authenticateWithShadow()` - Direct shadow file authentication (fallback)

### 2. Public Key Authentication

Public key authentication reads the user's `~/.ssh/authorized_keys` file to verify the client's public key.

#### Setup

1. **Add Your Public Key**

   On the server, add your public key to the user's authorized_keys:

   ```bash
   mkdir -p ~/.ssh
   chmod 700 ~/.ssh
   echo "ssh-ed25519 AAAA... your-key-comment" >> ~/.ssh/authorized_keys
   chmod 600 ~/.ssh/authorized_keys
   ```

2. **Client Authentication**

   ```bash
   sl shell -i ~/.ssh/id_ed25519 user@host
   ```

#### Supported Key Types

- **ssh-ed25519** (recommended)
- ssh-rsa
- ecdsa-sha2-nistp256

#### How It Works

The library (`lib/auth/system.zig`) provides:

- `validatePublicKey(username, algorithm, public_key_blob)` - Validates public key
- Parses `~/.ssh/authorized_keys` file
- Supports standard OpenSSH authorized_keys format

## Library API

### Using in Your Application

```zig
const syslink = @import("syslink");

// Setup authentication server
var server_conn = try listener.acceptConnection();
defer server_conn.deinit();

// Define validators using library functions
const Validators = struct {
    fn passValidator(user: []const u8, pass: []const u8) bool {
        return syslink.auth.system.validatePassword(user, pass);
    }

    fn keyValidator(user: []const u8, algorithm: []const u8, public_key_blob: []const u8) bool {
        return syslink.auth.system.validatePublicKey(user, algorithm, public_key_blob);
    }
};

// Handle authentication
const authed = try server_conn.handleAuthentication(
    Validators.passValidator,
    Validators.keyValidator,
);
```

### Custom Validators

You can also implement custom validators if you don't want to use system authentication:

```zig
fn customPasswordValidator(username: []const u8, password: []const u8) bool {
    // Your custom logic here
    return checkDatabase(username, password);
}

fn customKeyValidator(username: []const u8, algorithm: []const u8, public_key_blob: []const u8) bool {
    // Your custom logic here
    return checkKeyDatabase(username, algorithm, public_key_blob);
}
```

## Security Considerations

1. **PAM Configuration**
   - Default configuration uses `pam_unix.so`
   - Can be customized for different authentication backends
   - Respects system security policies

2. **Authorized Keys**
   - File must be owned by the user
   - Recommended permissions: 600
   - Directory permissions: 700 for `~/.ssh`

3. **Transport Security**
   - All authentication happens over encrypted SSH/QUIC connection
   - Credentials are never sent in plaintext

4. **Privileges**
   - PAM authentication: No special privileges required
   - Shadow file access: Requires root (not recommended)
   - Public key auth: No special privileges required

## Dependencies

The authentication system requires:

- **libpam** - PAM library
- **libcrypt** - Password hashing library

These are linked automatically via `build.zig`:

```zig
lib.linkSystemLibrary("pam");
lib.linkSystemLibrary("crypt");
```

On Debian/Ubuntu:
```bash
sudo apt-get install libpam0g-dev
```

On Fedora/RHEL:
```bash
sudo dnf install pam-devel
```

## Testing

```bash
# Build
zig build

# Test authentication module
zig build test

# Manual testing
# Terminal 1: Start server
./zig-out/bin/sl server start

# Terminal 2: Connect with password
./zig-out/bin/sl shell user@localhost

# Terminal 2: Connect with key
./zig-out/bin/sl shell -i ~/.ssh/id_ed25519 user@localhost
```

## Troubleshooting

### PAM Authentication Fails

1. Check PAM configuration exists:
   ```bash
   ls -l /etc/pam.d/syslink
   ```

2. Check PAM logs:
   ```bash
   sudo tail -f /var/log/auth.log  # Debian/Ubuntu
   sudo journalctl -f              # systemd systems
   ```

3. Test with a simple PAM config:
   ```
   auth required pam_permit.so
   ```

### Public Key Authentication Fails

1. Check authorized_keys permissions:
   ```bash
   ls -la ~/.ssh/authorized_keys
   # Should be: -rw------- (600)
   ```

2. Check key format matches:
   ```bash
   cat ~/.ssh/authorized_keys
   # Should start with: ssh-ed25519 AAAA...
   ```

3. Verify key fingerprint:
   ```bash
   ssh-keygen -lf ~/.ssh/id_ed25519.pub
   ```
