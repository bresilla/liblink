const std = @import("std");
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("pwd.h");
    @cInclude("string.h");
});

/// System-level authentication for Linux/Unix systems
///
/// NOTE: Full PAM/shadow authentication requires:
/// - libpam0g-dev (Debian/Ubuntu) or pam-devel (Fedora/RHEL)
/// - Uncomment PAM/shadow code below and link with -lpam -lcrypt
///
/// Current implementation provides basic user validation only.

/// Validate system user password
///
/// SECURITY WARNING: This is a basic implementation that only checks
/// if the user exists. For production use, install PAM development
/// libraries and uncomment the full authentication code below.
pub fn validatePassword(username: []const u8, password: []const u8) bool {
    _ = password; // TODO: Implement real password checking with PAM

    var user_buf: [256]u8 = undefined;
    if (username.len >= user_buf.len) {
        return false;
    }

    // Create null-terminated string for C
    @memcpy(user_buf[0..username.len], username);
    user_buf[username.len] = 0;
    const user_cstr: [*:0]const u8 = @ptrCast(&user_buf);

    // Check if user exists
    const pwd = c.getpwnam(user_cstr);
    if (pwd == null) {
        std.log.debug("User '{s}' not found on system", .{username});
        return false;
    }

    std.log.warn("⚠️  WARNING: Password authentication is not fully implemented!", .{});
    std.log.warn("⚠️  Install libpam0g-dev and rebuild with PAM support for real authentication.", .{});
    std.log.warn("⚠️  Currently accepting any password for existing users (INSECURE!).", .{});

    // TODO: Implement PAM or shadow file authentication
    // For now, accept any password if user exists (INSECURE - for demo only)
    return true;
}

/// Parse authorized_keys line and extract key blob
/// Returns true if the line matches the provided algorithm and key
fn matchAuthorizedKey(
    line: []const u8,
    algorithm: []const u8,
    public_key_blob: []const u8,
    allocator: Allocator,
) bool {
    // Skip empty lines and comments
    const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
    if (trimmed.len == 0 or trimmed[0] == '#') {
        return false;
    }

    // Format: [options] keytype base64-key [comment]
    var iter = std.mem.tokenizeAny(u8, trimmed, &std.ascii.whitespace);

    // First token might be options or keytype
    const first = iter.next() orelse return false;
    const second = iter.next();

    var keytype: []const u8 = undefined;
    var base64_key: []const u8 = undefined;

    if (second == null) {
        return false;
    } else if (std.mem.indexOf(u8, first, "=") != null) {
        // First token has '=' so it's an option
        keytype = second.?;
        base64_key = iter.next() orelse return false;
    } else {
        // No options
        keytype = first;
        base64_key = second.?;
    }

    // Check if algorithm matches
    if (!std.mem.eql(u8, keytype, algorithm)) {
        return false;
    }

    // Decode base64 key
    const decoded_size = std.base64.standard.Decoder.calcSizeForSlice(base64_key) catch return false;
    const decoded = allocator.alloc(u8, decoded_size) catch return false;
    defer allocator.free(decoded);

    std.base64.standard.Decoder.decode(decoded, base64_key) catch return false;

    // Compare with provided public key blob
    return std.mem.eql(u8, decoded, public_key_blob);
}

/// Validate public key against user's authorized_keys
pub fn validatePublicKey(
    username: []const u8,
    algorithm: []const u8,
    public_key_blob: []const u8,
) bool {
    var user_buf: [256]u8 = undefined;
    if (username.len >= user_buf.len) {
        return false;
    }

    @memcpy(user_buf[0..username.len], username);
    user_buf[username.len] = 0;
    const user_cstr: [*:0]const u8 = @ptrCast(&user_buf);

    // Get user's home directory
    const pwd = c.getpwnam(user_cstr);
    if (pwd == null) {
        std.log.debug("User '{s}' not found on system", .{username});
        return false;
    }

    const home_dir = std.mem.span(pwd.*.pw_dir);

    // Build path to authorized_keys
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const auth_keys_path = std.fmt.bufPrint(&path_buf, "{s}/.ssh/authorized_keys", .{home_dir}) catch {
        std.log.debug("Path too long for authorized_keys", .{});
        return false;
    };

    // Read authorized_keys file
    const file = std.fs.openFileAbsolute(auth_keys_path, .{}) catch |err| {
        std.log.debug("Failed to open authorized_keys: {}", .{err});
        return false;
    };
    defer file.close();

    var allocator = std.heap.page_allocator;

    // Read file content
    const content = file.readToEndAlloc(allocator, 1024 * 1024) catch |err| {
        std.log.debug("Failed to read authorized_keys: {}", .{err});
        return false;
    };
    defer allocator.free(content);

    // Check each line
    var line_iter = std.mem.tokenizeScalar(u8, content, '\n');
    while (line_iter.next()) |line| {
        if (matchAuthorizedKey(line, algorithm, public_key_blob, allocator)) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// Full PAM/Shadow Implementation (requires development libraries)
// ============================================================================

// Uncomment and use the code below if you have libpam0g-dev installed
// Then add to build.zig:
//   sl.linkSystemLibrary("pam");
//   sl.linkSystemLibrary("crypt");

/*
const pam_c = @cImport({
    @cInclude("security/pam_appl.h");
    @cInclude("shadow.h");
    @cInclude("crypt.h");
});

/// PAM conversation function for non-interactive authentication
fn pamConvFunction(
    num_msg: c_int,
    msg: [*c][*c]const pam_c.pam_message,
    resp: [*c][*c]pam_c.pam_response,
    appdata_ptr: ?*anyopaque,
) callconv(.C) c_int {
    if (num_msg <= 0 or msg == null or resp == null) {
        return pam_c.PAM_CONV_ERR;
    }

    const password = if (appdata_ptr) |ptr| @as([*:0]const u8, @ptrCast(@alignCast(ptr))) else return pam_c.PAM_CONV_ERR;

    const response_array = pam_c.calloc(@intCast(num_msg), @sizeOf(pam_c.pam_response)) orelse return pam_c.PAM_CONV_ERR;
    const responses: [*c]pam_c.pam_response = @ptrCast(@alignCast(response_array));

    var i: usize = 0;
    while (i < num_msg) : (i += 1) {
        const message = msg[i];
        if (message == null) continue;

        const msg_style = message.*.msg_style;

        if (msg_style == pam_c.PAM_PROMPT_ECHO_OFF or msg_style == pam_c.PAM_PROMPT_ECHO_ON) {
            const pass_len = std.mem.len(password);
            const pass_copy = pam_c.malloc(pass_len + 1) orelse {
                var j: usize = 0;
                while (j < i) : (j += 1) {
                    if (responses[j].resp != null) {
                        pam_c.free(responses[j].resp);
                    }
                }
                pam_c.free(responses);
                return pam_c.PAM_CONV_ERR;
            };

            @memcpy(@as([*]u8, @ptrCast(pass_copy))[0..pass_len], password[0..pass_len]);
            @as([*]u8, @ptrCast(pass_copy))[pass_len] = 0;

            responses[i].resp = @ptrCast(pass_copy);
            responses[i].resp_retcode = 0;
        } else {
            responses[i].resp = null;
            responses[i].resp_retcode = 0;
        }
    }

    resp.* = responses;
    return pam_c.PAM_SUCCESS;
}

/// Authenticate using PAM
pub fn authenticateWithPam(username: [*:0]const u8, password: [*:0]const u8) bool {
    var pamh: ?*pam_c.pam_handle_t = null;

    var conv = pam_c.pam_conv{
        .conv = pamConvFunction,
        .appdata_ptr = @constCast(@ptrCast(password)),
    };

    var result = pam_c.pam_start("syslink", username, &conv, &pamh);
    if (result != pam_c.PAM_SUCCESS) {
        std.log.debug("PAM start failed: {d}", .{result});
        return false;
    }
    defer _ = pam_c.pam_end(pamh, result);

    result = pam_c.pam_authenticate(pamh, 0);
    if (result != pam_c.PAM_SUCCESS) {
        std.log.debug("PAM authentication failed: {d}", .{result});
        return false;
    }

    result = pam_c.pam_acct_mgmt(pamh, 0);
    if (result != pam_c.PAM_SUCCESS) {
        std.log.debug("PAM account management failed: {d}", .{result});
        return false;
    }

    return true;
}

/// Authenticate using shadow file (requires root)
pub fn authenticateWithShadow(username: [*:0]const u8, password: [*:0]const u8) bool {
    const shadow_entry = pam_c.getspnam(username);
    if (shadow_entry == null) {
        std.log.debug("Shadow entry not found (may need root)", .{});
        return false;
    }

    const encrypted_password = shadow_entry.*.sp_pwdp;
    if (encrypted_password == null) {
        return false;
    }

    const encrypted = std.mem.span(encrypted_password);
    if (encrypted.len == 0 or encrypted[0] == '!' or encrypted[0] == '*') {
        std.log.debug("Account is locked", .{});
        return false;
    }

    const crypted = pam_c.crypt(password, encrypted_password);
    if (crypted == null) {
        return false;
    }

    return c.strcmp(crypted, encrypted_password) == 0;
}
*/

// ============================================================================
// Tests
// ============================================================================

test "validatePassword - invalid user" {
    const testing = std.testing;

    const result = validatePassword("nonexistent_user_12345", "anypassword");
    try testing.expect(!result);
}

test "validatePublicKey - invalid user" {
    const testing = std.testing;

    const dummy_key = [_]u8{0} ** 32;
    const result = validatePublicKey("nonexistent_user_12345", "ssh-ed25519", &dummy_key);
    try testing.expect(!result);
}

test "matchAuthorizedKey - basic parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test comment line
    const comment = "# This is a comment";
    const result1 = matchAuthorizedKey(comment, "ssh-ed25519", "dummy", allocator);
    try testing.expect(!result1);

    // Test empty line
    const empty = "   ";
    const result2 = matchAuthorizedKey(empty, "ssh-ed25519", "dummy", allocator);
    try testing.expect(!result2);
}
