const std = @import("std");
const posix = std.posix;

/// Terminal mode opcodes from RFC 4254 Section 8
pub const TTY_OP_END = 0;
pub const VINTR = 1;
pub const VQUIT = 2;
pub const VERASE = 3;
pub const VKILL = 4;
pub const VEOF = 5;
pub const VEOL = 6;
pub const VEOL2 = 7;
pub const VSTART = 8;
pub const VSTOP = 9;
pub const VSUSP = 10;
pub const VDSUSP = 11;
pub const VREPRINT = 12;
pub const VWERASE = 13;
pub const VLNEXT = 14;
pub const VFLUSH = 15;
pub const VSWTCH = 16;
pub const VSTATUS = 17;
pub const VDISCARD = 18;

// Input modes
pub const IGNPAR = 30;
pub const PARMRK = 31;
pub const INPCK = 32;
pub const ISTRIP = 33;
pub const INLCR = 34;
pub const IGNCR = 35;
pub const ICRNL = 36;
pub const IUCLC = 37;
pub const IXON = 38;
pub const IXANY = 39;
pub const IXOFF = 40;
pub const IMAXBEL = 41;

// Local modes
pub const ISIG = 50;
pub const ICANON = 51;
pub const XCASE = 52;
pub const ECHO = 53;
pub const ECHOE = 54;
pub const ECHOK = 55;
pub const ECHONL = 56;
pub const NOFLSH = 57;
pub const TOSTOP = 58;
pub const IEXTEN = 59;
pub const ECHOCTL = 60;
pub const ECHOKE = 61;
pub const PENDIN = 62;

// Output modes
pub const OPOST = 70;
pub const OLCUC = 71;
pub const ONLCR = 72;
pub const OCRNL = 73;
pub const ONOCR = 74;
pub const ONLRET = 75;

// Control modes
pub const CS7 = 90;
pub const CS8 = 91;
pub const PARENB = 92;
pub const PARODD = 93;

// Baud rates
pub const TTY_OP_ISPEED = 128;
pub const TTY_OP_OSPEED = 129;

/// Encode current terminal modes for SSH PTY request
///
/// Returns encoded byte stream according to RFC 4254 Section 8
pub fn encodeTerminalModes(allocator: std.mem.Allocator) ![]u8 {
    const c = @cImport({
        @cInclude("termios.h");
        @cInclude("unistd.h");
    });

    // Get current terminal settings
    var termios_p: c.termios = undefined;
    if (c.tcgetattr(posix.STDIN_FILENO, &termios_p) != 0) {
        // If we can't get terminal settings, return minimal modes
        return try encodeMinimalModes(allocator);
    }

    // Allocate buffer for encoded modes (max ~300 bytes)
    var buffer: [512]u8 = undefined;
    var offset: usize = 0;

    // Helper to encode a mode
    const encodeByte = struct {
        fn call(buf: []u8, idx: *usize, opcode: u8, value: u32) !void {
            buf[idx.*] = opcode;
            idx.* += 1;
            buf[idx.*] = @intCast((value >> 24) & 0xFF);
            idx.* += 1;
            buf[idx.*] = @intCast((value >> 16) & 0xFF);
            idx.* += 1;
            buf[idx.*] = @intCast((value >> 8) & 0xFF);
            idx.* += 1;
            buf[idx.*] = @intCast(value & 0xFF);
            idx.* += 1;
        }
    }.call;

    // Encode control characters
    if (termios_p.c_cc[c.VINTR] != 0) try encodeByte(&buffer, &offset, VINTR, termios_p.c_cc[c.VINTR]);
    if (termios_p.c_cc[c.VQUIT] != 0) try encodeByte(&buffer, &offset, VQUIT, termios_p.c_cc[c.VQUIT]);
    if (termios_p.c_cc[c.VERASE] != 0) try encodeByte(&buffer, &offset, VERASE, termios_p.c_cc[c.VERASE]);
    if (termios_p.c_cc[c.VKILL] != 0) try encodeByte(&buffer, &offset, VKILL, termios_p.c_cc[c.VKILL]);
    if (termios_p.c_cc[c.VEOF] != 0) try encodeByte(&buffer, &offset, VEOF, termios_p.c_cc[c.VEOF]);
    if (termios_p.c_cc[c.VEOL] != 0) try encodeByte(&buffer, &offset, VEOL, termios_p.c_cc[c.VEOL]);
    if (termios_p.c_cc[c.VSUSP] != 0) try encodeByte(&buffer, &offset, VSUSP, termios_p.c_cc[c.VSUSP]);

    // Encode input modes
    try encodeByte(&buffer, &offset, IGNPAR, if (termios_p.c_iflag & c.IGNPAR != 0) 1 else 0);
    try encodeByte(&buffer, &offset, PARMRK, if (termios_p.c_iflag & c.PARMRK != 0) 1 else 0);
    try encodeByte(&buffer, &offset, INPCK, if (termios_p.c_iflag & c.INPCK != 0) 1 else 0);
    try encodeByte(&buffer, &offset, ISTRIP, if (termios_p.c_iflag & c.ISTRIP != 0) 1 else 0);
    try encodeByte(&buffer, &offset, INLCR, if (termios_p.c_iflag & c.INLCR != 0) 1 else 0);
    try encodeByte(&buffer, &offset, IGNCR, if (termios_p.c_iflag & c.IGNCR != 0) 1 else 0);
    try encodeByte(&buffer, &offset, ICRNL, if (termios_p.c_iflag & c.ICRNL != 0) 1 else 0);
    try encodeByte(&buffer, &offset, IXON, if (termios_p.c_iflag & c.IXON != 0) 1 else 0);
    try encodeByte(&buffer, &offset, IXANY, if (termios_p.c_iflag & c.IXANY != 0) 1 else 0);
    try encodeByte(&buffer, &offset, IXOFF, if (termios_p.c_iflag & c.IXOFF != 0) 1 else 0);

    // Encode local modes
    try encodeByte(&buffer, &offset, ISIG, if (termios_p.c_lflag & c.ISIG != 0) 1 else 0);
    try encodeByte(&buffer, &offset, ICANON, if (termios_p.c_lflag & c.ICANON != 0) 1 else 0);
    try encodeByte(&buffer, &offset, ECHO, if (termios_p.c_lflag & c.ECHO != 0) 1 else 0);
    try encodeByte(&buffer, &offset, ECHOE, if (termios_p.c_lflag & c.ECHOE != 0) 1 else 0);
    try encodeByte(&buffer, &offset, ECHOK, if (termios_p.c_lflag & c.ECHOK != 0) 1 else 0);
    try encodeByte(&buffer, &offset, ECHONL, if (termios_p.c_lflag & c.ECHONL != 0) 1 else 0);
    try encodeByte(&buffer, &offset, NOFLSH, if (termios_p.c_lflag & c.NOFLSH != 0) 1 else 0);
    try encodeByte(&buffer, &offset, TOSTOP, if (termios_p.c_lflag & c.TOSTOP != 0) 1 else 0);
    try encodeByte(&buffer, &offset, IEXTEN, if (termios_p.c_lflag & c.IEXTEN != 0) 1 else 0);

    // Encode output modes
    try encodeByte(&buffer, &offset, OPOST, if (termios_p.c_oflag & c.OPOST != 0) 1 else 0);
    try encodeByte(&buffer, &offset, ONLCR, if (termios_p.c_oflag & c.ONLCR != 0) 1 else 0);

    // Encode baud rates
    const ispeed = c.cfgetispeed(&termios_p);
    const ospeed = c.cfgetospeed(&termios_p);
    try encodeByte(&buffer, &offset, TTY_OP_ISPEED, @intCast(ispeed));
    try encodeByte(&buffer, &offset, TTY_OP_OSPEED, @intCast(ospeed));

    // Terminate with TTY_OP_END
    buffer[offset] = TTY_OP_END;
    offset += 1;

    return try allocator.dupe(u8, buffer[0..offset]);
}

/// Encode minimal terminal modes for when we can't get real terminal settings
fn encodeMinimalModes(allocator: std.mem.Allocator) ![]u8 {
    var buffer: [256]u8 = undefined;
    var offset: usize = 0;

    const encodeByte = struct {
        fn call(buf: []u8, idx: *usize, opcode: u8, value: u32) !void {
            buf[idx.*] = opcode;
            idx.* += 1;
            buf[idx.*] = @intCast((value >> 24) & 0xFF);
            idx.* += 1;
            buf[idx.*] = @intCast((value >> 16) & 0xFF);
            idx.* += 1;
            buf[idx.*] = @intCast((value >> 8) & 0xFF);
            idx.* += 1;
            buf[idx.*] = @intCast(value & 0xFF);
            idx.* += 1;
        }
    }.call;

    // Set reasonable defaults
    try encodeByte(&buffer, &offset, VINTR, 3);    // Ctrl+C
    try encodeByte(&buffer, &offset, VQUIT, 28);   // Ctrl+\
    try encodeByte(&buffer, &offset, VERASE, 127); // Backspace
    try encodeByte(&buffer, &offset, VEOF, 4);     // Ctrl+D
    try encodeByte(&buffer, &offset, ISIG, 1);     // Enable signals
    try encodeByte(&buffer, &offset, ICANON, 1);   // Canonical mode
    try encodeByte(&buffer, &offset, ECHO, 1);     // Echo input
    try encodeByte(&buffer, &offset, ECHOE, 1);    // Visual erase
    try encodeByte(&buffer, &offset, ECHOK, 1);    // Echo kill
    try encodeByte(&buffer, &offset, OPOST, 1);    // Output processing
    try encodeByte(&buffer, &offset, ONLCR, 1);    // NL to CR+NL

    // Terminate
    buffer[offset] = TTY_OP_END;
    offset += 1;

    return try allocator.dupe(u8, buffer[0..offset]);
}
