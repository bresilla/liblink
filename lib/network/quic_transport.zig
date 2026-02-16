const runquic_transport = @import("runquic_transport");

/// SysLink QUIC transport adapter type.
///
/// This indirection keeps runquic transport integration behind a local module
/// boundary so SysLink internals do not depend on dependency import names.
pub const QuicTransport = runquic_transport.QuicTransport;
