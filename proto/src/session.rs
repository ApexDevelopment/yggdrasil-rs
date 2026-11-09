//! The first byte of every packet a node sends over an Ironwood session.

/// IPv6 traffic, or other application data.
pub const TYPE_SESSION_TRAFFIC: u8 = 1;
/// Nodeinfo and debug requests, handled by [`crate::requests`].
pub const TYPE_SESSION_PROTO: u8 = 2;
