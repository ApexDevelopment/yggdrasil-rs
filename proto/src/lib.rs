//! The parts of [yggdrasil-rs](https://github.com/ApexDevelopment/yggdrasil-rs)
//! that need no operating system: addresses, the link handshake, multicast
//! beacons, nodeinfo and debug requests, and IPv6 address-to-key routing.
//!
//! It needs only `alloc`, so it can run on microcontrollers alongside
//! [petrified](https://github.com/ApexDevelopment/petrified). The stateful
//! parts are sans-IO: the caller moves the packets and keeps the clock.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod address;
pub mod advertisement;
pub mod go_hex;
pub mod handshake;
pub mod icmpv6;
pub mod ipv6;
pub mod json;
pub mod requests;
pub mod session;

pub use petrified::types::{Instant, PrivateKey, PublicKey};
