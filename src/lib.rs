//! A Rust port of [Yggdrasil](https://yggdrasil-network.github.io/), an
//! end-to-end encrypted IPv6 mesh network, built on the
//! [petrified](https://github.com/ApexDevelopment/petrified) port of its Ironwood
//! routing protocol. The parts that need no operating system are in
//! [`yggdrasil_proto`], and re-exported here.
//!
//! The modules mirror yggdrasil-go's packages:
//!
//! - [`core`]: the node itself, its peer links and their transports
//! - [`address`]: IPv6 addresses and subnets derived from keys
//! - [`ipv6rwc`]: reading and writing IPv6 packets addressed by IP rather than key
//! - [`tun`]: the TUN adapter
//! - [`multicast`]: peer discovery on local networks
//! - [`admin`]: the admin socket
//! - [`config`]: the configuration file

pub use yggdrasil_proto::address;
pub mod admin;
#[doc(hidden)]
pub mod cli;
pub mod config;
pub mod core;
pub use yggdrasil_proto::go_hex;
pub mod ipv6rwc;
pub use yggdrasil_proto::json;
pub mod multicast;
pub mod tun;
pub mod version;

pub use petrified::types::{PrivateKey, PublicKey};
