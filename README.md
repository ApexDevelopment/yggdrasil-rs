# yggdrasil-rs

A Rust port of [Yggdrasil](https://yggdrasil-network.github.io/), the end-to-end
encrypted IPv6 mesh network. Routing comes from
[petrified](../petrified), the Rust port of Ironwood.

It is compatible with [yggdrasil-go](https://github.com/yggdrasil-network/yggdrasil-go)
v0.5.15: nodes of both implementations peer with each other over every transport,
route traffic for each other, and answer each other's nodeinfo and debug requests.
The command-line tools take the same flags, read the same configuration files and
speak the same admin socket protocol, so either `yggdrasilctl` works with either node.

## Programs

| Program        | Purpose                                              |
| -------------- | ---------------------------------------------------- |
| `yggdrasil`    | The node: `yggdrasil -useconffile /etc/yggdrasil.conf` |
| `yggdrasilctl` | Queries a running node: `yggdrasilctl getPeers`      |
| `genkeys`      | Searches for keys with higher addresses              |

```sh
cargo build --release
./target/release/yggdrasil -genconf > yggdrasil.conf
sudo ./target/release/yggdrasil -useconffile yggdrasil.conf
```

## Layout

The modules mirror yggdrasil-go's packages:

| Go          | Rust                   |                                                     |
| ----------- | ---------------------- | --------------------------------------------------- |
| `core`      | `yggdrasil::core`      | The node, peer links and transports, nodeinfo       |
| `address`   | `yggdrasil::address`   | IPv6 addresses and subnets derived from keys        |
| `ipv6rwc`   | `yggdrasil::ipv6rwc`   | IPv6 packets addressed by IP instead of key         |
| `tun`       | `yggdrasil::tun`       | The TUN adapter                                     |
| `multicast` | `yggdrasil::multicast` | Peer discovery on local networks                    |
| `admin`     | `yggdrasil::admin`     | The admin socket                                    |
| `config`    | `yggdrasil::config`    | Configuration files                                 |
| `version`   | `yggdrasil::version`   | Build information                                   |

## Transports

Peers are given as URIs, with the same options as yggdrasil-go
(`key`, `priority`, `password`, `maxbackoff`, `sni`):

| Scheme              | Dial | Listen |                                           |
| ------------------- | ---- | ------ | ----------------------------------------- |
| `tcp://`            | yes  | yes    |                                           |
| `tls://`            | yes  | yes    | Self-signed certificates, as in Go        |
| `quic://`           | yes  | yes    | One bidirectional stream per connection   |
| `ws://`             | yes  | yes    | Binary messages, `ygg-ws` subprotocol     |
| `wss://`            | yes  | no     | Put a `ws://` listener behind a proxy     |
| `unix://`           | yes  | yes    | Unix only                                 |
| `socks://`, `sockstls://` | yes | no | `socks://[user:pass@]proxy:port/host:port` |

Other transports plug in through `core::LinkProtocol`, which turns a URI into a
byte stream. Register one with `Core::register_link_protocol`, and peers and
listeners with its scheme will use it.

## As a library

```rust
use yggdrasil::core::{Core, Options};
use yggdrasil::PrivateKey;

let core = Core::new(PrivateKey::from_seed(&seed), Options::default()).await?;
let listener = core.listen("tls://[::]:0", "").await?;
core.add_peer("tls://example.com:443", "")?;

core.write_to(b"hello", &their_key)?;
let (from, packet) = core.recv().await?;
```

`Core` runs on tokio. Wrap it in `ipv6rwc::ReadWriteCloser` to send and receive
IPv6 packets addressed by Yggdrasil IP; it looks up the keys behind addresses.

## Differences from Go

### Fixed

These yggdrasil-go behaviours look unintended, so yggdrasil-rs does not copy them:

- In `MulticastInterfaces`, Go fills fields an entry leaves out from the default
  entry in the same position: on Linux, `[{Regex: "eth0"}]` beacons and listens,
  while a second entry written the same way does neither. Here every entry
  starts empty, so unset fields are always `false`, `""` or `0`.
- Interfaces use the first matching entry of `MulticastInterfaces`, in order. Go
  iterates a map, so with overlapping regexes its choice varies between runs.
- `getPeers` sorts by exact priority, cost and uptime. Go compares by
  subtracting, which wraps around for large priorities and costs, and treats
  uptimes less than a second apart as equal.

### Other differences

- Goroutines and actors are tokio tasks. Configuration is an `Options` struct
  rather than a list of `SetupOption`s, and `Core::new` takes the private key and
  makes the TLS certificate itself.
- I/O errors use Rust's wording, e.g. `Connection refused (os error 111)`.
- A `null` list in the configuration is treated as empty, where Go would keep it
  `null` when writing the configuration back out.
- Not ported: the Windows service wrapper, OpenBSD `pledge`, the mobile bindings,
  and WebSocket proxies from `HTTP_PROXY`.
- On Android and iOS, the TUN adapter takes a file descriptor from the VPN API
  (`tun::InterfaceSource::FileDescriptor`).
- The build name and version default to this crate's. Set `YGGDRASIL_BUILD_NAME`
  and `YGGDRASIL_BUILD_VERSION` at build time to override them, or
  `YGGDRASIL_DEFAULT_CONFIG` and `YGGDRASIL_DEFAULT_ADMIN_LISTEN` to change the
  platform defaults, as Go's linker flags do.

## Known issues

The first nodeinfo or `debug_remote*` request to a node right after peering
with it usually times out, and later ones succeed. yggdrasil-go does the same, so
this comes from the protocol rather than the port: the request is sent once,
and appears to be lost while the session or route is still being set up. Retry
if a request times out.

## Platforms

Linux, macOS, Windows (with `wintun.dll` next to the binary), FreeBSD and
Android build from the same code. Build with `--no-default-features` to leave
out the TUN adapter.

## Testing

```sh
cargo test --lib --test links    # Rust only
cargo test                       # also runs the yggdrasil-go interop tests
```

The interop tests need Go 1.26 or newer (set `GO=/path/to/go` if it is not on
`PATH`) and network access to download yggdrasil-go. `interop/build.sh` builds
yggdrasil-go's own `yggdrasil` and `yggdrasilctl`, and a harness from an
unmodified copy of upstream with only files that export internals added. Then:

- `tests/go_vectors.rs` sends random inputs through both implementations with
  proptest and requires identical results: addresses, link handshakes (including
  corrupted ones), multicast beacons, ICMPv6 replies, and configuration files,
  which must parse, normalise and print as HJSON and JSON byte for byte alike;
- `tests/go_network.rs` runs mixed networks: daemons of each implementation peer
  over every transport in both directions, query each other's nodeinfo, agree on
  the spanning tree, and enforce passwords and allowed keys alike; IPv6 traffic
  crosses a Go–Rust–Go–Rust chain; each `yggdrasilctl` gives the same output
  against each node; and both `yggdrasil` binaries print the same for the same
  configurations and flags;
- `tests/go_tun.rs` puts nodes in unprivileged network namespaces with real TUN
  adapters and pings between them, including ICMPv6 "packet too big" replies. It
  skips itself where user namespaces are unavailable.
