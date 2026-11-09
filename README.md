# yggdrasil-rs

A Rust port of [Yggdrasil](https://yggdrasil-network.github.io/), the end-to-end
encrypted IPv6 mesh network.

It works alongside [yggdrasil-go](https://github.com/yggdrasil-network/yggdrasil-go)
v0.5.15. Nodes of both implementations can peer with each other, route traffic for
each other, and answer each other's nodeinfo and debug requests. The programs take
the same flags, read the same configuration files and use the same admin socket
protocol, so either implementation's `yggdrasilctl` can query either node.

## Building

You need a recent stable Rust toolchain (it is developed with 1.97). Routing comes from
[petrified](../petrified), the Rust port of Ironwood, which must be checked out
next to this repository as `../petrified`.

```sh
cargo build --release
```

This builds three programs in `target/release`:

| Program        | Purpose                                 |
| -------------- | --------------------------------------- |
| `yggdrasil`    | Runs a node                             |
| `yggdrasilctl` | Queries a running node's admin socket   |
| `genkeys`      | Searches for keys with higher addresses |

To run a node, generate a configuration and start it with that file. Creating
the TUN adapter needs root, or `CAP_NET_ADMIN` on Linux:

```sh
./target/release/yggdrasil -genconf > yggdrasil.conf
sudo ./target/release/yggdrasil -useconffile yggdrasil.conf
```

Then query it with `yggdrasilctl`, for example `yggdrasilctl getPeers`.

The build name and version come from git: the version is the latest `v*.*.*`
tag, and builds from a branch other than `main` are named after it. Set
`YGGDRASIL_BUILD_NAME` or `YGGDRASIL_BUILD_VERSION` when building to override
them. Outside a git checkout, they come from `Cargo.toml`.

## Running as a systemd service

`contrib/systemd` has the same units as yggdrasil-go. The first time the service
starts, it generates `/etc/yggdrasil.conf`. Members of the `yggdrasil` group can
use `yggdrasilctl`.

1. Install the programs:

   ```sh
   sudo install -m 755 target/release/yggdrasil target/release/yggdrasilctl /usr/bin/
   ```

2. Install the units:

   ```sh
   sudo cp contrib/systemd/*.service /etc/systemd/system/
   ```

3. Create the group, then start the service:

   ```sh
   sudo groupadd --system yggdrasil
   sudo systemctl daemon-reload
   sudo systemctl enable --now yggdrasil
   ```

To add peers, edit `/etc/yggdrasil.conf`, then run `sudo systemctl restart yggdrasil`.

## Peering

Peers and listeners are given as URIs, such as `tls://example.com:443`. They take
the same query options as in yggdrasil-go: `key`, `priority`, `password`,
`maxbackoff` and `sni`.

| Scheme                    | Connect | Listen | Notes                                      |
| ------------------------- | ------- | ------ | ------------------------------------------ |
| `tcp://`                  | yes     | yes    |                                            |
| `tls://`                  | yes     | yes    | Self-signed certificates, as in Go         |
| `quic://`                 | yes     | yes    |                                            |
| `ws://`                   | yes     | yes    | Uses the `ygg-ws` subprotocol              |
| `wss://`                  | yes     | no     | Put a `ws://` listener behind a TLS proxy  |
| `unix://`                 | yes     | yes    | Unix-like systems                          |
| `socks://`, `sockstls://` | yes     | no     | `socks://[user:pass@]proxy:port/host:port` |

To carry links over another transport, implement `core::LinkProtocol`, which
turns a URI into a byte stream, and register it for a URI scheme with
`Core::register_link_protocol`.

## Using the library

```rust
use yggdrasil::core::{Core, Options};
use yggdrasil::PrivateKey;

let core = Core::new(PrivateKey::from_seed(&seed), Options::default()).await?;
let listener = core.listen("tls://[::]:0", "").await?;
core.add_peer("tls://example.com:443", "")?;

core.write_to(b"hello", &their_key)?;
let (from, packet) = core.recv().await?;
```

`Core` runs on tokio. To send and receive IPv6 packets addressed by Yggdrasil IP
address instead of by key, wrap it in `ipv6rwc::ReadWriteCloser`.

The modules match yggdrasil-go's packages:

| Go package  | Rust module            | Contents                                      |
| ----------- | ---------------------- | --------------------------------------------- |
| `core`      | `yggdrasil::core`      | The node, peer links, transports and nodeinfo |
| `address`   | `yggdrasil::address`   | IPv6 addresses and subnets derived from keys  |
| `ipv6rwc`   | `yggdrasil::ipv6rwc`   | IPv6 packets addressed by IP address          |
| `tun`       | `yggdrasil::tun`       | The TUN adapter                               |
| `multicast` | `yggdrasil::multicast` | Peer discovery on local networks              |
| `admin`     | `yggdrasil::admin`     | The admin socket                              |
| `config`    | `yggdrasil::config`    | Configuration files                           |
| `version`   | `yggdrasil::version`   | Build information                             |

## Platforms

The code builds for Linux, macOS, Windows, FreeBSD and Android. On Windows, put
`wintun.dll` next to the program. On Android and iOS, the operating system's VPN
API creates the TUN device, so pass its file descriptor with
`tun::InterfaceSource::FileDescriptor`. To build without the TUN adapter, use
`--no-default-features`.

## Differences from yggdrasil-go

### Fixed behaviour

yggdrasil-rs does not copy these yggdrasil-go behaviours, which look unintended:

- In yggdrasil-go, an entry in `MulticastInterfaces` takes any field it leaves
  out from the default entry in the same position. On Linux, a first entry of
  `{Regex: "eth0"}` therefore beacons and listens, and a second entry written the
  same way does neither. In yggdrasil-rs, fields that an entry leaves out are
  always `false`, empty or zero.
- When several `MulticastInterfaces` regexes match an interface, yggdrasil-rs
  uses the first match in the list. yggdrasil-go's choice can change between runs.
- `getPeers` sorts by exact priority, cost and uptime. yggdrasil-go sorts costs
  more than 2^63 apart in the wrong order, and treats uptimes less than a
  second apart as equal.

### Other differences

- The library API differs. Configuration is an `Options` struct instead of a list
  of `SetupOption` values, and `Core::new` takes the private key and creates the
  TLS certificate itself.
- I/O error messages use Rust's wording, such as `Connection refused (os error 111)`.
- A configuration list set to `null` is read as an empty list. yggdrasil-go keeps
  it as `null` when it writes the configuration back out.
- The Windows service wrapper, OpenBSD `pledge`, the mobile bindings, and
  WebSocket proxies from `HTTP_PROXY` are not ported.
- The default configuration file and admin socket address can be changed with
  `YGGDRASIL_DEFAULT_CONFIG` and `YGGDRASIL_DEFAULT_ADMIN_LISTEN` when building.
  These replace the linker flags yggdrasil-go uses.

## Known issues

The first nodeinfo or `debug_remote*` request to a node usually times out if it
is sent right after the two nodes connect. Later requests succeed. yggdrasil-go
behaves the same way. The request is sent once, and it probably gets lost while
the encrypted session or the route is still being set up. If a request times
out, send it again.

## Testing

```sh
cargo test --lib --test links    # Rust only
cargo test                       # also runs the yggdrasil-go interop tests
```

The interop tests need Go 1.26 or newer and network access to download
yggdrasil-go. If `go` is not on your `PATH`, set `GO=/path/to/go`. The tests build
yggdrasil-go from unmodified upstream source. They check that both
implementations give the same results for the same inputs, that their nodes work
together in mixed networks, and that each implementation's programs work with
the other's nodes.
The TUN tests run nodes in unprivileged network namespaces, and skip themselves
where those are unavailable.
