# yggdrasil-rs

A Rust port of [Yggdrasil](https://yggdrasil-network.github.io/), the end-to-end encrypted IPv6 mesh network.

It works alongside [yggdrasil-go](https://github.com/yggdrasil-network/yggdrasil-go) v0.5.15 and should be fully compatible. The programs take the same flags, read the same configuration files and use the same admin socket protocol, so either implementation's `yggdrasilctl` can query either node.

## Installing

On Linux, `contrib/install.sh` installs static x86_64 or aarch64 binaries from a release. It puts the programs in `/usr/local/bin`, installs and starts a systemd service, and creates the `yggdrasil` group. It uses `sudo` or `doas` when it needs root.

```sh
curl -fsSL https://github.com/ApexDevelopment/yggdrasil-rs/releases/latest/download/install.sh | sh
```

To pass options, add `-s --` after `sh`:

- `--user` installs the programs to `~/.local/bin` without root, and without the service.
- `--version v0.1.0` installs that release instead of the latest.
- `--no-start` installs the service without starting it.
- `--uninstall` removes the programs and service, and keeps `/etc/yggdrasil.conf`.

To build the release files, run `contrib/release.sh`. It builds static binaries in Podman or Docker containers, and writes the archives, their checksums and `install.sh` to `dist/`. Building for an architecture other than the host's needs `qemu-user-static`.

## Building

You need a recent stable Rust toolchain (it is developed with 1.97). Routing comes from [petrified](https://github.com/ApexDevelopment/petrified), the Rust port of Ironwood, which must be checked out next to this repository:

```sh
git clone https://github.com/ApexDevelopment/petrified
git clone https://github.com/ApexDevelopment/yggdrasil-rs
cd yggdrasil-rs
```

```sh
cargo build --release
```

This builds three programs in `target/release`: `yggdrasil`, `yggdrasilctl`, and `genkeys`.

To run a node, generate a configuration and start it with that file. Creating the TUN adapter needs root, or `CAP_NET_ADMIN` on Linux:

```sh
./target/release/yggdrasil -genconf > yggdrasil.conf
sudo ./target/release/yggdrasil -useconffile yggdrasil.conf
```

Then query it with `yggdrasilctl`, for example `yggdrasilctl getPeers`.

## Packages

To build Debian and RPM packages, install [cargo-deb](https://crates.io/crates/cargo-deb) and [cargo-generate-rpm](https://crates.io/crates/cargo-generate-rpm), then run:

```sh
cargo deb                                    # target/debian/*.deb
cargo build --release && cargo generate-rpm  # target/generate-rpm/*.rpm
```

Both packages install the programs and the systemd units below, and create the `yggdrasil` group. The Debian package also enables and starts the service. The RPM package follows Fedora's convention and leaves it to the user to run `sudo systemctl enable --now yggdrasil` after installing.

## Running as a systemd service

Without a package, you can install the service by hand. `contrib/systemd` has the same units as yggdrasil-go. The first time the service starts, it generates `/etc/yggdrasil.conf`. Members of the `yggdrasil` group can use `yggdrasilctl`.

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

## Using the library

The crate is published as `yggdrasil-mesh`, and imported as `yggdrasil`:

```toml
[dependencies]
yggdrasil-mesh = "0.1"
```

```rust
use yggdrasil::core::{Core, Options};
use yggdrasil::PrivateKey;

let core = Core::new(PrivateKey::from_seed(&seed), Options::default()).await?;
let listener = core.listen("tls://[::]:0", "").await?;
core.add_peer("tls://example.com:443", "")?;

core.write_to(b"hello", &their_key)?;
let (from, packet) = core.recv().await?;
```

`Core` runs on tokio. To send and receive IPv6 packets addressed by Yggdrasil IP address instead of by key, wrap it in `ipv6rwc::ReadWriteCloser`.

The module names match yggdrasil-go's packages.

## Platforms

The code builds for Linux, macOS, Windows, FreeBSD and Android. On Windows, put `wintun.dll` next to the program. On Android and iOS, the operating system's VPN API creates the TUN device, so pass its file descriptor with `tun::InterfaceSource::FileDescriptor`. To build without the TUN adapter, use `--no-default-features`.

## Differences from yggdrasil-go

### Fixed behaviour

yggdrasil-rs does not copy these yggdrasil-go behaviours, since they seem unintentional:

- In yggdrasil-go, any missing entry in `MulticastInterfaces` is filled in from the default entry in the same position. Therefore, on Linux, a first entry of `{Regex: "eth0"}` beacons and listens, and a second entry written the same way does nothing. In yggdrasil-rs, fields that an entry leaves out are always `false`, empty or zero.
- When several `MulticastInterfaces` regexes match an interface, yggdrasil-rs uses the first match in the list. yggdrasil-go's choice can change between runs.
- `getPeers` sorts by exact priority, cost and uptime. yggdrasil-go sorts costs more than 2^63 apart in the wrong order, and treats uptimes less than a second apart as equal.

### Other differences

- The library API differs. Configuration is an `Options` struct instead of a list of `SetupOption` values, and `Core::new` takes the private key and creates the TLS certificate itself.
- I/O error messages use Rust's wording, such as `Connection refused (os error 111)`.
- A configuration list set to `null` is read as an empty list. yggdrasil-go keeps it as `null` when it writes the configuration back out.
- The Windows service wrapper, OpenBSD `pledge`, the mobile bindings, and WebSocket proxies from `HTTP_PROXY` are not ported.
- The default configuration file and admin socket address can be changed with `YGGDRASIL_DEFAULT_CONFIG` and `YGGDRASIL_DEFAULT_ADMIN_LISTEN` when building. These replace the linker flags yggdrasil-go uses.

## Known issues

The first nodeinfo or `debug_remote*` request to a node usually times out if it is sent right after the two nodes connect. Later requests succeed. **This matches the behaviour of yggdrasil-go.**

## Testing

```sh
cargo test --lib --test links    # Rust only
cargo test                       # also runs the yggdrasil-go interop tests
```

The interop tests need Go 1.26 or newer and will download yggdrasil-go. The tests build yggdrasil-go from unmodified upstream source. They check that both implementations give the same results for the same inputs, that their nodes work together in mixed networks, and that each implementation's programs work with the other's nodes. The TUN tests run nodes in unprivileged network namespaces, and skip themselves where those are unavailable.

`contrib/test-packages.sh` installs the Debian package, the RPM package and `install.sh` in Debian and Fedora containers, and checks that the nodes start and can reach each other. It needs Podman or Docker, cargo-deb and cargo-generate-rpm.

## License

yggdrasil-rs uses the same license as yggdrasil-go: the LGPLv3, with an exception that allows static linking without the LGPL's relinking requirements. See [LICENSE](LICENSE).
