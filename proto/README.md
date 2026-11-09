# yggdrasil-proto

The parts of [yggdrasil-rs](https://github.com/ApexDevelopment/yggdrasil-rs) that
need no operating system, for running Yggdrasil nodes on microcontrollers. It
needs only `alloc`, and works alongside
[petrified](https://github.com/ApexDevelopment/petrified), the port of Yggdrasil's
routing protocol.

| Module          | Contents                                                     |
| --------------- | ------------------------------------------------------------ |
| `address`       | IPv6 addresses and subnets derived from keys                 |
| `handshake`     | The metadata exchanged when a peer link opens                |
| `advertisement` | Multicast peer discovery beacons                             |
| `requests`      | Nodeinfo and remote debug requests                           |
| `ipv6`          | Which node an IPv6 packet goes to, and which packets to keep |
| `icmpv6`        | ICMPv6 messages for the local host                           |
| `session`       | The packet types carried in sessions                         |

The `requests` and `ipv6` modules are state machines: you pass in packets and the
current time, and they say what to send, deliver or look up. They do no I/O.

The crate is compatible with yggdrasil-go v0.5.15. yggdrasil-rs runs its tests
against yggdrasil-go, and those tests cover this crate.

## License

The LGPLv3, with yggdrasil-go's exception for static linking. See
[LICENSE](https://github.com/ApexDevelopment/yggdrasil-rs/blob/main/LICENSE). `json` and `go_hex` port code from the Go standard
library, listed with its license in [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES).
