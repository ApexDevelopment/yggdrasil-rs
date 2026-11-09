use super::MulticastInterfaceConfig;

/// Per-platform defaults. Build-time overrides use the same environment
/// variables yggdrasil-go's linker flags set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformDefaults {
	pub admin_listen: String,
	/// Where yggdrasilctl looks for the admin socket address.
	pub config_file: String,
	pub multicast_interfaces: Vec<MulticastInterfaceConfig>,
	pub maximum_if_mtu: u64,
	pub if_mtu: u64,
	pub if_name: String,
}

fn interface(regex: &str, beacon: bool, listen: bool) -> MulticastInterfaceConfig {
	MulticastInterfaceConfig {
		regex: regex.into(),
		beacon,
		listen,
		..Default::default()
	}
}

pub fn get_defaults() -> PlatformDefaults {
	let mut defaults = platform_defaults();
	if let Some(config) = option_env!("YGGDRASIL_DEFAULT_CONFIG") {
		defaults.config_file = config.into();
	}
	if let Some(admin) = option_env!("YGGDRASIL_DEFAULT_ADMIN_LISTEN") {
		defaults.admin_listen = admin.into();
	}
	defaults
}

#[cfg(target_os = "linux")]
fn platform_defaults() -> PlatformDefaults {
	PlatformDefaults {
		admin_listen: "unix:///var/run/yggdrasil.sock".into(),
		config_file: "/etc/yggdrasil.conf".into(),
		multicast_interfaces: vec![interface(".*", true, true)],
		maximum_if_mtu: 65535,
		if_mtu: 65535,
		if_name: "auto".into(),
	}
}

#[cfg(target_os = "macos")]
fn platform_defaults() -> PlatformDefaults {
	PlatformDefaults {
		admin_listen: "unix:///var/run/yggdrasil.sock".into(),
		config_file: "/etc/yggdrasil.conf".into(),
		multicast_interfaces: vec![
			interface("en.*", true, true),
			interface("bridge.*", true, true),
			interface("awdl0", false, false),
		],
		maximum_if_mtu: 65535,
		if_mtu: 65535,
		if_name: "auto".into(),
	}
}

#[cfg(target_os = "freebsd")]
fn platform_defaults() -> PlatformDefaults {
	PlatformDefaults {
		admin_listen: "unix:///var/run/yggdrasil.sock".into(),
		config_file: "/usr/local/etc/yggdrasil.conf".into(),
		multicast_interfaces: vec![interface(".*", true, true)],
		maximum_if_mtu: 32767,
		if_mtu: 32767,
		if_name: "/dev/tun0".into(),
	}
}

#[cfg(target_os = "openbsd")]
fn platform_defaults() -> PlatformDefaults {
	PlatformDefaults {
		admin_listen: "unix:///var/run/yggdrasil.sock".into(),
		config_file: "/etc/yggdrasil.conf".into(),
		multicast_interfaces: vec![interface(".*", true, true)],
		maximum_if_mtu: 16384,
		if_mtu: 16384,
		if_name: "tun0".into(),
	}
}

#[cfg(windows)]
fn platform_defaults() -> PlatformDefaults {
	PlatformDefaults {
		admin_listen: "tcp://localhost:9001".into(),
		config_file: "C:\\Program Files\\Yggdrasil\\yggdrasil.conf".into(),
		multicast_interfaces: vec![interface(".*", true, true)],
		maximum_if_mtu: 65535,
		if_mtu: 65535,
		if_name: "Yggdrasil".into(),
	}
}

#[cfg(not(any(
	target_os = "linux",
	target_os = "macos",
	target_os = "freebsd",
	target_os = "openbsd",
	windows
)))]
fn platform_defaults() -> PlatformDefaults {
	PlatformDefaults {
		admin_listen: "tcp://localhost:9001".into(),
		config_file: "/etc/yggdrasil.conf".into(),
		multicast_interfaces: vec![interface(".*", true, true)],
		maximum_if_mtu: 65535,
		if_mtu: 65535,
		if_name: "none".into(),
	}
}
