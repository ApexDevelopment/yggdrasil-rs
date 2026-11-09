//! The Yggdrasil node, with the same flags and behaviour as yggdrasil-go's.

use std::io::Read;
use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::Arc;

use log::LevelFilter;
use regex::Regex;
use yggdrasil::admin::AdminSocket;
use yggdrasil::cli::flags::{Flags, ParseError, Parsed};
use yggdrasil::cli::logging;
use yggdrasil::config::NodeConfig;
use yggdrasil::core::{BoxError, Core, Options, Peer};
use yggdrasil::ipv6rwc::ReadWriteCloser;
use yggdrasil::multicast::{Multicast, MulticastInterface};
use yggdrasil::tun::{InterfaceSource, TunAdapter};
use yggdrasil::{PublicKey, version};

fn flags() -> Flags {
	Flags::default()
		.bool("genconf", false, "print a new config to stdout")
		.bool("useconf", false, "read HJSON/JSON config from stdin")
		.string("useconffile", "", "read HJSON/JSON config from specified file path")
		.bool(
			"normaliseconf",
			false,
			"use in combination with either -useconf or -useconffile, outputs your configuration normalised",
		)
		.bool(
			"exportkey",
			false,
			"use in combination with either -useconf or -useconffile, outputs your private key in PEM format",
		)
		.bool("json", false, "print configuration from -genconf or -normaliseconf as JSON instead of HJSON")
		.bool("autoconf", false, "automatic mode (dynamic IP, peer with IPv6 neighbors)")
		.bool("version", false, "prints the version of this build")
		.string("logto", "stdout", "file path to log to, \"syslog\" or \"stdout\"")
		.bool(
			"address",
			false,
			"use in combination with either -useconf or -useconffile, outputs your IPv6 address",
		)
		.bool(
			"subnet",
			false,
			"use in combination with either -useconf or -useconffile, outputs your IPv6 subnet",
		)
		.bool(
			"publickey",
			false,
			"use in combination with either -useconf or -useconffile, outputs your public key",
		)
		.string("loglevel", "info", "loglevel to enable")
		.string("user", "", "user (and, optionally, group) to set UID/GID to")
		.int(
			"notifyfd",
			-1,
			"write a newline to this file-descriptor to indicate readiness to a service manager",
		)
}

fn main() -> ExitCode {
	let flags = flags();
	let parsed = match flags.parse(std::env::args().skip(1)) {
		Ok(parsed) => parsed,
		Err(ParseError::Help) => {
			eprintln!("Usage of {}:\n{}", program_name(), flags.defaults());
			return ExitCode::SUCCESS;
		}
		Err(ParseError::Invalid(error)) => {
			eprintln!(
				"{error}\nUsage of {}:\n{}",
				program_name(),
				flags.defaults()
			);
			return ExitCode::from(2);
		}
	};
	let level = if parsed.bool("normaliseconf") {
		LevelFilter::Error
	} else {
		logging::parse_level(&parsed.string("loglevel")).unwrap_or(LevelFilter::Info)
	};
	logging::init(&parsed.string("logto"), level);
	if !parsed.bool("normaliseconf") && logging::parse_level(&parsed.string("loglevel")).is_none() {
		log::info!("Loglevel parse failed. Set default level(info)");
	}
	match run(&flags, &parsed) {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			eprintln!("{error}");
			ExitCode::FAILURE
		}
	}
}

fn program_name() -> String {
	std::env::args()
		.next()
		.unwrap_or_else(|| "yggdrasil".into())
}

fn load_config(parsed: &Parsed) -> Result<Option<NodeConfig>, BoxError> {
	if parsed.bool("autoconf") {
		return Ok(Some(NodeConfig::generate()));
	}
	if parsed.bool("useconf") {
		let mut data = Vec::new();
		std::io::stdin().read_to_end(&mut data)?;
		return Ok(Some(NodeConfig::read_from(&data)?));
	}
	let path = parsed.string("useconffile");
	if !path.is_empty() {
		return Ok(Some(NodeConfig::read_from(&std::fs::read(&path)?)?));
	}
	Ok(None)
}

fn print_config(config: &mut NodeConfig, json: bool) {
	config.admin_listen.clear();
	println!(
		"{}",
		if json {
			config.to_json()
		} else {
			config.to_hjson()
		}
	);
}

fn run(flags: &Flags, parsed: &Parsed) -> Result<(), BoxError> {
	if parsed.bool("version") {
		println!("Build name: {}", version::build_name());
		println!("Build version: {}", version::build_version());
		return Ok(());
	}
	let Some(mut config) = load_config(parsed)? else {
		if parsed.bool("genconf") {
			print_config(&mut NodeConfig::generate(), parsed.bool("json"));
			return Ok(());
		}
		println!("Usage:");
		print!("{}", flags.defaults());
		if parsed.bool("address") || parsed.bool("subnet") {
			println!(
				"\nError: You need to specify some config data using -useconf or -useconffile."
			);
		}
		return Ok(());
	};
	let public_key = config.public_key();
	if parsed.bool("address") {
		println!("{}", yggdrasil::address::addr_for_key(&public_key));
		return Ok(());
	}
	if parsed.bool("subnet") {
		println!("{}", yggdrasil::address::subnet_for_key(&public_key));
		return Ok(());
	}
	if parsed.bool("publickey") {
		println!("{}", hex::encode(public_key.0));
		return Ok(());
	}
	if parsed.bool("normaliseconf") {
		if !config.private_key_path.is_empty() {
			config.private_key.clear();
		}
		print_config(&mut config, parsed.bool("json"));
		return Ok(());
	}
	if parsed.bool("exportkey") {
		println!("{}", config.marshal_pem_private_key());
		return Ok(());
	}
	let runtime = tokio::runtime::Runtime::new()?;
	runtime.block_on(run_node(config, parsed))
}

fn core_options(config: &NodeConfig) -> Result<Options, BoxError> {
	let mut peers: Vec<Peer> = config
		.peers
		.iter()
		.map(|uri| Peer {
			uri: uri.clone(),
			source_interface: String::new(),
		})
		.collect();
	for (interface, uris) in &config.interface_peers {
		peers.extend(uris.iter().map(|uri| Peer {
			uri: uri.clone(),
			source_interface: interface.clone(),
		}));
	}
	let allowed_public_keys = config
		.allowed_public_keys
		.iter()
		.map(|key| {
			let bytes = hex::decode(key)?;
			let mut key = [0u8; 32];
			let len = bytes.len().min(32);
			key[..len].copy_from_slice(&bytes[..len]);
			Ok(PublicKey(key))
		})
		.collect::<Result<_, hex::FromHexError>>()?;
	Ok(Options {
		peers,
		listen: config.listen.clone(),
		node_info: config.node_info.clone().unwrap_or_default(),
		node_info_privacy: config.node_info_privacy,
		allowed_public_keys,
		peer_filter: Some(Arc::new(|ip: IpAddr| match ip {
			// Never peer over Yggdrasil itself (200::/7)
			IpAddr::V6(ip) => ip.octets()[0] & 0xfe != 0x02,
			IpAddr::V4(_) => true,
		})),
		group_password: config.group_password.clone(),
		max_message_size: None,
	})
}

async fn run_node(config: NodeConfig, parsed: &Parsed) -> Result<(), BoxError> {
	let core = Core::new(config.secret(), core_options(&config)?).await?;
	log::info!("Your public key is {}", hex::encode(core.public_key().0));
	log::info!("Your IPv6 address is {}", core.address());
	log::info!("Your IPv6 subnet is {}", core.subnet());

	let admin = AdminSocket::new(core.clone(), &config.admin_listen, config.log_lookups).await?;
	if let Some(admin) = &admin {
		admin.setup_admin_handlers();
	}

	let interfaces = config
		.multicast_interfaces
		.iter()
		.map(|interface| {
			Ok(MulticastInterface {
				regex: Regex::new(&interface.regex)?,
				beacon: interface.beacon,
				listen: interface.listen,
				port: interface.port,
				priority: interface.priority as u8,
				password: interface.password.clone(),
			})
		})
		.collect::<Result<Vec<_>, regex::Error>>()?;
	let multicast = Multicast::new(core.clone(), interfaces).await?;
	if let Some(admin) = &admin {
		multicast.setup_admin_handlers(admin);
	}

	let rwc = ReadWriteCloser::new(core.clone());
	let tun = TunAdapter::new(
		rwc,
		InterfaceSource::Name(config.if_name.clone()),
		config.if_mtu,
	)
	.await?;
	if let Some(admin) = &admin {
		tun.setup_admin_handlers(admin);
	}

	let user = parsed.string("user");
	if !user.is_empty() {
		chuser(&user, &config.admin_listen)?;
	}
	notify_ready(parsed.int("notifyfd"));

	wait_for_shutdown().await;

	if let Some(admin) = &admin {
		admin.stop();
	}
	multicast.stop();
	tun.stop();
	core.stop();
	Ok(())
}

#[cfg(unix)]
fn notify_ready(fd: i64) {
	use std::io::Write;
	use std::os::fd::FromRawFd;
	if fd > 2 {
		// The service manager passed us this descriptor to own
		let mut file = unsafe { std::fs::File::from_raw_fd(fd as i32) };
		let _ = file.write_all(b"\n");
	}
}

#[cfg(not(unix))]
fn notify_ready(_fd: i64) {}

#[cfg(unix)]
async fn wait_for_shutdown() {
	use tokio::signal::unix::{SignalKind, signal};
	let mut terminate = signal(SignalKind::terminate()).expect("signal handler");
	tokio::select! {
		_ = tokio::signal::ctrl_c() => {}
		_ = terminate.recv() => {}
	}
}

#[cfg(not(unix))]
async fn wait_for_shutdown() {
	let _ = tokio::signal::ctrl_c().await;
}

/// Drops privileges to `user[:group]`, given by name or ID.
#[cfg(unix)]
fn chuser(input: &str, admin_listen: &str) -> Result<(), BoxError> {
	use std::ffi::CString;

	let (user, group) = match input.split_once(':') {
		Some((_, "")) => return Err("group is empty".into()),
		Some((user, group)) => (user, Some(group)),
		None => (input, None),
	};
	if user.is_empty() {
		return Err("user is empty".into());
	}
	let passwd = {
		let by_id = user.parse().ok().map(|uid| unsafe { libc::getpwuid(uid) });
		let by_id = by_id.filter(|entry| !entry.is_null());
		let name = CString::new(user)?;
		by_id.unwrap_or_else(|| unsafe { libc::getpwnam(name.as_ptr()) })
	};
	if passwd.is_null() {
		return Err(format!("user: unknown user {user}").into());
	}
	// Safe: checked non-null, and read before any other passwd call
	let (uid, mut gid) = unsafe { ((*passwd).pw_uid, (*passwd).pw_gid) };
	if let Some(group) = group {
		let by_id = group.parse().ok().map(|gid| unsafe { libc::getgrgid(gid) });
		let by_id = by_id.filter(|entry| !entry.is_null());
		let name = CString::new(group)?;
		let entry = by_id.unwrap_or_else(|| unsafe { libc::getgrnam(name.as_ptr()) });
		if entry.is_null() {
			return Err(format!("group: unknown group {group}").into());
		}
		gid = unsafe { (*entry).gr_gid };
	}
	if let Some(path) = admin_listen.strip_prefix("unix://") {
		std::os::unix::fs::chown(path, Some(uid), Some(gid))
			.map_err(|error| format!("chown {admin_listen} {uid}:{gid}: {error}"))?;
	}
	if unsafe { libc::setgroups(1, &gid) } != 0 {
		return Err(format!("setgroups: {gid}: {}", std::io::Error::last_os_error()).into());
	}
	if unsafe { libc::setgid(gid) } != 0 {
		return Err(format!("setgid: {gid}: {}", std::io::Error::last_os_error()).into());
	}
	if unsafe { libc::setuid(uid) } != 0 {
		return Err(format!("setuid: {uid}: {}", std::io::Error::last_os_error()).into());
	}
	Ok(())
}

#[cfg(not(unix))]
fn chuser(_input: &str, _admin_listen: &str) -> Result<(), BoxError> {
	Err("changing user is not supported on this platform".into())
}
