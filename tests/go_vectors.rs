//! Differential tests: random inputs go through both yggdrasil-go and this
//! crate, and the results must match exactly.

mod common;

use common::vectors;
use proptest::prelude::*;
use serde_json::{Map, Value, json};
use yggdrasil::address::{Address, Subnet, addr_for_key, subnet_for_key};
use yggdrasil::config::NodeConfig;
use yggdrasil::core::build_nodeinfo;
use yggdrasil::core::version::{HandshakeError, Metadata};
use yggdrasil::ipv6rwc::packet_too_big;
use yggdrasil::multicast::Advertisement;
use yggdrasil::{PrivateKey, PublicKey};

fn decode_hex(value: &Value) -> Vec<u8> {
	hex::decode(value.as_str().unwrap()).unwrap()
}

proptest! {
	#![proptest_config(ProptestConfig::with_cases(128))]

	#[test]
	fn addresses_match(key in any::<[u8; 32]>()) {
		let go = vectors(json!({"op": "address", "key": hex::encode(key)}));
		let key = PublicKey(key);
		let address = addr_for_key(&key);
		let subnet = subnet_for_key(&key);
		prop_assert_eq!(decode_hex(&go["address"]), address.0.to_vec());
		prop_assert_eq!(decode_hex(&go["subnet"]), subnet.0.to_vec());
		prop_assert_eq!(decode_hex(&go["address_key"]), address.get_key().0.to_vec());
		prop_assert_eq!(decode_hex(&go["subnet_key"]), subnet.get_key().0.to_vec());
		prop_assert_eq!(go["text"].as_str().unwrap(), address.to_string());
	}

	#[test]
	fn keys_from_arbitrary_addresses_match(bytes in any::<[u8; 16]>()) {
		let go = vectors(json!({"op": "address_key", "data": hex::encode(bytes)}));
		let address = Address(bytes);
		let subnet = Subnet(bytes[..8].try_into().unwrap());
		prop_assert_eq!(decode_hex(&go["address_key"]), address.get_key().0.to_vec());
		prop_assert_eq!(decode_hex(&go["subnet_key"]), subnet.get_key().0.to_vec());
		prop_assert_eq!(go["address_valid"].as_bool().unwrap(), address.is_valid());
		prop_assert_eq!(go["subnet_valid"].as_bool().unwrap(), subnet.is_valid());
	}

	#[test]
	fn handshake_encodings_match(
		seed in any::<[u8; 32]>(),
		major in any::<u16>(),
		minor in any::<u16>(),
		priority in any::<u8>(),
		password in "[ -~]{0,70}",
	) {
		let go = vectors(json!({
			"op": "meta_encode", "seed": hex::encode(seed), "major": major,
			"minor": minor, "priority": priority, "password": password,
		}));
		let secret = PrivateKey::from_seed(&seed);
		let meta = Metadata { major_ver: major, minor_ver: minor, public_key: Some(secret.public_key()), priority };
		match meta.encode(&secret, password.as_bytes()) {
			Ok(encoded) => prop_assert_eq!(decode_hex(&go["data"]), encoded),
			Err(error) => prop_assert_eq!(go["error"].as_str().unwrap(), error.to_string()),
		}
	}

	#[test]
	fn handshake_decodings_match(
		seed in any::<[u8; 32]>(),
		priority in any::<u8>(),
		encode_password in prop_oneof![Just(String::new()), "[a-z]{1,8}"],
		decode_password in prop_oneof![Just(String::new()), "[a-z]{1,8}", "[a-z]{65}"],
		corruption in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..3),
		truncate in prop::option::of(any::<prop::sample::Index>()),
		random in prop::option::of(proptest::collection::vec(any::<u8>(), 0..200)),
	) {
		let secret = PrivateKey::from_seed(&seed);
		let meta = Metadata { public_key: Some(secret.public_key()), priority, ..Metadata::base() };
		let mut data = random.unwrap_or_else(|| meta.encode(&secret, encode_password.as_bytes()).unwrap());
		if !data.is_empty() {
			for (index, value) in corruption {
				let index = index.index(data.len());
				data[index] = value;
			}
		}
		if let Some(cut) = truncate {
			data.truncate(cut.index(data.len() + 1));
		}
		let go = vectors(json!({"op": "meta_decode", "data": hex::encode(&data), "password": decode_password}));
		match Metadata::decode(&data, decode_password.as_bytes()) {
			Ok(decoded) => {
				prop_assert_eq!(go["error"].as_str().unwrap(), "");
				prop_assert_eq!(go["major"].as_u64().unwrap(), u64::from(decoded.major_ver));
				prop_assert_eq!(go["minor"].as_u64().unwrap(), u64::from(decoded.minor_ver));
				prop_assert_eq!(go["priority"].as_u64().unwrap(), u64::from(decoded.priority));
				prop_assert_eq!(decode_hex(&go["key"]), decoded.public_key.unwrap().0.to_vec());
			}
			Err(HandshakeError::Io(error)) => prop_assert_eq!(go["error"].as_str().unwrap(), error),
			Err(error) => prop_assert_eq!(go["error"].as_str().unwrap(), error.to_string()),
		}
	}

	#[test]
	fn beacon_encodings_match(
		major in any::<u16>(),
		minor in any::<u16>(),
		key in any::<[u8; 32]>(),
		port in any::<u16>(),
		hash in proptest::collection::vec(any::<u8>(), 0..100),
	) {
		let go = vectors(json!({
			"op": "adv_encode", "major": major, "minor": minor, "key": hex::encode(key),
			"port": port, "hash": hex::encode(&hash),
		}));
		let beacon = Advertisement { major_version: major, minor_version: minor, public_key: PublicKey(key), port, hash };
		prop_assert_eq!(decode_hex(&go["data"]), beacon.encode());
	}

	#[test]
	fn beacon_decodings_match(data in proptest::collection::vec(any::<u8>(), 0..120)) {
		let go = vectors(json!({"op": "adv_decode", "data": hex::encode(&data)}));
		match Advertisement::decode(&data) {
			Some(beacon) => {
				prop_assert_eq!(go["error"].as_str().unwrap(), "");
				prop_assert_eq!(go["major"].as_u64().unwrap(), u64::from(beacon.major_version));
				prop_assert_eq!(go["minor"].as_u64().unwrap(), u64::from(beacon.minor_version));
				prop_assert_eq!(decode_hex(&go["key"]), beacon.public_key.0.to_vec());
				prop_assert_eq!(go["port"].as_u64().unwrap(), u64::from(beacon.port));
				prop_assert_eq!(decode_hex(&go["hash"]), beacon.hash);
			}
			None => prop_assert_ne!(go["error"].as_str().unwrap(), ""),
		}
	}

	#[test]
	fn packet_too_big_messages_match(
		packet in proptest::collection::vec(any::<u8>(), 40..1400),
		mtu in 1280u32..65535,
	) {
		let go = vectors(json!({"op": "icmp_ptb", "data": hex::encode(&packet), "mtu": mtu}));
		prop_assert_eq!(decode_hex(&go["data"]), packet_too_big(&packet, mtu).unwrap());
	}
}

/// Strings that exercise quoting, escaping and multiline output.
fn tricky_string() -> impl Strategy<Value = String> {
	prop_oneof![
		4 => "[a-zA-Z0-9:/._@-]{0,16}",
		2 => "[ -~]{0,16}",
		1 => "\\PC{0,8}",
		1 => "[a-z \n\t\"'\\\\]{0,12}",
		1 => prop::sample::select(vec![
			"", "true", "false", "null", "12", "-3.5e2", "0x10", " lead", "trail ", "#hash", "//slash",
			"{brace", "[bracket", ":colon", ",comma", "a\nb", "multi\n\nline\n", "x<y&z>", "'''",
			"tcp://[::1]:1234", "\u{2028}", "\u{7f}", "a\u{1}b",
		])
		.prop_map(str::to_string),
	]
}

/// Keys are matched case-insensitively, so vary their case.
fn key_case(name: &'static str) -> impl Strategy<Value = String> {
	prop_oneof![
		3 => Just(name.to_string()),
		1 => Just(name.to_lowercase()),
		1 => Just(name.to_uppercase()),
	]
}

fn number() -> impl Strategy<Value = Value> {
	prop_oneof![
		any::<i32>().prop_map(Value::from),
		any::<u64>().prop_map(Value::from),
		any::<f64>()
			.prop_filter("finite", |f| f.is_finite())
			.prop_map(Value::from),
		(-30i32..30).prop_map(|exponent| Value::from(1.5 * 10f64.powi(exponent))),
	]
}

fn nodeinfo_value() -> impl Strategy<Value = Value> {
	let leaf = prop_oneof![
		Just(Value::Null),
		any::<bool>().prop_map(Value::from),
		number(),
		tricky_string().prop_map(Value::from),
	];
	leaf.prop_recursive(3, 16, 4, |inner| {
		prop_oneof![
			proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
			proptest::collection::vec((tricky_string(), inner), 0..4)
				.prop_map(|fields| Value::Object(fields.into_iter().collect())),
		]
	})
}

fn multicast_interface() -> impl Strategy<Value = Value> {
	(
		prop::option::of(tricky_string()),
		prop::option::of(any::<bool>()),
		prop::option::of(any::<bool>()),
		prop::option::of(prop_oneof![
			(0u64..70000).prop_map(Value::from),
			Just(json!(1.5))
		]),
		prop::option::of(any::<u8>()),
		prop::option::of(tricky_string()),
	)
		.prop_map(|(regex, beacon, listen, port, priority, password)| {
			let mut object = Map::new();
			let mut set = |name: &str, value: Option<Value>| {
				if let Some(value) = value {
					object.insert(name.into(), value);
				}
			};
			set("Regex", regex.map(Value::from));
			set("beacon", beacon.map(Value::from));
			set("Listen", listen.map(Value::from));
			set("Port", port);
			set("priority", priority.map(Value::from));
			set("Password", password.map(Value::from));
			Value::Object(object)
		})
}

fn strings() -> impl Strategy<Value = Value> {
	proptest::collection::vec(tricky_string(), 0..4).prop_map(Value::from)
}

/// Field names, and strategies for their values. Some values have the wrong type on purpose.
fn config() -> impl Strategy<Value = Value> {
	let fields = (
		any::<[u8; 32]>(),
		prop::option::of((key_case("Peers"), strings())),
		prop::option::of((
			key_case("InterfacePeers"),
			proptest::collection::btree_map(tricky_string(), strings(), 0..3),
		)),
		prop::option::of((key_case("Listen"), strings())),
		prop::option::of((key_case("AdminListen"), tricky_string())),
		prop::option::of((
			key_case("MulticastInterfaces"),
			proptest::collection::vec(multicast_interface(), 0..4),
		)),
		prop::option::of((key_case("AllowedPublicKeys"), strings())),
		prop::option::of((key_case("GroupPassword"), tricky_string())),
	);
	let more = (
		prop::option::of((key_case("IfName"), tricky_string())),
		prop::option::of((
			key_case("IfMTU"),
			prop_oneof![(0u64..100000).prop_map(Value::from), number()],
		)),
		prop::option::of((key_case("LogLookups"), any::<bool>())),
		prop::option::of((key_case("NodeInfoPrivacy"), any::<bool>())),
		prop::option::of((
			key_case("NodeInfo"),
			prop_oneof![
				4 => proptest::collection::vec((tricky_string(), nodeinfo_value()), 0..5)
					.prop_map(|fields| Value::Object(fields.into_iter().collect())),
				1 => Just(Value::Null),
			],
		)),
		prop::option::of(Just(("Unknown", json!(1)))),
	);
	(fields, more).prop_map(|(fields, more)| {
		let (seed, peers, interface_peers, listen, admin, multicast, allowed, group) = fields;
		let (if_name, if_mtu, log_lookups, privacy, nodeinfo, unknown) = more;
		let mut config = Map::new();
		config.insert(
			"PrivateKey".into(),
			hex::encode(PrivateKey::from_seed(&seed).0).into(),
		);
		let mut set = |entry: Option<(String, Value)>| {
			if let Some((key, value)) = entry {
				config.insert(key, value);
			}
		};
		set(peers);
		set(interface_peers.map(|(key, map)| (key, json!(map))));
		set(listen);
		set(admin.map(|(key, value)| (key, value.into())));
		set(multicast.map(|(key, items)| (key, Value::Array(items))));
		set(allowed);
		set(group.map(|(key, value)| (key, value.into())));
		set(if_name.map(|(key, value)| (key, value.into())));
		set(if_mtu);
		set(log_lookups.map(|(key, value)| (key, value.into())));
		set(privacy.map(|(key, value)| (key, value.into())));
		set(nodeinfo);
		set(unknown.map(|(key, value)| (key.to_string(), value)));
		Value::Object(config)
	})
}

/// Reads `text` with both implementations and compares everything they output.
fn assert_configs_match(text: &str) -> Result<Option<NodeConfig>, TestCaseError> {
	let go = vectors(json!({"op": "config", "text": text}));
	let go_error = go["error"].as_str().unwrap_or_default();
	let rust = NodeConfig::read_from(text.as_bytes());
	let mut config = match rust {
		Ok(config) => config,
		Err(error) => {
			prop_assert_ne!(go_error, "", "only Rust rejected the config: {}", error);
			return Ok(None);
		}
	};
	let node_info = build_nodeinfo(&config.node_info.clone().unwrap_or_default(), true);
	if !go_error.is_empty() {
		prop_assert!(
			node_info.is_err(),
			"only Go rejected the config: {}",
			go_error
		);
		return Ok(None);
	}
	config.admin_listen.clear();
	prop_assert_eq!(go["json"].as_str().unwrap(), config.to_json());
	prop_assert_eq!(go["hjson"].as_str().unwrap(), config.to_hjson());
	prop_assert_eq!(
		go["pem"].as_str().unwrap(),
		config.marshal_pem_private_key()
	);
	prop_assert_eq!(
		go["nodeinfo"].as_str().unwrap().as_bytes(),
		&node_info.unwrap()[..]
	);
	Ok(Some(config))
}

proptest! {
	#![proptest_config(ProptestConfig::with_cases(256))]

	#[test]
	fn configs_match(config in config()) {
		let text = config.to_string();
		if let Some(parsed) = assert_configs_match(&text)? {
			// What Rust writes must read back the same in both implementations
			assert_configs_match(&parsed.to_hjson())?;
			assert_configs_match(&parsed.to_json())?;
		}
	}

	#[test]
	fn arbitrary_documents_are_judged_alike(text in "\\PC{0,64}") {
		// Without a private key each side generates a random one, so only compare acceptance
		let go = vectors(json!({"op": "config", "text": text}));
		let go_accepts = go["error"].as_str().unwrap_or_default().is_empty();
		let rust_accepts = NodeConfig::read_from(text.as_bytes())
			.is_ok_and(|config| build_nodeinfo(&config.node_info.unwrap_or_default(), true).is_ok());
		prop_assert_eq!(go_accepts, rust_accepts, "Go error: {}", go["error"]);
	}
}
