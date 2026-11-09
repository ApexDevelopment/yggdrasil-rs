//! The node configuration file. It reads the same HJSON or JSON files as
//! yggdrasil-go, with the same quirks: keys match case-insensitively, and
//! values are merged onto a freshly generated default configuration.

mod defaults;
mod hjson;
mod hjson_parse;

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine;
use petrified::types::{PrivateKey, PublicKey};
use serde_json::{Map, Value};

pub use defaults::{PlatformDefaults, get_defaults};

use crate::core::tls::{pkcs8_der, seed_from_pkcs8_der};
use hjson_parse::Hjson;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

impl std::error::Error for ConfigError {}

fn error(message: impl Into<String>) -> ConfigError {
	ConfigError(message.into())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MulticastInterfaceConfig {
	pub regex: String,
	pub beacon: bool,
	pub listen: bool,
	pub port: u16,
	/// Really a u8, but yggdrasil-go stores it as a u64.
	pub priority: u64,
	pub password: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeConfig {
	/// 64 bytes, the seed followed by the public key, as Go stores ed25519 keys.
	pub private_key: Vec<u8>,
	pub private_key_path: String,
	pub peers: Vec<String>,
	pub interface_peers: BTreeMap<String, Vec<String>>,
	pub listen: Vec<String>,
	pub admin_listen: String,
	pub multicast_interfaces: Vec<MulticastInterfaceConfig>,
	pub allowed_public_keys: Vec<String>,
	pub group_password: String,
	pub if_name: String,
	pub if_mtu: u64,
	pub log_lookups: bool,
	pub node_info_privacy: bool,
	pub node_info: Option<Map<String, Value>>,
}

const COMMENT_PRIVATE_KEY: &str = "Your private key. DO NOT share this with anyone!";
const COMMENT_PRIVATE_KEY_PATH: &str = "The path to your private key file in PEM format.";
const COMMENT_PEERS: &str = "List of outbound peer connection strings (e.g. tls://a.b.c.d:e or\nsocks://a.b.c.d:e/f.g.h.i:j). Connection strings can contain options,\nsee https://yggdrasil-network.github.io/configurationref.html#peers.\nYggdrasil has no concept of bootstrap nodes - all network traffic\nwill transit peer connections. Therefore make sure to only peer with\nnearby nodes that have good connectivity and low latency. Avoid adding\npeers to this list from distant countries as this will worsen your\nnode's connectivity and performance considerably.";
const COMMENT_INTERFACE_PEERS: &str = "List of connection strings for outbound peer connections in URI format,\narranged by source interface, e.g. { \"eth0\": [ \"tls://a.b.c.d:e\" ] }.\nYou should only use this option if your machine is multi-homed and you\nwant to establish outbound peer connections on different interfaces.\nOtherwise you should use \"Peers\".";
const COMMENT_LISTEN: &str = "Listen addresses for incoming connections. You will need to add\nlisteners in order to accept incoming peerings from non-local nodes.\nThis is not required if you wish to establish outbound peerings only.\nMulticast peer discovery will work regardless of any listeners set\nhere. Each listener should be specified in URI format as above, e.g.\ntls://0.0.0.0:0 or tls://[::]:0 to listen on all interfaces.";
const COMMENT_ADMIN_LISTEN: &str = "Listen address for admin connections. Default is to listen for local\nconnections either on TCP/9001 or a UNIX socket depending on your\nplatform. Use this value for yggdrasilctl -endpoint=X. To disable\nthe admin socket, use the value \"none\" instead.";
const COMMENT_MULTICAST_INTERFACES: &str = "Configuration for which interfaces multicast peer discovery should be\nenabled on. Regex is a regular expression which is matched against an\ninterface name, and interfaces use the first configuration that they\nmatch against. Beacon controls whether or not your node advertises its\npresence to others, whereas Listen controls whether or not your node\nlistens out for and tries to connect to other advertising nodes. See\nhttps://yggdrasil-network.github.io/configurationref.html#multicastinterfaces\nfor more supported options.";
const COMMENT_ALLOWED_PUBLIC_KEYS: &str = "List of peer public keys to allow incoming peering connections\nfrom. If left empty/undefined then all connections will be allowed\nby default. This does not affect outgoing peerings, nor does it\naffect link-local peers discovered via multicast.\nWARNING: THIS IS NOT A FIREWALL and DOES NOT limit who can reach\nopen ports or services running on your machine, for that see the\nGroupPassword option below.";
const COMMENT_GROUP_PASSWORD: &str = "Traffic is only allowed to/from nodes with the same group password.\nIf you want to form a private sub-network or ensure that other public\nusers cannot connect to your machines, choose a strong group password\nand then configure the same password only with other group members.\nIf left empty or not specified, public connectivity will be permitted.\nIf specified, you WILL NOT be able to reach public services or hosts.\nThis option DOES NOT affect peering connections or traffic routing.";
const COMMENT_IF_NAME: &str = "Local network interface name for TUN adapter, or \"auto\" to select\nan interface automatically, or \"none\" to run without TUN.";
const COMMENT_IF_MTU: &str = "Maximum Transmission Unit (MTU) size for your local TUN interface.\nDefault is the largest supported size for your platform. The lowest\npossible value is 1280.";
const COMMENT_NODE_INFO_PRIVACY: &str = "By default, nodeinfo contains some defaults including the platform,\narchitecture and Yggdrasil version. These can help when surveying\nthe network and diagnosing network routing problems. Enabling\nnodeinfo privacy prevents this, so that only items specified in\n\"NodeInfo\" are sent back if specified.";
const COMMENT_NODE_INFO: &str = "Optional nodeinfo. This must be a { \"key\": \"value\", ... } map\nor set as null. This is entirely optional but, if set, is visible\nto the whole network on request.";

fn new_private_key() -> Vec<u8> {
	let mut seed = [0u8; 32];
	getrandom::fill(&mut seed).expect("OS random number generator failed");
	PrivateKey::from_seed(&seed).0.to_vec()
}

impl NodeConfig {
	/// A new configuration with a random key and the platform defaults.
	pub fn generate() -> Self {
		let defaults = get_defaults();
		NodeConfig {
			private_key: new_private_key(),
			private_key_path: String::new(),
			peers: Vec::new(),
			interface_peers: BTreeMap::new(),
			listen: Vec::new(),
			admin_listen: defaults.admin_listen,
			multicast_interfaces: defaults.multicast_interfaces,
			allowed_public_keys: Vec::new(),
			group_password: String::new(),
			if_name: defaults.if_name,
			if_mtu: defaults.if_mtu,
			log_lookups: false,
			node_info_privacy: false,
			node_info: None,
		}
	}

	/// Reads an HJSON or JSON configuration (UTF-8, or UTF-16 with a byte order
	/// mark). Anything it does not set keeps its generated default.
	pub fn read_from(data: &[u8]) -> Result<Self, ConfigError> {
		let text = decode_text(data)?;
		let value = hjson_parse::parse(&text).map_err(|e| error(e.to_string()))?;
		let mut config = NodeConfig::generate();
		config.apply(&value)?;
		config.postprocess()?;
		Ok(config)
	}

	/// Loads the key file, if any, and checks the key.
	fn postprocess(&mut self) -> Result<(), ConfigError> {
		if !self.private_key_path.is_empty() {
			let pem = std::fs::read(&self.private_key_path)
				.map_err(|e| error(format!("open {}: {e}", self.private_key_path)))?;
			self.private_key.clear();
			self.unmarshal_pem_private_key(&pem)?;
		}
		match self.private_key.len() {
			0 => self.private_key = new_private_key(),
			64 => {}
			_ => return Err(error("invalid private key length")),
		}
		let seed: [u8; 32] = self.private_key[..32].try_into().expect("64-byte key");
		if PrivateKey::from_seed(&seed).0[..] != self.private_key[..] {
			return Err(error(
				"x509: signature returned by signer is invalid: x509: Ed25519 verification failure",
			));
		}
		Ok(())
	}

	pub fn secret(&self) -> PrivateKey {
		let seed: [u8; 32] = self.private_key[..32]
			.try_into()
			.expect("checked when loaded");
		PrivateKey::from_seed(&seed)
	}

	pub fn public_key(&self) -> PublicKey {
		self.secret().public_key()
	}

	/// The private key as a PKCS#8 PEM block.
	pub fn marshal_pem_private_key(&self) -> String {
		let encoded = base64::engine::general_purpose::STANDARD.encode(pkcs8_der(&self.secret()));
		let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
		for line in encoded.as_bytes().chunks(64) {
			pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
			pem.push('\n');
		}
		pem.push_str("-----END PRIVATE KEY-----\n");
		pem
	}

	pub fn unmarshal_pem_private_key(&mut self, pem: &[u8]) -> Result<(), ConfigError> {
		let text = String::from_utf8_lossy(pem);
		let (label, body) = pem_block(&text).ok_or_else(|| error("failed to parse PEM file"))?;
		if label != "PRIVATE KEY" {
			return Err(error(format!("unexpected PEM type {label:?}")));
		}
		let der = base64::engine::general_purpose::STANDARD
			.decode(body)
			.map_err(|_| error("failed to parse PEM file"))?;
		let seed = seed_from_pkcs8_der(&der).ok_or_else(|| {
			error("failed to unmarshal PKCS8 key: private key must be ed25519 key")
		})?;
		self.private_key = PrivateKey::from_seed(&seed).0.to_vec();
		Ok(())
	}

	/// The fields in Go's order, without those Go omits when empty.
	fn fields(&self) -> Vec<hjson::Field<'static>> {
		let mut fields = Vec::new();
		let mut push = |name: &'static str, comment: &'static str, value: Value| {
			fields.push(hjson::Field {
				name,
				comment,
				value,
			});
		};
		if !self.private_key.is_empty() {
			push(
				"PrivateKey",
				COMMENT_PRIVATE_KEY,
				hex::encode(&self.private_key).into(),
			);
		}
		if !self.private_key_path.is_empty() {
			push(
				"PrivateKeyPath",
				COMMENT_PRIVATE_KEY_PATH,
				self.private_key_path.clone().into(),
			);
		}
		push("Peers", COMMENT_PEERS, string_array(&self.peers));
		let interface_peers = self
			.interface_peers
			.iter()
			.map(|(name, peers)| (name.clone(), string_array(peers)))
			.collect();
		push(
			"InterfacePeers",
			COMMENT_INTERFACE_PEERS,
			Value::Object(interface_peers),
		);
		push("Listen", COMMENT_LISTEN, string_array(&self.listen));
		if !self.admin_listen.is_empty() {
			push(
				"AdminListen",
				COMMENT_ADMIN_LISTEN,
				self.admin_listen.clone().into(),
			);
		}
		let interfaces = self
			.multicast_interfaces
			.iter()
			.map(multicast_value)
			.collect();
		push(
			"MulticastInterfaces",
			COMMENT_MULTICAST_INTERFACES,
			Value::Array(interfaces),
		);
		push(
			"AllowedPublicKeys",
			COMMENT_ALLOWED_PUBLIC_KEYS,
			string_array(&self.allowed_public_keys),
		);
		push(
			"GroupPassword",
			COMMENT_GROUP_PASSWORD,
			self.group_password.clone().into(),
		);
		push("IfName", COMMENT_IF_NAME, self.if_name.clone().into());
		push("IfMTU", COMMENT_IF_MTU, self.if_mtu.into());
		if self.log_lookups {
			push("LogLookups", "", true.into());
		}
		push(
			"NodeInfoPrivacy",
			COMMENT_NODE_INFO_PRIVACY,
			self.node_info_privacy.into(),
		);
		push(
			"NodeInfo",
			COMMENT_NODE_INFO,
			self.node_info.clone().map_or(Value::Null, Value::Object),
		);
		fields
	}

	/// Like Go's `json.MarshalIndent(cfg, "", "  ")`.
	pub fn to_json(&self) -> String {
		let object: Map<String, Value> = self
			.fields()
			.into_iter()
			.map(|field| (field.name.to_string(), field.value))
			.collect();
		crate::json::to_string_pretty(&Value::Object(object)).expect("config is serializable")
	}

	/// Like hjson-go's `Marshal(cfg)`, with each field's description as a comment.
	pub fn to_hjson(&self) -> String {
		let mut fields = self.fields();
		for field in &mut fields {
			// hjson-go writes a nil map as an empty one
			if field.value.is_null() {
				field.value = Value::Object(Map::new());
			}
		}
		hjson::to_string(&fields)
	}

	/// Merges a parsed document onto this configuration with Go's `encoding/json` rules.
	fn apply(&mut self, value: &Hjson) -> Result<(), ConfigError> {
		let Hjson::Object(object) = value.resolved() else {
			return Err(error(format!(
				"json: cannot unmarshal {} into Go value of type config.NodeConfig",
				json_kind(value)
			)));
		};
		for (key, value) in object {
			let field = |go_type: &'static str| FieldRef {
				name: key,
				go_type,
				value,
			};
			match key.to_ascii_lowercase().as_str() {
				"privatekey" => {
					if let Some(text) = field("config.KeyBytes").string()? {
						self.private_key =
							hex::decode(text).map_err(|e| error(format!("encoding/hex: {e}")))?;
					}
				}
				"privatekeypath" => field("string").set_string(&mut self.private_key_path)?,
				"peers" => field("[]string").set_strings(&mut self.peers)?,
				"interfacepeers" => match value.resolved() {
					Hjson::Null => self.interface_peers.clear(),
					Hjson::Object(map) => {
						for (name, peers) in map {
							let mut list = Vec::new();
							FieldRef {
								name,
								go_type: "[]string",
								value: peers,
							}
							.set_strings(&mut list)?;
							self.interface_peers.insert(name.clone(), list);
						}
					}
					_ => return Err(field("map[string][]string").mismatch()),
				},
				"listen" => field("[]string").set_strings(&mut self.listen)?,
				"adminlisten" => field("string").set_string(&mut self.admin_listen)?,
				"multicastinterfaces" => match value.resolved() {
					Hjson::Null => self.multicast_interfaces.clear(),
					Hjson::Array(items) => {
						// Go decodes into the existing elements, merging with the defaults
						let mut merged = Vec::with_capacity(items.len());
						for (i, item) in items.iter().enumerate() {
							let mut interface = self
								.multicast_interfaces
								.get(i)
								.cloned()
								.unwrap_or_default();
							apply_multicast(&mut interface, item)?;
							merged.push(interface);
						}
						self.multicast_interfaces = merged;
					}
					_ => return Err(field("[]config.MulticastInterfaceConfig").mismatch()),
				},
				"allowedpublickeys" => {
					field("[]string").set_strings(&mut self.allowed_public_keys)?
				}
				"grouppassword" => field("string").set_string(&mut self.group_password)?,
				"ifname" => field("string").set_string(&mut self.if_name)?,
				"ifmtu" => {
					if let Some(mtu) = field("uint64").unsigned(u64::MAX)? {
						self.if_mtu = mtu;
					}
				}
				"loglookups" => field("bool").set_bool(&mut self.log_lookups)?,
				"nodeinfoprivacy" => field("bool").set_bool(&mut self.node_info_privacy)?,
				"nodeinfo" => match value.resolved() {
					Hjson::Null => self.node_info = None,
					Hjson::Object(map) => {
						let node_info = self.node_info.get_or_insert_with(Map::new);
						for (name, item) in map {
							node_info.insert(name.clone(), as_go_interface(item)?);
						}
						sort_keys(node_info);
					}
					_ => return Err(field("map[string]interface {}").mismatch()),
				},
				_ => {}
			}
		}
		Ok(())
	}
}

fn apply_multicast(
	interface: &mut MulticastInterfaceConfig,
	value: &Hjson,
) -> Result<(), ConfigError> {
	let object = match value.resolved() {
		Hjson::Null => return Ok(()),
		Hjson::Object(object) => object,
		_ => {
			return Err(error(format!(
				"json: cannot unmarshal {} into Go struct field NodeConfig.MulticastInterfaces of type config.MulticastInterfaceConfig",
				json_kind(value)
			)));
		}
	};
	for (key, value) in object {
		let field = |go_type: &'static str| FieldRef {
			name: key,
			go_type,
			value,
		};
		match key.to_ascii_lowercase().as_str() {
			"regex" => field("string").set_string(&mut interface.regex)?,
			"beacon" => field("bool").set_bool(&mut interface.beacon)?,
			"listen" => field("bool").set_bool(&mut interface.listen)?,
			"port" => {
				if let Some(port) = field("uint16").unsigned(u16::MAX as u64)? {
					interface.port = port as u16;
				}
			}
			"priority" => {
				if let Some(priority) = field("uint64").unsigned(u64::MAX)? {
					interface.priority = priority;
				}
			}
			"password" => field("string").set_string(&mut interface.password)?,
			_ => {}
		}
	}
	Ok(())
}

/// A parsed value being decoded into a Go struct field.
struct FieldRef<'a> {
	name: &'a str,
	go_type: &'static str,
	value: &'a Hjson,
}

impl FieldRef<'_> {
	fn mismatch(&self) -> ConfigError {
		error(format!(
			"json: cannot unmarshal {} into Go struct field NodeConfig.{} of type {}",
			json_kind(self.value),
			self.name,
			self.go_type
		))
	}

	/// `None` for null, which Go treats as "leave unchanged". Unquoted values are text here.
	fn string(&self) -> Result<Option<&str>, ConfigError> {
		if let Some(text) = self.value.as_text() {
			return Ok(Some(text));
		}
		match self.value {
			Hjson::Null => Ok(None),
			_ => Err(self.mismatch()),
		}
	}

	fn set_string(&self, target: &mut String) -> Result<(), ConfigError> {
		if let Some(s) = self.string()? {
			*target = s.to_string();
		}
		Ok(())
	}

	fn set_bool(&self, target: &mut bool) -> Result<(), ConfigError> {
		match self.value.resolved() {
			Hjson::Null => Ok(()),
			Hjson::Bool(b) => {
				*target = *b;
				Ok(())
			}
			_ => Err(self.mismatch()),
		}
	}

	fn set_strings(&self, target: &mut Vec<String>) -> Result<(), ConfigError> {
		match self.value.resolved() {
			Hjson::Null => target.clear(),
			Hjson::Array(items) => {
				*target = items
					.iter()
					.map(|item| {
						let element = FieldRef {
							value: item,
							..*self
						};
						element
							.string()
							.map(|text| text.unwrap_or_default().to_string())
					})
					.collect::<Result<_, _>>()?;
			}
			_ => return Err(self.mismatch()),
		}
		Ok(())
	}

	/// An unsigned integer no larger than `max`. Go rejects fractions and overflow.
	fn unsigned(&self, max: u64) -> Result<Option<u64>, ConfigError> {
		match self.value.resolved() {
			Hjson::Null => Ok(None),
			Hjson::Number(text) => match text.parse::<u64>().ok().filter(|n| *n <= max) {
				Some(n) => Ok(Some(n)),
				None => Err(error(format!(
					"json: cannot unmarshal number {text} into Go struct field NodeConfig.{} of type {}",
					self.name, self.go_type
				))),
			},
			_ => Err(self.mismatch()),
		}
	}
}

fn json_kind(value: &Hjson) -> &'static str {
	match value.resolved() {
		Hjson::Null => "null",
		Hjson::Bool(_) => "bool",
		Hjson::Number(_) => "number",
		Hjson::String(_) | Hjson::Bare(..) => "string",
		Hjson::Array(_) => "array",
		Hjson::Object(_) => "object",
	}
}

/// Converts a value the way Go decodes into `interface{}`: numbers become floats.
fn as_go_interface(value: &Hjson) -> Result<Value, ConfigError> {
	Ok(match value.resolved() {
		Hjson::Null => Value::Null,
		Hjson::Bool(b) => Value::Bool(*b),
		Hjson::Number(text) => {
			let number: f64 = text
				.parse()
				.map_err(|_| error(format!("invalid number {text}")))?;
			serde_json::Number::from_f64(number).map_or(Value::Null, Value::Number)
		}
		Hjson::String(text) | Hjson::Bare(text, _) => Value::String(text.clone()),
		Hjson::Array(items) => Value::Array(
			items
				.iter()
				.map(as_go_interface)
				.collect::<Result<_, _>>()?,
		),
		Hjson::Object(fields) => {
			let mut map = Map::new();
			for (key, item) in fields {
				map.insert(key.clone(), as_go_interface(item)?);
			}
			sort_keys(&mut map);
			Value::Object(map)
		}
	})
}

/// Go writes maps with sorted keys.
fn sort_keys(map: &mut Map<String, Value>) {
	map.sort_keys();
}

fn string_array(items: &[String]) -> Value {
	Value::Array(items.iter().cloned().map(Value::String).collect())
}

fn multicast_value(interface: &MulticastInterfaceConfig) -> Value {
	let mut object = Map::new();
	object.insert("Regex".into(), interface.regex.clone().into());
	object.insert("Beacon".into(), interface.beacon.into());
	object.insert("Listen".into(), interface.listen.into());
	if interface.port != 0 {
		object.insert("Port".into(), interface.port.into());
	}
	if interface.priority != 0 {
		object.insert("Priority".into(), interface.priority.into());
	}
	object.insert("Password".into(), interface.password.clone().into());
	Value::Object(object)
}

/// The `AdminListen` value of a configuration file, as yggdrasilctl reads it:
/// `None` if it is missing, empty or `none`.
pub fn read_admin_listen(data: &[u8]) -> Result<Option<String>, ConfigError> {
	let text = decode_text(data)?;
	let Hjson::Object(fields) = hjson_parse::parse(&text).map_err(|e| error(e.to_string()))? else {
		return Ok(None);
	};
	Ok(fields
		.iter()
		.find(|(key, _)| key == "AdminListen")
		.and_then(|(_, value)| match value {
			Hjson::String(text) => Some(text.clone()),
			Hjson::Bare(_, value) => match value.as_ref() {
				Hjson::String(text) => Some(text.clone()),
				_ => None,
			},
			_ => None,
		})
		.filter(|listen| !listen.is_empty() && listen != "none"))
}

/// Decodes UTF-8, or UTF-16 if there is a byte order mark, as Go's config loader does.
fn decode_text(data: &[u8]) -> Result<String, ConfigError> {
	let little_endian = match data {
		[0xff, 0xfe, ..] => true,
		[0xfe, 0xff, ..] => false,
		_ => {
			return String::from_utf8(data.to_vec()).map_err(|e| error(e.to_string()));
		}
	};
	let units: Vec<u16> = data[2..]
		.chunks_exact(2)
		.map(|pair| {
			let pair = [pair[0], pair[1]];
			if little_endian {
				u16::from_le_bytes(pair)
			} else {
				u16::from_be_bytes(pair)
			}
		})
		.collect();
	Ok(String::from_utf16_lossy(&units))
}

/// Finds the first PEM block, returning its label and base64 body.
fn pem_block(text: &str) -> Option<(&str, String)> {
	let start = text.find("-----BEGIN ")?;
	let rest = &text[start + "-----BEGIN ".len()..];
	let (label, rest) = rest.split_once("-----")?;
	let end = rest.find(&format!("-----END {label}-----"))?;
	let body: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
	Some((label, body))
}

#[cfg(test)]
mod tests {
	use super::*;

	const KEY: &str = "e70c61bd87126cd1ef122911582a231cf2239b27ac2c1522a31fb924ec3208c66f960a37c718041a7de3062090904d5d27043faad8e22f663b493879250c7e3c";

	#[test]
	fn merges_onto_defaults_like_go() {
		let text = format!(
			"{{\n privatekey: {KEY}\n multicastinterfaces: [{{Regex: \"eth0\"}}, {{regex: \"wl.*\", port: 5}}]\n Nodeinfo: {{b: 1.0, a: \"x<y\"}}\n IfMTU: 1500\n}}"
		);
		let config = NodeConfig::read_from(text.as_bytes()).unwrap();
		assert_eq!(hex::encode(&config.private_key), KEY);
		assert_eq!(config.if_mtu, 1500);
		let defaults = get_defaults();
		assert_eq!(config.multicast_interfaces[0].regex, "eth0");
		assert_eq!(
			config.multicast_interfaces[0].beacon,
			defaults.multicast_interfaces[0].beacon
		);
		assert!(!config.multicast_interfaces[1].beacon);
		assert_eq!(config.multicast_interfaces[1].port, 5);
		assert!(
			config
				.to_json()
				.contains("\"a\": \"x\\u003cy\",\n    \"b\": 1\n")
		);
	}

	#[test]
	fn rejects_bad_values_like_go() {
		for text in [
			"{IfMTU: 1500.5}",
			"{IfMTU: -1}",
			"{Peers: 5}",
			"{PrivateKey: abcd}",
		] {
			assert!(NodeConfig::read_from(text.as_bytes()).is_err(), "{text}");
		}
	}

	#[test]
	fn reads_utf16_with_bom() {
		let text = format!("{{PrivateKey: {KEY}\n}}");
		let mut data = vec![0xff, 0xfe];
		data.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
		assert_eq!(
			hex::encode(NodeConfig::read_from(&data).unwrap().private_key),
			KEY
		);
	}

	#[test]
	fn pem_round_trips() {
		let config = NodeConfig::generate();
		let pem = config.marshal_pem_private_key();
		let mut loaded = NodeConfig::generate();
		loaded.unmarshal_pem_private_key(pem.as_bytes()).unwrap();
		assert_eq!(loaded.private_key, config.private_key);
	}

	#[test]
	fn output_round_trips() {
		let mut config = NodeConfig::generate();
		config.peers = vec!["tls://a.b.c.d:1".into(), "true".into()];
		config.node_info = Some(Map::from_iter([(
			"name".to_string(),
			Value::from("multi\nline"),
		)]));
		assert_eq!(
			NodeConfig::read_from(config.to_hjson().as_bytes()).unwrap(),
			config
		);
		assert_eq!(
			NodeConfig::read_from(config.to_json().as_bytes()).unwrap(),
			config
		);
	}
}
