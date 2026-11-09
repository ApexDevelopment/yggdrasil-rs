//! Rust nodes peering with each other over every transport.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use yggdrasil::PrivateKey;
use yggdrasil::core::{Core, Options};

async fn node(seed: u8) -> Core {
	Core::new(PrivateKey::from_seed(&[seed; 32]), Options::default())
		.await
		.unwrap()
}

/// Waits until `a` and `b` can exchange a packet in both directions.
async fn assert_connected(a: &Core, b: &Core) {
	let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
	for (from, to) in [(a, b), (b, a)] {
		let message = format!("hello from {}", from.address());
		loop {
			from.write_to(message.as_bytes(), &to.public_key()).unwrap();
			match tokio::time::timeout(Duration::from_millis(250), to.recv()).await {
				Ok(Ok((sender, packet))) => {
					assert_eq!(sender, from.public_key());
					assert_eq!(packet, message.as_bytes());
					break;
				}
				_ => assert!(
					tokio::time::Instant::now() < deadline,
					"no traffic between nodes"
				),
			}
		}
	}
}

async fn assert_peers_over(scheme: &str, listen: &str) {
	let a = node(1).await;
	let b = node(2).await;
	let listener = a.listen(&format!("{scheme}://{listen}"), "").await.unwrap();
	b.add_peer(&format!("{scheme}://{}", listener.local_addr()), "")
		.unwrap();
	assert_connected(&a, &b).await;
	let peers = b.get_peers();
	assert_eq!(peers.len(), 1);
	assert!(peers[0].up && !peers[0].inbound);
	assert_eq!(peers[0].key, Some(a.public_key()));
	assert!(
		a.get_peers()
			.iter()
			.any(|peer| peer.inbound && peer.key == Some(b.public_key()))
	);
	a.stop();
	b.stop();
}

#[tokio::test]
async fn peers_over_tcp() {
	assert_peers_over("tcp", "127.0.0.1:0").await;
}

#[tokio::test]
async fn peers_over_tls() {
	assert_peers_over("tls", "127.0.0.1:0").await;
}

#[tokio::test]
async fn peers_over_quic() {
	assert_peers_over("quic", "127.0.0.1:0").await;
}

#[tokio::test]
async fn peers_over_websockets() {
	assert_peers_over("ws", "127.0.0.1:0").await;
}

#[cfg(unix)]
#[tokio::test]
async fn peers_over_unix_sockets() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("ygg.sock");
	assert_peers_over("unix", path.to_str().unwrap()).await;
}

/// A SOCKS5 proxy that supports only unauthenticated CONNECT to IPv4 addresses.
async fn socks_proxy() -> String {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap().to_string();
	tokio::spawn(async move {
		loop {
			let (mut client, _) = listener.accept().await.unwrap();
			tokio::spawn(async move {
				let mut greeting = [0u8; 2];
				client.read_exact(&mut greeting).await.unwrap();
				let mut methods = vec![0u8; greeting[1] as usize];
				client.read_exact(&mut methods).await.unwrap();
				client.write_all(&[5, 0]).await.unwrap();
				let mut request = [0u8; 10];
				client.read_exact(&mut request).await.unwrap();
				assert_eq!(request[3], 1, "only IPv4 targets are supported");
				let ip = std::net::Ipv4Addr::new(request[4], request[5], request[6], request[7]);
				let port = u16::from_be_bytes([request[8], request[9]]);
				let mut target = TcpStream::connect((ip, port)).await.unwrap();
				client
					.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
					.await
					.unwrap();
				let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
			});
		}
	});
	addr
}

#[tokio::test]
async fn peers_through_socks() {
	let proxy = socks_proxy().await;
	for (scheme, target_scheme) in [("socks", "tcp"), ("sockstls", "tls")] {
		let a = node(3).await;
		let b = node(4).await;
		let listener = a
			.listen(&format!("{target_scheme}://127.0.0.1:0"), "")
			.await
			.unwrap();
		b.add_peer(&format!("{scheme}://{proxy}/{}", listener.local_addr()), "")
			.unwrap();
		assert_connected(&a, &b).await;
		a.stop();
		b.stop();
	}
}

#[tokio::test]
async fn rejects_wrong_link_password() {
	let a = node(5).await;
	let b = node(6).await;
	let listener = a
		.listen("tcp://127.0.0.1:0?password=right", "")
		.await
		.unwrap();
	b.add_peer(
		&format!("tcp://{}?password=wrong", listener.local_addr()),
		"",
	)
	.unwrap();
	tokio::time::sleep(Duration::from_secs(2)).await;
	let peers = b.get_peers();
	assert!(!peers[0].up);
	assert_eq!(
		peers[0].last_error.as_deref(),
		Some("password does not match remote side")
	);
	a.stop();
	b.stop();
}

#[tokio::test]
async fn rejects_unpinned_keys() {
	let a = node(7).await;
	let b = node(8).await;
	let listener = a.listen("tcp://127.0.0.1:0", "").await.unwrap();
	let wrong_key = "00".repeat(32);
	b.add_peer(
		&format!("tcp://{}?key={wrong_key}", listener.local_addr()),
		"",
	)
	.unwrap();
	tokio::time::sleep(Duration::from_secs(2)).await;
	assert_eq!(
		b.get_peers()[0].last_error.as_deref(),
		Some("node public key that does not match pinned keys")
	);
	a.stop();
	b.stop();
}

#[tokio::test]
async fn enforces_allowed_public_keys() {
	let a = Core::new(
		PrivateKey::from_seed(&[9; 32]),
		Options {
			allowed_public_keys: vec![PrivateKey::from_seed(&[10; 32]).public_key()],
			..Options::default()
		},
	)
	.await
	.unwrap();
	let allowed = node(10).await;
	let denied = node(11).await;
	let listener = a.listen("tcp://127.0.0.1:0", "").await.unwrap();
	allowed
		.add_peer(&format!("tcp://{}", listener.local_addr()), "")
		.unwrap();
	denied
		.add_peer(&format!("tcp://{}", listener.local_addr()), "")
		.unwrap();
	assert_connected(&a, &allowed).await;
	tokio::time::sleep(Duration::from_secs(1)).await;
	assert!(!denied.get_peers()[0].up);
	for node in [a, allowed, denied] {
		node.stop();
	}
}

#[tokio::test]
async fn refuses_to_peer_with_itself() {
	let a = node(12).await;
	let listener = a.listen("tcp://127.0.0.1:0", "").await.unwrap();
	a.add_peer(&format!("tcp://{}", listener.local_addr()), "")
		.unwrap();
	tokio::time::sleep(Duration::from_secs(1)).await;
	let outbound: Vec<_> = a
		.get_peers()
		.into_iter()
		.filter(|peer| !peer.inbound)
		.collect();
	assert_eq!(
		outbound[0].last_error.as_deref(),
		Some("node cannot connect to self")
	);
	a.stop();
}

#[tokio::test]
async fn removing_a_peer_disconnects_it() {
	let a = node(13).await;
	let b = node(14).await;
	let listener = a.listen("tcp://127.0.0.1:0", "").await.unwrap();
	let uri = format!("tcp://{}", listener.local_addr());
	b.add_peer(&uri, "").unwrap();
	assert_connected(&a, &b).await;
	assert!(b.add_peer(&uri, "").is_err());
	b.remove_peer(&uri, "").unwrap();
	tokio::time::sleep(Duration::from_millis(500)).await;
	assert!(b.get_peers().is_empty());
	assert!(a.get_peers().is_empty());
	a.stop();
	b.stop();
}

#[tokio::test]
async fn answers_nodeinfo_and_debug_requests() {
	let a = node(15).await;
	let b = node(16).await;
	let listener = a.listen("tcp://127.0.0.1:0", "").await.unwrap();
	b.add_peer(&format!("tcp://{}", listener.local_addr()), "")
		.unwrap();
	assert_connected(&a, &b).await;
	let a_key = hex::encode(a.public_key().0);
	let nodeinfo = b.get_node_info(&a_key).await.unwrap();
	assert_eq!(
		nodeinfo[&a_key]["buildname"],
		yggdrasil::version::build_name()
	);
	let remote_self = b.remote_get_self(&a_key).await.unwrap();
	assert_eq!(remote_self[a.address().to_string()]["key"], a_key);
	let remote_peers = b.remote_get_peers(&a_key).await.unwrap();
	assert_eq!(
		remote_peers[a.address().to_string()]["keys"][0],
		hex::encode(b.public_key().0)
	);
	a.stop();
	b.stop();
}
