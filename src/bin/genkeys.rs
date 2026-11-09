//! Searches for keys whose addresses have more leading ones, which gives them
//! more address bits. Prints each better key it finds, forever.

use std::sync::mpsc;
use std::time::Instant;

use yggdrasil::address::addr_for_key;
use yggdrasil::cli::go_duration;
use yggdrasil::{PrivateKey, PublicKey};

/// Smaller keys are better, as they invert to more leading ones.
fn is_better(old: &PublicKey, new: &PublicKey) -> bool {
	new.0 < old.0
}

fn search(found: mpsc::Sender<(PrivateKey, u64)>) {
	let mut best = PublicKey([0xff; 32]);
	let mut tried = 0u64;
	let mut seed = [0u8; 32];
	loop {
		getrandom::fill(&mut seed).expect("OS random number generator failed");
		let secret = PrivateKey::from_seed(&seed);
		tried += 1;
		let public = secret.public_key();
		if !is_better(&best, &public) {
			continue;
		}
		best = public;
		if found.send((secret, tried)).is_err() {
			return;
		}
		tried = 0;
	}
}

fn main() {
	let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
	println!("Threads: {threads}");
	let start = Instant::now();
	let (sender, receiver) = mpsc::channel();
	for _ in 0..threads {
		let sender = sender.clone();
		std::thread::spawn(move || search(sender));
	}
	let mut total = 0u64;
	let mut best: Option<PublicKey> = None;
	for (secret, tried) in receiver {
		let public = secret.public_key();
		if best.is_some_and(|best| !is_better(&best, &public)) {
			continue;
		}
		total += tried;
		best = Some(public);
		println!(
			"----- {} --- {total} keys tried",
			go_duration(start.elapsed())
		);
		println!("Priv: {}", hex::encode(secret.0));
		println!("Pub: {}", hex::encode(public.0));
		println!("IP: {}", addr_for_key(&public));
	}
}
