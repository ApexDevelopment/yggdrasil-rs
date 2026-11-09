//! Names the build from git, as yggdrasil-go's build script does. Set
//! YGGDRASIL_BUILD_NAME or YGGDRASIL_BUILD_VERSION to override either.

use std::path::Path;
use std::process::Command;

/// Runs git in this crate's own repository, if it has one.
fn git(dir: &Path, args: &[&str]) -> Option<String> {
	let output = Command::new("git")
		.arg("-C")
		.arg(dir)
		.args(args)
		.output()
		.ok()?;
	let text = String::from_utf8(output.stdout).ok()?.trim().to_string();
	(output.status.success() && !text.is_empty()).then_some(text)
}

fn main() {
	let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
	// Ignore any enclosing repository, such as a project using this crate
	let own_repository = git(dir, &["rev-parse", "--show-toplevel"])
		.is_some_and(|top| Path::new(&top).canonicalize().ok() == dir.canonicalize().ok());
	let repo = own_repository.then_some(dir);

	let name = std::env::var("YGGDRASIL_BUILD_NAME")
		.ok()
		.unwrap_or_else(|| {
			match repo.and_then(|dir| git(dir, &["symbolic-ref", "--short", "HEAD"])) {
				Some(branch) if branch != "main" && branch != "master" => {
					format!("yggdrasil-{}", branch.replace('/', ""))
				}
				_ => "yggdrasil".into(),
			}
		});
	let version = std::env::var("YGGDRASIL_BUILD_VERSION")
		.ok()
		.unwrap_or_else(|| {
			repo.and_then(|dir| {
				git(
					dir,
					&["describe", "--tags", "--match=v[0-9]*.[0-9]*.[0-9]*"],
				)
			})
			.map(|tag| tag.trim_start_matches('v').to_string())
			.unwrap_or_else(|| env!("CARGO_PKG_VERSION").into())
		});
	println!("cargo:rustc-env=YGGDRASIL_BUILD_NAME={name}");
	println!("cargo:rustc-env=YGGDRASIL_BUILD_VERSION={version}");
	println!("cargo:rerun-if-env-changed=YGGDRASIL_BUILD_NAME");
	println!("cargo:rerun-if-env-changed=YGGDRASIL_BUILD_VERSION");
	if own_repository {
		println!("cargo:rerun-if-changed=.git/HEAD");
		println!("cargo:rerun-if-changed=.git/refs/tags");
		println!("cargo:rerun-if-changed=.git/packed-refs");
	}
}
