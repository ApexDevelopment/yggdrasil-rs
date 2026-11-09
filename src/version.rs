//! Build information, as reported in nodeinfo and by the admin socket. `build.rs`
//! sets it from git, like yggdrasil-go's build script.

pub fn build_name() -> &'static str {
	env!("YGGDRASIL_BUILD_NAME")
}

pub fn build_version() -> &'static str {
	env!("YGGDRASIL_BUILD_VERSION")
}

/// The operating system, named as Go's `runtime.GOOS` names it.
pub fn build_platform() -> &'static str {
	match std::env::consts::OS {
		"macos" => "darwin",
		os => os,
	}
}

/// The CPU architecture, named as Go's `runtime.GOARCH` names it.
pub fn build_arch() -> &'static str {
	match std::env::consts::ARCH {
		"x86_64" => "amd64",
		"x86" => "386",
		"aarch64" => "arm64",
		"powerpc64" if cfg!(target_endian = "little") => "ppc64le",
		"powerpc64" => "ppc64",
		"powerpc" => "ppc",
		"loongarch64" => "loong64",
		"mips64" if cfg!(target_endian = "little") => "mips64le",
		"mips" if cfg!(target_endian = "little") => "mipsle",
		arch => arch,
	}
}
