#!/bin/sh
# Builds static Linux release archives in containers, for contrib/install.sh to
# download. Upload everything in the output directory to a release.
#
# Usage: contrib/release.sh [OUTPUT_DIR]
#   PLATFORMS         container platforms to build (default: linux/amd64 linux/arm64)
#   CONTAINER_ENGINE  podman or docker (default: whichever is installed)
# Other platforms are built with emulation, which needs qemu-user-static.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
petrified="$(cd "$root/../petrified" && pwd)"
out="$(mkdir -p "${1:-$root/dist}" && cd "${1:-$root/dist}" && pwd)"
engine="${CONTAINER_ENGINE:-$(command -v podman || command -v docker)}"
platforms="${PLATFORMS:-linux/amd64 linux/arm64}"
# Pass through version overrides, otherwise build.rs reads them from git
version_env=""
for name in YGGDRASIL_BUILD_NAME YGGDRASIL_BUILD_VERSION; do
	eval "value=\${$name:-}"
	[ -n "$value" ] && version_env="$version_env -e $name=$value"
done

for platform in $platforms; do
	case "$platform" in
		linux/amd64) target=x86_64-unknown-linux-musl ;;
		linux/arm64) target=aarch64-unknown-linux-musl ;;
		*) echo "unsupported platform: $platform" >&2; exit 1 ;;
	esac
	name="yggdrasil-rs-$target"
	echo "Building $name"
	# shellcheck disable=SC2086
	# label=disable lets SELinux hosts read the sources without relabelling them
	"$engine" run --rm --platform "$platform" --security-opt label=disable \
		-v "$root:/src/yggdrasil-rs:ro" \
		-v "$petrified:/src/petrified:ro" \
		-v "$out:/out" \
		-v "yggdrasil-rs-cargo-$target:/usr/local/cargo/registry" \
		-e CARGO_TARGET_DIR=/build \
		-e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
		$version_env \
		docker.io/library/rust:alpine sh -euc "
			apk add --no-cache musl-dev git >/dev/null
			cd /src/yggdrasil-rs
			cargo build --release --locked --target $target
			mkdir -p /tmp/$name
			cp /build/$target/release/yggdrasil /build/$target/release/yggdrasilctl /build/$target/release/genkeys \
				contrib/systemd/*.service README.md /tmp/$name/
			tar -C /tmp -czf /out/$name.tar.gz $name
		"
	(cd "$out" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
done
cp "$root/contrib/install.sh" "$out/install.sh"
echo "Release files are in $out"
