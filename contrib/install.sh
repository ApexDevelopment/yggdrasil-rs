#!/bin/sh
# Installs yggdrasil-rs from a release on Linux.
#
#   curl -fsSL https://github.com/ApexDevelopment/yggdrasil-rs/releases/latest/download/install.sh | sh
#   curl -fsSL https://github.com/ApexDevelopment/yggdrasil-rs/releases/latest/download/install.sh | sh -s -- --user
#
# Run with --help for the options.
set -eu

# Where releases are published, in GitHub's layout: assets are fetched from
# $RELEASES_URL/latest/download/ or $RELEASES_URL/download/<tag>/.
RELEASES_URL="${YGGDRASIL_RS_RELEASES:-https://github.com/ApexDevelopment/yggdrasil-rs/releases}"

PROGRAMS="yggdrasil yggdrasilctl genkeys"
UNITS="yggdrasil.service yggdrasil-default-config.service"
SYSTEM_BIN=/usr/local/bin
SYSTEM_DOC=/usr/local/share/doc/yggdrasil
LICENSES="LICENSE THIRD-PARTY-NOTICES"
UNIT_DIR=/etc/systemd/system

usage() {
	cat <<EOF
Usage: install.sh [options]

Installs the yggdrasil, yggdrasilctl and genkeys programs to $SYSTEM_BIN,
and a systemd service that runs yggdrasil with /etc/yggdrasil.conf.

Options:
  --user           Install the programs to ~/.local/bin only, without root
                   and without the service
  --version TAG    Install this release, such as v0.1.0, instead of the latest
  --no-start       Install the service without enabling or starting it
  --uninstall      Remove what this script installed
  -h, --help       Show this help

Set YGGDRASIL_RS_RELEASES to download from another release location.
EOF
}

say() {
	printf '%s\n' "$*"
}

fail() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

download() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1" -o "$2" || fail "could not download $1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q "$1" -O "$2" || fail "could not download $1"
	else
		fail "curl or wget is required"
	fi
}

verify() {
	if command -v sha256sum >/dev/null 2>&1; then
		(cd "$(dirname "$1")" && sha256sum -c "$(basename "$1").sha256" >/dev/null) ||
			fail "checksum mismatch for $(basename "$1")"
	elif command -v shasum >/dev/null 2>&1; then
		(cd "$(dirname "$1")" && shasum -a 256 -c "$(basename "$1").sha256" >/dev/null) ||
			fail "checksum mismatch for $(basename "$1")"
	else
		fail "sha256sum or shasum is required to check the download"
	fi
}

target_triple() {
	[ "$(uname -s)" = Linux ] || fail "only Linux is supported; build from source on $(uname -s)"
	case "$(uname -m)" in
		x86_64 | amd64) echo x86_64-unknown-linux-musl ;;
		aarch64 | arm64) echo aarch64-unknown-linux-musl ;;
		*) fail "no release is built for $(uname -m); build from source instead" ;;
	esac
}

# Sets $as_root to the command that runs a command as root.
find_root() {
	if [ "$(id -u)" -eq 0 ]; then
		as_root=""
	elif command -v sudo >/dev/null 2>&1; then
		as_root=sudo
	elif command -v doas >/dev/null 2>&1; then
		as_root=doas
	else
		fail "run as root, or install sudo or doas"
	fi
}

has_systemd() {
	[ -d /run/systemd/system ]
}

user_bin() {
	echo "${XDG_BIN_HOME:-$HOME/.local/bin}"
}

# Downloads and unpacks the release, leaving its files in $release.
fetch_release() {
	[ -n "$RELEASES_URL" ] || fail "no release location is set; set YGGDRASIL_RS_RELEASES"
	asset="yggdrasil-rs-$(target_triple).tar.gz"
	if [ -n "$version" ]; then
		base="$RELEASES_URL/download/$version"
	else
		base="$RELEASES_URL/latest/download"
	fi
	say "Downloading $base/$asset"
	download "$base/$asset" "$tmp/$asset"
	download "$base/$asset.sha256" "$tmp/$asset.sha256"
	verify "$tmp/$asset"
	tar -xzf "$tmp/$asset" -C "$tmp"
	release="$tmp/${asset%.tar.gz}"
}

install_user() {
	bin="$(user_bin)"
	mkdir -p "$bin"
	for program in $PROGRAMS; do
		install -m 755 "$release/$program" "$bin/$program"
	done
	doc="${XDG_DATA_HOME:-$HOME/.local/share}/doc/yggdrasil"
	mkdir -p "$doc"
	for file in $LICENSES; do
		install -m 644 "$release/$file" "$doc/$file"
	done
	say "Installed $PROGRAMS to $bin"
	case ":$PATH:" in
		*":$bin:"*) ;;
		*) say "Add $bin to your PATH to run them." ;;
	esac
	say "Running a node with a TUN adapter needs root, for example:"
	say "  sudo $bin/yggdrasil -useconffile /path/to/yggdrasil.conf"
}

install_system() {
	find_root
	$as_root install -d "$SYSTEM_BIN"
	for program in $PROGRAMS; do
		# A fresh copy gets the right SELinux label; a moved file would keep its temporary one
		$as_root install -m 755 "$release/$program" "$SYSTEM_BIN/$program"
	done
	$as_root install -d "$SYSTEM_DOC"
	for file in $LICENSES; do
		$as_root install -m 644 "$release/$file" "$SYSTEM_DOC/$file"
	done
	say "Installed $PROGRAMS to $SYSTEM_BIN"
	if [ -x /usr/bin/yggdrasil ]; then
		say "Note: /usr/bin/yggdrasil, probably from a package, is also installed. The service installed here uses $SYSTEM_BIN/yggdrasil."
	fi
	if ! has_systemd; then
		say "systemd is not running, so no service was installed. Start the node with:"
		say "  sudo $SYSTEM_BIN/yggdrasil -useconffile /etc/yggdrasil.conf"
		return
	fi
	for unit in $UNITS; do
		sed "s|/usr/bin/yggdrasil |$SYSTEM_BIN/yggdrasil |" "$release/$unit" >"$tmp/$unit"
		$as_root install -m 644 "$tmp/$unit" "$UNIT_DIR/$unit"
	done
	if command -v restorecon >/dev/null 2>&1; then
		for program in $PROGRAMS; do
			$as_root restorecon "$SYSTEM_BIN/$program" 2>/dev/null || true
		done
	fi
	getent group yggdrasil >/dev/null || $as_root groupadd --system yggdrasil
	$as_root systemctl daemon-reload
	if [ "$no_start" = yes ]; then
		say "Installed the yggdrasil service. Start it with: sudo systemctl enable --now yggdrasil"
	elif $as_root systemctl is-active --quiet yggdrasil; then
		$as_root systemctl restart yggdrasil
		say "Restarted the yggdrasil service"
	else
		$as_root systemctl enable --now yggdrasil
		say "Started the yggdrasil service. Its configuration is /etc/yggdrasil.conf."
	fi
	say "To use yggdrasilctl without sudo, add yourself to the yggdrasil group:"
	say "  sudo usermod -aG yggdrasil \"\$USER\""
}

uninstall_user() {
	bin="$(user_bin)"
	for program in $PROGRAMS; do
		rm -f "$bin/$program"
	done
	rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/doc/yggdrasil"
	say "Removed $PROGRAMS from $bin"
}

uninstall_system() {
	find_root
	if has_systemd && [ -f "$UNIT_DIR/yggdrasil.service" ]; then
		$as_root systemctl disable --now yggdrasil 2>/dev/null || true
	fi
	for unit in $UNITS; do
		$as_root rm -f "$UNIT_DIR/$unit"
	done
	if has_systemd; then
		$as_root systemctl daemon-reload
	fi
	for program in $PROGRAMS; do
		$as_root rm -f "$SYSTEM_BIN/$program"
	done
	$as_root rm -rf "$SYSTEM_DOC"
	say "Removed the yggdrasil service and programs. /etc/yggdrasil.conf and the yggdrasil group are kept."
}

main() {
	user=no
	version=""
	no_start=no
	uninstall=no
	while [ $# -gt 0 ]; do
		case "$1" in
			--user) user=yes ;;
			--version)
				[ $# -ge 2 ] || fail "--version needs a release tag"
				version="$2"
				shift
				;;
			--no-start) no_start=yes ;;
			--uninstall) uninstall=yes ;;
			-h | --help)
				usage
				exit 0
				;;
			*) fail "unknown option: $1 (see --help)" ;;
		esac
		shift
	done

	if [ "$uninstall" = yes ]; then
		if [ "$user" = yes ]; then uninstall_user; else uninstall_system; fi
		return
	fi
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT
	fetch_release
	if [ "$user" = yes ]; then install_user; else install_system; fi
}

# Called last, so a partly downloaded script does nothing
main "$@"
