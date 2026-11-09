#!/bin/sh
# Installs the Debian package, the RPM package and install.sh in Debian and
# Fedora containers running systemd, and checks that the nodes start, find each
# other with multicast and can ping each other.
#
# Usage: contrib/test-packages.sh
#   CONTAINER_ENGINE  podman or docker (default: whichever is installed)
# Needs cargo-deb, cargo-generate-rpm and /dev/net/tun. Builds the release
# archive with contrib/release.sh for the host's architecture only.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
engine="${CONTAINER_ENGINE:-$(command -v podman || command -v docker)}"
network=yggdrasil-rs-test
work="$(mktemp -d)"
containers=""
failures=0

cleanup() {
	for container in $containers; do
		"$engine" rm -f "$container" >/dev/null 2>&1 || true
	done
	"$engine" network rm "$network" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

pass() {
	printf 'ok    %s\n' "$*"
}

fail() {
	printf 'FAIL  %s\n' "$*"
	failures=$((failures + 1))
}

# Builds a test image with systemd and a user who can use sudo.
build_image() {
	name="$1"
	base="$2"
	install="$3"
	cat >"$work/Containerfile.$name" <<EOF
FROM $base
RUN $install
RUN useradd -m tester && mkdir -p /etc/sudoers.d && echo 'tester ALL=(ALL) NOPASSWD: ALL' >/etc/sudoers.d/tester
CMD ["/sbin/init"]
EOF
	if ! "$engine" build -t "yggdrasil-rs-test-$name" -f "$work/Containerfile.$name" "$work" >"$work/build-$name.log" 2>&1; then
		cat "$work/build-$name.log" >&2
		exit 1
	fi
}

# Starts a container from a test image.
start() {
	container="yggdrasil-rs-test-$1-$2"
	# label=disable lets SELinux hosts pass /dev/net/tun through
	"$engine" run -d --name "$container" --network "$network" --systemd=always \
		--security-opt label=disable --device /dev/net/tun --cap-add NET_ADMIN \
		"yggdrasil-rs-test-$1" >/dev/null
	containers="$containers $container"
	sleep 2
}

in_container() {
	container="$1"
	shift
	"$engine" exec "$container" sh -c "$*"
}

# Waits for the service to run and have its address, and prints the address.
wait_for_node() {
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		address="$(in_container "$1" "ip -6 addr show scope global 2>/dev/null | sed -n 's/.*inet6 \(2[0-9a-f:]*\)\/7.*/\1/p'")"
		if [ -n "$address" ]; then
			echo "$address"
			return
		fi
		sleep 1
	done
}

check_pair() {
	label="$1"
	debian="$2"
	fedora="$3"
	debian_address="$(wait_for_node "$debian")"
	fedora_address="$(wait_for_node "$fedora")"
	if [ -n "$debian_address" ] && [ -n "$fedora_address" ]; then
		pass "$label: both nodes run with TUN addresses"
	else
		fail "$label: a node did not start (Debian: ${debian_address:-none}, Fedora: ${fedora_address:-none})"
		return
	fi
	if in_container "$debian" "for i in \$(seq 20); do ping -6 -c 1 -W 1 $fedora_address >/dev/null && exit 0; done; exit 1" &&
		in_container "$fedora" "ping -6 -c 3 -W 2 $debian_address >/dev/null"; then
		pass "$label: the nodes found each other with multicast and ping both ways"
	else
		fail "$label: the nodes could not ping each other"
	fi
}

echo "Building packages"
(cd "$root" && cargo deb -q && cargo build -q --release && cargo generate-rpm) >"$work/packages.log" 2>&1 || {
	cat "$work/packages.log" >&2
	exit 1
}
deb="$(ls "$root"/target/debian/yggdrasil_*.deb | tail -n 1)"
rpm="$(ls "$root"/target/generate-rpm/yggdrasil-*.rpm | tail -n 1)"
case "$(uname -m)" in
	x86_64) platform=linux/amd64 ;;
	aarch64) platform=linux/arm64 ;;
	*) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
PLATFORMS="$platform" "$root/contrib/release.sh" "$work/release" >/dev/null

echo "Building test images"
build_image debian docker.io/library/debian:trixie \
	"apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus iproute2 iputils-ping kmod curl ca-certificates sudo && apt-get clean && rm -f /usr/sbin/policy-rc.d"
build_image fedora registry.fedoraproject.org/fedora:latest \
	"dnf install -y systemd iproute iputils kmod sudo && dnf clean all"
"$engine" network create "$network" >/dev/null

echo "Testing the packages"
start debian packages
start fedora packages
"$engine" cp "$deb" yggdrasil-rs-test-debian-packages:/tmp/yggdrasil.deb
"$engine" cp "$rpm" yggdrasil-rs-test-fedora-packages:/tmp/yggdrasil.rpm
if in_container yggdrasil-rs-test-debian-packages "apt-get install -y /tmp/yggdrasil.deb >/dev/null 2>&1"; then
	pass "the Debian package installs"
else
	fail "the Debian package does not install"
fi
if in_container yggdrasil-rs-test-fedora-packages "dnf install -y /tmp/yggdrasil.rpm >/dev/null 2>&1 && systemctl enable --now yggdrasil >/dev/null 2>&1"; then
	pass "the RPM package installs and its service starts"
else
	fail "the RPM package does not install"
fi
check_pair packages yggdrasil-rs-test-debian-packages yggdrasil-rs-test-fedora-packages

echo "Testing install.sh"
start debian script
start fedora script
for container in yggdrasil-rs-test-debian-script yggdrasil-rs-test-fedora-script; do
	in_container "$container" "mkdir -p /release/latest/download"
	"$engine" cp "$work/release/." "$container:/release/latest/download/"
	if "$engine" exec -u tester -w /home/tester "$container" sh -c \
		"curl -fsSL file:///release/latest/download/install.sh | YGGDRASIL_RS_RELEASES=file:///release sh" >"$work/install.log" 2>&1; then
		pass "install.sh installs on ${container##*-test-}"
	else
		fail "install.sh fails on ${container##*-test-}:"
		cat "$work/install.log"
	fi
done
check_pair install.sh yggdrasil-rs-test-debian-script yggdrasil-rs-test-fedora-script
if "$engine" exec -u tester -w /home/tester yggdrasil-rs-test-fedora-script sh -c \
	"curl -fsSL file:///release/latest/download/install.sh | YGGDRASIL_RS_RELEASES=file:///release sh -s -- --uninstall >/dev/null &&
	! test -e /usr/local/bin/yggdrasil && ! test -e /etc/systemd/system/yggdrasil.service"; then
	pass "install.sh --uninstall removes the programs and service"
else
	fail "install.sh --uninstall leaves files behind"
fi

if [ "$failures" -gt 0 ]; then
	echo "$failures checks failed"
	exit 1
fi
echo "All checks passed"
