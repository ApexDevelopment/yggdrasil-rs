#!/bin/sh
# Builds the Go interop harness and yggdrasil-go's binaries from a pristine
# copy of upstream yggdrasil-go, with yggdrasil-rs's export files added.
# Usage: build.sh OUTPUT_DIR
set -eu
out="$1"
here="$(cd "$(dirname "$0")" && pwd)"
go="${GO:-go}"
module=github.com/yggdrasil-network/yggdrasil-go
cd "$here/harness"
"$go" mod download "$module"
src="$("$go" list -m -f '{{.Dir}}' "$module")"
rm -rf "$out"
mkdir -p "$out"
cp -R "$src" "$out/yggdrasil-go"
chmod -R u+w "$out/yggdrasil-go"
cp "$here/inject/core/"*.go "$out/yggdrasil-go/src/core/"
cp "$here/inject/multicast/"*.go "$out/yggdrasil-go/src/multicast/"
cp -R "$here/harness" "$out/harness"
cd "$out/harness"
"$go" mod edit -replace "$module=$out/yggdrasil-go"
"$go" build -o "$out/harness-bin" .
cd "$out/yggdrasil-go"
"$go" build -o "$out/yggdrasil" ./cmd/yggdrasil
"$go" build -o "$out/yggdrasilctl" ./cmd/yggdrasilctl
