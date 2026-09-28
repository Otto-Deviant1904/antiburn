#!/usr/bin/env bash
set -euo pipefail

version=${1:?usage: package-remote-helper.sh VERSION TARGET OUTPUT_DIRECTORY}
target=${2:?missing target}
output=${3:?missing output directory}
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid helper archive version" >&2
  exit 1
fi
case "$target" in
  x86_64-unknown-linux-musl|aarch64-unknown-linux-musl) ;;
  *) echo "Unsupported helper target" >&2; exit 1 ;;
esac

binary="${CARGO_TARGET_DIR:-crates/antiburn-remote/target}/$target/release/antiburn-remote"
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct HEAD)}
if [[ ! "$epoch" =~ ^[0-9]+$ ]]; then
  echo "Invalid source timestamp" >&2
  exit 1
fi
test -x "$binary"
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
readelf --program-headers "$binary" > "$stage/program-headers"
readelf --dynamic "$binary" > "$stage/dynamic"
if grep -q 'INTERP' "$stage/program-headers" || grep -q '(NEEDED)' "$stage/dynamic"; then
  echo "The remote helper must not require a dynamic loader or shared libraries" >&2
  exit 1
fi

name="antiburn-remote-$version-$target"
mkdir -p "$stage/$name" "$output"
install -m 755 "$binary" "$stage/$name/antiburn-remote"
cp LICENSE NOTICE THIRD_PARTY_NOTICES docs/remote-sessions.md "$stage/$name/"
tar --create --gzip --sort=name \
  --mtime="@$epoch" \
  --owner=0 --group=0 --numeric-owner \
  --directory "$stage" --file "$output/$name.tar.gz" "$name"

mkdir "$stage/extracted"
tar -xzf "$output/$name.tar.gz" -C "$stage/extracted"
cmp "$binary" "$stage/extracted/$name/antiburn-remote"
test -x "$stage/extracted/$name/antiburn-remote"
"$stage/extracted/$name/antiburn-remote" --version
