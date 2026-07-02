#!/usr/bin/env bash
set -euo pipefail

# Build the AuditeDB server against several OpenWrt SDK Docker images.
#
# Output:
#   target/openwrt-matrix/results.csv
#   target/openwrt-matrix/results.md
#   target/openwrt-matrix/<platform>/auditedb
#
# This script intentionally uses bundled SQLite. It tests the portable
# "one binary in /tmp" path; dynamic system-sqlite linking is a separate track.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/target/openwrt-matrix"
mkdir -p "$OUT"

# Pin by default so matrix sizes and linker behavior stay reproducible.
# Override with RUST_NIGHTLY=nightly-YYYY-MM-DD when refreshing the toolchain.
RUST_NIGHTLY="${RUST_NIGHTLY:-nightly-2026-05-22}"
OPENWRT_CARGO_FEATURES="${OPENWRT_CARGO_FEATURES:-bundled-sqlite,unstable-engine}"
HOST_UID="${HOST_UID:-$(id -u 2>/dev/null || printf '')}"
HOST_GID="${HOST_GID:-$(id -g 2>/dev/null || printf '')}"

# platform|docker image tag|rust target|OpenWrt toolchain prefix|extra rustflags
#
# MIPS rows use the OpenWrt MIPS32r2 soft-float ABI. The mediatek-filogic SDK
# is pinned to 23.05.5 because that target was not published in the 21.02 SDK
# image set used by the older router platforms.
MATRIX="${MATRIX:-\
ramips-mt76x8|openwrt/sdk:ramips-mt76x8-21.02.0|mipsel-unknown-linux-musl|mipsel-openwrt-linux-musl|-C target-cpu=mips32r2 -C target-feature=+soft-float
ramips-mt7621|openwrt/sdk:ramips-mt7621-21.02.0|mipsel-unknown-linux-musl|mipsel-openwrt-linux-musl|-C target-cpu=mips32r2 -C target-feature=+soft-float
ath79-generic|openwrt/sdk:ath79-generic-21.02.0|mips-unknown-linux-musl|mips-openwrt-linux-musl|-C target-cpu=mips32r2 -C target-feature=+soft-float
mediatek-filogic|openwrt/sdk:mediatek-filogic-23.05.5|aarch64-unknown-linux-musl|aarch64-openwrt-linux-musl|
bcm27xx-bcm2711|openwrt/sdk:bcm27xx-bcm2711-21.02.0|aarch64-unknown-linux-musl|aarch64-openwrt-linux-musl|
x86-64|openwrt/sdk:x86-64-21.02.0|x86_64-unknown-linux-musl|x86_64-openwrt-linux-musl|
}"

CSV="$OUT/results.csv"
MD="$OUT/results.md"
printf 'platform,image,rust_target,status,bytes,mib,sha256,artifact\n' >"$CSV"
{
  printf '| platform | image | rust target | status | size | sha256 |\n'
  printf '|---|---|---|---|---:|---|\n'
} >"$MD"

run_one() {
  local platform="$1"
  local image="$2"
  local rust_target="$3"
  local prefix="$4"
  local extra_flags="$5"
  local platform_out="$OUT/$platform"
  local cargo_target_dir="/src/target/openwrt-matrix/$platform/cargo-target"
  mkdir -p "$platform_out"

  echo "==> $platform ($image -> $rust_target)"

  local log="$platform_out/build.log"
  set +e
  docker run --rm --user root \
    -v "$ROOT:/src" \
    -v "auditedb-openwrt-cargo:/root/.cargo" \
    -v "auditedb-openwrt-rustup:/root/.rustup" \
    -e "HOME=/root" \
    -e "PLATFORM=$platform" \
    -e "RUST_TARGET=$rust_target" \
    -e "CROSS_PREFIX=$prefix" \
    -e "EXTRA_RUSTFLAGS=$extra_flags" \
    -e "RUST_NIGHTLY=$RUST_NIGHTLY" \
    -e "OPENWRT_CARGO_FEATURES=$OPENWRT_CARGO_FEATURES" \
    -e "CARGO_TARGET_DIR=$cargo_target_dir" \
    -e "HOST_UID=$HOST_UID" \
    -e "HOST_GID=$HOST_GID" \
    "$image" sh -s <<'EOF' >"$log" 2>&1
set -eux

cat >/etc/apt/sources.list <<'APT'
deb http://archive.debian.org/debian buster main
deb http://archive.debian.org/debian-security buster/updates main
APT
printf 'Acquire::Check-Valid-Until "false";\n' >/etc/apt/apt.conf.d/99archive
apt-get update >/dev/null
apt-get install -y curl ca-certificates pkg-config file >/dev/null

if [ ! -x "$HOME/.cargo/bin/cargo" ]; then
  curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain "$RUST_NIGHTLY"
fi
. "$HOME/.cargo/env"
rustup toolchain install "$RUST_NIGHTLY" --profile minimal
rustup component add rust-src --toolchain "$RUST_NIGHTLY"

cd /src/core
SDK_ROOT="/home/build/openwrt"
if [ ! -d "$SDK_ROOT/staging_dir" ] && [ -d "/builder/staging_dir" ]; then
  SDK_ROOT="/builder"
fi
TOOLCHAIN_DIR="$(find "$SDK_ROOT/staging_dir" -maxdepth 1 -type d -name 'toolchain-*musl' | head -n 1)"
GCC_LIB_DIR="$(dirname "$(find "$TOOLCHAIN_DIR/lib/gcc" -name 'crtbegin*.o' | head -n 1)")"
UNWIND_SHIM="/tmp/auditedb-libunwind-shim"
mkdir -p "$UNWIND_SHIM"
# OpenWrt SDKs provide libgcc_eh rather than libunwind. Rust's build-std path
# may still ask for -lunwind, so the shim keeps the link inside SDK artifacts.
ln -sf "$GCC_LIB_DIR/libgcc_eh.a" "$UNWIND_SHIM/libunwind.a"
export PATH="$TOOLCHAIN_DIR/bin:$PATH"
export STAGING_DIR="$SDK_ROOT/staging_dir"

target_env_upper="$(printf '%s' "$RUST_TARGET" | tr '[:lower:]-' '[:upper:]_')"
target_env_lower="$(printf '%s' "$RUST_TARGET" | tr '-' '_')"
export "CARGO_TARGET_${target_env_upper}_LINKER=${CROSS_PREFIX}-gcc"
export "CC_${target_env_lower}=${CROSS_PREFIX}-gcc"
export "AR_${target_env_lower}=${CROSS_PREFIX}-gcc-ar"

# OpenWrt musl targets are dynamic-libc systems. The explicit -crt-static off
# prevents ARM64/x86 static-pie attempts and is harmless on the MIPS rows.
export RUSTFLAGS="$EXTRA_RUSTFLAGS -C target-feature=-crt-static -L native=$UNWIND_SHIM -L native=$TOOLCHAIN_DIR/lib -L native=$GCC_LIB_DIR -C link-arg=-B$GCC_LIB_DIR"

cargo +"$RUST_NIGHTLY" build \
  --manifest-path /src/bin/Cargo.toml \
  -Z build-std=std,panic_abort \
  --profile rut241 \
  --target "$RUST_TARGET" \
  --no-default-features \
  --features "$OPENWRT_CARGO_FEATURES"

out="$CARGO_TARGET_DIR/$RUST_TARGET/rut241/auditedb"
ls -lh "$out"
file "$out" || true
if [ -n "${HOST_UID:-}" ] && [ -n "${HOST_GID:-}" ]; then
  chown -R "$HOST_UID:$HOST_GID" "$CARGO_TARGET_DIR"
fi
EOF
  local code=$?
  set -e

  local src="$platform_out/cargo-target/$rust_target/rut241/auditedb"
  local dst="$platform_out/auditedb"
  if [ "$code" -eq 0 ] && [ -f "$src" ]; then
    cp "$src" "$dst"
    local bytes
    bytes="$(wc -c <"$dst" | tr -d ' ')"
    local mib
    mib="$(awk -v b="$bytes" 'BEGIN { printf "%.2f", b / 1024 / 1024 }')"
    local sha256
    sha256="$(sha256sum "$dst" | awk '{print $1}')"
    local short_sha
    short_sha="$(printf '%s' "$sha256" | cut -c1-12)"
    printf '%s,%s,%s,ok,%s,%s,%s,%s\n' "$platform" "$image" "$rust_target" "$bytes" "$mib" "$sha256" "$dst" >>"$CSV"
    printf '| `%s` | `%s` | `%s` | ok | %s bytes / %s MiB | `%s` |\n' "$platform" "$image" "$rust_target" "$bytes" "$mib" "$short_sha" >>"$MD"
  else
    printf '%s,%s,%s,fail,0,0,,%s\n' "$platform" "$image" "$rust_target" "$log" >>"$CSV"
    printf '| `%s` | `%s` | `%s` | fail | see `%s` |  |\n' "$platform" "$image" "$rust_target" "$log" >>"$MD"
  fi
}

while IFS='|' read -r platform image rust_target prefix extra_flags; do
  [ -n "$platform" ] || continue
  run_one "$platform" "$image" "$rust_target" "$prefix" "$extra_flags"
done <<EOF
$MATRIX
EOF

echo "Wrote $CSV"
echo "Wrote $MD"
