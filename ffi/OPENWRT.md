# OpenWrt and MIPS FFI Targets

The hosted FFI artifact matrix builds the targets GitHub can actually run and
smoke today:

- Linux x64: `libelastik_ffi.so`
- Linux ARM64: `libelastik_ffi.so`
- macOS x64: `libelastik_ffi.dylib`
- macOS ARM64: `libelastik_ffi.dylib`
- Windows x64: `elastik_ffi.dll`

OpenWrt/MIPS is a cross-toolchain target, not another hosted runner row. The
stable Rust toolchain recognises MIPS target triples such as
`mipsel-unknown-linux-musl`, but `rustup target add
mipsel-unknown-linux-musl` currently has no prebuilt standard library artifact.
That means CI cannot honestly promise an OpenWrt MIPS `.so` by adding a single
matrix entry.

## Required Proof Before Shipping

An OpenWrt/MIPS FFI artifact needs its own stack layer with these proofs:

1. Select the exact OpenWrt target triple and libc ABI for the device family.
2. Build Rust standard library support for that target, or use a toolchain that
   provides it.
3. Provide the matching OpenWrt SDK C compiler and linker for bundled SQLite.
4. Build `elastik-ffi` as a `cdylib` for that target.
5. Generate host-side UniFFI language bindings from the resulting library.
6. Smoke the library under QEMU or on real hardware before attaching it to a
   release.

Until those proofs exist, OpenWrt/MIPS should be documented as an explicit
cross-toolchain target. It should not be presented as a guaranteed release
artifact.
