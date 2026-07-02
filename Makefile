# AuditeDB — local Rust workflows + cross-compile
#
# dev    : edit-iterate-restart loop (cargo run)
# test   : Rust core/bin/ffi tests + Python FFI smoke
# build  : release server binary + FFI library
# cross  : cross-compile to multiple Linux/Mac targets via cargo-zigbuild
#
# 显式 > 隐式. No auto-cargo-build, no implicit fallbacks. If a step
# is missing, the next step refuses with a clear error, not magic.
#
# CI is the canonical source of release artifacts. Local cross-compile
# (`make cross`) is a convenience for testing one target at a time.

.PHONY: dev test build cross install clean help info

PY        ?= python
CARGO     ?= cargo
HOST_OS    = $(shell uname -s 2>/dev/null || echo Windows)
BIN_NAME   = auditedb$(if $(filter Windows%,$(HOST_OS)),.exe,)
RUST_TGT   = bin/target/release/$(BIN_NAME)

# Cross-compile target list. zigbuild handles all of these without Docker.
# This is a local convenience surface, not the current release artifact matrix.
# FFI release assets intentionally omit macOS x64.
# Windows ARM64 needs MSVC ARM64 cross tools; CI handles that one.
CROSS_TARGETS = \
    x86_64-unknown-linux-gnu \
    aarch64-unknown-linux-gnu \
    x86_64-unknown-linux-musl \
    aarch64-unknown-linux-musl \
    x86_64-apple-darwin \
    aarch64-apple-darwin

help:
	@echo "  make dev                 run rust core in foreground (cargo run)"
	@echo "  make test                run core, bin, and ffi tests"
	@echo "  make build               release server binary + FFI library"
	@echo "  make cross               cross-compile to all supported targets via zigbuild"
	@echo "  make cross-TARGET        cross-compile one target, e.g."
	@echo "                             make cross-aarch64-unknown-linux-gnu"
	@echo "  make install             pip install -e ./sdk (editable)"
	@echo "  make clean               cargo clean + rm Python build artifacts"
	@echo "  make info                show host info + which targets are installed"

info:
	@echo "  host:    $(HOST_OS)"
	@echo "  cargo:   $$(cargo --version)"
	@echo "  rustc:   $$(rustc --version)"
	@echo "  targets installed:"
	@rustup target list --installed | sed 's/^/    /'
	@echo "  zig (for zigbuild): $$($(PY) -c 'import ziglang, os; print(os.path.dirname(ziglang.__file__))' 2>/dev/null || echo 'NOT INSTALLED — run: pip install ziglang cargo-zigbuild')"

# ── workflow 1: dev ────────────────────────────────────────────────
dev:
	cd bin && $(CARGO) run

# ── workflow 2: test ───────────────────────────────────────────────
test:
	cd core && $(CARGO) test --locked
	cd bin && $(CARGO) test --locked
	cd ffi && $(CARGO) test --locked
	cd ffi && $(CARGO) build --release
	mkdir -p sdk/src/l5/_ffi
	cp ffi/target/release/libl5_ffi.* sdk/src/l5/_ffi/ 2>/dev/null || cp ffi/target/release/l5_ffi.dll sdk/src/l5/_ffi/
	PYTHONPATH=sdk/src $(PY) tools/l5_python_smoke.py

# ── workflow 3: build (HOST only) ──────────────────────────────────
build: $(RUST_TGT)
	cd ffi && $(CARGO) build --release

# ── workflow 4: cross-compile via cargo-zigbuild (no Docker) ──────
# Per-target invocation lets you build just one without rebuilding all.
cross: $(addprefix cross-,$(CROSS_TARGETS))
	@echo
	@echo "  ✓ all $$(echo $(CROSS_TARGETS) | wc -w) cross targets built"
	@echo "  binaries at bin/target/<TARGET>/release/auditedb[.exe]"

cross-%:
	@echo
	@echo "═══ $* ═══"
	@which zig >/dev/null 2>&1 || { \
	    ZIG_DIR=$$($(PY) -c "import ziglang, os; print(os.path.dirname(ziglang.__file__))" 2>/dev/null); \
	    if [ -n "$$ZIG_DIR" ]; then export PATH="$$ZIG_DIR:$$PATH"; \
	    else echo "  ERROR: install zig — run: pip install ziglang cargo-zigbuild"; exit 1; fi; \
	}
	@cd bin && PATH="$$($(PY) -c 'import ziglang, os; print(os.path.dirname(ziglang.__file__))'):$$PATH" \
	    cargo zigbuild --release --target $*

# ── helpers ────────────────────────────────────────────────────────
$(RUST_TGT):
	cd bin && $(CARGO) build --release

install:
	$(PY) -m pip install -e ./sdk

clean:
	cd bin && $(CARGO) clean
	cd core && $(CARGO) clean
	cd ffi && $(CARGO) clean
	rm -rf sdk/dist sdk/build sdk/src/*.egg-info
	rm -f sdk/src/l5/_ffi/*.dll sdk/src/l5/_ffi/*.so sdk/src/l5/_ffi/*.dylib

# ── notes ──────────────────────────────────────────────────────────
# - Why zigbuild, not cross? cross needs Docker; zig ships a 60 MB
#   binary that compiles for ~all the targets we care about, no
#   container runtime. Tradeoff: a tiny chance zig's libc emulation
#   diverges from glibc/musl. For our deps (axum + rusqlite +
#   reqwest + hmac), zig has been shipping clean builds for years.
# - For Windows ARM64 + macOS targets: GitHub Actions runners are
#   native. CI is the canonical source. Local cross via zigbuild
#   handles the Linux + Mac cases just for development convenience.
