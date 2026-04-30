# elastik — three commands, three workflows + cross-compile
#
# dev    : edit-iterate-restart loop (cargo run + python in two terminals)
# test   : build + bundle + smoke (verifies the whole chain)
# build  : produce shippable artifacts (release binary + wheel for HOST)
# cross  : cross-compile to multiple Linux/Mac targets via cargo-zigbuild
# wheels : retag wheels per-platform (mostly for CI; locally use 'cross')
#
# 显式 > 隐式. No auto-cargo-build, no implicit fallbacks. If a step
# is missing, the next step refuses with a clear error, not magic.
#
# CI is the canonical source of release wheels — see
# .github/workflows/build.yml. Local cross-compile (`make cross`) is a
# convenience for testing one target at a time.

.PHONY: dev test build wheel cross install clean help info

PY        ?= python
CARGO     ?= cargo
HOST_OS    = $(shell uname -s 2>/dev/null || echo Windows)
BIN_NAME   = elastik-core$(if $(filter Windows%,$(HOST_OS)),.exe,)
RUST_TGT   = core/target/release/$(BIN_NAME)
SDK_BIN    = sdk/src/elastik/_bin/$(BIN_NAME)

# Cross-compile target list. zigbuild handles all of these without Docker.
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
	@echo "  make test                build release + bundle + python smoke"
	@echo "  make build               release binary + wheel (HOST platform)"
	@echo "  make cross               cross-compile to all supported targets via zigbuild"
	@echo "  make cross-TARGET        cross-compile one target, e.g."
	@echo "                             make cross-aarch64-unknown-linux-gnu"
	@echo "  make wheels              retag per-platform wheels for ALL existing binaries"
	@echo "  make install             pip install -e ./sdk (editable)"
	@echo "  make clean               cargo clean + rm wheels + rm bundled binaries"
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
	cd core && $(CARGO) run

# ── workflow 2: test (HOST only) ───────────────────────────────────
test: $(SDK_BIN)
	$(PY) sdk/tests/e2e_blackbox.py --no-build

# ── workflow 3: build (HOST only) ──────────────────────────────────
build: $(SDK_BIN) wheel

wheel:
	cd sdk && $(PY) -m pip install --quiet build && $(PY) -m build --wheel

# ── workflow 4: cross-compile via cargo-zigbuild (no Docker) ──────
# Per-target invocation lets you build just one without rebuilding all.
cross: $(addprefix cross-,$(CROSS_TARGETS))
	@echo
	@echo "  ✓ all $$(echo $(CROSS_TARGETS) | wc -w) cross targets built"
	@echo "  binaries at core/target/<TARGET>/release/elastik-core[.exe]"

cross-%:
	@echo
	@echo "═══ $* ═══"
	@which zig >/dev/null 2>&1 || { \
	    ZIG_DIR=$$($(PY) -c "import ziglang, os; print(os.path.dirname(ziglang.__file__))" 2>/dev/null); \
	    if [ -n "$$ZIG_DIR" ]; then export PATH="$$ZIG_DIR:$$PATH"; \
	    else echo "  ERROR: install zig — run: pip install ziglang cargo-zigbuild"; exit 1; fi; \
	}
	@cd core && PATH="$$($(PY) -c 'import ziglang, os; print(os.path.dirname(ziglang.__file__))'):$$PATH" \
	    cargo zigbuild --release --target $*

# ── workflow 5: re-tag wheels for each cross-built binary ─────────
# Produces N wheels, one per platform, in sdk/dist/.
wheels: $(addprefix wheel-,$(CROSS_TARGETS))

# Map target triple → wheel platform tag (PEP 600 / 425 / 656)
PLAT_x86_64-unknown-linux-gnu    = manylinux_2_17_x86_64.manylinux2014_x86_64
PLAT_aarch64-unknown-linux-gnu   = manylinux_2_17_aarch64.manylinux2014_aarch64
PLAT_x86_64-unknown-linux-musl   = musllinux_1_2_x86_64
PLAT_aarch64-unknown-linux-musl  = musllinux_1_2_aarch64
PLAT_x86_64-apple-darwin         = macosx_10_12_x86_64
PLAT_aarch64-apple-darwin        = macosx_11_0_arm64
PLAT_x86_64-pc-windows-msvc      = win_amd64
PLAT_aarch64-pc-windows-msvc     = win_arm64

wheel-%:
	@target_bin="core/target/$*/release/elastik-core"; \
	[ "$*" = "x86_64-pc-windows-msvc" ] || [ "$*" = "aarch64-pc-windows-msvc" ] && target_bin="$$target_bin.exe"; \
	if [ ! -f "$$target_bin" ]; then \
	    echo "  ERROR: $$target_bin not built — run 'make cross-$*' first"; exit 1; \
	fi; \
	echo "═══ wheel for $* ═══"; \
	mkdir -p sdk/src/elastik/_bin; \
	cp "$$target_bin" sdk/src/elastik/_bin/; \
	cd sdk && $(PY) -m build --wheel --quiet; \
	$(PY) -m wheel tags --remove --platform-tag $(PLAT_$*) --abi-tag none --python-tag py3 dist/*-py3-none-any.whl; \
	echo "  ✓ sdk/dist/*-$(PLAT_$*).whl"

# ── helpers ────────────────────────────────────────────────────────
$(SDK_BIN): $(RUST_TGT)
	@mkdir -p sdk/src/elastik/_bin
	cp $(RUST_TGT) $(SDK_BIN)
	@echo "  bundled: $(SDK_BIN)"

$(RUST_TGT):
	cd core && $(CARGO) build --release

install:
	$(PY) -m pip install -e ./sdk

clean:
	cd core && $(CARGO) clean
	rm -f sdk/src/elastik/_bin/elastik-core*
	rm -rf sdk/dist sdk/build sdk/src/elastik.egg-info

# ── notes ──────────────────────────────────────────────────────────
# - cibuildwheel-equivalent for Rust+Python: maturin. We skip maturin
#   because we ship a STANDALONE BINARY (subprocess), not a PyO3 ext
#   module. cargo zigbuild + setup.py shim is enough.
# - Why zigbuild, not cross? cross needs Docker; zig ships a 60 MB
#   binary that compiles for ~all the targets we care about, no
#   container runtime. Tradeoff: a tiny chance zig's libc emulation
#   diverges from glibc/musl. For our deps (axum + rusqlite +
#   reqwest + hmac), zig has been shipping clean builds for years.
# - For Windows ARM64 + macOS targets: GitHub Actions runners are
#   native. CI is the canonical source. Local cross via zigbuild
#   handles the Linux + Mac cases just for development convenience.
