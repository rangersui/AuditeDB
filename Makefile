# AuditeDB -- local Rust workflows
#
# dev    : edit-iterate-restart loop (cargo run)
# test   : Rust core/bin/ffi tests + Python FFI smoke
# build  : release server binary + FFI library
#
# Explicit > implicit. No auto-cargo-build, no implicit fallbacks. If a step
# is missing, the next step refuses with a clear error, not magic.
#
# CI is the canonical source of release artifacts.

.PHONY: dev test build install clean help info

PY        ?= python
CARGO     ?= cargo
HOST_OS    = $(shell uname -s 2>/dev/null || echo Windows)
BIN_NAME   = auditedb$(if $(filter Windows%,$(HOST_OS)),.exe,)
RUST_TGT   = bin/target/release/$(BIN_NAME)

help:
	@echo "  make dev                 run rust core in foreground (cargo run)"
	@echo "  make test                run core, bin, and ffi tests"
	@echo "  make build               release server binary + FFI library"
	@echo "  make install             pip install -e ./sdk (editable)"
	@echo "  make clean               cargo clean + rm Python build artifacts"
	@echo "  make info                show host info + which targets are installed"

info:
	@echo "  host:    $(HOST_OS)"
	@echo "  cargo:   $$(cargo --version)"
	@echo "  rustc:   $$(rustc --version)"
	@echo "  targets installed:"
	@rustup target list --installed | sed 's/^/    /'

# -- workflow 1: dev ------------------------------------------------
dev:
	cd bin && $(CARGO) run

# -- workflow 2: test -----------------------------------------------
test:
	cd core && $(CARGO) test --locked
	cd bin && $(CARGO) test --locked
	cd ffi && $(CARGO) test --locked
	cd ffi && $(CARGO) build --release
	mkdir -p sdk/src/l5/_ffi
	cp ffi/target/release/libl5_ffi.* sdk/src/l5/_ffi/ 2>/dev/null || cp ffi/target/release/l5_ffi.dll sdk/src/l5/_ffi/
	PYTHONPATH=sdk/src $(PY) tools/l5_python_smoke.py

# -- workflow 3: build (HOST only) ----------------------------------
build: $(RUST_TGT)
	cd ffi && $(CARGO) build --release

# -- helpers --------------------------------------------------------
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
