all: component

rocq: Makefile.rocq
	@+$(MAKE) -f Makefile.rocq all

component: rocq
	node tools/build-component.mjs

test: component
	node test/ffi-adapters.mjs
	node test/component.mjs

crypto-components:
	mkdir -p build
	cargo build --locked --release --target wasm32-unknown-unknown --manifest-path crypto/argon2/Cargo.toml
	cargo build --locked --release --target wasm32-unknown-unknown --manifest-path crypto/ed25519/Cargo.toml
	wasm-tools component new crypto/argon2/target/wasm32-unknown-unknown/release/authentikate_argon2.wasm -o build/argon2.component.wasm
	wasm-tools component new crypto/ed25519/target/wasm32-unknown-unknown/release/authentikate_ed25519.wasm -o build/ed25519.component.wasm

clean: Makefile.rocq
	@+$(MAKE) -f Makefile.rocq cleanall
	@rm -f Makefile.rocq Makefile.rocq.conf *.wasm

Makefile.rocq: _RocqProject
	$(COQBIN)rocq makefile -f _RocqProject -o Makefile.rocq

force _RocqProject Makefile: ;

%: Makefile.rocq force
	@+$(MAKE) -f Makefile.rocq $@

.PHONY: all rocq component test crypto-components clean force
