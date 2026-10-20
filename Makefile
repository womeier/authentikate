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

email-stdout-component:
	mkdir -p build
	cargo build --locked --release --target wasm32-unknown-unknown --manifest-path email/Cargo.toml
	wasm-tools component new email/target/wasm32-unknown-unknown/release/authentikate_email.wasm -o build/email-stdout.component.wasm
	wasm-tools validate build/email-stdout.component.wasm

email-components: email-stdout-component
	cargo build --locked --release --target wasm32-unknown-unknown --manifest-path email/Cargo.toml --no-default-features --features lettermint
	wasm-tools component new email/target/wasm32-unknown-unknown/release/authentikate_email.wasm -o build/email-lettermint.component.wasm
	wasm-tools validate build/email-lettermint.component.wasm

test-email-stdout: email-stdout-component
	cargo test --locked --manifest-path email/Cargo.toml
	node --test-name-pattern=stdout test/email.mjs --stdout

test-email: email-components
	cargo test --locked --manifest-path email/Cargo.toml
	cargo test --locked --manifest-path email/Cargo.toml --no-default-features --features lettermint
	node test/email.mjs

clean: Makefile.rocq
	@+$(MAKE) -f Makefile.rocq cleanall
	@rm -f Makefile.rocq Makefile.rocq.conf *.wasm

Makefile.rocq: _RocqProject
	$(COQBIN)rocq makefile -f _RocqProject -o Makefile.rocq

force _RocqProject Makefile: ;

%: Makefile.rocq force
	@+$(MAKE) -f Makefile.rocq $@

.PHONY: all rocq component test crypto-components email-stdout-component email-components test-email-stdout test-email clean force
