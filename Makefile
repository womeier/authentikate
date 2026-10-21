all: component

rocq: Makefile.rocq
	@mkdir -p build
	@+$(MAKE) -f Makefile.rocq $(if $(wildcard build/Authentikate.extraction.authentikate_api.wasm),,-W components/service/theories/extraction.v) all

component: rocq
	node components/service/build.mjs

test: component
	node tests/ffi-adapters.mjs
	node tests/component.mjs

crypto-components:
	mkdir -p build
	cargo build --locked --release --target wasm32-unknown-unknown --manifest-path components/crypto/argon2/Cargo.toml
	cargo build --locked --release --target wasm32-unknown-unknown --manifest-path components/crypto/ed25519/Cargo.toml
	wasm-tools component new components/crypto/argon2/target/wasm32-unknown-unknown/release/authentikate_argon2.wasm -o build/argon2.component.wasm
	wasm-tools component new components/crypto/ed25519/target/wasm32-unknown-unknown/release/authentikate_ed25519.wasm -o build/ed25519.component.wasm

email-stdout-component:
	mkdir -p build
	cargo build --locked --release --target wasm32-unknown-unknown --manifest-path components/email/Cargo.toml
	wasm-tools component new components/email/target/wasm32-unknown-unknown/release/authentikate_email.wasm -o build/email-stdout.component.wasm
	wasm-tools validate build/email-stdout.component.wasm

email-components: email-stdout-component
	cargo build --locked --release --target wasm32-unknown-unknown --manifest-path components/email/Cargo.toml --no-default-features --features lettermint
	wasm-tools component new components/email/target/wasm32-unknown-unknown/release/authentikate_email.wasm -o build/email-lettermint.component.wasm
	wasm-tools validate build/email-lettermint.component.wasm

# Component-level composition; wasm-merge remains internal to the Rocq build.
host-component: component crypto-components email-stdout-component
	$(MAKE) compose-host

# Also usable with existing build/*.component.wasm, without rebuilding Rocq.
compose-host:
	wac compose host/composition.wac \
		-d authentikate:service=build/authentikate.component.wasm \
		-d authentikate:argon2=build/argon2.component.wasm \
		-d authentikate:ed25519=build/ed25519.component.wasm \
		-d authentikate:email-stdout=build/email-stdout.component.wasm \
		-o build/host.component.wasm
	wasm-tools validate build/host.component.wasm

test-host: compose-host
	cargo test --locked

test-email-stdout: email-stdout-component
	cargo test --locked --manifest-path components/email/Cargo.toml
	node --test-name-pattern=stdout tests/email.mjs --stdout

test-email: email-components
	cargo test --locked --manifest-path components/email/Cargo.toml
	cargo test --locked --manifest-path components/email/Cargo.toml --no-default-features --features lettermint
	node tests/email.mjs

clean: Makefile.rocq
	@+$(MAKE) -f Makefile.rocq cleanall
	@rm -f Makefile.rocq Makefile.rocq.conf build/*.wasm

Makefile.rocq: _RocqProject
	$(COQBIN)rocq makefile -f _RocqProject -o Makefile.rocq

force _RocqProject Makefile: ;

%: Makefile.rocq force
	@mkdir -p build
	@+$(MAKE) -f Makefile.rocq $@

.PHONY: all rocq component test crypto-components email-stdout-component email-components host-component compose-host test-host test-email-stdout test-email clean force
