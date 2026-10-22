all: component

crypto-components:
	mkdir -p build
	cargo build --locked --release --target wasm32-unknown-unknown -p authentikate-argon2 -p authentikate-ed25519
	wasm-tools component new target/wasm32-unknown-unknown/release/authentikate_argon2.wasm -o build/argon2.component.wasm
	wasm-tools component new target/wasm32-unknown-unknown/release/authentikate_ed25519.wasm -o build/ed25519.component.wasm

email-stdout-component:
	mkdir -p build
	cargo build --locked --release --target wasm32-unknown-unknown -p authentikate-email
	wasm-tools component new target/wasm32-unknown-unknown/release/authentikate_email.wasm -o build/email-stdout.component.wasm
	wasm-tools validate build/email-stdout.component.wasm

email-components: email-stdout-component
	cargo build --locked --release --target wasm32-unknown-unknown -p authentikate-email --no-default-features --features lettermint
	wasm-tools component new target/wasm32-unknown-unknown/release/authentikate_email.wasm -o build/email-lettermint.component.wasm
	wasm-tools validate build/email-lettermint.component.wasm

gateway-component:
	mkdir -p build
	cargo build --locked --release --target wasm32-unknown-unknown -p authentikate-gateway
	wasm-tools component new target/wasm32-unknown-unknown/release/authentikate_gateway.wasm -o build/gateway.component.wasm
	wasm-tools validate build/gateway.component.wasm

# The gateway vendors the pinned WASI copies plus the service, crypto, email
# and keyvalue interfaces so `wit_bindgen::generate!` can see them; that macro
# needs a literal path, so it cannot stage them the way host/build.rs does.
# Fail loudly if a vendored copy has drifted from its authoritative source.
check-wit:
	diff -u components/service/wit/service.wit components/gateway/wit/deps/service/service.wit
	diff -u components/crypto/wit/argon2.wit components/gateway/wit/deps/crypto/argon2.wit
	diff -u components/crypto/wit/ed25519.wit components/gateway/wit/deps/crypto/ed25519.wit
	diff -u components/email/wit/email.wit components/gateway/wit/deps/email/email.wit
	diff -ru components/service/wit/deps/keyvalue components/gateway/wit/deps/keyvalue
	diff -u components/service/wit/deps/clocks/wall-clock.wit 'components/gateway/wit/deps/clocks@0.2.0/wall-clock.wit'

# Component-level composition; wasm-merge remains internal to the Rocq build.
host-component: check-wit component crypto-components email-stdout-component gateway-component
	$(MAKE) compose-host

# Also usable with existing build/*.component.wasm, without rebuilding Rocq.
compose-host:
	wac compose host/composition.wac \
		-d authentikate:service=build/authentikate.component.wasm \
		-d authentikate:argon2=build/argon2.component.wasm \
		-d authentikate:ed25519=build/ed25519.component.wasm \
		-d authentikate:email-stdout=build/email-stdout.component.wasm \
		-d authentikate:gateway=build/gateway.component.wasm \
		-o build/host.component.wasm
	wasm-tools validate build/host.component.wasm

test-host: compose-host
	cargo test --locked

test-email-stdout: email-stdout-component
	cargo test --locked -p authentikate-email
	node --test-name-pattern=stdout tests/email.mjs --stdout

test-email: email-components
	cargo test --locked -p authentikate-email
	cargo test --locked -p authentikate-email --no-default-features --features lettermint
	node tests/email.mjs

rocq component test clean:
	$(MAKE) -C components/service $@

.PHONY: all rocq component test clean crypto-components email-stdout-component email-components gateway-component check-wit host-component compose-host test-host test-email-stdout test-email
