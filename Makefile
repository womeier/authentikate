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
	cargo test --locked -p authentikate-email
	node --test-name-pattern=stdout tests/email.mjs --stdout

test-email: email-components
	cargo test --locked -p authentikate-email
	cargo test --locked -p authentikate-email --no-default-features --features lettermint
	node tests/email.mjs

rocq component test clean:
	$(MAKE) -C components/service $@

.PHONY: all rocq component test clean crypto-components email-stdout-component email-components host-component compose-host test-host test-email-stdout test-email
