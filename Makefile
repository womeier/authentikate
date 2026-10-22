all: component

crypto-components:
	mkdir -p build
	cargo build --locked --release --target wasm32-unknown-unknown -p authentikate-argon2 -p authentikate-hmac
	wasm-tools component new target/wasm32-unknown-unknown/release/authentikate_argon2.wasm -o build/argon2.component.wasm
	wasm-tools component new target/wasm32-unknown-unknown/release/authentikate_hmac.wasm -o build/hmac.component.wasm

email-stdout-component:
	mkdir -p build
	cargo build --locked --release --target wasm32-unknown-unknown -p authentikate-email
	wasm-tools component new target/wasm32-unknown-unknown/release/authentikate_email.wasm -o build/email-stdout.component.wasm
	wasm-tools validate build/email-stdout.component.wasm

email-components: email-stdout-component
	cargo build --locked --release --target wasm32-unknown-unknown -p authentikate-email --no-default-features --features lettermint
	wasm-tools component new target/wasm32-unknown-unknown/release/authentikate_email.wasm -o build/email-lettermint.component.wasm
	wasm-tools validate build/email-lettermint.component.wasm

gateway-component: check-wit
	mkdir -p build
	cargo build --locked --release --target wasm32-unknown-unknown -p authentikate-gateway
	wasm-tools component new target/wasm32-unknown-unknown/release/authentikate_gateway.wasm -o build/gateway.component.wasm
	wasm-tools validate build/gateway.component.wasm

storage-component:
	mkdir -p build
	cargo build --locked --release --target wasm32-unknown-unknown -p authentikate-storage
	wasm-tools component new target/wasm32-unknown-unknown/release/authentikate_storage.wasm -o build/storage.component.wasm
	wasm-tools validate build/storage.component.wasm

# The gateway vendors the pinned WASI copies plus `authentikate:config` and the
# service's `api` interface, because `wit_bindgen::generate!` needs a literal
# path and cannot stage sources the way host/build.rs does.  Only two of those
# have an authoritative source elsewhere in the tree; fail loudly if a copy has
# drifted.  The list used to be six: splitting `world service` out of api.wit
# removed the keyvalue, email, wall-clock and wasi:random packages, which were
# present only because a world the gateway never instantiates named them.
check-wit:
	diff -u wit/config.wit components/gateway/wit/deps/config/config.wit
	diff -u components/service/wit/api.wit components/gateway/wit/deps/service/api.wit

# Component-level composition; wasm-merge remains internal to the Rocq build.
host-component: component crypto-components email-stdout-component
	$(MAKE) compose-host

# Also usable with existing build/*.component.wasm, without rebuilding Rocq --
# which is the expensive part, so the gateway is a prerequisite rather than
# something the caller has to remember.  CI composes a downloaded Rocq
# component with freshly built providers, and would otherwise need the list
# kept in step with this file.
compose-host: gateway-component storage-component
	wac compose host/composition.wac \
		-d authentikate:service=build/authentikate.component.wasm \
		-d authentikate:argon2=build/argon2.component.wasm \
		-d authentikate:hmac=build/hmac.component.wasm \
		-d authentikate:email-stdout=build/email-stdout.component.wasm \
		-d authentikate:gateway=build/gateway.component.wasm \
		-d authentikate:storage=build/storage.component.wasm \
		-o build/host.component.wasm
	wasm-tools validate build/host.component.wasm

test-host: compose-host
	cargo test --locked -p authentikate-host -p authentikate-storage

test-email-stdout: email-stdout-component
	cargo test --locked -p authentikate-email
	node --test-name-pattern=stdout tests/email.mjs --stdout

test-email: email-components
	cargo test --locked -p authentikate-email
	cargo test --locked -p authentikate-email --no-default-features --features lettermint
	node tests/email.mjs

rocq component test clean:
	$(MAKE) -C components/service $@

.PHONY: all rocq component test clean crypto-components email-stdout-component email-components gateway-component storage-component check-wit host-component compose-host test-host test-email-stdout test-email
