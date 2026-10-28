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

email-smtp-component:
	mkdir -p build
	cargo build --locked --release --target-dir target/email-smtp --target wasm32-unknown-unknown -p authentikate-email --no-default-features --features smtp
	wasm-tools component new target/email-smtp/wasm32-unknown-unknown/release/authentikate_email.wasm -o build/email-smtp.component.wasm
	wasm-tools validate build/email-smtp.component.wasm

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

config-component:
	mkdir -p build
	cargo build --locked --release --target wasm32-unknown-unknown -p authentikate-config
	wasm-tools component new target/wasm32-unknown-unknown/release/authentikate_config.wasm -o build/config.component.wasm
	wasm-tools validate build/config.component.wasm

# The gateway vendors the pinned WASI copies plus `authentikate:config` and the
# service's `api` interface, because `wit_bindgen::generate!` needs a literal
# path. Only two of those
# have an authoritative source elsewhere in the tree; fail loudly if a copy has
# drifted.  The list used to be six: splitting `world service` out of api.wit
# removed the keyvalue, email, wall-clock and wasi:random packages, which were
# present only because a world the gateway never instantiates named them.
check-wit:
	diff -u wit/config.wit components/gateway/wit/deps/config/config.wit
	diff -u components/service/wit/api.wit components/gateway/wit/deps/service/api.wit

# Component-level composition; wasm-merge remains internal to the Rocq build.
app-component: component crypto-components email-stdout-component
	$(MAKE) compose-app

app-live-component: component crypto-components email-smtp-component
	$(MAKE) compose-live-app

# Also usable with existing build/*.component.wasm, without rebuilding Rocq --
# which is the expensive part, so the gateway is a prerequisite rather than
# something the caller has to remember.  CI composes a downloaded Rocq
# component with freshly built providers, and would otherwise need the list
# kept in step with this file.
compose-app: EMAIL_BACKEND = stdout
compose-app: APP_COMPONENT = build/app.component.wasm
compose-live-app: EMAIL_BACKEND = smtp
compose-live-app: APP_COMPONENT = build/app-live.component.wasm

compose-app compose-live-app: gateway-component storage-component config-component
	wac compose composition.wac \
		-d authentikate:service=build/authentikate.component.wasm \
		-d authentikate:argon2=build/argon2.component.wasm \
		-d authentikate:hmac=build/hmac.component.wasm \
		-d authentikate:email-stdout=build/email-$(EMAIL_BACKEND).component.wasm \
		-d authentikate:gateway=build/gateway.component.wasm \
		-d authentikate:storage=build/storage.component.wasm \
		-d authentikate:config=build/config.component.wasm \
		-o $(APP_COMPONENT)
	wasm-tools validate $(APP_COMPONENT)
	node tests/app-interface.mjs $(EMAIL_BACKEND)

test-app: compose-app
	node tests/http.mjs

test-email-stdout: email-stdout-component
	cargo test --locked -p authentikate-email
	node tests/email.mjs

test-email-smtp: email-smtp-component
	cargo test --locked -p authentikate-email --no-default-features --features smtp
	node tests/email-smtp.mjs

test-smtp-runtime: compose-live-app
	node tests/http-smtp.mjs

rocq component test clean:
	$(MAKE) -C components/service $@

.PHONY: all rocq component test clean crypto-components email-stdout-component email-smtp-component gateway-component storage-component config-component check-wit app-component app-live-component compose-app compose-live-app test-app test-email-stdout test-email-smtp test-smtp-runtime
