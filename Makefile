.PHONY: all build test clean setup

all: build

setup:
	mkdir -p plugins reports payloads

build:
	cargo build --release

test:
	cargo test

clean:
	cargo clean
	rm -rf reports/*

# Helper per compilare il plugin di esempio in wasm32-unknown-unknown
build-plugin:
	cd plugin_dev && cargo build --target wasm32-wasi --release
	cp plugin_dev/target/wasm32-wasi/release/example_waf_plugin.wasm plugins/