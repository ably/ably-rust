.PHONY: all
all: build

.PHONY: build
build:
	cargo build --target wasm32-unknown-unknown

.PHONY: check
check:
	cargo check --target wasm32-unknown-unknown

.PHONY: wasm
wasm:
	wasm-pack build --target web

.PHONY: serve
serve: wasm
	python3 -m http.server 3000
