.PHONY: run build release check clean watch fmt lint test

run:
	cargo run --example proxy

build:
	cargo build

release:
	cargo build --release

check:
	cargo check

clean:
	cargo clean

watch:
	cargo watch -x "run --example proxy"

test:
	cargo test
