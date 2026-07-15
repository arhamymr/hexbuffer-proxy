.PHONY: run build release check clean watch fmt lint test

run:
	cargo run

build:
	cargo build

release:
	cargo build --release

check:
	cargo check

clean:
	cargo clean

watch:
	cargo watch -x run

fmt:
	cargo fmt

lint:
	cargo clippy -- -D warnings

test:
	cargo test
