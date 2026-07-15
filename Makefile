.PHONY: run build release check clean watch fmt lint

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
