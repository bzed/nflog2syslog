.PHONY: all build test check vendor deb clean integration-test

all: build

build:
	cargo build --release

test:
	cargo test

check: test
	cargo clippy --all-targets -- -D warnings
	cargo fmt --check

# Vendor all dependencies for offline builds (Debian/sbuild).
# Creates vendor/ and .cargo/config.toml; cargo then uses the vendored copy.
# cargo vendor leaves checksum entries for files it excludes (Cargo.toml.orig
# and friends); without removing them, offline builds fail checksum
# verification of the vendored crates.
vendor:
	mkdir -p .cargo
	cargo vendor --locked vendor > .cargo/config.toml
	find vendor -name .cargo-checksum.json -exec sh -c \
	  'jq "del(.files[\"Cargo.toml.orig\"], .files[\".cargo_vcs_info.json\"])" "$$1" > "$$1.tmp" && mv "$$1.tmp" "$$1"' _ {} \;

deb: vendor
	dpkg-buildpackage -us -uc -b

# Root-only end-to-end test in a throwaway network namespace
integration-test:
	sudo scripts/root-integration-test.sh

clean:
	cargo clean
	rm -rf vendor .cargo
