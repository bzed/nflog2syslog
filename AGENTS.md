# AGENTS.md — nflog2syslog

Clean-room Rust rewrite of nflog-to-syslog: NFLOG over netlink → packet
dissection → JSON to stdout/remote syslog. Apache-2.0.

## Toolchain

- Rust >= 1.88 (time 0.3.55 MSRV; also the `rust-version` in `Cargo.toml`).
- Debian's packaged rustc is too old for CI builds; use rustup (curl | sh
  variant) there. Locally the distro toolchain is fine.

## Before you commit

All of these must pass — CI runs them on every push and PR:

```
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Test coverage

- Coverage must stay at **>= 85% of lines**, measured with
  `cargo llvm-cov --summary-only --ignore-filename-regex 'src/main\.rs'`.
  `src/main.rs` is thin binary wiring, exercised by the CI smoke and
  integration jobs instead; the GitHub Actions coverage job enforces the
  gate and fails the build below it.
- Every new module or function ships with tests. Pure logic gets unit tests
  in `src/` (`#[cfg(test)]`); parsing/formatting gets golden tests in
  `tests/` with byte-level fixtures. Tests must pass in every environment
  (unprivileged, root, containers that run as root without CAP_NET_ADMIN):
  assert the documented outcome per case instead of branching on the uid.
- Only code that is untestable without a live kernel (the netlink receive
  loop in `src/receiver.rs`, error paths that kill the process) may go
  uncovered; prefer factoring the testable part out over leaving it dark.
- Run locally: `cargo llvm-cov --summary-only --ignore-filename-regex 'src/main\.rs'`
  (needs `cargo llvm-cov install`).

## unsafe policy

`unsafe` is allowed only for unavoidable libc/netlink FFI. Every `unsafe`
block carries a short comment stating the invariant that makes it sound
(e.g. "kernel-checked attribute length", "CStr is NUL-terminated here").
No new `unsafe` for something the standard library already provides.

## Dependencies

- Keep the dependency tree minimal. Prefer std over a crate; drop crates
  that became unused.
- Licenses: Apache-2.0 / MIT / BSD only (the whole tree, transitive
  included). No GPL/LGPL/AGPL anywhere — this is a deliberate clean-room
  decision against the old tool's licensing.
- `Cargo.lock` is committed and built with `--locked` in packaging; update
  it in the same commit as `Cargo.toml` changes.
- The dissectors come from the packet-dissector crate, enabled via cargo
  features — do not hand-roll protocol parsers that it already provides.

## Code conventions

- Output is a single JSON object per packet (serde_json). Never `k=v` lines.
- Errors: user-facing messages on stderr, prefixed `Error:`, exit code 2 for
  bad configuration, 1 for runtime/socket failures. The process never
  panics on bad input — malformed packets are counted and reported.
- Bounded queues with `try_send` everywhere: a stalled sink must never block
  the netlink receive path.
- Keep the netlink wire code in `src/wire.rs` byte-identical to the kernel
  uapi definitions; changes there need a comment citing the header.
- Every source file starts with the Apache-2.0 copyright header:
  `Copyright 2026 Bernd Zeimetz <bernd@bzed.de>`.

## CI / packaging

- GitHub Actions (`.github/workflows/`) and GitLab CI (`.gitlab-ci.yml`) both
  exist on purpose — keep both working. Don't delete one because the other
  is green.
- Debian packaging (`debian/`) is built with plain debhelper + cargo
  (rustup toolchain, see `debian/rules`). Test local package changes with
  `dpkg-buildpackage -us -uc -b` before pushing. The package
  Conflicts/Replaces `nflog-to-syslog`.
- Vendored builds (`make vendor`) feed the package build; after touching
  `Cargo.toml`, re-run `make vendor` so `vendor/` stays consistent.
- Version bumps go into `debian/changelog` in the same commit.

## Releases

1. Update the version in `Cargo.toml` (the single source of the version).
   Run any cargo command afterwards so `Cargo.lock` picks it up, and commit
   it together.
2. Add a new entry at the top of `debian/changelog` with the new version
   (`nflog2syslog (<version>-1) ...`) summarizing the changes since the
   previous entry.
3. Tag `v<version>` and push the tag. The `release` workflow then builds
   the binary tarball and the `.deb` and publishes both as the GitHub
   release, with a `SHA256SUMS` file.
4. The release workflow verifies the tag matches both `Cargo.toml` and the
   top `debian/changelog` entry before building — a mismatched or
   half-bumped release cannot be published.
