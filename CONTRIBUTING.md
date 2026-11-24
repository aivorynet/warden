# Contributing

Thank you for helping. Warden is MIT licensed. By sending a change you agree to license it under the MIT licence.

## Set up

You need Rust 1.95 or newer (`rust-toolchain.toml` pins it). The extension needs Node 22.

```sh
git clone https://github.com/aivorynet/warden
cd warden
cargo build --workspace
```

## Layout

See the table in [AGENTS.md](AGENTS.md). The spec is [docs/PLAN.md](docs/PLAN.md). The types and traits in `warden-core` are frozen. Open an issue before you propose a change there.

## Checks

Run these before you open a pull request:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

For the extension: `cd extension && npm ci && npm test`.

## Rules

- Fix every warning. The workspace denies `unsafe_code`. Only the per-OS IPC module may use it.
- Write rustdoc on every public item.
- A secret must never reach a log, an error message, an MCP result or a test fixture. Use the `aivw_test_` style fake values in tests.
- Add a test for each fix.
- Keep a pull request to one topic.

## Releases

A maintainer pushes a tag `v<version>`. The pipelines in `.github/workflows/release.yml` and `.gitlab-ci.yml` build the archives, the desktop bundles and the extension zip. `packaging/render-packages.sh` fills the Homebrew, winget and Scoop manifests.

## Security problems

Do not use a public issue. See [SECURITY.md](SECURITY.md).
