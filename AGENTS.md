# Rules for coding agents

Read this file before you change anything in this repo.

## Start here

1. Read `docs/PLAN.md`. It is the spec. Do not change it.
2. If `nextsession.txt` exists, read it and do the next open step. Keep the scope to that step.

## Layout

| Crate | Responsibility |
|---|---|
| `warden-core` | Item model, policy, token naming, secret types, errors, traits, wire types |
| `warden-vault` | Crypto, op log, merge, keychain cache, audit |
| `warden-providers` | Provider implementations |
| `warden-sinks` | Sink implementations, atomic writes |
| `warden-engine` | Rotation state machine, journal, scheduler |
| `warden-ipc` | Unix socket / named pipe, peer checks, pairing |
| `warden-mcp` | stdio MCP server |
| `warden-coffee` | Honor-system paid year, weekly cadence |
| `warden-verify` | OS user check for quick unlock: trait, fake, Windows Hello, Touch ID, polkit |
| `aivory-warden` | Binary `aivory-warden` and alias `awd` |

`warden-core` types and traits are frozen. Change them only with the owner approval.

## Gates

Every change passes these gates before you report it as done.

| Part | Commands |
|---|---|
| One crate | `cargo fmt -p <crate> -- --check`, `cargo clippy -p <crate> --all-targets -- -D warnings`, `cargo test -p <crate>` |
| Workspace | `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` |
| Licenses | `cargo deny check` (when `cargo-deny` is installed) |

- Fix every warning.
- The workspace lints deny `unsafe_code`. Only these Windows FFI modules may allow it, each with SAFETY comments: `warden-ipc/src/os/windows.rs` (pipe DACL, SID check), `warden-sinks/src/broadcast.rs` (WM_SETTINGCHANGE), `warden-sinks/src/winacl.rs` (DACL copy), `warden-verify/src/windows_hello.rs` (UserConsentVerifier interop), `warden-verify/src/macos.rs` (LocalAuthentication, compiled only, not run). Add no other.
- Write rustdoc on every public item.

## Secrets

- Never log or print a secret value. Use `SecretValue`.
- Do not add a request that returns a secret value to the IPC protocol.
- Use synthetic fixtures in tests. Never use a real token.

## Licenses

- Allowed dependency licenses: MIT, Apache-2.0, BSD, ISC, Zlib, Unicode. `deny.toml` enforces this.

## Git

- Commit or push only when the user asks.
- Create a branch first. Do not commit to `main`.

## Reports

- Write reports to the user in ASD-STE100 (Simplified Technical English).
- Give a short answer. Do not add background.
- After a step, update `nextsession.txt`.
