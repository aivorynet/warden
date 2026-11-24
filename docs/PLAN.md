# Aivory Warden — plan

## Context
Paul does not want to manage access tokens by hand. Aivory Warden is an open-source, cross-OS token manager. The user stores admin tokens (with end date) and the places that consume tokens (files, env vars, remote files over SSH). A background daemon then creates, rotates, revokes and updates all derived tokens on a schedule, and rotates the admin tokens too. Apps use tokens through an MCP endpoint without reading them. An Edge extension captures tokens from provider pages. A weekly coffee reminder runs until the user paid once in the current year.

Architecture reviewed by Fable (advisor). Repo started empty.

## User decisions (fixed)
- Name: **Aivory Warden**. Binary `aivory-warden`, CLI alias `awd`.
- Token prefix `aivw_` (Paul confirmed). Tokens that Warden creates at a provider get the name `aivw_<item-slug>_<yyyymmdd>` where the provider has a name field (see matrix). Warden-issued local client/pairing tokens use `aivw_<base62>_<crc32>` (secret-scanner detectable).
- CI: push to a new GitLab repo is allowed to run the 3-OS CI matrix.
- Coffee: **signed receipt** (ed25519, offline check), weekly until paid this year.
- UI: **native desktop app** (Tauri v2) + tray. No localhost web UI.
- **Background daemon** with scheduler. Per-token policy: on/off, interval, lead time before end date. **Global default interval 30 days** (setting).
- Aivory brand: dark base `#05010D` / navy `#0D1624`, cream `#FAF6EF`, IBM Plex Sans + JetBrains Mono, AIVory "AIV" logo. Warden gets its own product accent (chosen in the design step).

## Step 1 — Design (/design, first action after approval)
Create a Design artifact from type `https://claude.ai/artifact/QKN21svewxgyPb6SYRqWnd` (title "Aivory Warden"), no design system. Artboards:
1. Desktop: unlock screen (password + Secret Key, first-run Emergency Kit).
2. Desktop: token list (name, provider, status, next rotation, end date, sinks count).
3. Desktop: token detail (policy editor: interval / lead time / auto-rotate toggle, sinks, history/audit).
4. Desktop: add token wizard (provider → admin token + end date → sinks incl. SSH host).
5. Desktop: settings (default interval, keychain cache, devices/rotator, MCP clients + pairing, coffee status/receipt entry).
6. Tray menu + rotation/expiry notification + weekly coffee note.
7. Edge extension popup: "Save to Warden" capture + pending inbox.
8. CLI output samples (`awd status`, `awd rotate`).
The desktop frontend then implements these artboards.

## Architecture
**Workspace** (copy conventions from the AIVory Code repo: `Cargo.toml` resolver 3, edition 2024, calver, `unsafe_code` denied except the per-OS IPC module, gates fmt/clippy -D warnings/test/deny; `AGENTS.md`, `nextsession.txt`, `release-plz.toml`, `cliff.toml`, `deny.toml`, `.github/workflows/{ci,release}.yml`).

| Crate | Responsibility |
|---|---|
| `crates/warden-core` | Item model, policy, token naming, secret types (`secrecy`/`zeroize`), errors, wire types |
| `crates/warden-vault` | Crypto, op log, merge, keychain cache, audit |
| `crates/warden-providers` | `Provider` trait (class `Overlap` / `AtomicSwap`), providers |
| `crates/warden-sinks` | `Sink` trait, sinks, atomic writes |
| `crates/warden-engine` | Rotation state machine, intent journal, scheduler, rotator lease |
| `crates/warden-ipc` | Unix socket / named pipe, peer checks, pairing tokens, protocol (pattern from the AIVory Code daemon endpoint) |
| `crates/warden-mcp` | stdio MCP server (rmcp), proxies to daemon |
| `crates/warden-coffee` | Receipt verify (embedded ed25519 pubkey), weekly cadence |
| `crates/aivory-warden` (bin) | `daemon`, CLI verbs, `mcp`, `native-host`, `service install/uninstall` |
| `apps/desktop` | Tauri v2 app + tray; talks to daemon over `warden-ipc` client (Tauri commands), never HTTP |
| `extension/` | Edge MV3 extension (TypeScript), native messaging |
| `services/coffee-receipt` | Cloudflare Worker: Stripe Checkout success → verify session → sign receipt `{year, receipt_id, issued}` |

**Vault** (decentral, 1Password-style 2SKD): directory `vault/header.json` + `vault/ops/<device-id>/<seq>.op`. Argon2id (64 MiB, t=3, p=4) over password, HKDF with 128-bit Secret Key → KEK wraps random 256-bit vault key. Each op: XChaCha20-Poly1305, AAD = vault id + item id + device id + seq + prev hash; per-device hash chain, Ed25519-signed. Merge = file set union (safe in Syncthing/Dropbox/git); Lamport clock + device id; tombstones are ops; rollback detection via highest seq seen. Audit log = op chain.

**Unattended rotation**: vault key cached in OS keychain (`keyring`) by default; daemon unlocks at login. `--no-cache` mode: rotations queue, user gets a notification. Headless Linux: explicit 0600 key file flag. Documented: the cache means password + Secret Key protect only the synced/backup copy. TPM/Secure Enclave → v2.

**Rotation engine**: `Overlap`: create new → write sinks → verify → grace → revoke old. `AtomicSwap` (e.g. GitLab self-rotate): journal intent → rotate → fsync new value into vault → write sinks (retry forward, never restore). One `rotator_device_id` per credential (other devices read-only; explicit handover). Scheduler: per-item interval or global default (30 d), plus lead time before end date; jitter; backoff on 401/403/429; notifications on failure. Admin tokens rotate themselves via the same engine.

**Providers v1** (AWS, Cloudflare, YAML and env sinks moved into v1 against the Fable report, because Paul asks for broad coverage). Rule: a cell that the provider agent cannot confirm in official API docs during the build becomes reminder-only for that capability.

| Provider | Self-rotate admin | Create derived | Revoke derived | `aivw_` name |
|---|---|---|---|---|
| GitLab | yes, `POST /personal_access_tokens/self/rotate` (AtomicSwap, always `expires_at`) | project/group access tokens (`POST /projects/:id/access_tokens`) | yes | on created tokens; rotated token keeps its name |
| AWS IAM | yes, Create new key → verify → Delete old (Overlap, max 2 keys) | access keys for other IAM users | yes | no name field → user tag keyed by access key id |
| Cloudflare | roll own token (`PUT /user/tokens/{id}/value`, verify) | `POST /user/tokens` | yes | yes |
| OpenAI | admin key create/delete (verify) | project service account + key | delete service account (verify) | yes |
| Command | user script | user script | user script | passed as arg |
| Manual | reminder only (GitHub fine-grained PATs etc.) | — | — | — |

v2: Azure Entra, GCP SA keys, GitHub App tokens.

**Sinks v1**: dotenv, JSON key path, TOML (`toml_edit`, keeps format), YAML scalar key path (line-preserving edit), regex template, SSH remote file (russh + russh-sftp, strict known_hosts, key auth, temp + rename), user env var (Windows HKCU\Environment + WM_SETTINGCHANGE; Unix: managed block in shell rc) with plaintext warning, `awd exec -- cmd` env injection (preferred). All local writes atomic (temp, fsync, rename), keep file mode. v2: GitHub Actions secrets.

**IPC auth**: socket in 0700 dir + peer UID; pipe with `PIPE_REJECT_REMOTE_CLIENTS`, owner-only DACL, SID check. Pairing tokens (`aivw_…`) per client with capability set: `cli`/`desktop` full, `mcp` use-only, `native-host` inbox-write-only.

**MCP tools**: `list_secrets` (metadata), `http_request` (secret injected into a fixed header slot defined in the vault; per-secret host allowlist; HTTPS only; no redirects; no private IPs; size cap; response redaction best effort), `request_rotation` (rate limit: 1 per item per hour; AtomicSwap items need confirmation in the desktop app), `get_policy`. `set_policy` needs the separate `mcp-admin` capability, and a change that disables rotation needs confirmation in the desktop app. `run_with_secret` off by default, per-secret opt-in with warning. No `get_secret`. README states the promises and the limits (no protection against same-user malware or agents with shell access).

**Edge extension**: capture only on user click; origin from `sender.origin`; native host manifest `allowed_origins` pinned to extension ID; captures land in a pending inbox; user confirms in desktop app or CLI. Known-provider hints (GitLab, AWS, Cloudflare, OpenAI token pages).

**Coffee**: `services/coffee-receipt` Worker signs `{year, receipt_id, issued}`; app embeds pubkey, verifies offline; receipt code pasted in settings or `awd coffee --receipt <code>` (deep link `aivory-warden://receipt/...` too). Stored in local settings, not synced. If no valid receipt for the current year: one note max every 7 days (desktop notification + CLI stderr on TTY), link `https://aivory.net/coffee`. Never in `mcp`/`native-host` mode, never blocks a rotation. Setting flag `coffee_reminder` as in `code/crates/aivory-protocol/src/settings.rs`.

**Packaging**: copy from `code/packaging/`: `install.sh` (macOS/Linux), `install.ps1`, Homebrew formula, winget manifests (id `Aivory.Warden`), MSIX, Tauri bundles (msi/dmg/AppImage/deb). Service install: systemd --user, launchd agent, Windows `HKCU\...\Run` autostart (Task Scheduler ONLOGON needs admin). Edge native-host registration in installer and `awd extension install`.

## Execution (subagents, sonnet unless noted; each brief per prompt-rules: scope, autonomy, gates, escalation, report)
| Phase | Owner | Done-gate |
|---|---|---|
| 0 Scaffold + core types (me) | workspace, `warden-core` | CI matrix 3 OS green fmt/clippy/test/deny; traits + wire types frozen |
| 1a Vault | agent | KATs; property test: diverged replicas converge in any order; tampered/dropped op rejected |
| 1b Sinks | agent | Golden files keep comments + mode; kill during write leaves old or new; SFTP test on Linux |
| 1c Providers | agent | Mock HTTP tests rotate/verify/expiry/401/403/429 per provider; names use `aivw_` |
| 1d IPC + coffee | agent | Other-user and unpaired client refused; receipt verify tests (valid/wrong year/tampered) |
| 2 Engine | agent | Fault injection at every state: no credential lost, no sink holds revoked token; non-rotator never calls provider; scheduler honours per-item + default interval |
| 3 Binary + service | agent | E2E with mock provider: init, add, rotate, daemon rotates on schedule; service install on 3 OS |
| 4a MCP | agent | No tool result contains a secret; redirect + non-allowlisted host refused |
| 4b Desktop (Tauri) | agent | Implements design artboards; screenshots of each screen; talks to daemon via IPC |
| 4c Extension | agent | Native host rejects foreign extension ID; capture reaches inbox in Edge test profile |
| 4d Coffee Worker | agent (haiku) | Worker unit test: Stripe session mock → signed receipt verifies in `warden-coffee` |
| 5 Release | agent | Packaging renders; release workflow builds artifacts per OS |
Phases 1a–1d parallel after 0; 4a–4d parallel after 3. Final: `/code-review` high + security-review on the branch.

- **Design checkpoint**: Paul approves the artboards before phase 4b. Backend phases continue in parallel.
- **Gate location**: unit tests, Windows pipe checks, Windows service install, desktop and Edge checks run locally on Windows. Linux/macOS peer checks, SFTP (sshd container), systemd/launchd install run in GitLab CI only (push to a new GitLab repo, as Paul allowed).
- **Owned by Paul**: Stripe secret, production signing key pair, Worker deploy to aivory.net, code signing certs. The plan builds and tests the Worker with a test key only.

## Verification
- `cargo fmt --check && cargo clippy --workspace -- -D warnings && cargo test --workspace && cargo deny check`.
- E2E script: `awd init` → `awd add` (mock GitLab + AWS) with dotenv + JSON + SSH (container) sinks → `awd rotate --all` → check sinks hold new value and provider mock shows old revoked → set policy interval 1 min → daemon rotates on schedule.
- MCP: run `aivory-warden mcp` with an MCP inspector; call `http_request` against a local HTTPS mock; assert the secret never appears in results.
- Desktop: `cargo tauri dev`, screenshot each screen, compare with design artboards.
- Extension: load unpacked in Edge, capture a fake token on a test page, confirm it in the inbox.
- Coffee: sign test receipt with test key; reminder fires after 7 days (clock injected), stops with valid receipt.
