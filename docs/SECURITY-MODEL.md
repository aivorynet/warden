# Security model

This page states what Warden protects, how, and where the limits are. The numbers come from the code in `crates/warden-vault`, `crates/warden-ipc` and `crates/warden-mcp`.

## Vault

The vault is a directory: `vault/header.json` and `vault/ops/<device-id>/<seq>.op`. It has no server.

Key derivation:

1. Argon2id over the password. Parameters: 64 MiB memory, 3 iterations, 4 lanes. The header stores the parameters.
2. HKDF-SHA256 with the 128-bit Secret Key as the salt and the Argon2id output as the input material. The info string is `aivory-warden/v1/kek`.
3. The result is the key-encryption key (KEK). The KEK wraps a random 256-bit vault key.

Both factors are needed. The password alone or the Secret Key alone cannot open the vault. The Secret Key is shown once, in the Emergency Kit, when you run `awd init`. Warden cannot recover it.

Items and history:

- Every change is an op. An op is encrypted with XChaCha20-Poly1305. The associated data holds the vault id, item id, device id, sequence number and the hash of the previous op.
- Each device has its own hash chain and an Ed25519 signing key. Each op is signed. The vault checks the chain and the signature (`verify_strict`) on load.
- A broken chain, a bad signature, or a missing op in the middle of a chain makes the load fail.
- The vault keeps the highest sequence it has seen for each device. A copy that goes back to an older state is detected.
- Merge is the union of the op files. Order is by Lamport clock, then device id. A synced folder (Syncthing, Dropbox, git) is safe to use. Deletes are tombstone ops.
- The audit log is the op chain. You can read it with `awd audit`.

## The keychain cache

A daemon cannot rotate tokens at 03:00 without a key. So by default Warden stores the vault key in the OS keychain (service `aivory-warden`, one entry per vault). The daemon reads it at login.

The trade-off:

- Your password and Secret Key protect the copy of the vault that sits in a synced folder or a backup.
- On the machine where the cache is on, they do not protect against a process that can read your keychain as your user. That process can open the vault without the password.
- With the cache off (`awd settings set keychain-cache off`), the daemon does not hold the key between sessions. Rotations wait until you run `awd unlock`. You get a notification.
- On a headless Linux host without a keychain, you can opt in to a key file with mode 0600. On Windows the file inherits the ACL of its folder. Use it only on a host that you control.
- The cache holds the vault key, not the password or the Secret Key.

Hardware-backed storage (TPM, Secure Enclave) is not in v1.

## Quick unlock

Quick unlock is off by default (`awd settings set quick-unlock on`, or the toggle in the desktop settings). It is a gate and not encryption.

- The vault key stays in the OS keychain cache, as before. The OS user check (Windows Hello, Touch ID, polkit) does not wrap or derive any key.
- With quick unlock on, `awd lock` and Lock keep the cached key (soft lock). A marker file keeps the daemon locked after a restart. `awd lock --forget` and "Lock and forget" remove the key.
- The client (desktop app or CLI) runs the OS check, then sends `Request::UnlockQuick`. The daemon reads the key from its own cache. No key travels over IPC. `UnlockQuick` needs the `Full` capability. The daemon refuses it when the setting is off or no cached key exists. Each use and each refusal writes an entry to the device-local audit log (`awd audit`).
- It needs the keychain cache on. The option is hidden when no OS check exists (Windows 11 or later, macOS, or Linux with `pkcheck` and the polkit policy).
- Protection claim: a person at your keyboard who does not have your face, finger or PIN cannot unlock the vault in the app or the CLI.
- No protection against software that runs as your user. It can read the keychain directly, or send `UnlockQuick` itself with `cli.token`. The master password and the Secret Key still protect the synced copy and other devices.

## IPC authentication

The daemon listens on a local endpoint. There is no network port and no HTTP.

- Unix: a socket in a directory with mode 0700. The server checks the peer UID.
- Windows: a named pipe `\\.\pipe\aivory-warden-<user-sid>`. It rejects remote clients, uses an owner-only DACL, and checks the client SID.
- A connection without a paired token is refused. There is no pairing window. A `full` session (CLI or desktop app) pairs a new client.
- Each client has a paired token (`aivw_<base62>_<crc32>`, so secret scanners find a leak) with a capability set:
  - `full`: CLI and desktop app.
  - `mcp`: use secrets through the proxy, read metadata, request a rotation.
  - `mcp-admin`: also change a policy.
  - `inbox`: the native host. It can write to the inbox and nothing else.
- The server checks the capability for every request. A request that the capability does not allow gets `forbidden`.
- You can pair and unpair clients. `awd pair <name> --cap <cap>` shows the token once.

## The coffee reminder

Warden makes no outbound call for the coffee reminder. It uses an honor system.

- Warden opens the donation link in your browser. The link has no query string and no identifier.
- Warden cannot see a payment. You confirm it with "Yes, it went through" or `awd coffee --paid`.
- The daemon stores the paid year and the time in the local settings file. Warden sends nothing.
- `Request::CoffeeMarkPaid` needs the `Full` capability. MCP clients and the native host cannot send it.

## MCP limits

See [crates/warden-mcp/README.md](../crates/warden-mcp/README.md) for the full list. In short:

- No tool returns a secret value. There is no `get_secret`.
- `http_request` puts the secret in one header that the vault defines. The agent cannot set `Authorization`, `Cookie`, `Proxy-Authorization` or the secret header. The URL, query and body cannot hold the placeholder.
- HTTPS on port 443 only. The host must be in the allowlist of that secret.
- The proxy resolves the host, refuses private, loopback, link-local, CGNAT, multicast and unspecified addresses, and connects to the address it checked. It follows no redirects.
- Limits: 1 MiB request body, 512 KiB response body (the proxy also cuts it so that its JSON form fits one 1 MiB IPC frame), 30 s.
- The proxy replaces the secret in the response body and headers with `[REDACTED:aivw]`. It also covers the base64 (also inside a longer stream), base64url, hex, URL-encoded, JSON-escaped and HTML-escaped forms, and every run of 16 or more characters of the secret.
- `request_rotation` allows 1 request per item per hour. Some items need confirmation in the desktop app.
- `set_policy` needs `mcp-admin`. Turning rotation off, a longer interval (or one above 365 days) and a lead time of 0 need confirmation in the desktop app.
- `run_with_secret` is off by default and needs an opt-in for each secret.

## Edge extension

- It captures only on a user click and has no host permissions (`activeTab` only).
- The origin comes from the browser, not from page content. For a selection in an iframe it is the frame URL.
- The value goes only to the native host `net.aivory.warden`. The host manifest lists one allowed origin, the pinned extension id.
- Captures land in a pending inbox. You accept or reject each one in the app or with `awd inbox`.

## What we do not promise

- Any process that runs as your user can read `cli.token` and so act as a `full` client. This is a design limit: the CLI needs the token without a prompt. The file is owner-only (mode 0600 on Unix, an owner-only DACL on Windows). That stops other users and not your own processes.
- Any process that runs as your user can also connect to the daemon endpoint. The token, not the endpoint, is the only barrier.

## Threat model

Warden defends against:

- Theft of a synced or backed-up vault. Without the password and the Secret Key the data is not readable.
- A tampered, replayed or truncated vault copy.
- Another OS user on the same machine.
- A remote client of the daemon endpoint.
- An agent that talks to Warden only through MCP, including a prompt-injected one that tries to read or send out a secret.
- An expired or long-lived token. Rotation keeps tokens short-lived.
- A crash in the middle of a rotation. An intent journal and forward-only retries keep the new value in the vault before the sinks change.

Warden does not defend against:

- Malware or an attacker that runs as your user. It can read the keychain, process memory, sink files and the environment.
- An agent with shell access. It reads your files directly.
- A token after it sits in a sink that an agent can read.
- A compromised provider, or an allowed host that passes a token on.
- A root or administrator attacker on the host.
- A lost password or Secret Key.
- Redaction that fails against an API that transforms the secret in an unusual way. Redaction is best effort.

Use `awd exec` instead of a file or an environment variable sink when you can. It gives the token to one process for one run.

Report a vulnerability as described in [SECURITY.md](../SECURITY.md).
