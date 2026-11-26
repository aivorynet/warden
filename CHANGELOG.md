# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/). Versions use the calendar scheme `YYYY.MM.patch`.

## Unreleased

### Added

- Encrypted vault with Argon2id, a Secret Key, XChaCha20-Poly1305 and a signed op log.
- Daemon that rotates tokens on a schedule. Providers: GitLab, AWS IAM, Cloudflare, OpenAI, command, manual.
- Sinks: dotenv, JSON, TOML, YAML, environment variable, SSH remote file, and `awd exec`.
- MCP server with a secret-injecting HTTPS proxy.
- Edge extension and native messaging host.
- Weekly coffee note with an offline signed receipt.
- Install scripts for macOS, Linux and Windows. Homebrew, winget and Scoop manifests.
- Release pipelines for GitHub Actions and GitLab CI.
- MCP tool `save_secret`: an agent puts a new token into the inbox; the user accepts it.
- `awd extension install` works with `WARDEN_HOME` (launcher) and uses the published extension id by default.
- `awd mcp-setup` pairs agents with `mcp` and `inbox`, so `save_secret` works without extra setup.

### Fixed

- Extension: GitLab tokens in the newer format (`glpat-….01.…`) were cut at the first dot.
- `awd add` and `awd inbox accept` write the token to its places at once, not only at the first rotation.
- Invalid places are refused at add time. Deleting a token that derived tokens use is refused.
- Cloudflare: the second rotation stored the old value in the vault (the token id stays the same).
- An empty provider token id no longer queues a revoke. Only HTTP 401 marks a credential as dead.
- AWS: orphan keys are found despite clock skew; old tags are removed. GitLab: `/api/v4` is added to a bare base URL.
- `awd unpair` ends open sessions. MCP rotation limit is atomic and survives a restart.
- MCP clients get no place paths. An interval of 0 is refused. A longer grace period needs confirmation.
- `awd exec` finds `.cmd` tools (npm, pnpm) on Windows. `awd mcp-setup` keeps file mode and the first backup.
- Vault: device key is not overwritten by a second `init`; lamport overflow, `seen.json` races and corrupt ops are errors.
