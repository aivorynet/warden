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
