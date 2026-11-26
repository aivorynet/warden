# Microsoft Store: AIVory Warden

Store ID `9MZ0VQZ1V112`, identity `AIVoryInc.AIVoryWarden`, link https://apps.microsoft.com/detail/9MZ0VQZ1V112

Build the package: `cargo build --profile store -p aivory-warden -p aivory-warden-desktop`, then
`packaging\msix\build-msix.ps1 -Version <version>`. The `store` profile keeps the MSIX small (about 6.5 MB).

## Done in submission 1 (2026-11-26)

- Packages: `aivory-warden-2026.11.1-x64.msix`, Windows 10/11 Desktop only.
- Properties: Developer tools, secondary Security; privacy policy https://aivory.net/warden-privacy/.
- Pricing: Free, all markets, public, release as soon as possible.
- Age ratings: questionnaire answered (all No), result 3+ / Everyone. The IARC terms checkbox is Paul's.

## Store listing (English, United States)

**Description**

AIVory Warden replaces your API tokens before they expire and updates every app that uses them.

Add a GitLab, AWS, Cloudflare or OpenAI token once. Warden creates a fresh token on a schedule (every 30 days by default, always before the end date), writes it into your .env files, environment variables and servers over SSH, checks that it works, and only then revokes the old one.

Your AI agents can use the tokens without ever seeing them. Warden adds its MCP server to Claude Code, Claude Desktop, Codex, Gemini CLI, Cursor, VS Code and Windsurf with one click. The agent asks Warden to call an API; Warden adds the token, sends the request only to hosts you allow, and removes the token from the answer.

- Encrypted local vault (Argon2id, XChaCha20-Poly1305) with a password and a Secret Key.
- No account, no cloud copy, no telemetry.
- Quick unlock with Windows Hello.
- Free and open source (MIT): https://github.com/aivorynet/warden

**Short description**

Rotates your API tokens before they expire and updates every app that uses them. AI agents use the tokens without seeing them.

**Features** (one per line)

```
Rotates GitLab, AWS, Cloudflare and OpenAI tokens on a schedule
Writes new values to .env files, environment variables and SSH hosts
Verifies the new token before it revokes the old one
AI agents use tokens over MCP without seeing them
One-click setup for Claude Code, Codex, Gemini CLI, Cursor and VS Code
Encrypted local vault, no account, no cloud copy
Quick unlock with Windows Hello
Free and open source (MIT)
```

**Keywords**: token rotation, API keys, secrets, MCP, AI agents, GitLab, AWS, Cloudflare

**Screenshots** (1920x1080): `docs/store/assets/ms/tokens-1920x1080.png`, `inbox-1920x1080.png`, `settings-1920x1080.png`.

**Copyright**: © 2026 AIVory, Inc. **Website**: https://aivory.net/warden/ **Support**: https://github.com/aivorynet/warden/issues

## Submission options: restricted capabilities

```
runFullTrust: AIVory Warden is a desktop app with a background rotation daemon and a command-line tool (aivory-warden.exe). The daemon runs at sign-in and calls provider APIs (GitLab, AWS, Cloudflare, OpenAI) over HTTPS to create and revoke the user's own access tokens.

unvirtualizedResources: Warden writes per-user state that other programs must read, so write virtualization is disabled: (1) the HKCU Run entry that starts the rotation daemon at sign-in, (2) the native messaging host registration under HKCU\Software\Microsoft\Edge\NativeMessagingHosts and HKCU\Software\Google\Chrome\NativeMessagingHosts that lets our browser extension "Save to Warden" talk to the app, (3) the MCP server entry in the config files of AI tools (for example %USERPROFILE%\.claude.json), and (4) the .env files in the user's own projects, which are the purpose of the app. With virtualization these writes would be invisible to the browser, the AI tools and the user. All paths point to the app alias %LOCALAPPDATA%\Microsoft\WindowsApps\aivory-warden.exe, so they survive updates.
```

## Notes for certification

```
To test: open the app, create a vault (any password), print or skip the Emergency Kit, then Add a token with the provider "Manual (reminder only)" and any dummy value. Settings > App shows the tray and start-at-login options. No account or network service of ours is needed.
```
