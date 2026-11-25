# Aivory Warden

Aivory Warden is an open-source access token manager for Windows, macOS and Linux. It keeps your tokens in an encrypted vault. A background daemon rotates them on a schedule and writes the new value to the files, environment variables and SSH hosts that use them. Agents use a token through an MCP server and never read the value.

The binary is `aivory-warden`. The short alias is `awd`.

## What it does

- Stores admin tokens with an end date, and the places that use tokens (sinks).
- Rotates tokens before they end: GitLab, AWS IAM, Cloudflare, OpenAI, a custom command, or a reminder for tokens that have no API.
- Rotates derived tokens that an admin token creates, and rotates the admin token itself.
- Updates sinks atomically: dotenv, JSON, TOML, YAML, environment variables, and remote files over SSH.
- Runs a command with a token in its environment: `awd exec <name> -- <command>`.
- Lets an agent call an API with a token through MCP, without showing the agent the value.
- Captures a token from a provider page with an Edge extension. You confirm each capture.

## Install

Windows:

```powershell
winget install Aivory.Warden
# or: scoop install aivory-warden
# or: irm https://github.com/aivorynet/warden/releases/latest/download/install.ps1 | iex
```

macOS:

```sh
brew install aivorynet/tap/aivory-warden
# or: curl -fsSL https://github.com/aivorynet/warden/releases/latest/download/install.sh | sh
```

Linux:

```sh
curl -fsSL https://github.com/aivorynet/warden/releases/latest/download/install.sh | sh
# or: brew install aivorynet/tap/aivory-warden
# or: download the .deb or .AppImage from the release page
```

The scripts check the SHA-256 of the download against `SHA256SUMS`. Add `--service` (shell) or `-Service` (PowerShell) to start the daemon at login. Add `--extension` or `-Extension` to register the browser native host. See [docs/INSTALL.md](docs/INSTALL.md) for all options.

## Quick start

```sh
awd init       # create a vault, print the Emergency Kit, register this device
awd add        # add a token (asks for the missing values)
awd status     # show the daemon state and your tokens
```

Add a token with flags:

```sh
awd add --name "GitLab admin" --provider gitlab --expires 2027-06-01 \
  --interval 30d --sink dotenv:./.env:GITLAB_TOKEN
```

Other commands:

```sh
awd rotate --all      # rotate every token now
awd list              # list tokens
awd audit             # show the audit log
awd exec "GitLab admin" -- glab auth status
```

Run `awd --help` for all commands. The default rotation interval is 30 days. Change it with `awd settings set default-interval`.

Print the Emergency Kit when `awd init` shows it, and store it somewhere safe. The vault needs your password and the Secret Key. Nobody can recover them for you.

## MCP

`aivory-warden mcp` runs a stdio MCP server. Pair the client once with `awd pair mcp`, then add the server to Claude Code, Claude Desktop, Cursor or another client. See [crates/warden-mcp/README.md](crates/warden-mcp/README.md) for the client configuration, the tools and the limits.

## Edge extension

The extension in [extension/](extension/) sends a token from a provider page to the Warden inbox. It acts only when you click. It has no access to your pages by default. Review and accept captures with `awd inbox`. Register the native host with `awd extension install`. The release page has the extension zip.

## Security model

Warden protects your tokens at rest, in sync, and from the agents that you give an MCP connection. It does not protect a machine that an attacker already controls. [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) has the details and [SECURITY.md](SECURITY.md) explains how to report a problem.

What we promise:

- The vault is encrypted with a key from your password and a 128-bit Secret Key. A copy in a synced folder or a backup is not readable without both.
- Every change to the vault is signed and chained. A tampered or removed change is detected.
- No MCP tool returns a secret value. There is no `get_secret`.
- An MCP request goes only over HTTPS, only to hosts that you allow for that token, and with no redirects and no private addresses.
- The proxy removes the secret from the answer, including its base64, hex and URL-encoded forms.
- Only your OS user can talk to the daemon. Every client needs a paired token with a limited permission set.
- The coffee reminder never stops a rotation.

What we do not promise:

- We do not protect against malware that runs as your user.
- We do not protect against an agent that has shell access. It can read your files and your environment.
- By default the vault key sits in the OS keychain so the daemon can rotate without you. A process that can read your keychain can open the vault. Turn the cache off with `awd settings set keychain-cache off` and rotations then wait for you to unlock.
- Redaction of API answers is best effort.
- We do not protect a token after you write it to a sink and let an agent read that place.
- An allowed host can send a token on to other parties.
- If you lose the password or the Secret Key, the vault is gone.

## Coffee

Warden is free and MIT licensed. There is no account, no trial and no locked feature. If it saves you time, buy the developer a coffee. Pay what you want; 5 EUR is the suggestion. Use Settings > Buy a coffee in the desktop app, or run `awd coffee --pay`. The donation link is https://buy.stripe.com/5kQbJ3csm21Xfz64DhdjO00 .

Warden uses an honor system, like Hopover. Warden cannot see your payment, so it trusts you. After the link opens, Warden asks "Did it go through?". Answer yes, and the note stops for that year. To mark a payment without a browser, run `awd coffee --paid`. Warden makes no network call for this.

Until you have paid once in the current year, Warden shows one short note per week, in the desktop app and on stderr of the CLI when it runs in a terminal. On 1 January the note starts again. You can turn the note off with `awd settings set coffee-reminder off`. The note never appears in `mcp` or native host mode, and it never blocks a rotation.

## Build from source

```sh
cargo build --release -p aivory-warden
```

You need Rust 1.95 or newer. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

MIT. See [LICENSE](LICENSE).
