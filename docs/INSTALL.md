# Install Aivory Warden

Every release has six CLI archives, `SHA256SUMS`, the install scripts, the desktop bundles and the Edge extension zip. The release page is <https://github.com/aivorynet/warden/releases>.

Archive names: `aivory-warden-<target>.tar.gz` (macOS, Linux) or `.zip` (Windows). Targets: `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`. Each archive holds `aivory-warden` and `awd`.

## Windows

```powershell
winget install Aivory.Warden
scoop bucket add aivory https://github.com/aivorynet/scoop-bucket
scoop install aivory-warden
```

Or run the script:

```powershell
irm https://github.com/aivorynet/warden/releases/latest/download/install.ps1 | iex
```

The script installs into `%LOCALAPPDATA%\Aivory\Warden\bin` and adds the folder to your user PATH. To pass flags, download the script and run `./install.ps1 -Service -Extension`.

## macOS

```sh
brew install aivorynet/tap/aivory-warden
brew services start aivory-warden   # optional: start the daemon at login
```

Or run the script:

```sh
curl -fsSL https://github.com/aivorynet/warden/releases/latest/download/install.sh | sh
```

## Linux

```sh
curl -fsSL https://github.com/aivorynet/warden/releases/latest/download/install.sh | sh
```

The script installs into `~/.local/bin`. The desktop app comes as `.deb` and `.AppImage` on the release page. Homebrew on Linux also works.

## Script options

| Option | Shell | PowerShell |
|---|---|---|
| Start the daemon at login | `--service` | `-Service` |
| Register the browser native host | `--extension` | `-Extension` |
| Fixed version | `WARDEN_VERSION=2026.11.0` | `$env:WARDEN_VERSION='2026.11.0'` |
| Install prefix | `WARDEN_PREFIX=/opt/warden` | `$env:WARDEN_PREFIX='D:\Warden'` |

Shell example with flags: `curl -fsSL .../install.sh | sh -s -- --service --extension`.

Without a flag the script installs the two binaries and nothing else. The service and the native host need your consent, so they stay off by default. You can run them later:

```sh
aivory-warden service install    # systemd --user, launchd agent, or an HKCU Run entry at logon (Windows)
aivory-warden extension install  # native messaging host for Edge and Chrome
```

Remove them with `aivory-warden service uninstall` and `aivory-warden extension uninstall`.

## Check a download

The scripts verify the SHA-256 of the archive against `SHA256SUMS` and stop on a mismatch. To check by hand:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

## Edge extension

Download `aivory-warden-edge-extension.zip` from the release page and unzip it. Open `edge://extensions`, turn on Developer mode, choose "Load unpacked" and pick the folder. Then run `aivory-warden extension install`. The extension id is pinned, so the native host accepts only this extension.

## Code signing

Release builds are signed only when the maintainers have set the signing secrets. An unsigned build can show a SmartScreen or Gatekeeper prompt. The package managers and the scripts avoid most of these prompts. Check the SHA-256 in every case.

## First run

```sh
awd init
awd status
```

## Build from source

```sh
cargo build --release -p aivory-warden
```

The binaries are in `target/release`. Rust 1.95 or newer is required.
