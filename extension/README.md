# Save to Warden (Edge extension)

Manifest V3 extension. It sends a token from a provider page to the Warden inbox.
You confirm each token in the Warden app or the CLI.

## Rules

- Capture runs only on a user action: the popup button "Scan this page" or the context menu "Save selection to Warden".
- The extension has no host permissions. It uses `activeTab` and injects a function with `chrome.scripting`.
- The origin comes from the browser tab URL. It never comes from page content.
- The popup shows the value masked (prefix and last 4 characters).
- The value never goes to `chrome.storage`. It goes only to the native host `net.aivory.warden`.

## Extension ID

The public `key` in `manifest.json` fixes the ID:

    ofafkpmfikeikdkldpkgmibfbphkmgai

The private key is in `extension/.keys/key.pem`. Git ignores it. Back it up outside the repo.
To make the Chrome Web Store or Edge Add-ons package, use this key.

## Build and test

    cd extension
    npm install
    npm run build   # tsc, then copy static files to dist/
    npm test        # build, then node:test for detectors and masking

## Manual test in Edge

1. Build the extension: `npm run build`.
2. Open `edge://extensions`. Turn on "Developer mode".
3. Click "Load unpacked". Select `extension/dist`.
4. Check that the ID is `ofafkpmfikeikdkldpkgmibfbphkmgai`.
5. Register the native host. Use the absolute path of the host executable.
   The executable must start the host with no arguments (a launcher for `aivory-warden native-host`):

        awd extension install --exe <absolute path>

   Or call `warden_native_host::register(exe_path, "ofafkpmfikeikdkldpkgmibfbphkmgai")` from Rust.
6. Check the registration on Windows:
   `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\net.aivory.warden` points to the manifest in
   `%LOCALAPPDATA%\Aivory\Warden\native-host\net.aivory.warden.json`.
   On macOS and Linux the manifest is in the per-user `NativeMessagingHosts` folder of Edge and Chrome.
7. Start the Warden daemon. Create a pairing token with only `inbox_write` and give its path to the host.
8. Open a local test page that shows a fake token, for example `glpat-` followed by 20 random characters.
9. Click the extension icon and click "Scan this page". Check that the value shows masked.
10. Set a name. Click "Send to inbox". Check that the status line says "Sent".
11. Open the Warden app or run `awd inbox`. Check that the entry is in the inbox. Confirm or reject it.
12. Select a token on the page, right-click, and choose "Save selection to Warden". Check that the popup opens with the masked value.
13. Unregister: `awd extension uninstall`, or `warden_native_host::unregister()`.

## Notes

- Fonts are IBM Plex Sans and JetBrains Mono when installed. The popup loads no remote font.
- The wire request `InboxAdd` has only `origin`, `label` and `value`. The host drops `provider_hint` and `expires_at`.
- A token with only `inbox_write` cannot call `inbox_list`. The popup then shows a note and the inbox shows in the app.
