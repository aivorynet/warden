# Store listing: Save to Warden

Use this text for the Chrome Web Store and for Edge Add-ons. Build the package with
`cd extension && npm run pack:store`. The zip is `extension/store/save-to-warden-<version>.zip`.

## Item

| Field | Value |
|---|---|
| Name | Save to Warden |
| Summary (max 132) | Send an access token from a provider page to your local Aivory Warden vault. Reads a page only when you click. |
| Category | Developer Tools |
| Language | English |
| Homepage | https://aivory.net/warden |
| Support | https://github.com/aivorynet/warden/issues |
| Privacy policy | https://aivory.net/warden-privacy/ |

## Description

Save to Warden is the browser companion of Aivory Warden, the open-source token manager that rotates your
GitLab, AWS, Cloudflare and OpenAI tokens on a schedule and writes the new values to your .env files.

You just created a token on a provider page. Click the Warden icon. The extension finds the token on the page,
shows it masked, and sends it to the Warden inbox on your computer. You accept it in the Warden app, and Warden
rotates it from then on. No copy and paste, no token in your clipboard history.

- Reads a page only when you click "Scan this page" or "Save selection to Warden".
- Sends the token only to the Warden app on the same computer (native messaging). No network request.
- Stores nothing in the browser.
- Open source (MIT): https://github.com/aivorynet/warden

Needs the Aivory Warden desktop app or CLI (Windows, macOS, Linux). Install it first:
https://aivory.net/warden

## Single purpose

Move an access token that the user chooses from the current tab into the user's local Aivory Warden vault inbox.

## Permission justifications

| Permission | Why |
|---|---|
| `activeTab` | Gives access to the current tab only after the user clicks the extension button or the context menu item. The extension then reads the token on that page. It has no host permissions. |
| `scripting` | Runs one function in the current tab, after the user click, to find token-shaped text or the selected text. |
| `contextMenus` | Adds "Save selection to Warden" to the right-click menu for selected text. |
| `nativeMessaging` | Sends the token to the Aivory Warden app on the same computer (host `net.aivory.warden`). This is the only place the token goes. |

Remote code: No. All code is in the package.

## Data usage disclosure

- Collected: **Authentication information** (the access token that the user chooses) and **Website content**
  (token-shaped text on the current page, on user click). The tab URL is used as the origin label.
- The data goes only to the local Warden app on the user's computer. It does not leave the device.
- Certify: not sold to third parties; not used for unrelated purposes; not used for creditworthiness or lending.

## Test steps for the reviewer

1. Install Aivory Warden from https://github.com/aivorynet/warden/releases (Windows: `install.ps1`; macOS:
   `brew install aivorynet/tap/aivory-warden`; Linux: `install.sh`).
2. Run `awd init`, then `awd daemon` (or `awd service install`), then `awd extension install`.
3. Open any page that shows a test token, for example a text file with
   `glpat-ABCDEFGHIJKLMNOPQRST` (a fake GitLab token).
4. Click the extension icon, then "Scan this page". The popup shows the token masked.
5. Click "Send to inbox". Run `awd inbox`. The entry is there.

Without the Warden app the popup says "Start the Warden app to see the inbox." That is the expected result.

## Screenshots (1280x800)

1. Popup on a GitLab token page: masked value, name field, "Send to inbox".
2. Warden desktop app: Inbox with the captured token and "Accept".
3. Warden desktop app: token list with next rotation dates.

## After the first upload

1. Read the item ID in the developer dashboard.
2. Add it to `EXTENSION_IDS` in `crates/aivory-warden/src/cli.rs`, so that `awd extension install` allows it.
3. Do the same for the Edge Add-ons ID.
4. Ship a Warden release with the new ids **before** you publish the extension.
