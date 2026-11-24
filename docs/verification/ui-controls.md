# Desktop UI controls (apps/desktop/ui)

Checked 2026-11-24. Every control calls a request type that exists in `warden-core::ipc::Request`
and in the `ALLOWED` list of `src-tauri/src/daemon.rs`, or a Tauri command that exists.

| Screen | Control | Backend |
|---|---|---|
| Start | Create vault / Sign pledge | `init_vault`, `sign_pledge` |
| Start | Unlock (+ keychain checkbox) | `unlock`, `set_settings` |
| Start | Start background service | `start_service` (`aivory-warden service install`) |
| Start | Save as PDF (Emergency Kit) | `window.print()` with the `@media print` rules in `styles.css` |
| Tokens | Add a token wizard (provider chips, selects, places) | `add_item` |
| Token | Auto-rotate toggle, Every, Before end date (rotation window) | `update_policy` |
| Token | Rotate now | `rotate_now` |
| Token | Add this place | `update_item` (sinks) |
| Token | Delete token | `delete_item` |
| Inbox | Accept / Reject | `inbox_accept`, `inbox_reject` |
| Settings | Default interval, keychain cache, coffee note | `set_settings` |
| Settings | Pair client / Unpair | `pair`, `unpair` |
| Settings | Apply receipt | `coffee_receipt` |
| Settings | Devices list (read only) | `list_devices` |

## Result

No dead control exists. No control was hidden or removed.
The candidates "change vault folder", "add device", "verify now" and "test this place"
have no control in the UI.

## v2 (not in the UI, no backend request yet)

- Change vault folder: CLI only (`--vault`, `init --join`).
- Add device: CLI only (`awd join`).
- Verify now: no daemon request. The CLI has no verb either.
- Test this place: no dry-run request. A sink is written on the next rotation.
