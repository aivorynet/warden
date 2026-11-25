# Coffee: honor system

Warden uses the Hopover model. Warden cannot see a payment, so it trusts the user.
There is no server, no receipt, no signing key and no network call.

## Flow

1. The user clicks "Buy a coffee" (desktop Settings, the pledge screen, the tray note)
   or runs `awd coffee --pay`.
2. Warden opens `COFFEE_URL` (the shared Aivory donation link, no query string).
3. Warden asks: "Did it go through?" with the text
   "Warden can't see your payment, so I'll just trust you on this one :)".
   Buttons: "Yes, it went through" and "Not yet".
4. "Yes" sends `Request::CoffeeMarkPaid`. The daemon sets `paid_year` to the current
   year and `paid_at` to now. The weekly note stops until the next year.
5. `awd coffee --paid` marks the year as paid without a browser (scripts, a payment on
   another device).

## Rules

- `Request::CoffeeMarkPaid` replaces `Request::CoffeeCheck` and `Request::CoffeeReceipt`.
  Capability: Full only.
- Remove the receipt path: receipt verify, `PRODUCTION_PUBLIC_KEY`, `--receipt`, the
  Settings receipt field, the `aivory-warden://receipt/` deep link, the claim id, the
  claim poll and its HTTP client.
- `CoffeeState` keeps `paid_year`, adds `paid_at: Option<DateTime<Utc>>`, and drops the
  receipt and claim fields. Old settings files still load (unknown fields are ignored).
- A paid year counts only for that year. On 1 January the weekly note starts again.
- The notes, the README and the CLI may print the bare donation link.
- The pledge, the first-rotation note, the weekly note, the ticket number and the
  `coffee_reminder` setting stay as they are.
