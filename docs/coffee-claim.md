# Coffee claim: contract

The coffee link is a shared Aivory donation link (Stripe Payment Link) with no
return page. A claim id in the link carries the payment back to the install.

## Flow

1. The daemon makes a claim id for the current year and stores it in `CoffeeState`.
2. The daemon puts the claim id into the pay link:
   `<COFFEE_URL>?client_reference_id=<claim id>`.
3. The user opens the link from the desktop app (Buy a coffee) or `awd coffee --pay`.
   That action sends `Request::CoffeeCheck` first, which arms the poll window.
4. Stripe sends `checkout.session.completed` to the Worker webhook. The session field
   `client_reference_id` holds the claim id.
5. The Worker signs a receipt and stores it in KV under the claim id.
6. The daemon fetches `GET <CLAIM_URL><claim id>` and runs the existing
   `warden_coffee::apply_receipt`. The weekly note stops for that year.

## Claim id

- Format: `aivw-c-` plus 32 lowercase hex characters (128 random bits from the OS RNG).
  Regex: `^aivw-c-[0-9a-f]{32}$`.
- A bearer secret. Do not derive it from the ticket or the device id.
- One claim id per year. A new year makes a new claim id.

## Worker

Base: `https://aivory.net/coffee`.

### `POST /coffee/webhook`

1. Verify the `Stripe-Signature` header with the secret `STRIPE_WEBHOOK_SECRET`:
   header `t=<unix s>,v1=<hex>[,v1=...]`; signed payload `<t>.<raw body>`;
   HMAC-SHA256; constant-time compare against each `v1`; tolerance 300 s.
   Failure: 400.
2. Accept the event types `checkout.session.completed` and
   `checkout.session.async_payment_succeeded`. Other types: 200, no action.
3. Require `data.object.payment_status == "paid"`. Else: 200, no action.
4. Require `data.object.client_reference_id` to match the claim regex. Else: 200, no
   action. (Hopover payments use the same link and the same webhook.)
5. Receipt: `year` = UTC year of `data.object.created`; `receipt_id` = `data.object.id`;
   `issued` = now. Sign with the existing receipt signing code.
6. Store in KV namespace binding `CLAIMS`: key = claim id, value = receipt code,
   TTL 90 days. Do not overwrite an existing value of the same year. Return 200.

### `GET /coffee/claim/<claim id>`

- Claim id does not match the regex: 400 `{"error":"bad_request"}`.
- No value: 404 `{"error":"not_found"}`.
- Value: 200 `{"code":"aivw-receipt-..."}`.
- Header `Cache-Control: no-store` on every response.

## Daemon

- `CoffeeState` new fields (serde default): `claim_id: Option<String>`,
  `claim_year: Option<i32>`, `claim_armed_at: Option<DateTime<Utc>>`,
  `claim_last_poll_at: Option<DateTime<Utc>>`.
- `CoffeeInfo.link` = the pay link with the claim id. Make the claim id when it is
  missing or `claim_year` is not the current year.
- New `Request::CoffeeCheck` (capability: Full only, the same as `CoffeeReceipt`).
  It sets `claim_armed_at = now`, polls once now, and returns `Response::Coffee(CoffeeInfo)`.
- Scheduler poll, only when the year is not paid and `claim_armed_at` is set:
  - every 2 minutes for 1 hour after `claim_armed_at`;
  - then every 6 hours until 7 days after `claim_armed_at`;
  - then stop until the next `CoffeeCheck`.
- The request sends only the claim id. https only, 10 s timeout, 16 KiB response cap.
  A test may use `http://127.0.0.1` through a daemon config field; production cannot.
- A poll failure is silent (log at debug). It never blocks a rotation.
- The `mcp` and `native-host` modes never poll.

## Text

- The notes do not print the bare donation URL. A payment through the bare URL has
  no claim id, so it cannot stop the note. Point the notes to Settings > Buy a coffee
  or `awd coffee --pay`.
