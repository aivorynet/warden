# Coffee receipt Worker

A Cloudflare Worker. It turns a paid Stripe payment into a signed Aivory Warden
coffee receipt. The Worker does not deploy itself. Paul owns the signing keys,
the Stripe account and every deploy.

## Flow

1. The daemon adds a claim id to the donation link:
   `https://buy.stripe.com/5kQbJ3csm21Xfz64DhdjO00?client_reference_id=<claim id>`.
   Hopover shares this link.
2. The buyer pays on the link.
3. Stripe sends `checkout.session.completed` to `https://aivory.net/coffee/webhook`.
4. The Worker checks the signature, the paid status, and the claim id format.
5. The Worker signs `{year, receipt_id, issued}` with Ed25519.
6. The Worker stores the code in KV under the claim id for 90 days.
7. The daemon reads `GET https://aivory.net/coffee/claim/<claim id>`.

The donation link stays without a return page. Do not set a success URL on it.

Code format (see `crates/warden-coffee/src/lib.rs`):
`aivw-receipt-<base64url(payload JSON)>.<base64url(ed25519 signature over payload bytes)>`

The spec is in `docs/coffee-claim.md`.

## Endpoints

- `POST /coffee/webhook` takes a Stripe event.
  A bad signature or a stale timestamp returns 400.
  An event that does not apply returns 200. The Worker does nothing.
  The Worker never overwrites a receipt of the same year.
- `GET /coffee/claim/<claim id>` returns 200 `{"code":"..."}`, 404 `{"error":"not_found"}`,
  or 400 `{"error":"bad_request"}`. Every response has `Cache-Control: no-store`.
- `GET /coffee/receipt?session_id=cs_...` is the older route. It returns an HTML page with the code.
  It needs a payment link with a return page. The donation link has none.

## Setup (Paul)

1. Install the dependencies:

   ```sh
   cd services/coffee-receipt
   npm install
   ```

2. Generate the signing key pair:

   ```sh
   npm run gen-keys
   ```

   The script prints the PKCS8 private key and the public key as a Rust array.
3. Store the private key as a secret. Do not commit it:

   ```sh
   npx wrangler secret put RECEIPT_SIGNING_KEY
   ```

4. Store the Stripe secret key:

   ```sh
   npx wrangler secret put STRIPE_SECRET_KEY
   ```

5. Paste the printed public key into `PRODUCTION_PUBLIC_KEY` in
   `crates/warden-coffee/src/lib.rs`. Do this in a separate change.
6. Create the KV namespace. Paste the printed id into `wrangler.toml`. Remove the comment marks.

   ```sh
   npx wrangler kv namespace create CLAIMS
   ```

7. In the Stripe Dashboard, add a webhook endpoint:
   - URL: `https://aivory.net/coffee/webhook`
   - Events: `checkout.session.completed` and `checkout.session.async_payment_succeeded`
8. Store the signing secret (`whsec_...`) of that endpoint:

   ```sh
   npx wrangler secret put STRIPE_WEBHOOK_SECRET
   ```

9. Route the Worker as `aivory.net/coffee/*`. See the comment in `wrangler.toml`.
10. Deploy when ready:

    ```sh
    npx wrangler deploy
    ```

## Checks

```sh
npm run typecheck   # tsc --noEmit
npm test            # vitest, Stripe and KV are mocked
```

`test/fixture-receipt.json` holds a public key and a code from a test key. The
Rust side can use it to test `verify_with_key`. It is not a production key.
