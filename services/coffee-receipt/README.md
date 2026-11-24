# Coffee receipt Worker

A Cloudflare Worker. It turns a paid Stripe Checkout session into a signed
Aivory Warden coffee receipt. The Worker does not deploy itself. Paul owns the
signing keys, the Stripe account and every deploy.

## Flow

1. The buyer pays on the Stripe Payment Link
   `https://buy.stripe.com/5kQbJ3csm21Xfz64DhdjO00` (the same link as Hopover).
2. Stripe redirects to `https://aivory.net/coffee/receipt?session_id={CHECKOUT_SESSION_ID}`.
3. The Worker fetches the session from Stripe and requires `payment_status == "paid"`.
4. The Worker signs `{year, receipt_id, issued}` with Ed25519 and shows the code.

Code format (see `crates/warden-coffee/src/lib.rs`):
`aivw-receipt-<base64url(payload JSON)>.<base64url(ed25519 signature over payload bytes)>`

## Endpoints

- `GET /coffee/receipt?session_id=cs_...` returns an HTML page with the code,
  a copy button and the link `aivory-warden://receipt/<code>`.
- Missing `session_id` returns 400. A malformed id returns 400.
- An unpaid session returns 402. An unknown session returns 404.

## Setup (Paul)

1. Install dependencies:

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
6. Set the success URL on the Stripe Payment Link to the line below.
   Hopover uses the same link, so Hopover buyers also get a Warden receipt page:

   `https://aivory.net/coffee/receipt?session_id={CHECKOUT_SESSION_ID}`

7. Route the Worker under `aivory.net/coffee/receipt`. See the comment in `wrangler.toml`.
8. Deploy when ready:

   ```sh
   npx wrangler deploy
   ```

## Checks

```sh
npm run typecheck   # tsc --noEmit
npm test            # vitest, Stripe is mocked
```

`test/fixture-receipt.json` holds a public key and a code from a test key. The
Rust side can use it to test `verify_with_key`. It is not a production key.
