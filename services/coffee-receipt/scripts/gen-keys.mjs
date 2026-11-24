// Generate an Ed25519 key pair for coffee receipts.
// Usage: node scripts/gen-keys.mjs
// Prints the PKCS8 private key (for `wrangler secret put RECEIPT_SIGNING_KEY`)
// and the raw 32-byte public key as a Rust array (for PRODUCTION_PUBLIC_KEY).
import { generateKeyPairSync } from "node:crypto";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");

const pkcs8Base64 = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");

// The JWK "x" member is the raw 32-byte Ed25519 public key in base64url.
const { x } = publicKey.export({ format: "jwk" });
const raw = Buffer.from(x, "base64url");
if (raw.length !== 32) {
  throw new Error(`unexpected public key length: ${raw.length}`);
}
const rustBytes = Array.from(raw, (b) => `0x${b.toString(16).padStart(2, "0")}`).join(", ");

console.log("# Private key: run `npx wrangler secret put RECEIPT_SIGNING_KEY` and paste this line.");
console.log(pkcs8Base64);
console.log("");
console.log("# Public key: replace PRODUCTION_PUBLIC_KEY in crates/warden-coffee/src/lib.rs with:");
console.log(`pub const PRODUCTION_PUBLIC_KEY: [u8; 32] = [${rustBytes}];`);
