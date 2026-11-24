import { describe, expect, it } from "vitest";
import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { handleRequest, type Env } from "../src/index";

const here = dirname(fileURLToPath(import.meta.url));
const CODE_PATTERN = /aivw-receipt-[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;

function makeKeys() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url");
  return { pkcs8, raw };
}

function publicKeyFromRaw(raw: Buffer) {
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") }, format: "jwk" });
}

/** Split a code into payload bytes and signature bytes, and verify the signature. */
function verifyCode(code: string, raw: Buffer): { ok: boolean; payload: Record<string, unknown> } {
  const rest = code.slice("aivw-receipt-".length);
  const [payloadB64, sigB64] = rest.split(".");
  const payloadBytes = Buffer.from(payloadB64, "base64url");
  const sig = Buffer.from(sigB64, "base64url");
  const ok = verify(null, payloadBytes, publicKeyFromRaw(raw), sig);
  return { ok, payload: JSON.parse(payloadBytes.toString("utf8")) };
}

function stripeFetch(session: Record<string, unknown> | null, status = 200): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    expect(url).toMatch(/^https:\/\/api\.stripe\.com\/v1\/checkout\/sessions\/cs_/);
    expect((init?.headers as Record<string, string>).Authorization).toBe("Bearer sk_test_mock");
    if (session === null) {
      return new Response("{}", { status: status });
    }
    return new Response(JSON.stringify(session), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
}

function envFor(pkcs8: string): Env {
  return { STRIPE_SECRET_KEY: "sk_test_mock", RECEIPT_SIGNING_KEY: pkcs8 };
}

describe("GET /coffee/receipt", () => {
  it("returns a signed code for a paid session that verifies with the matching key", async () => {
    const { pkcs8, raw } = makeKeys();
    const created = Date.UTC(2026, 10, 24, 9, 30, 0) / 1000;
    const session = { id: "cs_test_abc123", payment_status: "paid", created };
    const req = new Request("https://aivory.net/coffee/receipt?session_id=cs_test_abc123");

    const res = await handleRequest(req, envFor(pkcs8), stripeFetch(session));

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    const html = await res.text();
    const match = html.match(CODE_PATTERN);
    expect(match).not.toBeNull();
    const code = match![0];
    expect(html).toContain(`aivory-warden://receipt/${code}`);

    const { ok, payload } = verifyCode(code, raw);
    expect(ok).toBe(true);
    expect(payload.year).toBe(2026);
    expect(payload.receipt_id).toBe("cs_test_abc123");
    expect(typeof payload.issued).toBe("string");
    expect(payload.issued as string).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(Object.keys(payload)).toEqual(["year", "receipt_id", "issued"]);
  });

  it("uses the UTC year of the session creation time", async () => {
    const { pkcs8, raw } = makeKeys();
    // 2026-12-31 23:30 UTC is still 2026 in UTC, so use the first second of 2027 UTC.
    const created = Date.UTC(2027, 0, 1, 0, 0, 1) / 1000;
    const session = { id: "cs_test_newyear", payment_status: "paid", created };
    const req = new Request("https://aivory.net/coffee/receipt?session_id=cs_test_newyear");

    const html = await (await handleRequest(req, envFor(pkcs8), stripeFetch(session))).text();
    const { ok, payload } = verifyCode(html.match(CODE_PATTERN)![0], raw);
    expect(ok).toBe(true);
    expect(payload.year).toBe(2027);
  });

  it("returns 402 for an unpaid session", async () => {
    const { pkcs8 } = makeKeys();
    const session = { id: "cs_test_open", payment_status: "unpaid", created: 1800000000 };
    const req = new Request("https://aivory.net/coffee/receipt?session_id=cs_test_open");

    const res = await handleRequest(req, envFor(pkcs8), stripeFetch(session));

    expect(res.status).toBe(402);
    expect(await res.text()).not.toMatch(CODE_PATTERN);
  });

  it("returns 400 when session_id is missing", async () => {
    const { pkcs8 } = makeKeys();
    const req = new Request("https://aivory.net/coffee/receipt");
    let called = false;
    const fetchImpl = (async () => {
      called = true;
      return new Response("{}");
    }) as typeof fetch;

    const res = await handleRequest(req, envFor(pkcs8), fetchImpl);

    expect(res.status).toBe(400);
    expect(called).toBe(false);
  });

  it("returns 400 for a malformed session_id without calling Stripe", async () => {
    const { pkcs8 } = makeKeys();
    const req = new Request("https://aivory.net/coffee/receipt?session_id=..%2Fevil");
    const res = await handleRequest(req, envFor(pkcs8), stripeFetch(null));
    expect(res.status).toBe(400);
  });

  it("returns 404 for other paths", async () => {
    const { pkcs8 } = makeKeys();
    const req = new Request("https://aivory.net/other?session_id=cs_test_x");
    const res = await handleRequest(req, envFor(pkcs8), stripeFetch(null));
    expect(res.status).toBe(404);
  });
});

describe("test/fixture-receipt.json", () => {
  it("contains a code that verifies with its public key", () => {
    const fixture = JSON.parse(readFileSync(resolve(here, "fixture-receipt.json"), "utf8")) as {
      public_key_hex: string;
      code: string;
    };
    const raw = Buffer.from(fixture.public_key_hex, "hex");
    expect(raw.length).toBe(32);
    expect(verifyCode(fixture.code, raw).ok).toBe(true);
  });
});
