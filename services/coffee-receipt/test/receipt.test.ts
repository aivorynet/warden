import { describe, expect, it } from "vitest";
import { createHmac, createPublicKey, generateKeyPairSync, verify } from "node:crypto";
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

class MemoryKv {
  store = new Map<string, string>();
  puts: { key: string; opts?: { expirationTtl?: number } }[] = [];
  async get(key: string) {
    return this.store.get(key) ?? null;
  }
  async put(key: string, value: string, opts?: { expirationTtl?: number }) {
    this.puts.push({ key, opts });
    this.store.set(key, value);
  }
}

const WHSEC = "whsec_test_secret";

function envFor(pkcs8: string, kv: MemoryKv = new MemoryKv()): Env {
  return {
    STRIPE_SECRET_KEY: "sk_test_mock",
    RECEIPT_SIGNING_KEY: pkcs8,
    STRIPE_WEBHOOK_SECRET: WHSEC,
    CLAIMS: kv as unknown as KVNamespace,
  };
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

const CLAIM = "aivw-c-0123456789abcdef0123456789abcdef";
const NOW_MS = Date.UTC(2026, 10, 24, 10, 0, 0);
const NOW_S = Math.floor(NOW_MS / 1000);

function sign(body: string, t: number, secret = WHSEC): string {
  return `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")}`;
}

function event(over: Record<string, unknown> = {}, type = "checkout.session.completed") {
  return {
    type,
    data: {
      object: {
        id: "cs_live_hook1",
        payment_status: "paid",
        client_reference_id: CLAIM,
        created: Date.UTC(2026, 10, 24, 9, 30, 0) / 1000,
        ...over,
      },
    },
  };
}

function hook(body: unknown, header?: string, t = NOW_S): Request {
  const raw = JSON.stringify(body);
  return new Request("https://aivory.net/coffee/webhook", {
    method: "POST",
    body: raw,
    headers: { "stripe-signature": header ?? sign(raw, t) },
  });
}

describe("POST /coffee/webhook", () => {
  it("stores a receipt under the claim id and it verifies", async () => {
    const { pkcs8, raw } = makeKeys();
    const kv = new MemoryKv();
    const res = await handleRequest(hook(event()), envFor(pkcs8, kv), fetch, NOW_MS);
    expect(res.status).toBe(200);
    const code = kv.store.get(CLAIM)!;
    expect(code).toMatch(CODE_PATTERN);
    expect(kv.puts[0].opts?.expirationTtl).toBe(90 * 86400);
    const { ok, payload } = verifyCode(code, raw);
    expect(ok).toBe(true);
    expect(payload).toEqual({ year: 2026, receipt_id: "cs_live_hook1", issued: "2026-11-24T10:00:00Z" });
  });

  it("accepts async_payment_succeeded", async () => {
    const { pkcs8 } = makeKeys();
    const kv = new MemoryKv();
    const body = event({}, "checkout.session.async_payment_succeeded");
    expect((await handleRequest(hook(body), envFor(pkcs8, kv), fetch, NOW_MS)).status).toBe(200);
    expect(kv.store.has(CLAIM)).toBe(true);
  });

  it("returns 400 for a bad signature", async () => {
    const { pkcs8 } = makeKeys();
    const kv = new MemoryKv();
    const raw = JSON.stringify(event());
    const res = await handleRequest(hook(event(), sign(raw, NOW_S, "whsec_other")), envFor(pkcs8, kv), fetch, NOW_MS);
    expect(res.status).toBe(400);
    expect(kv.store.size).toBe(0);
  });

  it("returns 400 when the signature header is missing", async () => {
    const { pkcs8 } = makeKeys();
    const req = new Request("https://aivory.net/coffee/webhook", { method: "POST", body: "{}" });
    expect((await handleRequest(req, envFor(pkcs8), fetch, NOW_MS)).status).toBe(400);
  });

  it("returns 400 for a stale timestamp", async () => {
    const { pkcs8 } = makeKeys();
    const kv = new MemoryKv();
    const res = await handleRequest(hook(event(), undefined, NOW_S - 301), envFor(pkcs8, kv), fetch, NOW_MS);
    expect(res.status).toBe(400);
    expect(kv.store.size).toBe(0);
  });

  it("ignores an unpaid session", async () => {
    const { pkcs8 } = makeKeys();
    const kv = new MemoryKv();
    const res = await handleRequest(hook(event({ payment_status: "unpaid" })), envFor(pkcs8, kv), fetch, NOW_MS);
    expect(res.status).toBe(200);
    expect(kv.store.size).toBe(0);
  });

  it("ignores other event types", async () => {
    const { pkcs8 } = makeKeys();
    const kv = new MemoryKv();
    const res = await handleRequest(hook(event({}, "charge.refunded")), envFor(pkcs8, kv), fetch, NOW_MS);
    expect(res.status).toBe(200);
    expect(kv.store.size).toBe(0);
  });

  it("ignores a client_reference_id without the claim format (Hopover)", async () => {
    const { pkcs8 } = makeKeys();
    const kv = new MemoryKv();
    for (const ref of ["hopover-123", null, "aivw-c-XYZ", CLAIM.toUpperCase()]) {
      const res = await handleRequest(hook(event({ client_reference_id: ref })), envFor(pkcs8, kv), fetch, NOW_MS);
      expect(res.status).toBe(200);
    }
    expect(kv.store.size).toBe(0);
  });

  it("does not overwrite an existing receipt of the same year", async () => {
    const { pkcs8 } = makeKeys();
    const kv = new MemoryKv();
    const env = envFor(pkcs8, kv);
    await handleRequest(hook(event()), env, fetch, NOW_MS);
    const first = kv.store.get(CLAIM);
    const res = await handleRequest(hook(event({ id: "cs_live_hook2" })), env, fetch, NOW_MS + 5000);
    expect(res.status).toBe(200);
    expect(kv.store.get(CLAIM)).toBe(first);
    expect(kv.puts.length).toBe(1);
  });
});

describe("GET /coffee/claim/<id>", () => {
  const get = (id: string) => new Request(`https://aivory.net/coffee/claim/${id}`);

  it("returns 404 before, 200 after a webhook, 400 for a bad id", async () => {
    const { pkcs8, raw } = makeKeys();
    const kv = new MemoryKv();
    const env = envFor(pkcs8, kv);

    const miss = await handleRequest(get(CLAIM), env, fetch, NOW_MS);
    expect(miss.status).toBe(404);
    expect(await miss.json()).toEqual({ error: "not_found" });
    expect(miss.headers.get("cache-control")).toBe("no-store");

    await handleRequest(hook(event()), env, fetch, NOW_MS);
    const hit = await handleRequest(get(CLAIM), env, fetch, NOW_MS);
    expect(hit.status).toBe(200);
    expect(hit.headers.get("cache-control")).toBe("no-store");
    const { code } = (await hit.json()) as { code: string };
    expect(verifyCode(code, raw).ok).toBe(true);

    const bad = await handleRequest(get("aivw-c-short"), env, fetch, NOW_MS);
    expect(bad.status).toBe(400);
    expect(await bad.json()).toEqual({ error: "bad_request" });
    expect(bad.headers.get("cache-control")).toBe("no-store");
  });
});
