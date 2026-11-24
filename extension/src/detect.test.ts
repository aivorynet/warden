import { test } from "node:test";
import assert from "node:assert/strict";
import { defaultLabel, detectSelection, detectTokens, maskPair, maskValue, providerFromHost } from "./detect.js";

// Synthetic fixtures only. None of these is a real token.
const GL = "glpat-" + "Ab3dE6gH9jK2mN5pQ7xZ";
const OAI = "sk-proj-" + "Zx9Qw3Er7Ty1Ui5Op2As4Df6Gh8Jk0Lq";
const OAI_ADMIN = "sk-admin-" + "Zx9Qw3Er7Ty1Ui5Op2As4Df6Gh8Jk0Lq";
const OAI_OLD = "sk-" + "Zx9Qw3Er7Ty1Ui5Op2As4Df6Gh8Jk0Lq";
const GHP = "ghp_" + "aB3dE6gH9jK2mN5pQ7xZ1cV4bN8mL0qW2eRt";
const GHPAT = "github_pat_" + "11ABCDEFG0aB3dE6gH9jK2_mN5pQ7xZ1cV4bN8mL0qW2eRtYuIoPaSdFgHjKlZxCvBn";
const AKIA = "AKIA" + "IOSFODNN7EXAMPLE";
const AWS_SECRET = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCYEXAMPLEKEY";
const CF = "aB3dE6gH9jK2mN5pQ7xZ1cV4bN8mL0qW2eRt_-Yu";

test("gitlab token", () => {
  const r = detectTokens(`Your token: ${GL} copy it`, "gitlab.com");
  assert.equal(r.length, 1);
  assert.equal(r[0]?.provider, "gitlab");
  assert.equal(r[0]?.value, GL);
});

test("openai variants", () => {
  for (const k of [OAI, OAI_ADMIN, OAI_OLD]) {
    const r = detectTokens(`key=${k}`, "platform.openai.com");
    assert.equal(r.length, 1, k);
    assert.equal(r[0]?.provider, "openai");
    assert.equal(r[0]?.value, k);
  }
});

test("github tokens", () => {
  assert.equal(detectTokens(GHP, "github.com")[0]?.provider, "github");
  assert.equal(detectTokens(GHPAT, "github.com")[0]?.value, GHPAT);
});

test("aws pair and lone id", () => {
  const pair = detectTokens(`Access key ID ${AKIA}\nSecret access key ${AWS_SECRET}`, "console.aws.amazon.com");
  assert.equal(pair.length, 1);
  assert.equal(pair[0]?.value, `${AKIA}:${AWS_SECRET}`);
  const lone = detectTokens(`id ${AKIA}`, "console.aws.amazon.com");
  assert.equal(lone[0]?.value, AKIA);
  assert.match(lone[0]?.kind ?? "", /secret not found/);
});

test("cloudflare 40-char token only on dash.cloudflare.com", () => {
  assert.equal(CF.length, 40);
  const on = detectTokens(`token ${CF}`, "dash.cloudflare.com");
  assert.equal(on[0]?.provider, "cloudflare");
  const off = detectTokens(`token ${CF}`, "example.com");
  assert.ok(off.every((c) => c.provider !== "cloudflare"));
});

test("generic high-entropy fallback", () => {
  const v = "q8Zr2Lm9XvB4nT7yKc1WpS6dHj3GfA5e";
  const r = detectTokens(`secret ${v}`, "example.com");
  assert.equal(r[0]?.value, v);
  assert.equal(r[0]?.provider, "other");
});

test("no false positives on plain text, hex hash, long word, url", () => {
  const text = [
    "The quick brown fox jumps over the lazy dog and keeps running far away",
    "d41d8cd98f00b204e9800998ecf8427e",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "https://example.com/some/long/path/segment/that/goes-on-and-on-forever",
    "internationalization_and_localization_support_module",
  ].join("\n");
  assert.deepEqual(detectTokens(text, "example.com"), []);
});

test("duplicates collapse", () => {
  assert.equal(detectTokens(`${GL} ${GL}`, "gitlab.com").length, 1);
});

test("selection falls back to the selected word", () => {
  assert.equal(detectSelection("  hunter2hunter2  ", "example.com")[0]?.value, "hunter2hunter2");
  assert.deepEqual(detectSelection("two words here", "example.com"), []);
  assert.equal(detectSelection(GL, "gitlab.com")[0]?.provider, "gitlab");
});

test("mask shows prefix and last 4 only", () => {
  const m = maskValue(GL);
  assert.ok(m.startsWith("glpat-"));
  assert.ok(m.endsWith(GL.slice(-4)));
  assert.ok(!m.includes(GL.slice(8, 16)));
  assert.equal(maskValue(OAI_ADMIN).startsWith("sk-admin-"), true);
});

test("mask hides short values and never leaks the middle", () => {
  assert.ok(!maskValue("abcd1234").includes("abcd"));
  const v = "x".repeat(10) + "SECRETMIDDLE" + "y".repeat(10) + "7Qx2";
  const m = maskValue(v);
  assert.ok(m.endsWith("7Qx2"));
  assert.ok(!m.includes("SECRET"));
});

test("pair mask", () => {
  const m = maskPair(`${AKIA}:${AWS_SECRET}`);
  assert.ok(m.endsWith(AWS_SECRET.slice(-4)));
  assert.ok(!m.includes(AWS_SECRET.slice(0, 20)));
  assert.ok(!m.includes(AKIA.slice(4)));
});

test("provider hints", () => {
  assert.equal(providerFromHost("gitlab.com"), "gitlab");
  assert.equal(providerFromHost("evilgitlab.com"), "other");
  assert.equal(providerFromHost("dash.cloudflare.com"), "cloudflare");
  assert.equal(providerFromHost("platform.openai.com"), "openai");
  assert.equal(defaultLabel("gitlab"), "gitlab-token");
  assert.equal(defaultLabel("other"), "token");
});
