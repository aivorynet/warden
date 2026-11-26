// Token detectors and masking. Pure functions, no browser APIs.

export type Provider = "gitlab" | "cloudflare" | "openai" | "aws" | "github" | "other";

export interface Candidate {
  /** The token text. Keep it in memory only. */
  value: string;
  provider: Provider;
  /** Short kind, for example "GitLab personal access token". */
  kind: string;
}

const MAX_TEXT = 2_000_000;
const NOT_TOKEN_CHAR = "[A-Za-z0-9_-]";

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Map a page host name to a provider hint. */
export function providerFromHost(hostname: string): Provider {
  const h = hostname.toLowerCase();
  const is = (d: string) => h === d || h.endsWith(`.${d}`);
  if (is("gitlab.com")) return "gitlab";
  if (is("cloudflare.com")) return "cloudflare";
  if (is("openai.com")) return "openai";
  if (is("aws.amazon.com") || is("amazonaws.com")) return "aws";
  if (is("github.com")) return "github";
  return "other";
}

const KNOWN_PREFIXES = ["glpat-", "sk-admin-", "sk-proj-", "sk-svcacct-", "sk-", "ghp_", "github_pat_", "AKIA"];

/**
 * Mask a value. Show a known prefix and the last 4 characters.
 * A value shorter than 12 characters shows only bullets.
 */
export function maskValue(value: string): string {
  if (value.length < 12) return "•".repeat(Math.max(value.length, 4));
  const prefix = KNOWN_PREFIXES.find((p) => value.startsWith(p) && value.length >= p.length + 8) ?? "";
  const middle = value.length - prefix.length - 4;
  return `${prefix}${"•".repeat(Math.min(middle, 16))}${value.slice(-4)}`;
}

/** Mask an AWS pair "ACCESS:SECRET". Show the access key prefix and the last 4 of the secret. */
export function maskPair(value: string): string {
  const i = value.indexOf(":");
  if (i < 0) return maskValue(value);
  const id = value.slice(0, i);
  const secret = value.slice(i + 1);
  return `${id.slice(0, 4)}••••••••:${"•".repeat(12)}${secret.slice(-4)}`;
}

function classes(s: string): number {
  return [/[a-z]/, /[A-Z]/, /[0-9]/].filter((r) => r.test(s)).length;
}

function matches(text: string, re: RegExp): string[] {
  return [...text.matchAll(re)].map((m) => m[0]);
}

function findAws(text: string): Candidate[] {
  const out: Candidate[] = [];
  const idRe = new RegExp(`(?<!${NOT_TOKEN_CHAR})AKIA[0-9A-Z]{16}(?!${NOT_TOKEN_CHAR})`, "g");
  for (const m of text.matchAll(idRe)) {
    const id = m[0];
    const at = m.index ?? 0;
    const near = text.slice(Math.max(0, at - 400), at + 400);
    const secret = matches(near, /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g).find(
      (s) => classes(s) >= 2 && entropy(s) >= 4.0,
    );
    if (secret) out.push({ value: `${id}:${secret}`, provider: "aws", kind: "AWS access key and secret" });
    else out.push({ value: id, provider: "aws", kind: "AWS access key ID (secret not found)" });
  }
  return out;
}

/**
 * Find token-shaped strings in `text`. `hostname` comes from the browser, never from the page.
 */
export function detectTokens(text: string, hostname: string): Candidate[] {
  const t = text.slice(0, MAX_TEXT);
  const found: Candidate[] = [];
  const add = (re: RegExp, provider: Provider, kind: string) => {
    for (const value of matches(t, re)) found.push({ value, provider, kind });
  };

  // Newer GitLab tokens end in `.<version>.<checksum>`, for example `glpat-<payload>.01.<9 chars>`.
  add(
    new RegExp(
      `(?<!${NOT_TOKEN_CHAR})glpat-[A-Za-z0-9_-]{20,}(?:\\.[0-9a-z]{2}\\.[0-9a-z]{6,12})?(?!${NOT_TOKEN_CHAR}|\\.[0-9a-z])`,
      "g",
    ),
    "gitlab",
    "GitLab access token",
  );
  add(
    new RegExp(`(?<![A-Za-z0-9])sk-(?:admin-|proj-|svcacct-)?[A-Za-z0-9_-]{20,}(?!${NOT_TOKEN_CHAR})`, "g"),
    "openai",
    "OpenAI API key",
  );
  add(new RegExp(`(?<!${NOT_TOKEN_CHAR})ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9])`, "g"), "github", "GitHub personal access token");
  add(new RegExp(`(?<!${NOT_TOKEN_CHAR})github_pat_[A-Za-z0-9_]{50,}(?!${NOT_TOKEN_CHAR})`, "g"), "github", "GitHub fine-grained token");
  found.push(...findAws(t));

  const host = hostname.toLowerCase();
  if (host === "dash.cloudflare.com") {
    const re = new RegExp(`(?<!${NOT_TOKEN_CHAR})${NOT_TOKEN_CHAR}{40}(?!${NOT_TOKEN_CHAR})`, "g");
    for (const value of matches(t, re)) {
      if (classes(value) >= 2 && entropy(value) >= 3.5 && !value.includes("--")) {
        found.push({ value, provider: "cloudflare", kind: "Cloudflare API token" });
      }
    }
  }

  const known = found.map((c) => c.value);
  const genericRe = /(?<![A-Za-z0-9_\-+/=.:])[A-Za-z0-9_\-+/=]{32,256}(?![A-Za-z0-9_\-+/=.])/g;
  for (const value of matches(t, genericRe)) {
    if (known.some((k) => k.includes(value) || value.includes(k))) continue;
    if (/^[0-9a-fA-F]+$/.test(value)) continue;
    if (classes(value) < 2 || entropy(value) < 4.2) continue;
    found.push({ value, provider: providerFromHost(host), kind: "High-entropy string" });
  }

  const seen = new Set<string>();
  return found.filter((c) => !seen.has(c.value) && seen.add(c.value));
}

/**
 * Candidates for text that the user selected. A selection with no known pattern still counts
 * as one "selection" candidate, because the user chose it.
 */
export function detectSelection(selection: string, hostname: string): Candidate[] {
  const hits = detectTokens(selection, hostname);
  if (hits.length > 0) return hits;
  const v = selection.trim();
  if (v.length >= 8 && v.length <= 512 && !/\s/.test(v)) {
    return [{ value: v, provider: providerFromHost(hostname), kind: "Selected text" }];
  }
  return [];
}

/** Default item name from a provider hint. */
export function defaultLabel(provider: Provider): string {
  return provider === "other" ? "token" : `${provider}-token`;
}
