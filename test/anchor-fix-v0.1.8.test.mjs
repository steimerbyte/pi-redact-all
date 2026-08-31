// Regression test for v0.1.8 anchor fix in Layer 6.
//
// Bug: ENV_SECRET_PATTERN used `(?:^|[^A-Za-z0-9_])` as anchor. The
// character class excludes `_`, which is a WORD char in regex semantics.
// That meant any ENV-style variable name with one-or-more underscores BEFORE
// the SECRET_FIELD_NAMES suffix was silently miss-detected. Examples that
// slipped through before the fix:
//   IONOS_API_KEY=...
//   GITHUB_TOKEN=...
//   CLOUDFLARE_API_KEY=...
//   MY_API_TOKEN=...
// Fix: anchor now `\b|(?<=[A-Z0-9_])` — word-boundary OR lookbehind for a
// preceding WORD char (UPPER/UNDERSCORE) of an ENV-Var word-run.
//
// NOTE: All test values are clearly fake placeholders.

import { redactText } from "../dist/layers/index.js";
import { DEFAULT_CONFIG } from "../dist/config.js";

const ctx = {
  config: { ...DEFAULT_CONFIG },
  partialPrivateKeyPaths: new Set(),
};

// Values >= 32 chars (minLength filter) so they pass the hot-path fast-exit
const FAKE_IONOS =
  "029abcbbf5a94036b1a7fb2b5831e74e." +
  "LCfyFAKE01AAAABBBBCCCCDDDD" +
  "EEEEFFFFGGGGHHHHIIIIJJJJ";

let pass = 0;
let fail = 0;

function assert(name, condition, detail) {
  if (condition) {
    pass++;
    console.log("PASS: " + name);
  } else {
    fail++;
    console.log("FAIL: " + name);
    if (detail) console.log("   " + detail);
  }
}

// Tokens >= 32 chars so they survive the minLength fast-path in index.ts
const must_redact = [
  {
    name: "IONOS_API_KEY env-style",
    input: "IONOS_API_KEY=029abcbbf5a94036b1a7fb2b5831e74e.LCfyFAKE01AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ",
    pattern: /\[REDACTED:.*?\]/,
  },
  {
    name: "GITHUB_TOKEN env-style",
    // ghx_ avoids ghp_ prefix so Layer-3 prefix masking doesn't interfere
    input: "GH_TOKEN=ghx_FAKEFAKEFAKEFAKEFAKEFAKEPLACEHOLDER",
    pattern: /\[REDACTED:.*?\]/,
  },
  {
    name: "CLOUDFLARE_API_KEY env-style",
    input: "CLOUDFLARE_API_KEY=abc123def456ghi789jkl012mnof345pqrs678stu901vwxy234zAB",
    pattern: /\[REDACTED:.*?\]/,
  },
  {
    name: "MY_API_TOKEN env-style (custom prefix)",
    input: "MY_API_TOKEN=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
    pattern: /\[REDACTED:.*?\]/,
  },
  {
    name: "AWS_ACCESS_KEY_ID env-style",
    input: "AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF",
    pattern: /\[REDACTED:.*?\]/,
  },
];

console.log("\n--- must REDACT (regression cases) ---");
for (const c of must_redact) {
  const r = redactText(c.input, ctx);
  assert(c.name, c.pattern.test(r.text), "got: " + r.text);
}

// === Pre-fix behavior must still work ===
const still_works = [
  { name: "plain api_key=...", input: "api_key=[REDACTED:Env Secret Field]" },
  { name: "JSON api_key", input: '{"api_key": "[REDACTED:JSON Secret Field]"}' },
];

console.log("\n--- still works (no regression) ---");
for (const c of still_works) {
  const r = redactText(c.input, ctx);
  assert(c.name, /REDACTED/.test(r.text), "got: " + r.text);
}

const no_false_positives = [
  { name: "PATH env (innocent)", input: "PATH=/usr/local/bin" },
  { name: "HOME env (innocent)", input: "HOME=/home/user" },
  { name: "USER env (innocent)", input: "USER=alice" },
];

console.log("\n--- no false positives ---");
for (const c of no_false_positives) {
  const r = redactText(c.input, ctx);
  assert(c.name, !/REDACTED/.test(r.text), "got: " + r.text);
}

console.log("\n" + pass + "/" + (pass + fail) + " tests passed");
process.exit(fail > 0 ? 1 : 0);
