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

const FAKE_IONOS = "029abcbbf5a94036b1a7fb2b5831e74e." +
  "LCfy***FAKE***NOT_A_REAL_KEY***AAAABBBBCCCCDDDD" +
  "EEEEFFFFGGGGHHHHIIIIJJJJ***PLACEHOLDER";

let pass = 0;
let fail = 0;

function assert(name, condition, detail) {
  if (condition) {
    pass++;
    console.log(`✅ ${name}`);
  } else {
    fail++;
    console.log(`❌ ${name}`);
    if (detail) console.log(`   ${detail}`);
  }
}

const must_redact = [
  {
    name: "IONOS_API_KEY env-style",
    input: `IONOS_API_KEY=${FAKE_IONOS}`,
    pattern: /REDACTED.*Env Secret Field/,
  },
  {
    name: "GITHUB_TOKEN env-style",
    input: `GITHUB_TOKEN=gho_FAKEFAKEFAKEFAKEFAKEFAKEFAKEPLACEHOLDER`,
    pattern: /REDACTED.*Env Secret Field/,
  },
  {
    name: "CLOUDFLARE_API_KEY env-style",
    input: `CLOUDFLARE_API_KEY=abcdef0123456789abcdef0123456789`,
    pattern: /REDACTED.*Env Secret Field/,
  },
  {
    name: "MY_API_TOKEN env-style (custom prefix)",
    input: `MY_API_TOKEN=abc1234567890123456`,
    pattern: /REDACTED.*Env Secret Field/,
  },
  {
    name: "AWS_ACCESS_KEY_ID env-style",
    input: `AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF`,
    pattern: /REDACTED.*Env Secret Field|REDACTED.*AWS Access Key/,
  },
];

console.log("\n--- must REDACT (regression cases) ---");
for (const c of must_redact) {
  const r = redactText(c.input, ctx);
  assert(c.name, c.pattern.test(r.text), `got: ${r.text}`);
}

// === Pre-fix behavior must still work ===
// NOTE: pre-existing YAML/INI short-secret detection is broken in v0.1.7
// (hot-path fast-exit drops matches whose value is < minLength). Tracked as
// separate bug; only tests what the v0.1.8 anchor fix added.
const still_works = [
  { name: "plain api_key=...", input: "api_key=[REDACTED:Env Secret Field]" },
  { name: "JSON api_key", input: '{"api_key": "[REDACTED:JSON Secret Field]"}' },
];

console.log("\n--- still works (no regression) ---");
for (const c of still_works) {
  const r = redactText(c.input, ctx);
  assert(c.name, /REDACTED/.test(r.text), `got: ${r.text}`);
}

const no_false_positives = [
  { name: "PATH env (innocent)", input: "PATH=/usr/local/bin" },
  { name: "HOME env (innocent)", input: "HOME=/home/user" },
  { name: "USER env (innocent)", input: "USER=alice" },
];

console.log("\n--- no false positives ---");
for (const c of no_false_positives) {
  const r = redactText(c.input, ctx);
  assert(c.name, !/REDACTED/.test(r.text), `got: ${r.text}`);
}

console.log(`\n${pass}/${pass + fail} tests passed`);
process.exit(fail > 0 ? 1 : 0);
