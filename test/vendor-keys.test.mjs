// Regression: VENDOR_API_KEY-style secrets (with `_` separator) must be redacted
// after the Layer-6 boundary fix (`[^A-Za-z0-9_]` -> `[^A-Za-z0-9]`) plus the two
// new SECRET_FIELD_NAMES (`secret_access_key`, `access_key`, `access_key_id`).
// Boundary cases must NOT be false-positive.
//
// NOTE: all secret values are clearly-fake PLACEHOLDERS — never real-looking secrets.
// Tests import the built dist (../dist/...) — run `npm run build` before `npm test`.
// Tests import the built dist (../dist/...) — run `npm run build` before `npm test`.
// Run with: node test/vendor-keys.test.mjs
import { redactText } from "../dist/layers/index.js";
import { DEFAULT_CONFIG } from "../dist/config.js";

const baseCtx = () => ({
  config: { ...DEFAULT_CONFIG },
  partialPrivateKeyPaths: new Set(),
});

// Pad to >= 32 chars so the minLength hot-path guard does not short-circuit the detector.
const pad = (s) =>
  s.length >= 32 ? s : s + " ".repeat(32 - s.length) + " (padding)";

let pass = 0;
let fail = 0;
const ok = (desc, cond) => {
  if (cond) {
    pass++;
    console.log("PASS  " + desc);
  } else {
    fail++;
    console.log("FAIL  " + desc);
  }
};

// --- 5 MISSED samples from issue #8 (must now be redacted) ---
const MISSED = [
  ["OPENAI_API_KEY", "sk-" + "a".repeat(40)],
  ["ANTHROPIC_API_KEY", "sk-ant-" + "b".repeat(40)],
  ["AWS_SECRET_ACCESS_KEY", "wJal" + "c".repeat(36)],
  ["GOOGLE_API_KEY", "AIza" + "Sy" + "z".repeat(38)],
  ["QWEN_API_KEY", "sk-qw" + "e".repeat(37)],
  // user-supplied AWS-style access key id value (T0qmYAsPJ3p7sJGe)
  ["AWS_ACCESS_KEY_ID", "T0qmYAsPJ3p7sJGe"],
];

for (const [name, value] of MISSED) {
  const input = pad(name + "=" + value);
  const { matches, text } = redactText(input, baseCtx());
  ok(
    "MISSED " + name + " redacted",
    matches.length > 0 && text.includes("[REDACTED"),
  );
}

// --- Boundary cases that must NOT be redacted (anti false-positive) ---
const NO_MATCH = [
  ["readapi_key no separator", "readapi_key=12345678"],
  ["prose without =", "this is a prose about api_keys without equals sign padded enough to exceed the minimum length guard here please"],
  ["VENDOR_API_KEY no value", "VENDOR_API_KEY and then some prose to push the text length beyond the thirty two character minimum needed"],
  ["short value <8", "PREFIX_API_KEY=abc"],
];

for (const [desc, input] of NO_MATCH) {
  const { matches } = redactText(pad(input), baseCtx());
  ok("boundary " + desc + " NOT redacted", matches.length === 0);
}

// text < minLength(32) must short-circuit (no redaction)
{
  const input = "x some_api_key=" + "d".repeat(10); // < 32 chars
  const { matches } = redactText(input, baseCtx());
  ok("short text < minLength NOT redacted", matches.length === 0);
}

console.log("\n" + pass + "/" + (pass + fail) + " tests passed");
process.exit(fail > 0 ? 1 : 0);
