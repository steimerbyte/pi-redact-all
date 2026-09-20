// IONOS API Token tests for pi-redact-all
//
// Format: `<32-hex public id>.<base64url signature>`
// Example provided by user: 5bf71ccd4cff40179dc99971cdbbb5a4.sSUUvLUW8JEosSOI8wJKqpne3-Y9Oe1277yZfMiDbRKyWBSvpDoxlQAm033PD_25LtzbE94fSF4YDa9iD6TsYQ

import { redactText } from "../dist/layers/index.js";
import { applyRedaction } from "../dist/hooks/tool-result.js";
import { DEFAULT_CONFIG } from "../dist/config.js";

let pass = 0;
let fail = 0;
const ctx = () => ({ config: { ...DEFAULT_CONFIG }, partialPrivateKeyPaths: new Set() });

function assert(name, cond, detail) {
  if (cond) console.log(`✅ ${name}`);
  else {
    console.log(`❌ FAIL: ${name}` + (detail ? ` -- ${detail}` : ""));
    return false;
  }
  return true;
}

function ok(cond, name, detail) {
  if (assert(name, cond, detail)) pass++;
  else fail++;
}

// Synthetic valid IONOS tokens
// Public prefix: 32 lowercase hex chars. Signature: 32-100 chars URL-safe base64 (A-Z, a-z, 0-9, '-', '_').
// Use repeat() to get exact lengths — hand-counted strings are easy to miscount.
const SIG_88 = "aZ" + "9b".repeat(43);
const SIG_44 = "aZ" + "9b".repeat(21);
const SIG_32 = "aZ" + "9b".repeat(15);
console.assert(SIG_88.length === 88, `SIG_88 should be 88 chars, got ${SIG_88.length}`);
console.assert(SIG_44.length === 44, `SIG_44 should be 44 chars, got ${SIG_44.length}`);
console.assert(SIG_32.length === 32, `SIG_32 should be 32 chars, got ${SIG_32.length}`);

const IONOS_USER_KEY = `5bf71ccd4cff40179dc99971cdbbb5a4.${SIG_88}`;
const IONOS_SHORT_SIG = `5bf71ccd4cff40179dc99971cdbbb5a4.${SIG_44}`;
const IONOS_MIN_SIG = `5bf71ccd4cff40179dc99971cdbbb5a4.${SIG_32}`;
const IONOS_OTHER_PREFIX = `abcdef0123456789abcdef0123456789.${SIG_88}`;
console.assert(IONOS_USER_KEY.length === 121, `user key 121 chars, got ${IONOS_USER_KEY.length}`);
console.assert(IONOS_OTHER_PREFIX.length === 121, `other key 121 chars, got ${IONOS_OTHER_PREFIX.length}`);
const IONOS_UPPER = `5BF71CCD4CFF40179DC99971CDBBB5A4.${SIG_88}`;

// 1. The user's exact key in prose
{
  const padded = `api key is ${IONOS_USER_KEY}` + " ".repeat(Math.max(0, 64 - IONOS_USER_KEY.length));
  const r = redactText(padded, ctx());
  ok(r.text.includes("[REDACTED:IONOS API Token]"), "user-provided IONOS key in prose redacted");
  ok(r.matches.some((m) => m.type === "IONOS API Token"), "user-provided IONOS key type is 'IONOS API Token'");
  ok(!r.text.includes(IONOS_USER_KEY), "user-provided original IONOS key not in output");
}

// 2. Shorter signature (44 chars — HMAC-SHA256 base64url)
{
  const padded = `key=${IONOS_SHORT_SIG}` + " ".repeat(Math.max(0, 64 - IONOS_SHORT_SIG.length));
  const r = redactText(padded, ctx());
  ok(r.text.includes("[REDACTED:IONOS API Token]"), "IONOS key with 44-char signature redacted");
}

// 3. Minimum signature length (32 chars)
{
  const padded = `key=${IONOS_MIN_SIG}` + " ".repeat(Math.max(0, 64 - IONOS_MIN_SIG.length));
  const r = redactText(padded, ctx());
  ok(r.text.includes("[REDACTED:IONOS API Token]"), "IONOS key with 32-char signature (min) redacted");
}

// 4. Different public prefix
{
  const padded = `cred: ${IONOS_OTHER_PREFIX}` + " ".repeat(Math.max(0, 64 - IONOS_OTHER_PREFIX.length));
  const r = redactText(padded, ctx());
  ok(r.text.includes("[REDACTED:IONOS API Token]"), "IONOS key with different prefix redacted");
}

// 5. JSON-wrapped token
{
  const input = JSON.stringify({
    token: IONOS_USER_KEY,
    type: "ionos-api",
  });
  const r = redactText(input, ctx());
  ok(r.text.includes("[REDACTED:IONOS API Token]"), "IONOS key in JSON string redacted");
  ok(!r.text.includes(IONOS_USER_KEY), "IONOS key in JSON not in output");
}

// 6. ENV var prefix (should still be caught as IONOS — first-match wins via layering)
{
  const input = `IONOS_TOKEN=${IONOS_USER_KEY}`;
  const r = redactText(input, ctx());
  ok(r.text.includes("[REDACTED:IONOS API Token]"), "IONOS key with ENV prefix marked as IONOS API Token");
}

// 7. End-to-end via tool_result hook (real World)
{
  const event = {
    toolName: "bash",
    content: [{ type: "text", text: `output: ${IONOS_USER_KEY}\n` }],
  };
  const result = applyRedaction(event, ctx());
  const out = result.content[0].text;
  ok(out.includes("[REDACTED:IONOS API Token]"), "tool_result hook redacts IONOS key from bash output");
  ok(!out.includes(IONOS_USER_KEY), "tool_result hook does not leak IONOS key");
}

// 8. SSH-result end-to-end (the user's primary concern)
{
  const event = {
    toolName: "ssh_run",
    content: [{ type: "text", text: `Connected. Server reports: ${IONOS_USER_KEY}\n` }],
  };
  const result = applyRedaction(event, ctx());
  const out = result.content[0].text;
  ok(out.includes("[REDACTED:IONOS API Token]"), "tool_result hook redacts IONOS key from ssh output");
  ok(!out.includes(IONOS_USER_KEY), "tool_result hook does not leak IONOS key from ssh");
}

// 9. anti false-positive: UUID with dashes in prefix must NOT match
{
  const input = `uuid=12345678-1234-1234-1234-123456789012`;
  const r = redactText(input + " ".repeat(Math.max(0, 64 - input.length)), ctx());
  ok(
    !r.matches.some((m) => m.type === "IONOS API Token"),
    "UUID with dashes in prefix NOT matched as IONOS",
  );
}

// 10. anti false-positive: short hex without dot-signature NOT matched
{
  const input = `commit 5bf71ccd4cff40179dc99971cdbbb5a4`;
  const r = redactText(input + " ".repeat(Math.max(0, 64 - input.length)), ctx());
  ok(
    !r.matches.some((m) => m.type === "IONOS API Token"),
    "32-hex without dot-signature NOT matched as IONOS",
  );
}

// 11. anti false-positive: hex followed by base64url without dot NOT matched
{
  const input = `5bf71ccd4cff40179dc99971cdbbb5a4 ${SIG_88}`;
  const r = redactText(input + " ".repeat(Math.max(0, 64 - input.length)), ctx());
  ok(
    !r.matches.some((m) => m.type === "IONOS API Token"),
    "split hex+base64url without dot NOT matched as IONOS",
  );
}

// 12. anti false-positive: signature shorter than 32 chars NOT matched
{
  const tooShort = `5bf71ccd4cff40179dc99971cdbbb5a4.shortSig`;
  const r = redactText(tooShort + " ".repeat(Math.max(0, 64 - tooShort.length)), ctx());
  ok(
    !r.matches.some((m) => m.type === "IONOS API Token"),
    "signature <32 chars NOT matched as IONOS",
  );
}

// 13. Slack-token-style prefix (uppercase hex) NOT falsely matched as IONOS
//
// IONOS public prefix is lowercase 32 hex. Uppercase hex with 32 chars (rare in
// real text but possible in URL-encoded configs) currently does NOT match the
// IONOS regex. Verify it is caught by the entropy layer instead, or by layer-1
// for whatever other pattern it matches, but NOT falsely labelled "IONOS".
{
  const padded = `key=DEADBEEFCAFEBABE1234567890ABCDEF.${SIG_88}` + " ".repeat(Math.max(0, 64 - SIG_88.length - 35));
  const r = redactText(padded, ctx());
  ok(
    !r.matches.some((m) => m.type === "IONOS API Token"),
    "uppercase-hex prefix NOT labelled as IONOS",
  );
}

console.log(`\n${pass + fail} tests: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
