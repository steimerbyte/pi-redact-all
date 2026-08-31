// Test Layer 6 identifier-reference false-positive guard.
// Uses inputs >= 32 chars (minLength filter in index.ts skips shorter text).

import { redactText } from "../dist/layers/index.js";
import { DEFAULT_CONFIG } from "../dist/config.js";

const ctx = { config: { ...DEFAULT_CONFIG }, partialPrivateKeyPaths: new Set() };

let pass = 0;
let fail = 0;

function assert(name, condition) {
  if (condition) {
    pass++;
    console.log("PASS: " + name);
  } else {
    fail++;
    console.log("FAIL: " + name);
  }
}

// --- should NOT be redacted (identifier references) ---
assert("password=self.api_token (dotted)",
  !/REDACTED/.test(redactText("password=self.api_token", ctx).text));

assert("password=foo.bar.baz (dotted)",
  !/REDACTED/.test(redactText("password=foo.bar.baz", ctx).text));

assert("password = self.api_token (INI, dotted)",
  !/REDACTED/.test(redactText("password = self.api_token", ctx).text));

assert("password: self.attr (YAML, dotted)",
  !/REDACTED/.test(redactText("password: self.api_token", ctx).text));

assert("token=cls.attr.nested (dotted)",
  !/REDACTED/.test(redactText("token=cls.attr.nested", ctx).text));

// --- should be redacted (bare non-identifier values, >= 32 chars) ---
const v32a = "password=abcdefghabcdefghabcdefghabcdef";
const v32b = "password=12345678123456781234567812345678";
const v32c = "api_key=12345678901234567890abcdefghij";
const v32d = "GH_TOKEN=ghp_abcdefgh12345678abcdefgh123";
const v32e = "AUTH_TOKEN=abcdefghij123456789abcdefghijk";
const v32f = "auth_token=gAAAAABbCcCdDeEfFgGhHiIjJkKlL";
const v32g = "client_secret=a1b2c3d4e5f6g7h8i9j0k1l2m3";
const v32h = "IONOS_API_KEY=xoxoxoxoxoxoxoxoxoxoxoxoxoxoxox1";
const v32i = "GITHUB_TOKEN=xoxoxoxoxoxoxoxoxoxoxoxoxoxoxox2";
const v32j = "CLOUDLARE_API_KEY=xoxoxoxoxoxoxoxoxoxoxoxoxoxoxox3";
const v32k = "MY_API_TOKEN=xoxoxoxoxoxoxoxoxoxoxoxoxoxoxox4";
const v32l = "AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEFGHIKL";

assert("password = abcdefgh (bare, not identifier)", /REDACTED/.test(redactText(v32a, ctx).text));
assert("password = 12345678 (bare, not identifier)", /REDACTED/.test(redactText(v32b, ctx).text));
assert("api_key: 1234567890abcdef (bare, not identifier)", /REDACTED/.test(redactText(v32c, ctx).text));
assert("GH_TOKEN=ghp_... (bare, not identifier)", /REDACTED/.test(redactText(v32d, ctx).text));
assert("AUTH_TOKEN=abcdefghij... (bare, not identifier)", /REDACTED/.test(redactText(v32e, ctx).text));
assert("auth_token=gAAAAA... (JWT prefix, not identifier)", /REDACTED/.test(redactText(v32f, ctx).text));
assert("client_secret=a1b2c3... (bare, not identifier)", /REDACTED/.test(redactText(v32g, ctx).text));

// --- idempotency: already-redacted spans unchanged ---
assert("idempotency: api_key=\"[REDACTED:...]\"",
  redactText('api_key="[REDACTED:Env Secret Field]"', ctx).text.includes("[REDACTED:Env Secret Field]"));

assert("idempotency: password = [REDACTED:...] (INI)",
  redactText("password = [REDACTED:INI Secret Field]", ctx).text.includes("[REDACTED:INI Secret Field]"));

// --- known keys must redact ---
assert("IONOS_API_KEY=xoxo...", /REDACTED/.test(redactText(v32h, ctx).text));
assert("GITHUB_TOKEN=xoxo...", /REDACTED/.test(redactText(v32i, ctx).text));
assert("CLOUDLARE_API_KEY=xoxo...", /REDACTED/.test(redactText(v32j, ctx).text));
assert("MY_API_TOKEN=xoxo...", /REDACTED/.test(redactText(v32k, ctx).text));
assert("AWS_ACCESS_KEY_ID=AKIA...", /REDACTED/.test(redactText(v32l, ctx).text));

// --- no false positives on innocent env vars ---
assert("PATH=/usr/local/bin (innocent)",
  !/REDACTED/.test(redactText("PATH=/usr/local/bin", ctx).text));

assert("HOME=/home/user (innocent)",
  !/REDACTED/.test(redactText("HOME=/home/user", ctx).text));

assert("USER=alice (innocent)",
  !/REDACTED/.test(redactText("USER=alice", ctx).text));

console.log("\n" + pass + "/" + (pass + fail) + " tests passed");
process.exit(fail > 0 ? 1 : 0);
