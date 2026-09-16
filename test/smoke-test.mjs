// Quick smoke test for pi-redact-all — direct module test (no plugin hooks)
// NOTE: All test inputs use clearly-fake PLACEHOLDER values, never real-looking secrets.
import { redactText } from "../dist/layers/index.js";
import { DEFAULT_CONFIG } from "../dist/config.js";

const ctx = {
  config: { ...DEFAULT_CONFIG, pii: true },
  partialPrivateKeyPaths: new Set(),
};

const FAKE_GH = "ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa";
const FAKE_AWS = "AKIAIOSFODNN7PLACEHOLDER";
const FAKE_STRIPE = "sk_test_FAKE-STRIPE-TEST-KEY-PLACEHOLDER-1234567890";

// Synthetic Telegram tokens — generated dynamically to avoid literal secrets in source
const TG_1 = "123456789:" + "A".repeat(35);
const TG_2 = "9876543210:" + "B".repeat(35);
const TG_FAKE_MIXED = "123456789:ABCdefGhijKlmNoPqrStuVwxYz123456789";

const tests = [
  {
    name: "Telegram Bot Token (standalone)",
    input: TG_1,
    expect: /\[REDACTED:Telegram Bot Token\]/,
  },
  {
    name: "Telegram Bot Token (env var)",
    input: `TELEGRAM_BOT_TOKEN=${TG_FAKE_MIXED}`,
    expect: /\[REDACTED:/,
  },
  {
    name: "Telegram Bot Token (in sentence)",
    input: `My bot token is ${TG_2} please hide`,
    expect: /\[REDACTED:Telegram Bot Token\]/,
  },
  {
    name: "GitHub Token",
    input: `export GITHUB_TOKEN=${FAKE_GH}`,
    expect: /\[REDACTED/,
  },
  {
    name: "AWS Key",
    input: `${FAKE_AWS} is the access key`,
    expect: /\[REDACTED/,
  },
  {
    name: "JWT (well-formed fake)",
    input: `Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJURVNUIiwiaWF0IjoxfQ.fake-signature-not-real-token`,
    expect: /\[REDACTED/,
  },
  {
    name: "X.509 Certificate",
    input: `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKZ9Z9Z9Z9Z9MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTcwODA0MTI1MjU3WhcNMjcwODAyMTI1MjU3WjBF
-----END CERTIFICATE-----`,
    expect: /\[REDACTED:PEM CERTIFICATE\]/,
  },
  {
    name: "SSH Private Key",
    input: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtZW
-----END OPENSSH PRIVATE KEY-----`,
    expect: /\[REDACTED:PEM OPENSSH PRIVATE KEY\]/,
  },
  {
    name: "Connection String",
    input: `postgres://admin:s3cr3tPass123@localhost:5432/db`,
    expect: /\[REDACTED:Password\]/,
  },
  {
    name: "JSON secret field",
    input: `{"api_key": "superSecretValue12345"}`,
    expect: /\[REDACTED/,
  },
  {
    name: "Plain text (no redaction)",
    input: `Hello world, this is a normal message.`,
    expectNot: /\[REDACTED/,
  },
];

let pass = 0;
let fail = 0;

for (const test of tests) {
  const input = test.input;
  const result = redactText(input, ctx);
  const passed = test.expect
    ? test.expect.test(result.text)
    : test.expectNot && !test.expectNot.test(result.text);

  const status = passed ? "✅" : "❌";
  console.log(`${status} ${test.name}`);
  if (!passed) {
    console.log(`   Input:    ${JSON.stringify(input).slice(0, 100)}`);
    console.log(`   Output:   ${JSON.stringify(result.text).slice(0, 100)}`);
    console.log(`   Matches:  ${result.matches.length}`);
    fail++;
  } else {
    pass++;
    if (result.matches.length > 0) {
      console.log(`   → ${result.matches.map(m => m.type).join(", ")}`);
    }
  }
}

console.log(`\n${pass}/${tests.length} tests passed`);
process.exit(fail > 0 ? 1 : 0);
