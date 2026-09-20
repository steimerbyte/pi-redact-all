// input-event-v0.2.3.test.mjs
//
// Regression suite for the v0.2.2 → v0.2.3 bug fix:
//
// v0.2.0–v0.2.2 used the `before_agent_start` event and returned
// `{ prompt: redactedText }`. The framework's `BeforeAgentStartEventResult`
// type only accepts `{ message?, systemPrompt? }`. The `prompt` field is
// silently ignored, so the user prompt was sent to the LLM unredacted.
//
// v0.2.3 switches to the `input` event, which DOES support rewriting the
// text via `action: "transform"`. The framework fires `input` before
// skill/template expansion and before the agent loop, so redacted text
// flows correctly to the model.

import { transformInputText } from "../dist/hooks/user-input.js";
import { DEFAULT_CONFIG } from "../dist/config.js";

const ctx = {
  config: { ...DEFAULT_CONFIG, pii: true, blockMode: true },
  partialPrivateKeyPaths: new Set(),
};

let pass = 0;
let fail = 0;
function assert(name, condition, detail) {
  if (condition) {
    pass++;
    console.log(`✅ ${name}`);
  } else {
    fail++;
    console.log(`❌ ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

// 1. Basic redaction: secret in plain prompt gets transformed
{
  const text = "Look at this AKIAIOSFODNN7EXAMPLE please";
  const result = transformInputText(text, ctx);
  assert("input: secret triggers transform action", result.action === "transform");
  assert("input: redacted text contains [REDACTED]", result.text?.includes("[REDACTED"));
  assert("input: redacted text omits original secret", !result.text?.includes("AKIAIOSFODNN7EXAMPLE"));
  assert("input: redacted text preserves surrounding prose", result.text?.includes("Look at this"));
}

// 2. No secret: pass-through
{
  const text = "What is the capital of France?";
  const result = transformInputText(text, ctx);
  assert("input: no secret = action continue", result.action === "continue");
  assert("input: no secret = text undefined", result.text === undefined);
}

// 3. Slash commands: never transformed (framework intercepts before input,
//    but defend in depth)
{
  const slashCmds = ["/redact", "/redact status", "/help", "/compact", "/skill:test"];
  for (const cmd of slashCmds) {
    const result = transformInputText(cmd, ctx);
    assert(`input: slash command '${cmd}' passes through`, result.action === "continue");
  }
}

// 4. Disabled: pass-through
{
  const text = "AKIAIOSFODNN7EXAMPLE";
  const result = transformInputText(text, { ...ctx, enabled: false });
  assert("input: disabled session passes through", result.action === "continue");
}

// 5. Mode "off": pass-through
{
  const text = "AKIAIOSFODNN7EXAMPLE";
  const result = transformInputText(text, { ...ctx, config: { ...ctx.config, mode: "off" } });
  assert("input: mode off passes through", result.action === "continue");
}

// 6. Multiple secrets in one prompt
{
  const text = "Use ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa and AKIAIOSFODNN7EXAMPLE here";
  const result = transformInputText(text, ctx);
  assert("input: multiple secrets redacted", result.action === "transform");
  assert("input: no original secret survives", !result.text?.includes("ghp_FAKE") && !result.text?.includes("AKIAIOSFODNN7EXAMPLE"));
}

// 7. Empty / short text
{
  assert("input: empty string passes through", transformInputText("", ctx).action === "continue");
  assert("input: short text passes through (under minLength)", transformInputText("hello world", ctx).action === "continue");
}

// 8. Long config dump with secrets — regression for catastrophic input
{
  const lines = [
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    "GITHUB_TOKEN=ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa",
    "POSTGRES_URL=postgres://user:fakepassword1234567890@db.example.com:5432/mydb",
  ];
  const text = lines.join("\n");
  const result = transformInputText(text, ctx);
  assert("input: long config dump triggers transform", result.action === "transform");
  assert("input: no AKIA survives", !result.text?.includes("AKIAIOSFODNN7EXAMPLE"));
  assert("input: no fake github token survives", !result.text?.includes("ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL"));
}

console.log(`\n${pass}/${pass + fail} tests passed`);
process.exit(fail > 0 ? 1 : 0);
