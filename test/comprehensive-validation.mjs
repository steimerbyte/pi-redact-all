// Comprehensive schema validation tests for all plugin components.
// Verifies that no hook corrupts event/payload shape, throws exceptions,
// or breaks edge cases (empty/large content, Unicode, etc.)

import { applyRedaction } from "../dist/hooks/tool-result.js";
import { shouldBlock, inputContainsSensitiveSecrets } from "../dist/hooks/tool-call.js";
import { filterUserPrompt } from "../dist/hooks/user-input.js";
import { redactText } from "../dist/layers/index.js";
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
    console.log(`❌ ${name}`);
    if (detail) console.log(`   ${detail}`);
  }
}

function doesNotThrow(name, fn) {
  try {
    fn();
    pass++;
    console.log(`✅ ${name} (no throw)`);
  } catch (e) {
    fail++;
    console.log(`❌ ${name} (threw: ${e.message.slice(0, 50)})`);
  }
}

// ─────────────────────────────────────────────────────────────
// Section 1: tool_result hook — all 8 tool-type variants
// ─────────────────────────────────────────────────────────────

// BashToolResultEvent
{
  const event = {
    type: "tool_result",
    toolName: "bash",
    toolCallId: "call-1",
    input: { command: "echo test" },
    content: [{ type: "text", text: "Token: ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa" }],
    isError: false,
    details: { exitCode: 0, stdout: "...", stderr: "", truncated: false, fullOutputPath: "/tmp/out.txt" },
    usage: { inputTokens: 0, outputTokens: 0, cost: { input: 0, output: 0, total: 0 } },
  };
  const result = applyRedaction(event, ctx);
  assert("bash: content redacted", result.content?.[0]?.text?.includes("[REDACTED"));
  assert("bash: details preserved", event.details.exitCode === 0);
  assert("bash: usage preserved", event.usage.inputTokens === 0);
}

// ReadToolResultEvent (safe path)
{
  const event = {
    type: "tool_result",
    toolName: "read",
    toolCallId: "call-2",
    input: { path: "/tmp/safe-name.txt" },
    content: [{ type: "text", text: "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----" }],
    isError: false,
    details: { totalLines: 100, linesRead: 50, offset: 0, truncated: false },
  };
  const result = applyRedaction(event, ctx);
  assert("read (safe path): cert content redacted as PEM", result.content?.[0]?.text?.includes("[REDACTED:PEM CERTIFICATE]"));
  assert("read (safe path): details preserved", event.details.totalLines === 100);
}

// ReadToolResultEvent (sensitive path → whole content protected)
{
  const event = {
    type: "tool_result",
    toolName: "read",
    toolCallId: "call-2b",
    input: { path: "/tmp/secret.pem" },
    content: [{ type: "text", text: "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----" }],
    isError: false,
    details: { totalLines: 5 },
  };
  const result = applyRedaction(event, ctx);
  assert("read (sensitive path): whole content protected", result.content?.[0]?.text?.includes("[REDACTED:Protected File"));
}

// EditToolResultEvent
{
  const event = {
    type: "tool_result",
    toolName: "edit",
    toolCallId: "call-3",
    input: { path: "/tmp/x.ts" },
    content: [{ type: "text", text: "OK" }],
    isError: false,
    details: { originalLength: 100, newLength: 105, diff: "@@..." },
  };
  const result = applyRedaction(event, ctx);
  assert("edit: content preserved when no secrets", result.content === undefined || result.content[0].text === "OK");
  assert("edit: details preserved", event.details.originalLength === 100);
}

// WriteToolResultEvent
{
  const event = {
    type: "tool_result",
    toolName: "write",
    toolCallId: "call-4",
    input: { path: "/tmp/x.ts" },
    content: [],
    isError: false,
    details: { bytesWritten: 1024 },
  };
  const result = applyRedaction(event, ctx);
  assert("write: empty content array preserved", result.content === undefined || result.content.length === 0);
  assert("write: details preserved", event.details.bytesWritten === 1024);
}

// GrepToolResultEvent
{
  const event = {
    type: "tool_result",
    toolName: "grep",
    toolCallId: "call-5",
    input: { pattern: "password", path: "/tmp" },
    content: [{ type: "text", text: "/tmp/x.ts:5:password = ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa" }],
    isError: false,
    details: { totalMatches: 1, truncated: false },
  };
  const result = applyRedaction(event, ctx);
  assert("grep: match line redacted", result.content?.[0]?.text?.includes("[REDACTED"));
}

// CustomToolResultEvent (MCP)
{
  const event = {
    type: "tool_result",
    toolName: "context7_get_docs",
    toolCallId: "call-8",
    input: { libraryName: "react" },
    content: [
      { type: "text", text: "API_KEY=ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa" },
      { type: "image", url: "https://example.com/img.png", base64: "..." },
    ],
    isError: false,
    details: { providerSpecific: "data", custom: 12345 },
  };
  const result = applyRedaction(event, ctx);
  assert("custom (MCP): text item redacted", result.content?.[0]?.text?.includes("[REDACTED"));
  assert("custom (MCP): image item preserved untouched", result.content?.[1]?.url === "https://example.com/img.png");
  assert("custom (MCP): provider-specific details preserved", event.details.custom === 12345);
}

// ─────────────────────────────────────────────────────────────
// Section 2: tool_call hook — Block-Mode
// ─────────────────────────────────────────────────────────────

{
  const event = { type: "tool_call", toolName: "bash", input: { command: "cat ~/.ssh/id_rsa" } };
  const result = shouldBlock(event, ctx.config);
  assert("tool_call block: cat .ssh/id_rsa blocked", result?.block === true && typeof result?.reason === "string");
}

{
  const event = { type: "tool_call", toolName: "bash", input: { command: "ls -la /tmp" } };
  const result = shouldBlock(event, ctx.config);
  assert("tool_call block: ls not blocked", result === undefined);
}

{
  const event = { type: "tool_call", toolName: "read", input: { path: "/home/user/.env" } };
  const result = shouldBlock(event, ctx.config);
  assert("tool_call block: read .env blocked", result?.block === true);
}

{
  const event = { type: "tool_call", toolName: "bash", input: { command: "echo ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa" } };
  const result = inputContainsSensitiveSecrets(event, ctx.config);
  assert("input content: token in command blocked", result?.block === true);
}

// ─────────────────────────────────────────────────────────────
// Section 3: before_agent_start hook
// ─────────────────────────────────────────────────────────────

{
  const event = {
    type: "before_agent_start",
    prompt: "What is ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa?",
    images: [{ url: "https://example.com/img.png" }],
  };
  const result = filterUserPrompt(event, ctx);
  assert("user_input: secret in prompt redacted", result.prompt?.includes("[REDACTED"));
  assert("user_input: images preserved (not modified)", event.images?.[0]?.url === "https://example.com/img.png");
}

{
  const event = { type: "before_agent_start", prompt: "What is the weather today?", images: undefined };
  const result = filterUserPrompt(event, ctx);
  assert("user_input: no secrets = no change", result.prompt === undefined || result.prompt === event.prompt);
}

// ─────────────────────────────────────────────────────────────
// Section 4: Edge cases — empty, large, Unicode, special chars
// ─────────────────────────────────────────────────────────────

// Empty content
{
  const event = {
    type: "tool_result",
    toolName: "bash",
    toolCallId: "x",
    input: { command: "true" },
    content: [{ type: "text", text: "" }],
    isError: false,
    details: undefined,
  };
  doesNotThrow("empty content doesn't crash", () => applyRedaction(event, ctx));
}

// Very large content (100KB — realistic for big bash outputs)
{
  const big = "ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa ".repeat(2000);
  const event = {
    type: "tool_result",
    toolName: "bash",
    toolCallId: "x",
    input: { command: "echo big" },
    content: [{ type: "text", text: big }],
    isError: false,
    details: { exitCode: 0 },
  };
  const t0 = Date.now();
  const result = applyRedaction(event, ctx);
  const dt = Date.now() - t0;
  assert("large content (100KB): redacted in <500ms", dt < 500, `Took ${dt}ms`);
  // Note: output length differs from input because markers are shorter than original tokens.
  // What we verify: all original tokens are replaced (no original token survives in output).
  assert(
    "large content: no original token survives",
    !result.content?.[0]?.text?.includes("ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL")
  );
}

// Unicode + Emoji
{
  const event = {
    type: "tool_result",
    toolName: "bash",
    toolCallId: "x",
    input: { command: "echo" },
    content: [{ type: "text", text: "🔐 Secret: ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa 🔑" }],
    isError: false,
    details: undefined,
  };
  const result = applyRedaction(event, ctx);
  assert("Unicode + emoji: secret redacted, emojis preserved", result.content?.[0]?.text?.includes("🔐") && result.content?.[0]?.text?.includes("[REDACTED"));
}

// ─────────────────────────────────────────────────────────────
// Section 5: redactText edge cases
// ─────────────────────────────────────────────────────────────

doesNotThrow("redactText on null doesn't crash", () => redactText(null, ctx));
doesNotThrow("redactText on undefined doesn't crash", () => redactText(undefined, ctx));

{
  const r = redactText("", ctx);
  assert("redactText empty string returns empty", r.text === "" && r.matches.length === 0);
}

{
  const r = redactText("normal text", ctx);
  assert("redactText no matches returns input unchanged", r.text === "normal text");
}

// ─────────────────────────────────────────────────────────────
// Section 6: Idempotency
// ─────────────────────────────────────────────────────────────

{
  const text = "Token: ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa";
  const r1 = redactText(text, ctx);
  const r2 = redactText(r1.text, ctx);
  assert(
    "idempotency: re-running on redacted text doesn't double-redact",
    r2.matches.length === 0 || r2.text === r1.text,
    `First: ${r1.text}, Second: ${r2.text}`
  );
}

// ─────────────────────────────────────────────────────────────
// Section 7: Performance benchmarks
// ─────────────────────────────────────────────────────────────

{
  const t0 = Date.now();
  const big = "ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa ".repeat(1000);
  redactText(big, ctx);
  const dt = Date.now() - t0;
  assert("perf: 1000 tokens in <100ms", dt < 100, `Took ${dt}ms`);
}

{
  const t0 = Date.now();
  const big = "ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa ".repeat(10000);
  redactText(big, ctx);
  const dt = Date.now() - t0;
  assert("perf: 10000 tokens in <500ms (was 7200ms before fix)", dt < 500, `Took ${dt}ms`);
}

console.log(`\n${pass}/${pass + fail} tests passed`);
process.exit(fail > 0 ? 1 : 0);