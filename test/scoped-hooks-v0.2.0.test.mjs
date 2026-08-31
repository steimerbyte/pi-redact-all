// Scoped hooks v0.2.0 — write-tool exclusion tests
//
// Scope: only read/bash/user-input are filtered.
// Write-tool output (model-generated) is never filtered or blocked.

import { applyRedaction } from "../dist/hooks/tool-result.js";
import { shouldBlock, inputContainsSensitiveSecrets } from "../dist/hooks/tool-call.js";
import { filterUserPrompt } from "../dist/hooks/user-input.js";
import { DEFAULT_CONFIG } from "../dist/config.js";

const ctx = {
  config: { ...DEFAULT_CONFIG, pii: true, blockMode: true },
  partialPrivateKeyPaths: new Set(),
};

const WRITE_TOOLS = ["write", "edit", "ssh_write", "ssh_edit", "multi_edit"];

let pass = 0, fail = 0;
function assert(name, condition, detail) {
  if (condition) { pass++; console.log(`✅ ${name}`); }
  else { fail++; console.log(`❌ ${name}`); if (detail) console.log(`   ${detail}`); }
}
function doesNotThrow(name, fn) {
  try { fn(); pass++; console.log(`✅ ${name} (no throw)`); }
  catch (e) { fail++; console.log(`❌ ${name} (threw: ${e.message.slice(0, 80)})`); }
}

// ─────────────────────────────────────────────────────────────
// Section 1: tool_call — write tools must NOT be blocked
// ─────────────────────────────────────────────────────────────

for (const tool of WRITE_TOOLS) {
  const event = { toolName: tool, input: { path: "/tmp/test.ts" } };
  const result = shouldBlock(event, ctx.config);
  assert(`tool_call: ${tool} not blocked (path check skipped)`, result === undefined);
}

for (const tool of WRITE_TOOLS) {
  const event = {
    toolName: tool,
    input: { path: "/tmp", content: "ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa" },
  };
  const result = inputContainsSensitiveSecrets(event, ctx.config);
  assert(`tool_call: ${tool} input secret not blocked (secret scan skipped)`, result === undefined);
}

// mcp__write tool pattern
{
  const event = { toolName: "mcp__filesystem__write", input: { path: "/tmp/x.txt" } };
  assert("tool_call: mcp__*__write not blocked", shouldBlock(event, ctx.config) === undefined);
}
{
  const event = { toolName: "mcp__filesystem__write", input: { path: "/tmp", content: "ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa" } };
  assert("tool_call: mcp__*__write secret scan skipped", inputContainsSensitiveSecrets(event, ctx.config) === undefined);
}

// ─────────────────────────────────────────────────────────────
// Section 2: tool_result — write tools must NOT be filtered
// ─────────────────────────────────────────────────────────────

for (const tool of WRITE_TOOLS) {
  const event = {
    type: "tool_result",
    toolName: tool,
    toolCallId: "call-w",
    input: { path: "/tmp/test.ts" },
    content: [{ type: "text", text: "ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa" }],
    isError: false,
    details: { bytesWritten: 100 },
  };
  const result = applyRedaction(event, ctx);
  assert(`tool_result: ${tool} output NOT filtered (secret survives)`, !result.content?.[0]?.text?.includes("[REDACTED"));
}

// write tool result with PEM content (should NOT be redacted)
{
  const event = {
    type: "tool_result",
    toolName: "write",
    toolCallId: "call-w2",
    input: { path: "/tmp/cert.pem" },
    content: [{ type: "text", text: "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----" }],
    isError: false,
  };
  const result = applyRedaction(event, ctx);
  assert("tool_result: write tool with PEM content NOT filtered", !result.content?.[0]?.text?.includes("[REDACTED"));
}

// mcp__write tool result not filtered
{
  const event = {
    type: "tool_result",
    toolName: "mcp__filesystem__write",
    toolCallId: "call-mcp",
    input: { path: "/tmp/out.txt" },
    content: [{ type: "text", text: "AWS_SECRET_ACCESS_KEY=FakeSecretAccessKey1234567890abcdef" }],
    isError: false,
  };
  const result = applyRedaction(event, ctx);
  assert("tool_result: mcp__*__write not filtered", !result.content?.[0]?.text?.includes("[REDACTED"));
}

// write tool with self.api_token in content (the original issue)
{
  const event = {
    type: "tool_result",
    toolName: "write",
    toolCallId: "call-api",
    input: { path: "/tmp/config.py" },
    content: [{ type: "text", text: 'self.api_token = "ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa"' }],
    isError: false,
  };
  const result = applyRedaction(event, ctx);
  assert("tool_result: write with self.api_token NOT filtered (issue fix)", !result.content?.[0]?.text?.includes("[REDACTED"));
}

// ─────────────────────────────────────────────────────────────
// Section 3: read/bash — must still be filtered normally
// ─────────────────────────────────────────────────────────────

{
  const event = {
    type: "tool_result",
    toolName: "read",
    toolCallId: "call-r",
    input: { path: "/tmp/test.txt" },
    content: [{ type: "text", text: "ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa" }],
    isError: false,
  };
  const result = applyRedaction(event, ctx);
  assert("tool_result: read tool still filtered", result.content?.[0]?.text?.includes("[REDACTED"));
}

{
  const event = {
    type: "tool_result",
    toolName: "bash",
    toolCallId: "call-b",
    input: { command: "echo test" },
    content: [{ type: "text", text: "ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa" }],
    isError: false,
  };
  const result = applyRedaction(event, ctx);
  assert("tool_result: bash tool still filtered", result.content?.[0]?.text?.includes("[REDACTED"));
}

{
  const event = { toolName: "read", input: { path: "/home/user/.env" } };
  const result = shouldBlock(event, ctx.config);
  assert("tool_call: read .env still blocked", result?.block === true);
}

{
  const event = { toolName: "bash", input: { command: "cat ~/.ssh/id_rsa" } };
  const result = shouldBlock(event, ctx.config);
  assert("tool_call: bash cat .ssh/id_rsa still blocked", result?.block === true);
}

// user_input still filtered
{
  const event = { type: "before_agent_start", prompt: "What is ghp_FAKE-TOKEN-FOR-TESTING-ONLY-NOT-REAL-aaaaaaaaaaaa?" };
  const result = filterUserPrompt(event, ctx);
  assert("before_agent_start: user input still filtered", result.prompt?.includes("[REDACTED"));
}

// ─────────────────────────────────────────────────────────────
// Section 4: default whitelist includes write tools
// ─────────────────────────────────────────────────────────────

assert("default whitelist includes write tools", DEFAULT_CONFIG.toolPolicy.whitelist.includes("write"));
assert("default whitelist includes edit", DEFAULT_CONFIG.toolPolicy.whitelist.includes("edit"));
assert("default whitelist includes ssh_write", DEFAULT_CONFIG.toolPolicy.whitelist.includes("ssh_write"));
assert("default whitelist includes ssh_edit", DEFAULT_CONFIG.toolPolicy.whitelist.includes("ssh_edit"));
assert("default whitelist includes multi_edit", DEFAULT_CONFIG.toolPolicy.whitelist.includes("multi_edit"));

console.log(`\n${pass}/${pass + fail} tests passed`);
process.exit(fail > 0 ? 1 : 0);
