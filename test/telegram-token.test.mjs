// Telegram Bot Token tests for pi-redact-all
// Pattern: \b\d{5,20}:[A-Za-z0-9_-]{35}\b — synthetic tokens only, no real secrets
import { redactText } from "../dist/layers/index.js";
import { DEFAULT_CONFIG } from "../dist/config.js";
import { applyRedaction } from "../dist/hooks/tool-result.js";
import { filterUserPrompt } from "../dist/hooks/before-provider.js";
import { filterMessage } from "../dist/hooks/message-end.js";

const ctx = {
  config: { ...DEFAULT_CONFIG, pii: true },
  partialPrivateKeyPaths: new Set(),
};

let pass = 0;
let fail = 0;

function assert(name, cond, detail) {
  if (cond) {
    console.log(`✅ ${name}`);
    return true;
  } else {
    console.log(`❌ ${name}`);
    if (detail) console.log(`   ${detail}`);
    return false;
  }
}

function ok(cond, name, detail) {
  if (assert(name, cond, detail)) pass++;
  else fail++;
}

// Synthetic valid Telegram tokens (bot_id: 5-20 digits + ":" + 35 URL-safe chars)
const TG_1 = "123456789:" + "A".repeat(35);
const TG_2 = "9876543210:" + "B".repeat(35);
const TG_3 = "5555555555:" + "C".repeat(35);
const TG_MIXED = "123456789:ABCdefGhijKlmNoPqrStuVwxYz123456789";
const TG_HYPHEN = "123456789:AAHFAKETELEGRAM-TOKEN_1234567890123";

// 1. Standalone token
{
  const r = redactText(TG_1, ctx);
  ok(r.text.includes("[REDACTED:Telegram Bot Token]"), "standalone telegram token redacted");
  ok(r.matches.some((m) => m.type === "Telegram Bot Token"), "standalone type is Telegram Bot Token");
  ok(!r.text.includes(TG_1), "standalone original not in output");
}

// 2. Env var style — may also match Env Secret Field, so check generic redaction
{
  const input = `TELEGRAM_BOT_TOKEN=${TG_MIXED}`;
  const r = redactText(input, ctx);
  ok(r.text.includes("[REDACTED:"), "env var telegram token redacted (any marker)");
  ok(r.matches.some((m) => m.type === "Telegram Bot Token"), "env var type includes Telegram");
  ok(!r.text.includes(TG_MIXED), "env var original not leaked");
}

// 3. In sentence
{
  const input = `My bot token is ${TG_2} please hide`;
  const r = redactText(input, ctx);
  ok(r.text.includes("[REDACTED:Telegram Bot Token]"), "in-sentence redacted");
}

// 4. JSON secret field
{
  const input = `{"telegram_token": "${TG_MIXED}"}`;
  const r = redactText(input, ctx);
  ok(r.text.includes("[REDACTED:"), "JSON telegram token redacted");
}

// 5. Multiple tokens
{
  const input = `${TG_1} and ${TG_2} are two bots`;
  const r = redactText(input, ctx);
  ok(r.matches.filter((m) => m.type === "Telegram Bot Token").length === 2, "multiple tokens both redacted");
  ok(!r.text.includes("AAAA"), "multiple original not leaked");
}

// 6. Invalid — too short bot id (4 digits, below 5 min)
{
  const shortId = "1234:" + "A".repeat(35);
  const r = redactText(shortId, ctx);
  ok(!r.text.includes("[REDACTED:Telegram Bot Token]"), "short bot id (4 digits) not redacted");
}

// 7. Invalid — token part too short (34 chars, not 35)
{
  const shortTok = "123456789:" + "A".repeat(34);
  const r = redactText(shortTok, ctx);
  ok(!r.text.includes("[REDACTED:Telegram Bot Token]"), "short token part (34) not redacted");
}

// 8. Allowlist bypass — default allowlist would match hex bot id, but Telegram must not be suppressed
{
  const r = redactText(TG_3, ctx);
  ok(r.text.includes("[REDACTED:Telegram Bot Token]"), "allowlist does not suppress telegram (hex bot id)");
}

// 9. Idempotency
{
  const r1 = redactText(TG_1, ctx);
  const r2 = redactText(r1.text, ctx);
  ok(r2.text === r1.text, "idempotency: second pass unchanged");
  ok(r2.matches.length === 0, "idempotency: no new matches on second pass");
}

// 10. Already-redacted marker
{
  const already = "1234********************[REDACTED:Telegram Bot Token]";
  const r = redactText(already, ctx);
  ok(r.matches.length === 0, "already-redacted marker not re-redacted");
  ok(r.text === already, "already-redacted preserved");
}

// 11. Tool result hook — bash
{
  const event = {
    type: "tool_result",
    toolName: "bash",
    toolCallId: "tg-1",
    input: { command: "echo token" },
    content: [{ type: "text", text: `token is ${TG_1}` }],
    isError: false,
    details: { exitCode: 0 },
  };
  const result = applyRedaction(event, ctx);
  ok(result.content?.[0]?.text?.includes("[REDACTED:Telegram Bot Token]"), "tool_result bash redacts telegram");
}

// 12. Tool result hook — read (non-sensitive path)
{
  const event = {
    type: "tool_result",
    toolName: "read",
    toolCallId: "tg-2",
    input: { path: "/tmp/bot.txt" },
    content: [{ type: "text", text: `BOT_TOKEN=${TG_MIXED}` }],
    isError: false,
    details: { totalLines: 1 },
  };
  const result = applyRedaction(event, ctx);
  ok(result.content?.[0]?.text?.includes("[REDACTED:"), "tool_result read redacts telegram (any marker)");
  ok(!result.content?.[0]?.text?.includes(TG_MIXED), "tool_result read does not leak original");
}

// 13. before_agent_start hook — user input
{
  const event = { type: "before_agent_start", prompt: `my token ${TG_MIXED} help`, images: [] };
  const result = filterUserPrompt(event, ctx);
  ok(result.prompt?.includes("[REDACTED:"), "before_agent_start redacts telegram");
}

// 14. message_end hook — assistant message
{
  const event = { type: "message_end", message: { role: "assistant", content: `here is ${TG_1}`, timestamp: 1 } };
  const result = filterMessage(event, ctx);
  ok(JSON.stringify(result.message).includes("[REDACTED:Telegram Bot Token]"), "message_end redacts telegram");
}

// 15. Path context — token inside a file path should be suppressed to preserve filename
{
  const pathLike = `/tmp/some-thing-${TG_1}.txt is a file`;
  const r = redactText(pathLike, ctx);
  const isPathSuppressed = !r.text.includes("[REDACTED:Telegram Bot Token]");
  ok(isPathSuppressed, "path-context suppresses telegram in filename (preserves path)");
}

// 16. Hyphen/underscore alphabet
{
  const r = redactText(TG_HYPHEN, ctx);
  ok(r.text.includes("[REDACTED:Telegram Bot Token]"), "hyphen/underscore telegram token redacted");
}

// 17. Performance — many tokens
{
  const big = (`${TG_1} `).repeat(1000);
  const t0 = Date.now();
  const r = redactText(big, ctx);
  const dt = Date.now() - t0;
  ok(dt < 200, `perf: 1000 telegram tokens <200ms (took ${dt}ms)`);
  ok(!r.text.includes("AAAAA"), "perf: no original leaked");
}

console.log(`\n${pass}/${pass + fail} telegram tests passed`);
process.exit(fail > 0 ? 1 : 0);
