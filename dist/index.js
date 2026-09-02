// pi-redact-all — Extension entry point
// Hooks: tool_result (PostToolUse), tool_call (PreToolUse Block),
//        before_agent_start (User-Input Filter), message_end (Last Line),
//        before_provider_request (Final Defense)
import { loadConfig } from "./config.js";
import { createSessionStats, recordMatches, recordBlock, formatStats } from "./stats.js";
import { applyRedaction } from "./hooks/tool-result.js";
import { shouldBlock, inputContainsSensitiveSecrets } from "./hooks/tool-call.js";
import { filterUserPrompt, filterProviderPayload } from "./hooks/before-provider.js";
import { filterMessage } from "./hooks/message-end.js";
import { redactText } from "./layers/index.js";
/**
 * Default export — Pi calls this with the ExtensionAPI.
 */
export default function (pi) {
    const config = loadConfig();
    const stats = createSessionStats();
    const partialPrivateKeyPaths = new Set();
    const makeContext = (toolName, input) => ({
        config,
        partialPrivateKeyPaths,
        toolName,
        inputPath: input ? input.path : undefined,
        command: input ? input.command : undefined,
    });
    // ──────────────────────────────────────────────────────────────
    // POST-TOOL HOOK: Redact tool output before it reaches the LLM
    // ──────────────────────────────────────────────────────────────
    pi.on("tool_result", async (event) => {
        const e = event;
        const ctx = makeContext(e.toolName, e.input);
        const result = applyRedaction(e, ctx);
        // Track partial private key paths
        if (e.toolName === "read" && ctx.inputPath) {
            const textItem = e.content.find((c) => c.type === "text");
            if (textItem && textItem.type === "text") {
                if (/-----BEGIN[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.test(textItem.text) &&
                    !/-----END[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.test(textItem.text)) {
                    partialPrivateKeyPaths.add(ctx.inputPath);
                }
                else if (/-----END[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.test(textItem.text)) {
                    partialPrivateKeyPaths.delete(ctx.inputPath);
                }
            }
        }
        // Stats: count via length delta as approximation
        if (result.content) {
            let totalMatches = 0;
            for (let i = 0; i < e.content.length; i++) {
                const orig = e.content[i];
                const mod = result.content[i];
                if (orig.type === "text" && mod.type === "text" && orig.text !== mod.text) {
                    const scanResult = redactText(orig.text, ctx);
                    totalMatches += scanResult.matches.length;
                }
            }
            if (totalMatches > 0) {
                recordMatches(stats, Array(totalMatches).fill({ start: 0, end: 0, type: "unknown", replacement: "" }), e.toolName);
            }
        }
        return result;
    });
    // ──────────────────────────────────────────────────────────────
    // PRE-TOOL HOOK: Block sensitive tool calls
    // ──────────────────────────────────────────────────────────────
    pi.on("tool_call", async (event) => {
        const e = event;
        const blockResult = shouldBlock({ toolName: e.toolName, input: e.input }, config);
        if (blockResult) {
            recordBlock(stats);
            return blockResult;
        }
        const inputBlock = inputContainsSensitiveSecrets({ toolName: e.toolName, input: e.input }, config);
        if (inputBlock) {
            recordBlock(stats);
            return inputBlock;
        }
        return undefined;
    });
    // ──────────────────────────────────────────────────────────────
    // USER-INPUT HOOK: Filter user prompt before agent loop starts
    // ──────────────────────────────────────────────────────────────
    pi.on("before_agent_start", async (event) => {
        const e = event;
        const ctx = makeContext("user_input");
        const result = filterUserPrompt(e, ctx);
        if (result.prompt && result.prompt !== e.prompt) {
            const scanResult = redactText(e.prompt, ctx);
            if (scanResult.matches.length > 0) {
                recordMatches(stats, scanResult.matches, "user_input");
            }
        }
        return result;
    });
    // ──────────────────────────────────────────────────────────────
    // ASSISTANT-MESSAGE HOOK: Schema-aware filter (preserves AgentMessage union)
    // v0.1.2 fix: Now correctly handles custom/bashExecution/branchSummary/
    // compactionSummary by passing them through untouched, and only mutates
    // text content within user/assistant/custom roles.
    // ──────────────────────────────────────────────────────────────
    pi.on("message_end", async (event) => {
        const e = event;
        const ctx = makeContext(e.message.role);
        const result = filterMessage(e, ctx);
        if (result.message) {
            recordMatches(stats, Array(1).fill({ start: 0, end: 0, type: "assistant-message", replacement: "" }), `message:${e.message.role}`);
        }
        return result;
    });
    // ──────────────────────────────────────────────────────────────
    // PROVIDER-PAYLOAD HOOK: In-place mutation (no return value)
    // v0.1.2 fix: Mutates payload in place rather than returning a new object,
    // since providers strictly validate the payload schema.
    // ──────────────────────────────────────────────────────────────
    pi.on("before_provider_request", async (event) => {
        const e = event;
        const ctx = makeContext("provider_payload");
        filterProviderPayload(e, ctx);
        // Return undefined — relies on in-place mutation
        return undefined;
    });
    // ──────────────────────────────────────────────────────────────
    // COMMANDS
    // ──────────────────────────────────────────────────────────────
    pi.registerCommand("redact-all-stats", {
        description: "Show pi-redact-all session statistics",
        handler: () => formatStats(stats),
    });
    pi.registerCommand("redact-all-config", {
        description: "Show current pi-redact-all configuration",
        handler: () => JSON.stringify(config, null, 2),
    });
}
//# sourceMappingURL=index.js.map