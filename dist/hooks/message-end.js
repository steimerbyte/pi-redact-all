// message_end hook — Schema-aware filter for Assistant/User Messages
//
// AgentMessage is a discriminated union with role-based shapes:
//   - bashExecution: { role, command, output, exitCode, cancelled, truncated, ... }
//   - custom:        { role, customType, content, display, details?, timestamp }
//   - branchSummary: { role, summary, fromId, timestamp }
//   - compactionSummary: { role, summary, tokensBefore, timestamp }
//   - user:          { role, content: string | ContentItem[], timestamp }
//   - assistant:     { role, content: ContentItem[], ... }
//   - toolResult:    { role, toolCallId, toolName, content, isError, ... }
//
// We MUST preserve the exact shape — returning {role, content} breaks
// custom/bashExecution/branchSummary/compactionSummary types and causes
// 400 errors from the LLM provider.
//
// Strategy: Only redact the text content within known text-containing roles
// (user, assistant, custom). All other roles pass through untouched.
import { redactText } from "../layers/index.js";
/**
 * Filter message content while preserving the original message shape exactly.
 * Only mutates text fields where appropriate.
 */
export function filterMessage(event, ctx) {
    if (ctx.config.mode === "off")
        return {};
    if (ctx.config.toolPolicy.whitelist.includes(event.message.role))
        return {};
    const msg = event.message;
    switch (msg.role) {
        case "user":
        case "assistant": {
            // Content is string | (TextContent | ImageContent)[]
            const content = msg.content;
            if (typeof content === "string") {
                const result = redactText(content, ctx);
                if (result.matches.length === 0)
                    return {};
                return { message: { ...msg, content: result.text } };
            }
            if (Array.isArray(content)) {
                let changed = false;
                const newContent = content.map((item) => {
                    if (item && typeof item === "object" && item.type === "text" && typeof item.text === "string") {
                        const textItem = item;
                        const result = redactText(textItem.text, ctx);
                        if (result.matches.length > 0) {
                            changed = true;
                            return { ...textItem, text: result.text };
                        }
                    }
                    return item;
                });
                if (!changed)
                    return {};
                return { message: { ...msg, content: newContent } };
            }
            return {};
        }
        case "custom": {
            // Custom messages have content: string | ContentItem[]
            const content = msg.content;
            if (typeof content === "string") {
                const result = redactText(content, ctx);
                if (result.matches.length === 0)
                    return {};
                // Preserve customType, display, details, timestamp
                return {
                    message: {
                        ...msg,
                        content: result.text,
                    },
                };
            }
            if (Array.isArray(content)) {
                let changed = false;
                const newContent = content.map((item) => {
                    if (item && typeof item === "object" && item.type === "text" && typeof item.text === "string") {
                        const textItem = item;
                        const result = redactText(textItem.text, ctx);
                        if (result.matches.length > 0) {
                            changed = true;
                            return { ...textItem, text: result.text };
                        }
                    }
                    return item;
                });
                if (!changed)
                    return {};
                return { message: { ...msg, content: newContent } };
            }
            return {};
        }
        case "bashExecution":
        case "branchSummary":
        case "compactionSummary":
        case "toolResult":
        default:
            // Don't touch these — they have specialized shapes that don't fit
            // our text-redaction model. toolResult is already handled by tool_result hook.
            return {};
    }
}
//# sourceMappingURL=message-end.js.map