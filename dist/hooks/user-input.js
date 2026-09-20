// user-input hook — input event filter
//
// v0.2.3: Replaced the broken `before_agent_start` hook (which returned
// `{ prompt }` — a field the framework ignores) with the `input` event
// hook, which can return `action: "transform"` and a rewritten `text`.
// The input event fires before skill/template expansion and before the
// agent loop, so it is the correct place to redact secrets in user prompts
// before they reach the model.
//
// Framework reference: BeforeAgentStartEventResult in pi's
// `dist/core/extensions/types.d.ts` only accepts `{ message?, systemPrompt? }`.
// There is no `prompt` field. The `input` event is the supported API.
import { redactText } from "../layers/index.js";
/**
 * Redact the user's prompt before it is expanded and forwarded to the agent.
 *
 * @param text Raw user input (after slash-command intercept, before skill/template expansion).
 * @param ctx  Redaction context.
 * @returns `{ action: "transform", text }` if anything was redacted, otherwise
 *          `{ action: "continue" }` so the framework falls through to expansion.
 */
export function transformInputText(text, ctx) {
    if (ctx.enabled === false)
        return { action: "continue" };
    if (ctx.config.mode === "off")
        return { action: "continue" };
    // Slash commands (`/redact`, `/help`, …) are intercepted by the framework
    // before the input event fires, but defend in depth in case a hook chain
    // changes that. Never redact an internal command.
    if (text.startsWith("/"))
        return { action: "continue" };
    const result = redactText(text, { ...ctx, toolName: "user_input" });
    if (result.matches.length === 0)
        return { action: "continue" };
    return { action: "transform", text: result.text };
}
//# sourceMappingURL=user-input.js.map