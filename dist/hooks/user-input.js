// user-input hook — filterUserPrompt for before_agent_start
import { redactText } from "../layers/index.js";
export function filterUserPrompt(event, ctx) {
    if (ctx.enabled === false)
        return {};
    if (ctx.config.mode === "off")
        return {};
    if (ctx.config.toolPolicy.whitelist.includes("user_input"))
        return {};
    const result = redactText(event.prompt, { ...ctx, toolName: "user_input" });
    if (result.matches.length === 0)
        return {};
    return { prompt: result.text };
}
//# sourceMappingURL=user-input.js.map