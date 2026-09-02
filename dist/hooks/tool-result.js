// tool-result hook — PostToolUse redaction
import { redactText } from "../layers/index.js";
import { isTextItem } from "./content-utils.js";
/**
 * Apply redaction to all text items in tool result content.
 * Returns the patched content array (or undefined if no changes).
 */
export function applyRedaction(event, ctx) {
    if (ctx.config.mode === "off")
        return {};
    // Skip whitelisted tools
    if (ctx.config.toolPolicy.whitelist.includes(event.toolName))
        return {};
    // Apply blacklisted tools (always redact, regardless of whitelist)
    // For blacklisted, we just apply redaction normally
    const inputPath = extractPath(event.input);
    const command = extractCommand(event.input);
    const partialCtx = {
        ...ctx,
        toolName: event.toolName,
        inputPath,
        command,
    };
    let totalMatches = 0;
    let newContent;
    for (let i = 0; i < event.content.length; i++) {
        const item = event.content[i];
        if (!isTextItem(item))
            continue;
        const result = redactText(item.text, partialCtx);
        if (result.matches.length === 0)
            continue;
        if (!newContent)
            newContent = [...event.content];
        newContent[i] = { ...item, text: result.text };
        totalMatches += result.matches.length;
    }
    if (totalMatches === 0)
        return {};
    return { content: newContent ?? event.content };
}
function extractPath(input) {
    if (!input)
        return undefined;
    const path = input.path ?? input.file_path ?? input.file;
    return typeof path === "string" ? path : undefined;
}
function extractCommand(input) {
    if (!input)
        return undefined;
    const cmd = input.command ?? input.cmd;
    return typeof cmd === "string" ? cmd : undefined;
}
//# sourceMappingURL=tool-result.js.map