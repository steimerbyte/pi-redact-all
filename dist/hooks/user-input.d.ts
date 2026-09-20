import type { RedactionContext } from "../types.js";
/** What the input event handler expects back. */
export interface InputEventResult {
    /** "transform" rewrites the text via `text`; "continue" passes through. */
    action: "continue" | "transform" | "handled";
    /** Replacement text. Only meaningful when action === "transform". */
    text?: string;
}
/**
 * Redact the user's prompt before it is expanded and forwarded to the agent.
 *
 * @param text Raw user input (after slash-command intercept, before skill/template expansion).
 * @param ctx  Redaction context.
 * @returns `{ action: "transform", text }` if anything was redacted, otherwise
 *          `{ action: "continue" }` so the framework falls through to expansion.
 */
export declare function transformInputText(text: string, ctx: RedactionContext): InputEventResult;
//# sourceMappingURL=user-input.d.ts.map