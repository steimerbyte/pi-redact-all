import type { RedactionContext } from "../types.js";
import { type ContentItem } from "./content-utils.js";
export interface ToolResultLike {
    toolName: string;
    toolCallId: string;
    input?: Record<string, unknown>;
    content: ContentItem[];
}
/**
 * Apply redaction to all text items in tool result content.
 * Returns the patched content array (or undefined if no changes).
 */
export declare function applyRedaction(event: ToolResultLike, ctx: RedactionContext): {
    content?: ContentItem[];
};
//# sourceMappingURL=tool-result.d.ts.map