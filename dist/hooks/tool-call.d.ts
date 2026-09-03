import type { Config } from "../types.js";
export interface ToolCallLike {
    toolName: string;
    input?: Record<string, unknown>;
}
export interface BlockResult {
    block: true;
    reason: string;
}
/**
 * Check whether a tool call should be blocked.
 * Write-tools are always skipped (model output = never block).
 */
export declare function shouldBlock(event: ToolCallLike, config: Config, enabled?: boolean): BlockResult | undefined;
/**
 * Check if input contains secrets that should be blocked.
 * Write-tools are always skipped.
 */
export declare function inputContainsSensitiveSecrets(event: ToolCallLike, config: Config, enabled?: boolean): BlockResult | undefined;
//# sourceMappingURL=tool-call.d.ts.map