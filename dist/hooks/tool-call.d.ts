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
 * Returns a BlockResult if blocked, undefined otherwise.
 */
export declare function shouldBlock(event: ToolCallLike, config: Config): BlockResult | undefined;
/**
 * Check if input contains secrets that should be blocked (e.g., curl with --data
 * containing a token, or git commit -m with embedded credentials).
 */
export declare function inputContainsSensitiveSecrets(event: ToolCallLike, config: Config): BlockResult | undefined;
//# sourceMappingURL=tool-call.d.ts.map