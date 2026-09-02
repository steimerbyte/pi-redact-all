import type { RedactionContext, LayerResult } from "../types.js";
export declare function apply(text: string, ctx: RedactionContext): LayerResult;
/**
 * Returns true if the path should be blocked entirely (PreToolUse hook).
 */
export declare function shouldBlockPath(path: string): boolean;
/**
 * Returns true if the bash command reads sensitive paths.
 */
export declare function commandReadsSensitive(command: string): boolean;
//# sourceMappingURL=layer-7-path.d.ts.map