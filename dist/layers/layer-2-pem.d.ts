import type { Match, RedactionContext, LayerResult } from "../types.js";
/**
 * Track which paths are mid-private-key-block (multi-chunk reads).
 * Used in tool-result hook via ctx.partialPrivateKeyPaths.
 */
export declare function detectPartialKey(text: string, ctx: RedactionContext): Match[];
export declare function apply(text: string, ctx: RedactionContext): LayerResult;
//# sourceMappingURL=layer-2-pem.d.ts.map