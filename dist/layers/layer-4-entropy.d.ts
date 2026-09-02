import type { RedactionContext, LayerResult } from "../types.js";
/**
 * Calculate Shannon entropy in bits per character.
 *
 * Performance: O(n) on a 128-int frequency array (typed) instead of a Map.
 * For ASCII-only tokens (the only kind the entropy layer processes — every
 * token character is in `[A-Za-z0-9+/\-_]`), this is roughly 3-5× faster
 * than the Map version because (a) there's no hash lookup, (b) iteration
 * of a fixed-size array avoids Map's per-entry overhead, and (c) the inner
 * `Math.log2` loop only fires for buckets that saw at least one character.
 */
export declare function shannonEntropy(str: string): number;
export declare function apply(text: string, ctx: RedactionContext): LayerResult;
//# sourceMappingURL=layer-4-entropy.d.ts.map