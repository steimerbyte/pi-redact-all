import type { Match } from "../types.js";
/**
 * Build a redaction marker like: `AKIA****************[REDACTED:AWS Access Key]`
 * Preserves a short prefix for context, fills middle with asterisks, appends marker.
 */
export declare function buildMarker(value: string, type: string, preservePrefixChars?: number, asterisksMax?: number): string;
/**
 * Detects whether the [start, end) span in `text` is sitting inside a path-like
 * context. Specifically, returns true when one or more of these is true:
 *
 *  - the char immediately before start is a path separator (`/`, `\`)
 *  - the substring from start to the next 80 chars contains `/` or `\`
 *    (a directory or filename anchor further ahead)
 *  - within the 80 chars after end there's a file extension (`.md`, `.json`, ...)
 *    followed by a non-alphanumeric character or EOL
 *  - within the 60 chars before start there's a path-like prefix
 *    (e.g. `path:`, `File:`, `Z.`, `Located at`, "to ", `dir/`, `<`)
 *
 * The heuristic is intentionally loose. False positives are bounded by the
 * other redaction passes still running; missing real path-context matches
 * would leave users with corrupted file paths (e.g. an OpenAI key signature
 * inside an innocent filename being replaced with `[REDACTED:...]`).
 *
 * This is the v0.1.4 mitigation for the "redacted legitimate file path" bug
 * where Layer 1 vendor + Layer 4 entropy matched on long base64-looking tokens
 * that happened to be part of an Obsidian playbook name like
 * `zed-task-handle.md` and turned it into `zed-task-h***[REDACTED:...].md`.
 */
export declare function isInsidePathContext(text: string, start: number, end: number): boolean;
/**
 * Marker-Span-Cache: tracks existing [REDACTED:...] markers in the text.
 * Built ONCE per text via buildMarkerCache() — used by all layers via isInsideMarker().
 * This avoids the O(n) per-match scan that would make entropy layer O(n²).
 */
export interface MarkerCache {
    /** Sorted array of [start, end) spans that are inside existing [REDACTED:...] markers. */
    spans: [number, number][];
    /** Sorted array of [start, end) spans that are the marker bodies themselves (for reference). */
    markerSpans: [number, number][];
}
export declare function buildMarkerCache(text: string): MarkerCache;
/**
 * O(log n) check: is the [start, end) span inside any cached marker?
 */
export declare function isInsideMarker(cache: MarkerCache, start: number, end: number): boolean;
/**
 * Apply matches to text. All other whitespace, newlines, structure is preserved 1:1.
 *
 * PERFORMANCE: Uses array-parts + join instead of repeated string concatenation,
 * which would be O(n²) for large match counts. This is O(n + m).
 *
 * v0.1.6: in-place sort of the matches array (we own it — callers pass fresh
 * arrays from each layer). Saves the [...matches] clone for the common
 * small-matches case. Dedupe loop uses a pre-sized `filtered` array to avoid
 * Array.push() reallocation. The two-pass slice/join uses a single `parts`
 * array sized to (2m + 1) so each push is amortized O(1).
 */
export declare function applyMatches(text: string, matches: Match[]): string;
/**
 * Check whether the given [start, end) span overlaps an existing REDACTED marker.
 * This prevents re-redacting already-redacted spans.
 * @deprecated Use isInsideMarker with buildMarkerCache for O(log n) performance.
 */
export declare function isInsideExistingMarker(text: string, start: number, end: number): boolean;
/**
 * Check whether the given [start, end) span overlaps any existing match in the list.
 * Uses sorted-array binary search for O(log n) performance.
 */
export declare function hasOverlap(sortedMatches: Match[], start: number, end: number): boolean;
//# sourceMappingURL=shared.d.ts.map