// Shared utilities for layer implementations
/**
 * Build a redaction marker like: `AKIA****************[REDACTED:AWS Access Key]`
 * Preserves a short prefix for context, fills middle with asterisks, appends marker.
 */
export function buildMarker(value, type, preservePrefixChars = 4, asterisksMax = 20) {
    // Strip whitespace at boundaries; keep core chars
    const trimmed = value.replace(/^[\s"']+|[\s"']+$/g, "");
    const prefix = trimmed.slice(0, preservePrefixChars);
    const stars = "*".repeat(Math.min(asterisksMax, Math.max(8, trimmed.length - preservePrefixChars)));
    return `${prefix}${stars}[REDACTED:${type}]`;
}
/**
 * File-extension heuristic. Matches a leading dot followed by 1-6 alphanumeric
 * chars — `.md`, `.json`, `.ts`, `.docx`, `.tar.gz` (the trailing `.gz` is its
 * own extension). Used as one of the path-context signals.
 */
const FILE_EXT_RE = /\.[a-z0-9]{1,6}(?=[^a-z0-9]|$)/i;
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
export function isInsidePathContext(text, start, end) {
    const before = text.slice(Math.max(0, start - 60), start);
    const rawAfter = text.slice(end, Math.min(text.length, end + 80));
    // Strip any [REDACTED:...] marker bodies from the segment we look at AFTER the
    // match. Without this, our own redaction marker text like `[REDACTED:OpenAI/
    // Anthropic API Key]` would trigger the "path separator ahead" heuristic via the
    // `/` in `OpenAI/Anthropic` and incorrectly mark every vendor match as path
    // context. We strip the marker entirely and then add an extra space so the
    // surrounding whitespace semantics stay usable.
    const after = rawAfter.replace(/\[REDACTED[^\]]*\]/g, " ").trimStart();
    // 1. Path separator immediately before the match — strongly indicates a path segment.
    const lastChar = start > 0 ? text[start - 1] : "";
    if (lastChar === "/" || lastChar === "\\")
        return true;
    // 2. Path separator shortly after the match (in cleaned text only).
    if (after.length > 0 && /[\\/]/.test(after.slice(0, 20)))
        return true;
    // 3. File extension shortly after OR INSIDE the match (e.g.
    //    `zed-task-sk-XYZ<match>.md`). Layer 1's char class `[a-zA-Z0-9._\-]`
    //    greedily eats the trailing `.md`, so by the time we look at `after`
    //    the `.json` is *inside* the match span. We therefore also check a wider
    //    window forward of `end` and look for an extension-like suffix at the
    //    match boundary itself.
    if (after.length > 0 && FILE_EXT_RE.test(after))
        return true;
    // The match itself ends with `.<ext>` — peel that off and treat as path-context.
    // Layer-1 only ever matches `.md`-style suffixes of lengths 1-6, so this is safe.
    const tailWithinMatch = text.slice(Math.max(0, end - 7), end);
    if (/\.[a-z0-9]{1,6}$/i.test(tailWithinMatch))
        return true;
    // 4. Path-prefix cues immediately before the match.
    //    e.g. `path: zed-task-sk-XYZ...`, `to /home/foo/zed-task-sk-XYZ...`,
    //    `Z. zed-task-sk-XYZ...`, `<path>zed-task-sk-XYZ...`,
    //    `save sk-...`, `from sk-...`. We deliberately do NOT match generic
    //    words like "token" / "secret" / "key" (they often precede a real secret
    //    in user prose and would create false negatives).
    if (/(?:path|file|filename|filepath|dir|loc|tgt|target)\s*:\s*$/i.test(before)) {
        return true;
    }
    if (/\b(?:to|from|save|write|create|store|in|at|via|using)\s+$/i.test(before)) {
        return true;
    }
    if (/<\s*\/?\s*(?:path|file|filename|filepath)\s*>\s*$/i.test(before)) {
        return true;
    }
    // 5. Data-URL prefix: when a long high-entropy token sits *immediately* after
    //    a `data:image/...;base64,` (or `data:application/...;base64,`) prefix in
    //    the prior 60 chars, it's the base64 payload of an inline image or file.
    //    Redacting those to `[REDACTED:High Entropy Token]` corrupts the payload
    //    in the same way the Anthropic `invalid image content` 400 used to be
    //    triggered. Real secrets in this context (an attacker pasting a key into
    //    a data: URL) are still caught when the URL form passes the provider's
    //    payload schema check upstream — this suppression only affects the
    //    entropy layer's tendency to flag base64 alphabet text as suspicious.
    if (/data:[a-z0-9.\/+-]+;base64,?$/i.test(before)) {
        return true;
    }
    return false;
}
export function buildMarkerCache(text) {
    const spans = [];
    const markerSpans = [];
    // Match [REDACTED:...] where ... is anything that doesn't contain ]
    // The marker body starts AFTER "[REDACTED:" and ends at the closing "]"
    const re = /\[REDACTED[^\]]*\]/g;
    let m;
    while ((m = re.exec(text)) !== null) {
        const markerStart = m.index;
        const markerEnd = m.index + m[0].length;
        markerSpans.push([markerStart, markerEnd]);
        // The "redacted" portion is between prefix and marker (e.g. "AKIA****[REDACTED:Type]")
        // For our purposes, we treat the entire marker span as already-redacted
        spans.push([markerStart, markerEnd]);
    }
    return { spans, markerSpans };
}
/**
 * O(log n) check: is the [start, end) span inside any cached marker?
 */
export function isInsideMarker(cache, start, end) {
    const spans = cache.spans;
    // Binary search for first span with end > start
    let lo = 0;
    let hi = spans.length;
    while (lo < hi) {
        const mid = (lo + hi) >>> 1;
        if (spans[mid][1] <= start) {
            lo = mid + 1;
        }
        else {
            hi = mid;
        }
    }
    // Check if span at lo contains [start, end)
    if (lo < spans.length && spans[lo][0] <= start && spans[lo][1] >= end) {
        return true;
    }
    // Also check the span right before, in case start is just past it
    if (lo > 0 && spans[lo - 1][0] <= start && spans[lo - 1][1] >= end) {
        return true;
    }
    return false;
}
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
export function applyMatches(text, matches) {
    if (matches.length === 0)
        return text;
    // In-place sort — layer pipeline never reuses these arrays.
    matches.sort((a, b) => a.start - b.start);
    // Dedupe overlapping: keep the one starting first. Pre-size to avoid
    // repeated V8 array-growth.
    const filtered = new Array(matches.length);
    let fLen = 0;
    let lastEnd = -1;
    for (let i = 0; i < matches.length; i++) {
        const m = matches[i];
        if (m.start >= lastEnd) {
            filtered[fLen++] = m;
            lastEnd = m.end;
        }
    }
    // Build output: text slices interleaved with replacements.
    // Worst case: 2m+1 parts (text, rep, text, rep, ..., trailing text).
    const parts = new Array(fLen * 2 + 1);
    let cursor = 0;
    let p = 0;
    for (let i = 0; i < fLen; i++) {
        const m = filtered[i];
        if (m.start > cursor) {
            parts[p++] = text.slice(cursor, m.start);
        }
        parts[p++] = m.replacement;
        cursor = m.end;
    }
    if (cursor < text.length) {
        parts[p++] = text.slice(cursor);
    }
    // Trim trailing undefined slots if dedupe reduced the count.
    if (p < parts.length)
        parts.length = p;
    return parts.join("");
}
/**
 * Check whether the given [start, end) span overlaps an existing REDACTED marker.
 * This prevents re-redacting already-redacted spans.
 * @deprecated Use isInsideMarker with buildMarkerCache for O(log n) performance.
 */
export function isInsideExistingMarker(text, start, end) {
    // Walk backwards from start to find "[REDACTED"
    let i = start - 1;
    while (i >= 0) {
        const c = text[i];
        if (c === "[") {
            const ahead = text.slice(i, i + 9);
            if (ahead.startsWith("[REDACTED"))
                return true;
            return false;
        }
        if (c === "]") {
            // Closed marker passed — we're outside
            return false;
        }
        i--;
    }
    return false;
}
/**
 * Check whether the given [start, end) span overlaps any existing match in the list.
 * Uses sorted-array binary search for O(log n) performance.
 */
export function hasOverlap(sortedMatches, start, end) {
    // Binary search for first match with end > start
    let lo = 0;
    let hi = sortedMatches.length;
    while (lo < hi) {
        const mid = (lo + hi) >>> 1;
        if (sortedMatches[mid].end <= start) {
            lo = mid + 1;
        }
        else {
            hi = mid;
        }
    }
    // Check match at lo and lo-1 for overlap
    if (lo < sortedMatches.length) {
        const m = sortedMatches[lo];
        if (start < m.end && end > m.start)
            return true;
    }
    if (lo > 0) {
        const m = sortedMatches[lo - 1];
        if (start < m.end && end > m.start)
            return true;
    }
    return false;
}
//# sourceMappingURL=shared.js.map