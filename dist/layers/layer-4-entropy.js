// Layer 4: Shannon-Entropy-Heuristik
// Erkennt hoch-entropy Strings in isolierten Tokens
import { buildMarker, buildMarkerCache, isInsideMarker, isInsidePathContext } from "./shared.js";
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
export function shannonEntropy(str) {
    const n = str.length;
    if (n === 0)
        return 0;
    const freq = new Int32Array(128);
    for (let i = 0; i < n; i++) {
        const c = str.charCodeAt(i);
        if (c < 128)
            freq[c]++;
        // Anything outside ASCII is rare in this layer (we already filter
        // `[A-Za-z0-9+/\-_]` upstream) — we just drop it from the entropy calc.
    }
    let h = 0;
    for (let i = 0; i < 128; i++) {
        const count = freq[i];
        if (count === 0)
            continue;
        const p = count / n;
        h -= p * Math.log2(p);
    }
    return h;
}
/**
 * Single-pass classification: does this token look like hex, base64, both, or
 * neither? Hot path: 1000+ tokens × per-text processing, so we want this to
 * be a flat O(n) char-code loop instead of two anchored regex scans.
 *
 * Rules:
 *   - hex is valid: `[A-Fa-f0-9]+` (so digits + A-F + a-f)
 *   - base64 is valid: `[A-Za-z0-9+/=]+` (digits + A-Z + a-z + + / =)
 *   - the only chars in TOKEN_RE's class `[A-Za-z0-9+/\-_]` that disqualify
 *     BOTH alphabets are `_` (0x5f) and `-` (0x2d)
 *   - chars `g-z`/`G-Z` and `+`/`/`/`=` disqualify hex but keep base64 valid
 *
 * Returns { hex, base64 } so the caller can short-circuit with one test.
 */
function classifyChars(value) {
    let hex = true;
    let base64 = true;
    for (let i = 0; i < value.length; i++) {
        const c = value.charCodeAt(i);
        // 0-9 — both alphabets
        if (c >= 0x30 && c <= 0x39)
            continue;
        // A-F / a-f — both alphabets
        if (c >= 0x41 && c <= 0x46)
            continue;
        if (c >= 0x61 && c <= 0x66)
            continue;
        // G-Z / g-z — base64 only (not hex)
        if (c >= 0x47 && c <= 0x5a) {
            hex = false;
            continue;
        }
        if (c >= 0x67 && c <= 0x7a) {
            hex = false;
            continue;
        }
        // + / / = — base64 only (not hex)
        if (c === 0x2b || c === 0x2f || c === 0x3d) {
            hex = false;
            continue;
        }
        // _ or - or anything else in TOKEN_RE's class — neither
        return { hex: false, base64: false };
    }
    return { hex, base64 };
}
const HEX_RE = /^[A-Fa-f0-9]+$/;
const BASE64_RE = /^[A-Za-z0-9+/=]+$/;
const TOKEN_RE = /\b[A-Za-z0-9+/\-_]{20,}\b/g;
const ALLOWLIST_DEFAULT_PATTERNS = [
    // Git short SHAs
    /\b[0-9a-f]{7,40}\b.*?(?:commit|sha)/i,
    // UUIDs
    /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i,
    // Semver
    /\bv?\d+\.\d+\.\d+(?:-[\w.]+)?\b/,
];
export function apply(text, ctx) {
    const matches = [];
    const minEntropy = ctx.config.minEntropy;
    const minLength = ctx.config.minLength;
    // Combine default + user allowlist patterns
    const userPatterns = ctx.config.allowlistRegex
        .map((p) => {
        try {
            return new RegExp(p);
        }
        catch {
            return null;
        }
    })
        .filter((p) => p !== null);
    const allowlistPatterns = [...ALLOWLIST_DEFAULT_PATTERNS, ...userPatterns];
    // PERFORMANCE FIX: Build marker cache once, not per-match
    const markerCache = buildMarkerCache(text);
    TOKEN_RE.lastIndex = 0;
    let m;
    while ((m = TOKEN_RE.exec(text)) !== null) {
        const value = m[0];
        const start = m.index;
        const end = start + value.length;
        if (value.length < minLength)
            continue;
        // O(log n) marker check instead of O(n)
        if (isInsideMarker(markerCache, start, end))
            continue;
        // Single-pass classification replaces HEX_RE.test() + BASE64_RE.test()
        // (two anchored regex scans) with one flat char-code loop. Same answer,
        // ~2-3× faster per token.
        const cls = classifyChars(value);
        if (!cls.hex && !cls.base64)
            continue;
        // Allowlist check: if any allowlist pattern matches, skip
        let allowed = false;
        for (let p = 0; p < allowlistPatterns.length; p++) {
            if (allowlistPatterns[p].test(value)) {
                allowed = true;
                break;
            }
        }
        if (allowed)
            continue;
        const entropy = shannonEntropy(value);
        if (entropy < minEntropy)
            continue;
        // v0.1.4: skip matches inside path-like contexts so random alphanumeric
        // filename fragments are not flagged as high-entropy secrets.
        if (isInsidePathContext(text, start, end))
            continue;
        matches.push({
            start,
            end,
            type: "High Entropy Token",
            replacement: buildMarker(value, "High Entropy Token", ctx.config.preservePrefixChars, ctx.config.asterisksMax),
        });
    }
    return { matches };
}
//# sourceMappingURL=layer-4-entropy.js.map