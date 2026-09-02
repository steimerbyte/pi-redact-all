// Layer 1: Strukturierte Vendor-Patterns
// Erkennt API-Keys, Tokens, Credentials von bekannten Herstellern
import { buildMarker, buildMarkerCache, isInsideMarker, isInsidePathContext } from "./shared.js";
const PATTERNS = [
    // AKIA / ASIA: 4-char literal prefix, word boundary before.
    { name: "AWS Access Key", prefix: "AKIA", tail: /^AKIA[A-Z0-9]{16}\b/, wordBoundary: true },
    { name: "AWS Temp Access Key", prefix: "ASIA", tail: /^ASIA[A-Z0-9]{16}\b/, wordBoundary: true },
    // AWS Secret: long literal prefix. Match on the variable part.
    {
        name: "AWS Secret Key",
        prefix: "secret_access_key",
        tail: /^(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|secret_access_key|SecretAccessKey)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40,}["']?/,
        wordBoundary: true,
    },
    // Bearer
    { name: "Bearer Token", prefix: "Bearer", tail: /^Bearer\s+[a-zA-Z0-9._\-]{20,}\b/, wordBoundary: true },
    // sk- based
    { name: "OpenAI/Anthropic API Key", prefix: "sk-", tail: /^sk-[a-zA-Z0-9._\-]{20,}\b/, wordBoundary: true },
    { name: "Stripe Live Key", prefix: "sk_live_", tail: /^sk_live_[a-zA-Z0-9]{20,}\b/, wordBoundary: true },
    { name: "Stripe Test Key", prefix: "sk_test_", tail: /^sk_test_[a-zA-Z0-9]{20,}\b/, wordBoundary: true },
    // Hetzner
    {
        name: "Hetzner Token",
        prefix: "TOKEN",
        tail: /^(?:HCLOUD_TOKEN|hcloud_token|token)\s*[:=]\s*["']?[a-f0-9]{64}\b/i,
        wordBoundary: false,
    },
    // GitHub
    { name: "GitHub Token", prefix: "gh", tail: /^gh[pousr]_[a-zA-Z0-9]{36,}\b/, wordBoundary: true },
    { name: "GitHub Fine-grained PAT", prefix: "github_pat_", tail: /^github_pat_[a-zA-Z0-9_]{20,}\b/, wordBoundary: true },
    // JWT
    { name: "JWT", prefix: "eyJ", tail: /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/, wordBoundary: true },
    // Slack (multiple variants)
    { name: "Slack Token", prefix: "xoxb-", tail: /^xox[baprs]-[A-Za-z0-9-]{20,}\b/, wordBoundary: true },
    // GitLab
    { name: "GitLab Token", prefix: "glpat-", tail: /^glpat-[A-Za-z0-9_\-]{20,}\b/, wordBoundary: true },
    // Google AIza
    { name: "Google API Key", prefix: "AIza", tail: /^AIza[A-Za-z0-9_\-]{35}\b/, wordBoundary: true },
    // npm
    { name: "npm Token", prefix: "npm_", tail: /^npm_[A-Za-z0-9]{36,}\b/, wordBoundary: true },
    // SendGrid
    { name: "SendGrid API Key", prefix: "SG.", tail: /^SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{32,}\b/, wordBoundary: true },
    // Tavily
    { name: "Tavily API Key", prefix: "tvly-", tail: /^tvly-[a-zA-Z0-9_\-]{20,}\b/, wordBoundary: true },
    // Brave
    { name: "Brave API Key", prefix: "BSA", tail: /^BSA[A-Z0-9]{20,}\b/, wordBoundary: true },
    // Firecrawl
    { name: "Firecrawl API Key", prefix: "fc-", tail: /^fc-[a-f0-9]{32}\b/, wordBoundary: true },
];
/** A small char-class check used instead of `\\b` — much faster than the
 *  regex engine's word-boundary primitive. Word chars are `[A-Za-z0-9_]`. */
function isWordChar(c) {
    const code = c.charCodeAt(0);
    return ((code >= 0x30 && code <= 0x39) ||
        (code >= 0x41 && code <= 0x5a) ||
        (code >= 0x61 && code <= 0x7a) ||
        code === 0x5f /* _ */);
}
export function apply(text, ctx) {
    const matches = [];
    const allowlist = compileAllowlist(ctx.config.allowlistRegex);
    // PERFORMANCE: Build marker cache once, use O(log n) checks per match
    const markerCache = buildMarkerCache(text);
    for (const { name, prefix, tail, wordBoundary } of PATTERNS) {
        // PERFORMANCE (v0.1.6): indexOf pre-screen. Most texts don't contain
        // any vendor-prefixed token, so the regex engine would otherwise scan
        // the entire text with `\b`-anchored patterns — measurably expensive.
        // 19 `indexOf` calls are much cheaper than 19 anchored regex scans of
        // 100K+ characters of unstructured prose.
        let idx = 0;
        while (idx < text.length) {
            const found = text.indexOf(prefix, idx);
            if (found === -1)
                break;
            let candidateStart = found;
            if (wordBoundary) {
                // Manual word-boundary check — replaces `\b` so the regex tail
                // below can drop the leading `\\b` anchor (which is the expensive
                // part of the original pattern). Word boundary = prev char is
                // either absent or a non-word char.
                const prev = found > 0 ? text.charCodeAt(found - 1) : -1;
                if (prev !== -1 && isWordChar(String.fromCharCode(prev))) {
                    idx = found + 1;
                    continue;
                }
            }
            // Pull a small window (~80 chars) so the tail regex sees the full
            // remaining pattern body without us copying the entire text.
            const window = text.slice(found, Math.min(text.length, found + 96));
            const m = tail.exec(window);
            if (!m) {
                idx = found + 1;
                continue;
            }
            const start = found;
            const end = found + m[0].length;
            if (isInsideMarker(markerCache, start, end)) {
                idx = end;
                continue;
            }
            if (matchesOverlapExisting(matches, start, end)) {
                idx = end;
                continue;
            }
            if (allowlist.test(m[0])) {
                idx = end;
                continue;
            }
            // v0.1.4: skip matches inside path-like contexts so we never corrupt legitimate
            // file names that happen to contain a token shaped like a vendor key.
            if (isInsidePathContext(text, start, end)) {
                idx = end;
                continue;
            }
            matches.push({
                start,
                end,
                type: name,
                replacement: buildMarker(m[0], name, ctx.config.preservePrefixChars, ctx.config.asterisksMax),
            });
            idx = end;
        }
    }
    return { matches };
}
function matchesOverlapExisting(matches, start, end) {
    for (const m of matches) {
        if (start < m.end && end > m.start)
            return true;
    }
    return false;
}
function compileAllowlist(patterns) {
    if (patterns.length === 0)
        return /(?!)/; // never matches
    try {
        return new RegExp(patterns.join("|"), "g");
    }
    catch {
        return /(?!)/;
    }
}
//# sourceMappingURL=layer-1-vendor.js.map