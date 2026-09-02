// Layer 3: Vendor-Prefix-Erkennung
// Schnelle Vorprüfung auf bekannte Präfixe — getrennt von Layer 1 für schnellen Pass
import { buildMarker, buildMarkerCache, isInsideMarker, isInsidePathContext } from "./shared.js";
const PREFIX_PATTERNS = [
    { prefix: "ghp_", name: "GitHub Token" },
    { prefix: "gho_", name: "GitHub OAuth Token" },
    { prefix: "ghu_", name: "GitHub User Token" },
    { prefix: "ghs_", name: "GitHub Server Token" },
    { prefix: "ghr_", name: "GitHub Refresh Token" },
    { prefix: "github_pat_", name: "GitHub PAT" },
    { prefix: "xoxb-", name: "Slack Bot Token" },
    { prefix: "xoxp-", name: "Slack User Token" },
    { prefix: "xapp-", name: "Slack App Token" },
    { prefix: "glpat-", name: "GitLab Token" },
    { prefix: "npm_", name: "npm Token" },
    { prefix: "AIza", name: "Google API Key" },
    { prefix: "SG.", name: "SendGrid API Key" },
    { prefix: "sk-", name: "OpenAI/Anthropic API Key" },
    { prefix: "sk_live_", name: "Stripe Live Key" },
    { prefix: "sk_test_", name: "Stripe Test Key" },
    { prefix: "AKIA", name: "AWS Access Key" },
    { prefix: "ASIA", name: "AWS Temp Access Key" },
    { prefix: "BSA", name: "Brave API Key" },
    { prefix: "fc-", name: "Firecrawl API Key" },
    { prefix: "tvly-", name: "Tavily API Key" },
    { prefix: "eyJ", name: "JWT" },
];
// Char-code check for `[A-Za-z0-9_-]` — replaces a per-char regex test
// (`/[A-Za-z0-9_-]/.test(c)`) which is way slower than a single charCodeAt.
function isTokenChar(code) {
    return ((code >= 0x30 && code <= 0x39) || // 0-9
        (code >= 0x41 && code <= 0x5a) || // A-Z
        (code >= 0x61 && code <= 0x7a) || // a-z
        code === 0x5f || // _
        code === 0x2d // -
    );
}
export function apply(text, ctx) {
    const matches = [];
    // PERFORMANCE: Build marker cache once
    const markerCache = buildMarkerCache(text);
    for (const { prefix, name } of PREFIX_PATTERNS) {
        let searchFrom = 0;
        const minLen = prefix.length + 8;
        while (true) {
            const idx = text.indexOf(prefix, searchFrom);
            if (idx === -1)
                break;
            // Find end of token via charCode loop (no regex per char)
            let end = idx + prefix.length;
            while (end < text.length && isTokenChar(text.charCodeAt(end))) {
                end++;
            }
            const tokenLen = end - idx;
            if (tokenLen >= minLen) {
                const value = text.slice(idx, end);
                if (!isInsideMarker(markerCache, idx, end)) {
                    if (!matchesOverlapExisting(matches, idx, end)) {
                        // v0.1.4: skip matches inside path-like contexts so we never
                        // corrupt legitimate filename fragments shaped like vendor prefixes.
                        if (isInsidePathContext(text, idx, end)) {
                            searchFrom = idx + 1;
                            continue;
                        }
                        matches.push({
                            start: idx,
                            end,
                            type: name,
                            replacement: buildMarker(value, name, ctx.config.preservePrefixChars, ctx.config.asterisksMax),
                        });
                    }
                }
            }
            searchFrom = idx + 1;
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
//# sourceMappingURL=layer-3-prefix.js.map