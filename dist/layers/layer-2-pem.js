// Layer 2: PEM/X.509/PGP/SSH-Block-Erkennung
// Erkennt strukturierte PEM-Blöcke mit Header/Footer
import { buildMarkerCache, isInsideMarker } from "./shared.js";
const PEM_LABELS = [
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "DSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "PGP PRIVATE KEY BLOCK",
    "PGP PUBLIC KEY BLOCK",
    "PUBLIC KEY",
    "CERTIFICATE",
    "TRUSTED CERTIFICATE",
    "X509 CRL",
    "CERTIFICATE REQUEST",
    "NEW CERTIFICATE REQUEST",
    "PKCS7",
    "DH PARAMETERS",
];
// Build the dynamic pattern: matches -----BEGIN LABEL----- ... -----END LABEL-----
const PEM_BLOCK_REGEX = new RegExp(`-----BEGIN ([A-Z ]+)-----\\r?\\n([\\s\\S]*?)(?:\\r?\\n-----END \\1-----|$)`, "g");
/**
 * Track which paths are mid-private-key-block (multi-chunk reads).
 * Used in tool-result hook via ctx.partialPrivateKeyPaths.
 */
export function detectPartialKey(text, ctx) {
    // If we already know this path is mid-private-key, redact everything
    if (ctx.inputPath && ctx.partialPrivateKeyPaths.has(ctx.inputPath)) {
        const beginMatch = /-----BEGIN[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.exec(text);
        const endMatch = /-----END[ \t]+[\w -]*PRIVATE[ \t]+KEY-----/.exec(text);
        if (!endMatch) {
            // Whole content is a continuation
            return [
                {
                    start: 0,
                    end: text.length,
                    type: "Private Key Continuation",
                    replacement: "[REDACTED:Private Key Continuation]",
                },
            ];
        }
        else if (beginMatch) {
            // Has both — only redact between
            return [
                {
                    start: beginMatch.index,
                    end: endMatch.index + endMatch[0].length,
                    type: "Private Key",
                    replacement: "[REDACTED:Private Key]",
                },
            ];
        }
    }
    return [];
}
export function apply(text, ctx) {
    const matches = [];
    // First: handle multi-chunk private key paths
    matches.push(...detectPartialKey(text, ctx));
    // PERFORMANCE: marker cache for O(log n) checks
    const markerCache = buildMarkerCache(text);
    // Now scan PEM blocks
    PEM_BLOCK_REGEX.lastIndex = 0;
    let m;
    while ((m = PEM_BLOCK_REGEX.exec(text)) !== null) {
        const label = m[1];
        const start = m.index;
        const end = start + m[0].length;
        if (isInsideMarker(markerCache, start, end))
            continue;
        if (matchesOverlapExisting(matches, start, end))
            continue;
        matches.push({
            start,
            end,
            type: `PEM ${label.trim()}`,
            replacement: `[REDACTED:PEM ${label.trim()}]`,
        });
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
//# sourceMappingURL=layer-2-pem.js.map