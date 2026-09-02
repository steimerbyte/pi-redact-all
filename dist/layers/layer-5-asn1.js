// Layer 5: ASN.1 SEQUENCE-Detection
// Erkennt DER-encoded ASN.1-Strukturen (Base64 beginnend mit MII…)
import { buildMarkerCache, isInsideMarker } from "./shared.js";
const ASN1_RE = /(?:^|\s)(MI[A-Za-z0-9+/=]{100,}={0,2})(?=\s|$)/gm;
export function apply(text, ctx) {
    const matches = [];
    // PERFORMANCE: marker cache
    const markerCache = buildMarkerCache(text);
    ASN1_RE.lastIndex = 0;
    let m;
    while ((m = ASN1_RE.exec(text)) !== null) {
        // Skip if previous char is inside REDACTED marker
        const start = m.index + m[0].indexOf(m[1]);
        const end = start + m[1].length;
        if (isInsideMarker(markerCache, start, end))
            continue;
        if (matchesOverlapExisting(matches, start, end))
            continue;
        // Skip if already wrapped in a PEM block (Layer 2 would have caught it)
        // Check: is there a "-----BEGIN" within 200 chars before start?
        const before = text.slice(Math.max(0, start - 200), start);
        if (/-----BEGIN [A-Z ]+-----/.test(before))
            continue;
        matches.push({
            start,
            end,
            type: "ASN.1 SEQUENCE",
            replacement: "[REDACTED:ASN.1 SEQUENCE]",
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
//# sourceMappingURL=layer-5-asn1.js.map