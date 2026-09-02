// Layer 9 + 10: Connection-Strings & URL-Embedded-Credentials
// Erkennt postgres://user:pass@host und https://user:pass@host
import { buildMarkerCache, isInsideMarker } from "../layers/shared.js";
// Connection-string with `protocol://user:pass@host`. After finding `://`
// we walk back to the start of the protocol name and verify the whole string
// against the regex (so we don't miss the `\b` boundary the original regex
// used to enforce).
const CONNECTION_STRING_RE = /^([a-z][a-z0-9+.\-]*):\/\/([^:\s]+):([^@\s\/]+)@([^\s\/]+)/i;
const URL_WITH_CREDS_RE = /^https?:\/\/([^:\s]+):([^@\s\/]+)@([^\s\/]+)/i;
/**
 * Find the start of the run of word chars ending at position `endPos`.
 * Returns the index of the first char in the run, or `endPos` if none.
 * Bound by `[startBound, endPos]`. Used to walk back from `://` to the
 * protocol name's start.
 */
function findProtocolStart(text, colonSlashPos) {
    let i = colonSlashPos;
    while (i > 0) {
        const c = text.charCodeAt(i - 1);
        const isWord = (c >= 0x30 && c <= 0x39) ||
            (c >= 0x41 && c <= 0x5a) ||
            (c >= 0x61 && c <= 0x7a) ||
            c === 0x2b || c === 0x2d || c === 0x2e; // + - .
        if (!isWord)
            break;
        i--;
    }
    // We stopped at the first non-word char. The run must start with a letter.
    const firstChar = text.charCodeAt(i);
    if (i === colonSlashPos ||
        !((firstChar >= 0x61 && firstChar <= 0x7a) ||
            (firstChar >= 0x41 && firstChar <= 0x5a))) {
        return -1; // No valid protocol name
    }
    return i;
}
export function apply(text, ctx) {
    const matches = [];
    // PERFORMANCE: marker cache
    const markerCache = buildMarkerCache(text);
    // ===== Layer 9: Connection strings =====
    // IndexOf `://` is the rare literal — most texts have zero. Each `://`
    // hit goes through the regex (with manual back-walk to protocol start).
    let idx = 0;
    while (idx < text.length) {
        const found = text.indexOf("://", idx);
        if (found === -1)
            break;
        // Walk back to find the protocol name's start
        const protoStart = findProtocolStart(text, found);
        if (protoStart === -1) {
            idx = found + 1;
            continue;
        }
        // The match needs a word boundary BEFORE the protocol name (to mirror
        // `\b(...)` in the original regex). Accept start-of-string or non-word
        // boundary char.
        let boundaryOK = protoStart === 0;
        if (!boundaryOK) {
            const prev = text.charCodeAt(protoStart - 1);
            boundaryOK = !((prev >= 0x30 && prev <= 0x39) ||
                (prev >= 0x41 && prev <= 0x5a) ||
                (prev >= 0x61 && prev <= 0x7a) ||
                prev === 0x5f // _
            );
        }
        if (!boundaryOK) {
            idx = found + 1;
            continue;
        }
        const window = text.slice(protoStart, Math.min(text.length, protoStart + 512));
        const m = CONNECTION_STRING_RE.exec(window);
        if (!m) {
            idx = found + 1;
            continue;
        }
        const start = protoStart;
        const end = start + m[0].length;
        if (isInsideMarker(markerCache, start, end)) {
            idx = end;
            continue;
        }
        if (matchesOverlapExisting(matches, start, end)) {
            idx = end;
            continue;
        }
        matches.push({
            start,
            end,
            type: "Connection String",
            replacement: `${m[1]}://${m[2]}:[REDACTED:Password]@${m[4]}`,
        });
        idx = end;
    }
    // ===== Layer 10: URL credentials =====
    // The `https?://` prefix is unambiguous; pre-scan both literals.
    for (const prefix of ["http://", "https://"]) {
        let j = 0;
        while (j < text.length) {
            const found = text.indexOf(prefix, j);
            if (found === -1)
                break;
            const window = text.slice(found, Math.min(text.length, found + 256));
            const m = URL_WITH_CREDS_RE.exec(window);
            if (!m) {
                j = found + 1;
                continue;
            }
            const start = found;
            const end = found + m[0].length;
            if (!isInsideMarker(markerCache, start, end)) {
                if (!matchesOverlapExisting(matches, start, end)) {
                    matches.push({
                        start,
                        end,
                        type: "URL Credentials",
                        replacement: `https://${m[1]}:[REDACTED:Password]@${m[3]}`,
                    });
                }
            }
            j = end;
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
//# sourceMappingURL=layer-9-10-connection.js.map