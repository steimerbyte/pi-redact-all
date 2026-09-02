// Layer 8: PII-Erkennung
// Erkennt Email, Telefon, IPv4, Kreditkarten, SSN, IBAN
import { buildMarkerCache, isInsideMarker } from "./shared.js";
const EMAIL_RE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;
const PHONE_DE_RE = /\b(?:\+49|0)\s?[\d\s\-/()]{8,}\d\b/g;
const PHONE_E164_RE = /\+[1-9]\d{1,14}\b/g;
const IPV4_RE = /\b(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g;
const CREDIT_CARD_RE = /\b(?:\d[ -]?){13,19}\b/g;
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;
const IBAN_RE = /\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b/g;
/**
 * Luhn check for credit card numbers.
 */
function isLuhnValid(digits) {
    const d = digits.replace(/\D/g, "");
    if (d.length < 13 || d.length > 19)
        return false;
    let sum = 0;
    let alt = false;
    for (let i = d.length - 1; i >= 0; i--) {
        let n = parseInt(d[i], 10);
        if (alt) {
            n *= 2;
            if (n > 9)
                n -= 9;
        }
        sum += n;
        alt = !alt;
    }
    return sum % 10 === 0;
}
/**
 * PII patterns require specific characters that appear very rarely in
 * structured/programmatic output. We can short-circuit the regex scan when
 * none of the patterns' distinguishing characters are present in the text.
 *
 * - Email needs `@`
 * - Phone DE needs `+49` or digit-leading sequences (cheap to assume)
 * - Phone E.164 needs `+`
 * - IPv4 needs three `.` in sequence-like position (hard to pre-screen)
 * - Credit Card needs long digit run (assumed)
 * - SSN needs `\d{3}-\d{2}-` (rare in prose)
 * - IBAN needs `[A-Z]{2}\d{2}` (rare in prose)
 *
 * IndexOf on rare literals is much cheaper than letting the regex engine
 * scan the entire text only to find zero matches. This is a 5-8× speedup
 * on texts without any PII (e.g. logs of code, secrets dumps).
 */
function textContainsAny(text, needles) {
    for (let i = 0; i < needles.length; i++) {
        if (text.indexOf(needles[i]) !== -1)
            return true;
    }
    return false;
}
export function apply(text, ctx) {
    const matches = [];
    // PERFORMANCE: marker cache
    const markerCache = buildMarkerCache(text);
    // Email — needs `@`
    if (text.indexOf("@") !== -1) {
        pushAll(text, EMAIL_RE, matches, "Email", markerCache);
    }
    // Phone E.164 — needs `+` and a digit, cheap heuristic: `+` present
    // We still scan DE regex (`+49` or `0`+digits) because leading-zero dialing
    // doesn't require `+`. We don't pre-screen DE since `0` is too common.
    if (text.indexOf("+") !== -1) {
        pushAll(text, PHONE_E164_RE, matches, "Phone", markerCache);
    }
    pushAll(text, PHONE_DE_RE, matches, "Phone", markerCache);
    // IPv4 — three `.` chars needed, but that's expensive to indexOf.
    // We'll skip pre-screen; the IPv4 regex with word boundaries is cheap when
    // no IP-shaped cluster exists. Most non-PII text has < 50 IP candidates.
    pushAll(text, IPV4_RE, matches, "IPv4", markerCache);
    // Credit Card — needs a long digit run. We pre-screen for any 6+ char
    // sequence of digits. Most texts don't have any.
    if (textContainsAny(text, ["000000", "111111", "222222", "333333", "444444", "555555", "666666", "777777", "888888", "999999"])
        || /[\d]{6,}/.test(text)) {
        pushAll(text, CREDIT_CARD_RE, matches, "Credit Card", markerCache, (value) => {
            const digits = value.replace(/\D/g, "");
            return digits.length >= 13 && isLuhnValid(digits);
        });
    }
    // SSN — needs `\d{3}-\d{2}-`
    if (textContainsAny(text, ["000-00-", "111-11-", "222-22-", "333-33-", "444-44-", "555-55-", "666-66-", "777-77-", "888-88-", "999-99-"])
        || /[\d]{3}-\d{2}-/.test(text)) {
        pushAll(text, SSN_RE, matches, "SSN", markerCache);
    }
    // IBAN — `[A-Z]{2}\d{2}` followed by `[A-Z0-9]{4,}`. Hard to pre-screen
    // cheaply, but a long alphanumeric tail is a reasonable proxy.
    if (/[A-Z]{2}\d{2}[A-Z0-9]{4,}/.test(text)) {
        pushAll(text, IBAN_RE, matches, "IBAN", markerCache);
    }
    return { matches };
}
function pushAll(text, pattern, matches, type, markerCache, validator) {
    pattern.lastIndex = 0;
    let m;
    while ((m = pattern.exec(text)) !== null) {
        const start = m.index;
        const end = start + m[0].length;
        if (isInsideMarker(markerCache, start, end))
            continue;
        if (matchesOverlapExisting(matches, start, end))
            continue;
        if (validator && !validator(m[0]))
            continue;
        matches.push({
            start,
            end,
            type,
            replacement: `[REDACTED:${type}]`,
        });
    }
}
function matchesOverlapExisting(matches, start, end) {
    for (const m of matches) {
        if (start < m.end && end > m.start)
            return true;
    }
    return false;
}
//# sourceMappingURL=layer-8-pii.js.map