// Layer 6: Context-Anchored Detection
// Erkennt Key=Value-Paare mit sensitiven Schlüsselnamen

import type { Match, RedactionContext, LayerResult } from "../types.js";
import { buildMarkerCache, isInsideMarker } from "./shared.js";

const SECRET_FIELD_NAMES = [
  "password",
  "passwd",
  "secret",
  "token",
  "api_key",
  "api-key",
  "apikey",
  "access_token",
  "access-token",
  "accesstoken",
  "refresh_token",
  "refresh-token",
  "client_secret",
  "client-secret",
  "private_key",
  "private-key",
  "privatekey",
  "auth_token",
  "auth-token",
  "bearer",
  "authorization",
];

const ANCHORS = [
  "subject=",
  "issuer=",
  "verify return:",
  "BEGIN CERT",
  "BEGIN RSA",
  "BEGIN EC",
  "BEGIN PRIVATE",
  "BEGIN PUBLIC",
  "BEGIN OPENSSH",
];

const JSON_SECRET_KEY_PATTERN = new RegExp(
  `(?:"(?:${SECRET_FIELD_NAMES.join("|")})")\\s*:\\s*"((?:\\\\.|[^"\\\\]){8,})"`,
  "gi"
);

// Anchor-Semantik:
// \b (= Übergang word<->non-word) ODER Lookbehind auf UPPER/_ (= Suffix einer
// Word-Run wie "IONOS_API_KEY"). Der alte Anchor `(?:^|[^A-Za-z0-9_])` hat `_`
// ausgeschlossen — ein Word-Char — und so ENV-Namen wie `IONOS_API_KEY`,
// `GITHUB_TOKEN`, `CLOUDFLARE_API_KEY` etc. nicht erkannt.
// Fix: erlaube \b oder ein Lookbehind auf `[A-Z0-9_]` (Prefix-Teil der ENV-Run).
const _WORD_RUN_ANCHOR = String.raw`(?:\b|(?<=[A-Z0-9_]))`;

// Quote-handling via lookahead: check if a quote follows =, then branch accordingly.
// This ensures the closing quote is OUTSIDE the captured group (not in the span).
const ENV_SECRET_PATTERN = new RegExp(
  `${_WORD_RUN_ANCHOR}(?:${SECRET_FIELD_NAMES.join("|")})\\s*=\\s*["']?([^"'\s]{8,})["']?`,
  "gi"
);

// INI/YAML: am Zeilenanfang wird `^` durch (?:^|$) ersetzt, damit auch Whitespace
// vor dem Feldnamen akzeptiert wird. Anchor davor muss via Lookbehind ebenfalls
// Word-Run-Prefix erlauben.
const INI_SECRET_PATTERN = new RegExp(
  `^[ \\t]*(?:${SECRET_FIELD_NAMES.join("|")})[ \\t]*[=:][ \\t]*(.+)$`,
  "gim"
);

const YAML_SECRET_PATTERN = new RegExp(
  `^[ \\t]*(?:${SECRET_FIELD_NAMES.join("|")}):[ \\t](.+)$`,
  "gim"
);

const ANCHOR_RE = new RegExp(ANCHORS.map((a) => a.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "g");

/**
 * Returns true if `value` (after stripping surrounding whitespace and quotes)
 * looks like a Python/JavaScript/Go-style identifier reference:
 *   - bare:   `api_token`, `password`, `my_var`
 *   - dotted: `self.api_token`, `obj.password`, `foo.bar.baz`
 *
 * These are NOT secrets — they are variable/property names. The 8-char minimum
 * in ENV_SECRET_PATTERN can accidentally match e.g. `self.api_token` (15 chars)
 * as a secret. This filter prevents that false positive.
 *
 * Rationale for dots-only (no hyphens, underscores only):
 *   - Real tokens use `-` or `_` mixed (`ghp_xxx`, `sk-xxx`) — hyphenated identifiers
 *     like `my-token` are valid Python but extremely rare as class attribute chains.
 *   - The `.`-only rule catches the common `self.<attr>`, `obj.<attr>` patterns
 *     while keeping the filter fast and predictable.
 *
 * ponytail: intentionally narrow. Edge case: a bare identifier ≥8 chars that IS
 * a real secret (e.g. a UUID-style token with no hyphens like `a1b2c3d4e5f6`)
 * would be skipped. The 8-char threshold means this only affects tokens between
 * 8-15 chars without special chars — a narrow window. Layer 4 (entropy) still
 * catches those.
 */
function isLikelyIdentifierReference(value: string): boolean {
  // ponytail: single-segment identifiers are tokens — only skip dotted refs.
  const trimmed = value.replace(/^[\s"']+|[\s"']+$/g, "");
  // Never skip [REDACTED:...] markers — they are already-redacted spans.
  if (trimmed.includes("[REDACTED:")) return false;
  return /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$/.test(trimmed);
}

export function apply(text: string, ctx: RedactionContext): LayerResult {
  const matches: Match[] = [];

  // PERFORMANCE: marker cache
  const markerCache = buildMarkerCache(text);

  // JSON-style: "secret_key": "value"
  pushAllMatches(text, JSON_SECRET_KEY_PATTERN, matches, "JSON Secret Field", markerCache);
  // ENV-style: SECRET=value
  pushAllMatches(text, ENV_SECRET_PATTERN, matches, "Env Secret Field", markerCache);
  // INI-style: secret = value
  pushAllMatches(text, INI_SECRET_PATTERN, matches, "INI Secret Field", markerCache);
  // YAML-style: secret: value
  pushAllMatches(text, YAML_SECRET_PATTERN, matches, "YAML Secret Field", markerCache);

  // Anchor lines: subject=, issuer=, etc.
  ANCHOR_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ANCHOR_RE.exec(text)) !== null) {
    const anchorEnd = m.index + m[0].length;
    // Find value after =
    const eqIdx = text.indexOf("=", anchorEnd);
    if (eqIdx !== -1 && eqIdx - anchorEnd < 30) {
      const lineEnd = text.indexOf("\n", eqIdx);
      const valueEnd = lineEnd === -1 ? text.length : lineEnd;
      const valueStart = eqIdx + 1;
      const value = text.slice(valueStart, valueEnd).trim();
      if (value.length >= 4) {
        const start = valueStart + (text.slice(valueStart, valueEnd).length - text.slice(valueStart, valueEnd).trimStart().length);
        const end = valueEnd;
        if (!isInsideMarker(markerCache, start, end)) {
          if (!matchesOverlapExisting(matches, start, end)) {
            matches.push({
              start,
              end,
              type: "Certificate Metadata",
              replacement: "[REDACTED:Certificate Metadata]",
            });
          }
        }
      }
    }
  }

  return { matches };
}

function pushAllMatches(
  text: string,
  pattern: RegExp,
  matches: Match[],
  type: string,
  markerCache: ReturnType<typeof buildMarkerCache>,
  preserveCapturedGroup = 1
) {
  pattern.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(text)) !== null) {
    const raw = m[preserveCapturedGroup];
    if (!raw) continue;
    // ponytail: trim trailing whitespace (INI/YAML .+ captures line-end spaces)
    const captured = raw.trimEnd();
    if (!captured) continue;
    if (isLikelyIdentifierReference(captured)) continue;
    // Use trimmed string for identifier check and span; position is identical
    const capturedIdx = m[0].indexOf(captured);
    if (capturedIdx === -1) continue;
    const start = m.index + capturedIdx;
    const end = start + captured.length;
    if (isInsideMarker(markerCache, start, end)) continue;
    if (matchesOverlapExisting(matches, start, end)) continue;
    matches.push({
      start,
      end,
      type,
      replacement: `[REDACTED:${type}]`,
    });
  }
}

function matchesOverlapExisting(matches: Match[], start: number, end: number): boolean {
  for (const m of matches) {
    if (start < m.end && end > m.start) return true;
  }
  return false;
}