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
  "secret_access_key",
  "access_key",
  "access_key_id",
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

const ENV_SECRET_PATTERN = new RegExp(
  `(?:^|[^A-Za-z0-9])(?:${SECRET_FIELD_NAMES.join("|")})\\s*=\\s*["']?([^"'\\s]{8,})["']?`,
  "gi"
);

const INI_SECRET_PATTERN = new RegExp(
  `^\\s*(?:${SECRET_FIELD_NAMES.join("|")})\\s*[=:]\\s*(.+)$`,
  "gim"
);

const YAML_SECRET_PATTERN = new RegExp(
  `^\\s*(?:${SECRET_FIELD_NAMES.join("|")}):\\s*(.+)$`,
  "gim"
);

const ANCHOR_RE = new RegExp(ANCHORS.map((a) => a.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "g");

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
    const captured = m[preserveCapturedGroup];
    if (!captured) continue;
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