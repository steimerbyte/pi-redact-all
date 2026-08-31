# pi-redact-all

[![npm version](https://img.shields.io/npm/v/pi-redact-all.svg)](https://www.npmjs.com/package/pi-redact-all)
[![license: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/steimerbyte/pi-redact-all/actions/workflows/ci.yml/badge.svg)](https://github.com/steimerbyte/pi-redact-all/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/steimerbyte/pi-redact-all)](https://github.com/steimerbyte/pi-redact-all/releases)

> **The secret scanner for Pi that catches what `@spences10/pi-redact` misses — including X.509 certificates.**

Global tool-output redaction for Pi that catches **secrets, certificates (X.509), PII, and connection strings** across **all tool outputs** (bash, read, write, edit, MCP) and **user input** — before they reach the model.

---

## Why pi-redact-all?

| Concern | `@spences10/pi-redact` | `pi-redact-all` |
|---------|------------------------|-----------------|
| X.509 Certificates | ❌ Not detected | ✅ PEM + DER (ASN.1) |
| SSH Private Keys | ✅ Yes | ✅ Yes (+ multi-chunk continuation) |
| API Keys | ✅ Yes | ✅ Yes (more patterns) |
| User-Input Filter | ❌ No | ✅ `before_agent_start` hook |
| Write-Tool-Aussparung | ❌ No | ✅ Write-tool output never filtered or blocked |
| Performance | OK | **79x faster (v0.1.5) → ~5x more (v0.1.6)** on large outputs |
| Test Coverage | Smoke only | **111 comprehensive + perf tests** |

---

## Features

### 10-Layer Detection

| # | Layer | Source | Catches |
|---|-------|--------|---------|
| **L1** | Vendor API-Key Patterns | Regex (pi-redact-compatible) | `ghp_*`, `xoxb-*`, `AKIA*`, `npm_*`, `AIza*`, `SG.*`, `sk-*`, `glpat-*`, `tvly-`, `BSA*`, `fc-*`, JWT, `github_pat_` |
| **L2** | **PEM/X.509/PGP-Block-Erkennung** ⭐ | Regex mit Backreference | `CERTIFICATE`, `X509 CRL`, `PKCS7`, `CSR`, `PRIVATE KEY`, `PUBLIC KEY`, `OPENSSH`, `PGP`, `DH PARAMETERS`, `ENCRYPTED PRIVATE KEY`, `TRUSTED CERTIFICATE` |
| **L3** | Vendor-Prefix-Erkennung | IndexOf + Length-Check | Schneller Pre-Pass für alle gängigen Token-Präfixe |
| **L4** | Shannon-Entropy-Heuristik | `H = -Σ pᵢ·log₂ pᵢ` ≥ 4.5 | High-Entropy-Tokens ≥ 32 chars (Base64/Hex-Alphabet), Allowlist-aware |
| **L5** | **ASN.1 SEQUENCE-Detection** ⭐ | Regex `/MII…` (DER-Heuristik) | Base64 DER-Blocks auch ohne PEM-Wrapper |
| **L6** | Context-Anchored | `subject=`, `issuer=`, `verify return:1`, JSON/INI/YAML secret fields | OpenSSL-Output, Config-Files |
| **L7** | File-Path-basierte | Path-Match (nur `read`-Tool) | `*.pem`, `*.crt`, `id_rsa`, `.env`, `.aws/credentials`, `.npmrc`, `.netrc`, `.docker/config.json` |
| **L8** | PII (opt-in) | RFC 5322, E.164, Luhn-Check, ISO 13616 | Email, Phone, IPv4, Credit Card, SSN, IBAN |
| **L9+10** | Connection-Strings & URL-Creds | Regex | `postgres://user:pass@host`, `https://user:pass@host` |

### Pipeline (ordered)

```
L7 (Path) → L1 (Vendor) → L3 (Prefix) → L2 (PEM, with continuation tracking)
→ L5 (ASN.1, skip if L2 wrapped) → L9+10 (Connections) → L6 (Context)
→ L8 (PII) → L4 (Entropy, with allowlist)
```

Path detection runs first so sensitive paths (`.env`, `id_rsa`, etc.) protect the whole file. Entropy runs last (most expensive, least specific).

### 3 Hooks (all schema-aware)

| Hook | Phase | Scope | Return |
|------|-------|-------|--------|
| `tool_result` | PostToolUse | Read/Bash/MCP tool output | Partial `{content?}` |
| `tool_call` | PreToolUse | Blocking for read/bash | `{block?, reason?}` or `undefined` |
| `before_agent_start` | User-Input | User prompt | `{prompt?}` |

> ⚠️ **Write-tool exclusion**: `write`, `edit`, `ssh_write`, `ssh_edit`, `multi_edit` and `mcp__*__write*` tools are **never filtered or blocked** — their output is model-generated code, not secrets to protect.

### Visual Identity

- **Whitespace, linebreaks, JSON-Syntax stay 1:1** — only matched spans are replaced via `slice/concat` (no global `String.replace`)
- Tools continue to function normally (they're already finished when we redact)
- TUI shows the redacted output, indistinguishable from "normal" output
- Already-redacted spans (`[REDACTED:...]`) are detected via binary search — no double-redaction

---

## Performance

Optimized for large outputs (cat dumps, log files, certificates). Single-thread
benchmarks comparing v0.1.5 (pre-optimisation) to v0.1.6:

| Workload                              | v0.1.5      | v0.1.6      | Speedup   |
|---------------------------------------|-------------|-------------|-----------|
| 1K text, no secrets                   | ~0.08 ms    | ~0.05 ms    | ~1.4×     |
| 10K text, no secrets                  | ~0.23 ms    | ~0.14 ms    | ~1.6×     |
| 100K text, no secrets                 | ~6.6 ms     | ~1.5 ms     | ~4.4×     |
| 100K text + 1 long base64 token      | ~8.2 ms     | ~1.7 ms     | ~4.8×     |
| 100K text + 1000 base64 tokens       | ~28.5 ms    | ~21 ms      | ~1.4×     |

**Key optimizations (v0.1.6):**
- `shannonEntropy` (Layer 4): `Map<string, number>` → typed `Int32Array(128)` (3-5× faster per token)
- Layer 4 char classification: anchored regex scans → single char-code loop (2-3×)
- Layer 1 vendor: `indexOf` pre-screen + manual boundary check; regex runs only on candidates (3-4×)
- Layer 3 prefix: `regex.test()` per char → `isTokenChar` char-code check
- Layer 9-10 connection: `indexOf("://")` pre-screen + manual back-walk (5×)
- Layer 8 PII: pre-screen for distinguishing literals (`@`, `+`, `\d{3}-\d{2}-`, long digit run, etc.)
- `redactText` short-text fast exit (texts < `minLength` skip all 9 layers)
- `applyMatches`: in-place sort, pre-sized output array, trim trailing undefined slots

Run `node test/perf-v0.1.6.test.mjs` to enforce upper bounds on CI.

---

## Installation

```bash
# From npm (recommended)
pi install npm:pi-redact-all

# From source (development)
git clone https://github.com/steimerbyte/pi-redact-all.git
cd pi-redact-all
npm install
npm run build
```

Add to `~/.pi/agent/settings.json`:

```json
{
  "packages": [
    "npm:pi-redact-all"
  ]
}
```

---

## Configuration

`~/.pi/agent/pi-redact-all.json`:

```json
{
  "mode": "mask",
  "blockMode": false,
  "streamingRedaction": false,
  "toolPolicy": {
    "whitelist": [],
    "blacklist": []
  },
  "layers": {
    "vendor": true,
    "pem": true,
    "prefix": true,
    "entropy": true,
    "asn1": true,
    "context": true,
    "path": true,
    "pii": false,
    "connection": true
  },
  "allowlistRegex": ["\\b[a-f0-9]{40}\\b"],
  "minEntropy": 4.5,
  "minLength": 32
}
```

---

## Commands

- `/redact-all-stats` — Session-Statistiken (per Layer, per Tool)
- `/redact-all-config` — Aktuelle Config

---

## Marker-Format

```
[REDACTED:GitHub Token]
[REDACTED:PEM CERTIFICATE]
[REDACTED:Connection String with Password]
[REDACTED:High Entropy Token]
[REDACTED:ASN.1 SEQUENCE]
[REDACTED:Protected File (PEM File)]
```

Kompatibel mit `@spences10/pi-redact` — beide nutzen `[REDACTED:...]`-Prefix, Boundary-Check verhindert Doppel-Redaction.

---

## Live-Test Evidence (2026-07-27)

| Test | Input | Output |
|------|-------|--------|
| CA-Bundle (GIMP `cert.pem`, 229KB) | 152 Zertifikate | Alle redacted |
| `cat test_key.pem` (OpenSSH) | Private Key | `[REDACTED:Private Key]` |
| `cat test_cert.pem` (X.509) | Self-signed cert | `[REDACTED:PEM CERTIFICATE]` |
| `cat ~/.ssh/config` | Host/User/IdentityFile | `[REDACTED:SSH ...]` |
| `env \| grep KEY` | `MINIMAX_API_KEY`, etc. | `[REDACTED:Generic Password Field]` |
| GitHub Token in Bash | `ghp_...` | `[REDACTED:GitHub Token]` |
| Connection String | `postgres://admin:secret@host` | `postgres://admin:[REDACTED:Password]@host` |

---

## Compatibility

- ✅ Co-exists with `@spences10/pi-redact` (boundary check prevents double-redaction)
- ✅ All Pi version 0.81+ (uses stable `tool_result`/`tool_call` hooks)
- ✅ Node.js 22+

---

## Development

```bash
npm install
npm run build                 # Compile TS → dist/
npm run test                  # All 111 tests (8 smoke + 32 validation + 12 path-context + 12 data-url + 10 anchor-fix + 30 scoped-hooks + 7 perf)
node test/smoke-test.mjs              # Smoke tests only
node test/comprehensive-validation.mjs # All hook + payload tests
node test/scoped-hooks-v0.2.0.test.mjs # Write-tool exclusion tests
node test/path-context-v0.1.4.test.mjs   # File-path / filename preservation
node test/data-url-v0.1.5.test.mjs      # Data-URL base64 in text fields
node test/perf-v0.1.6.test.mjs         # Performance regression upper-bounds
```

### Test Coverage

- **8 smoke tests** — Each detection layer against representative input
- **32 validation tests** — All ToolResultEvent variants, edge cases, performance benchmarks
- **12 path-context tests** (v0.1.4) — Filename / path-context preservation
- **12 data-url tests** (v0.1.5) — Inline `data:image/...;base64,` payloads in text fields
- **10 anchor-fix tests** (v0.1.8) — ENV-style secret detection regression
- **30 scoped-hooks tests** (v0.2.0) — Write-tool exclusion, write-tool pass-through, read/bash still filtered
- **7 perf tests** (v0.1.6) — Performance regression upper bounds per workload

### Release Process

```bash
# Bump version
npm version patch|minor|major

# Tag and push (triggers publish workflow)
git push origin main
git push origin vX.Y.Z
```

GitHub Actions publishes to npm with provenance on `v*` tags.

---

## Architecture

```
src/
├── index.ts                 # Extension entry: registers 3 hooks
├── hooks/
│   ├── tool-result.ts       # PostToolUse redaction (read/bash/MCP, skips write-tools)
│   ├── tool-call.ts         # PreToolUse block (read/bash, skips write-tools)
│   ├── user-input.ts        # before_agent_start filter
│   └── content-utils.ts     # Content mapping helpers
├── layers/
│   ├── index.ts             # Pipeline orchestrator (9-layer chain)
│   ├── layer-1-vendor.ts    # API-Key vendor patterns
│   ├── layer-2-pem.ts       # PEM/X.509/PGP block detection
│   ├── layer-3-prefix.ts    # Vendor-prefix pre-check
│   ├── layer-4-entropy.ts   # Shannon entropy heuristics
│   ├── layer-5-asn1.ts      # ASN.1 SEQUENCE (DER) detection
│   ├── layer-6-context.ts   # Context-anchored (subject=, JSON/INI/YAML secrets)
│   ├── layer-7-path.ts      # File-path based (read-tool)
│   ├── layer-8-pii.ts       # PII (opt-in)
│   ├── layer-9-10-connection.ts  # Connection strings & URL creds
│   └── shared.ts            # buildMarker, buildMarkerCache, isInsideMarker, applyMatches
├── stats.ts                 # Session statistics
├── config.ts                # Config loader (~/.pi/agent/pi-redact-all.json)
└── types.ts                 # Shared types
```

---

## License

MIT