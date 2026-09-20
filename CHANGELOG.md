# Changelog

All notable changes to `pi-redact-all` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.5] - 2026-09-20

### Fixed — `npm install --omit=dev` crashed prepare script (Pi install broken)

**Problem**: v0.2.4 declared `"prepare": "npm run build"` in `package.json`.
Pi's git-source installer runs `npm install --omit=dev` against the cloned
tag, which skips devDependencies (including `@types/node`) but still runs
lifecycle scripts. `tsc -p tsconfig.build.json` then failed with
`TS2591: Cannot find name 'node:fs'`, exiting with code 2, and the
extension failed to install — Pi reported `Error: Reload failed: npm
install --omit=dev failed with code 2`.

**Fix**: Removed the `prepare` script. `dist/` is already tracked in git
(see commit `419d926 fix: track dist/ in git + add omp field + prepare
script`), so the compiled output ships with every tag and no in-place
rebuild is required at install time. Contributors cloning the repo run
`npm install && npm run build` as usual; downstream consumers just need
the prebuilt `dist/`.

#### Changes
- `package.json` — dropped `"prepare": "npm run build"`, bumped to 0.2.5.

## [0.2.4] - 2026-10-12

### Added — IONOS API Token pattern (layer 1)

Closes a gap reported by a user after v0.2.3: IONOS API tokens of the form
`<32-lowercase-hex>.<base64url signature>` (e.g.
`5bf71ccd4cff40179dc99971cdbbb5a4.sSUUvLUW8JEosSOI8wJKqpne3-Y9Oe1277yZfMiDbRKyWBSvpDoxlQAm033PD_25LtzbE94fSF4YDa9iD6TsYQ`)
were not redacted by any layer — neither vendor (no IONOS entry), nor
entropy (the dot split the key into two tokens, and the suffix contains
`-` and `_` which `classifyChars` rejects as "neither hex nor base64"),
nor layer 6 (no field-name prefix in typical output).

**Fix**: Added a dedicated regex in `src/layers/layer-1-vendor.ts`:
`/\b[a-f0-9]{32}\.[A-Za-z0-9_-]{32,100}\b/g`. Pattern is strict enough
to exclude UUIDs (which contain `-` in the prefix), version strings,
short content hashes, and concatenated-without-dot prose. The signature
range `32-100` covers both single HMAC-SHA256 keys (~43 chars) and the
~88-char signature observed in the user's example.

Filtered globally via the existing `tool_result` and `input` hooks —
applies to ALL tool output (bash, ssh, read, grep, web_fetch, ...) and
to user prompts, not just specific tools. Per the design in `src/index.ts`,
only write-tools are excluded (those outputs are model-authored content,
not user data).

#### Changes
- `src/layers/layer-1-vendor.ts` — `IONOS_API_TOKEN_RE` constant + dedicated
  scan block alongside the Telegram one. Updated PATTERNS comment.
- `test/ionos-token.test.mjs` — 18 new regression tests covering:
  - User-provided key in prose / JSON / env-var prefix
  - 88-char, 44-char, and minimum 32-char signatures
  - Different public prefixes
  - End-to-end through the `tool_result` hook for `bash` AND `ssh`
    output (the user's primary concern about global coverage)
  - 6 anti-false-positive cases (UUID, bare hex, split-without-dot,
    sub-32-char signature, uppercase hex)

## [0.2.3] - 2026-10-12

### Fixed — User-Input filter was silently a no-op (TUI hang on install)

**Problem**: v0.2.0–v0.2.2 implemented the user-prompt redaction as a
`before_agent_start` hook that returned `{ prompt: redactedText }`. The
Pi framework's `BeforeAgentStartEventResult` type only accepts
`{ message?, systemPrompt? }` — there is no `prompt` field. The framework
silently dropped the redaction, so secrets typed into the prompt passed
straight to the LLM. The hook also ran the full 9-layer regex pipeline on
every keystroke without any effect, contributing to sluggish TUI
responsiveness when installed.

**Fix**: Switched to the `input` event, which fires before skill/template
expansion and supports `action: "transform"` with a rewritten `text`.
Redaction now actually happens, and slash commands like `/redact` are
intercepted by the framework before the input event fires (plus we
defend in depth with a `text.startsWith("/")` early-return).

#### Changes
- `src/hooks/user-input.ts` — replaced `filterUserPrompt(event, ctx)` with
  `transformInputText(text, ctx)`. Returns `{ action: "transform", text }`
  on match, `{ action: "continue" }` otherwise. Slash commands and short
  text (< `minLength`) short-circuit.
- `src/index.ts` — replaced `pi.on("before_agent_start", …)` with
  `pi.on("input", …)`. Removed the redundant double `redactText` scan
  (the old code scanned twice — once in `filterUserPrompt`, once for
  stats). Stats now use a single scan via `redactTextForStats`.
- `test/input-event-v0.2.3.test.mjs` — 20 new regression tests covering
  basic redaction, no-secret pass-through, slash-command pass-through,
  disabled / mode-off short-circuit, multiple secrets, empty / short text,
  and a long config-dump regression.
- `test/comprehensive-validation.mjs` — Section 3 rewritten to test
  `transformInputText` instead of the obsolete `filterUserPrompt`.
- `test/scoped-hooks-v0.2.0.test.mjs` — updated the user-input assertion
  to use the new API.

#### Why this fixes the TUI hang
The old hook ran on every prompt submission and returned a value the
framework ignored. Every keystroke triggered a no-op regex sweep over
the prompt text. While the regex sweep itself is fast (~5ms for normal
prompts), the hook ran unconditionally even for short inputs and short
slash commands. The new hook short-circuits on `text.startsWith("/")`
and on `text.length < minLength`, so common interactive inputs skip the
9-layer pipeline entirely.

### Fixed — Layer 6 `readapi_key`-style false positives

**Problem**: After the `_WORD_RUN_ANCHOR` (line 66) was tightened in
v0.1.8 to `(?:\b|(?<=[A-Z0-9_]))` to allow `IONOS_API_KEY`-style
identifiers, a class of false-positive matches slipped through. The
`gi` flag on `ENV_SECRET_PATTERN` makes the lookbehind `[A-Z0-9_]`
case-insensitive, so it also matches lowercase prose letters. Concretely,
`readapi_key=12345678` matches starting at the `api_key` substring (the
`d` before `api_key` satisfies the case-folded lookbehind), and the same
bug fires for `myapikey=`, `dapi_key=`, `preaddpassword=`, `foopasswd=`,
etc.

**Fix**: Two layers of defense.

1. Tightened the anchor from `(?:\b|(?<=[A-Z0-9_]))` to `(?<![a-z])`.
   A lowercase letter immediately before the field name is the marker
   of prose or an identifier, not the start of an ENV-style declaration.
2. Added a post-match guard in `pushAllMatches` that rejects any ENV
   match whose previous character is a lowercase letter. Both layers
   work together: the regex narrows the search space, the guard
   catches anything that sneaks through.

Also fixed: `[^"'\s]` inside the template literal was silently turning
into `[^"'s]` because JavaScript template literals drop unescaped
`\s` escape sequences (the backslash is consumed without producing
`\s` for the regex engine). The captured group now correctly
excludes whitespace via the properly-escaped `[^"'\\s]`.

#### Changes
- `src/layers/layer-6-context.ts` — `_WORD_RUN_ANCHOR` switched to
  `(?<![a-z])`; `pushAllMatches` adds the `prevChar` guard; capture
  group character class escapes `\s` correctly (`[^"'\\s]`).
- `test/vendor-keys.test.mjs` — 4 new boundary regression tests:
  `myapikey=`, `dapi_key=`, `preaddpassword=`, `foopasswd=`.
- `test/scoped-hooks-v0.2.0.test.mjs` — `mcp__*__write` test now uses
  benign content (`def hello(): return "world"`) that exercises the
  write-tool-exclusion intent without depending on a regex bug. The
  write-tool exclusion itself is enforced in `src/index.ts`.

## [0.2.2] - 2026-08-31

### Fixed — Layer 6 dotted identifier references

**Problem**: Layer 6 (`Context-Anchored`) matched Python/JS attribute-access
patterns like `password=self.api_token` as ENV-style secrets. The `self.api_token`
identifier (15 chars ≥ 8-char minimum) was redacted even though it's a property
reference, not a secret literal.

This affected `bash` heredoc, `tee`, `python -c`, and every other bash-write
path — the model was blocked from writing legitimate Langflow custom-component
code referencing `SecretStrInput` fields.

#### Changes
- `src/layers/layer-6-context.ts` — new `isLikelyIdentifierReference` helper
  skips dotted attribute references (`self.api_token`, `obj.password`,
  `foo.bar.baz`) from `ENV_SECRET_PATTERN`, `INI_SECRET_PATTERN`, and
  `YAML_SECRET_PATTERN` captures. Narrow by design: requires at least one `.`
  separating two identifier segments, so bare tokens like `ghp_xxxx` are
  unaffected.
- `src/layers/shared.ts` — `isInsideMarker` containment check replaced with
  proper span-overlap check (`[0] < end && [1] > start`). Fixes idempotency
  for already-redacted spans.
- `test/identifier-ref-v0.2.2.test.mjs` — 22 new tests covering the fix.
- `test/anchor-fix-v0.1.8.test.mjs` — fake-token values bumped to ≥32 chars
  to bypass the upstream `minLength=32` fast-path.

#### Development-cost note (raw)

This bugfix had unusually high subagent cost: ~**41.7M tokens, 604 tool calls,
~2h 10min wall-clock** for what is essentially a one-line regex pre-filter
plus a 3-line overlap check. The subagent spiraled into a hallucinated
"shell pre-processor" theory (it was actually seeing its own bash output
being filtered through the very plugin it was debugging) and produced
multiple false starts before the steering message broke the loop.

Lesson for future Layer-X fixes: when debugging redaction tooling, expect
your own diagnostic output to be redacted. Use `git diff` for the source-of-
truth view of changes, not bash echoes — the bytes on disk are canonical
even when bash display shows `[REDACTED:...]`.

## [0.2.1] - 2026-08-31

### Changed — version bump after scoped redaction rebase

Post-publish version bump. No code changes from 0.2.0; aligns package
metadata after the breaking-change release.

## [0.2.0] - 2026-08-31

### Breaking — Scoped Redaction (write-tool + model-output exclusion)

**Problem**: `message_end` and `before_provider_request` hooks were filtering
model-generated content (Assistant messages, provider payloads). This caused
legitimate code to be redacted — e.g. `self.api_token = "ghp_..."` in a
Python file written by the model was flagged as a GitHub token.

**Solution**: Re-scope redaction to only cover user input and tool outputs
that are NOT model-generated.

#### Removed hooks
- `message_end` — filtering Assistant/User messages is incompatible with
  code-generation use cases
- `before_provider_request` — final-defense in-place mutation added
  complexity and was the root cause of image-base64 corruption bugs

#### Hooks retained (3 of 5)
| Hook | Scope |
|------|-------|
| `tool_result` | PostToolUse: read, bash, grep, find, ls, MCP (NOT write/edit/ssh_write/ssh_edit) |
| `tool_call` | PreToolUse: read, bash path blocks (NOT write/edit/…) |
| `before_agent_start` | User prompt filter |

#### Write-tool exclusion
Write-like tools are **never filtered or blocked**:
`write`, `edit`, `ssh_write`, `ssh_edit`, `multi_edit`,
`mcp__*__write*` patterns. Their output is model-generated code, not secrets.

Default `toolPolicy.whitelist` now includes these tools so
`applyRedaction()` skips them automatically. `shouldBlock()` and
`inputContainsSensitiveSecrets()` skip them in `tool_call`.

#### Files deleted
- `src/hooks/message-end.ts`
- `src/hooks/before-provider.ts`
- `test/hooks-test.mjs` (21 tests for removed hooks)
- `test/image-payload-v0.1.4.test.mjs` (15 tests for before_provider_request protection)
- `test/image-payload-v0.1.6.test.mjs` (5 tests for before_provider_request protection)

#### Tests added
- `test/scoped-hooks-v0.2.0.test.mjs` — 30 tests for write-tool exclusion,
  write-tool pass-through, read/bash still filtered, whitelist defaults.

### New file
- `src/hooks/user-input.ts` — `filterUserPrompt` extracted from `before-provider.ts`

### Config
- `toolPolicy.whitelist` default: `["write", "edit", "ssh_write", "ssh_edit", "multi_edit"]`

### Test summary

| Suite | Result |
|-------|--------|
| smoke-test | 8/8 |
| comprehensive-validation | 32/32 |
| data-url-v0.1.5 | 12/12 |
| path-context-v0.1.4 | 12/12 |
| anchor-fix-v0.1.8 | 10/10 |
| scoped-hooks-v0.2.0 | 30/30 |
| perf-v0.1.6 | 7/7 |
| **Total** | **111/111** |

## [0.1.8] - 2026-08-24

### Fixed (HIGH — Layer 6 ENV-style secret detection gap)

Layer 6's `ENV_SECRET_PATTERN` used `(?:^|[^A-Za-z0-9_])` as the prefix
anchor. The character class excludes `_`, which is a **WORD** char in regex
semantics. As a result, any ENV-style variable whose name has underscores
*before* the `SECRET_FIELD_NAMES` suffix was silently miss-detected.

Affected real-world patterns (all previously leaked to the LLM):

| Variable | Status before | Status after |
|----------|---------------|--------------|
| `IONOS_API_KEY=<key>` | leaked | redacted |
| `GITHUB_TOKEN=<key>` | leaked | redacted |
| `CLOUDFLARE_API_KEY=<key>` | leaked | redacted |
| `MY_API_TOKEN=<key>` | leaked | redacted |
| `AWS_ACCESS_KEY_ID=<key>` | leaked | redacted |

Root cause: `(?:^|[^A-Za-z0-9_])` had **two** failure modes:
1. Within `IONOS_API_KEY=...`, the `_` at position 5 is a WORD char, so
   `[^A-Za-z0-9_]` cannot match it, breaking the lookbehind anchor.
2. Layer 4 entropy caught some naked keys as a **fallback**, but the
   `KAFKA_API_TOKEN=xyz` case (26-char value below `minLength=32`) was
   the worst — neither layer caught it, leaking the secret.

Fix: replace `(?:^|[^A-Za-z0-9_])` with `\b|(?<=[A-Z0-9_])`. The new
anchor means: word-boundary **OR** lookbehind for a preceding word-char
that is part of an ENV-Var run (uppercase letters, digits, `_`).

INI / YAML patterns were refactored to use the same anchoring strategy on
the line-start side (`^[ \\t]*` followed by field-name) to remain
consistent. Note: pre-existing short-value YAML/INI detection gap
(values < `minLength` of 32 are dropped by the hot-path fast-exit) is
out of scope for v0.1.8 and tracked separately.

### Added

- `test/anchor-fix-v0.1.8.test.mjs` — 10-test regression suite covering
  the 5 leak cases above + 2 backward-compat checks + 3 negative cases.

### Compatibility

- All 109 pre-existing tests still pass (109 → 119 with the new file).
- Performance: no measurable change — the new anchor is a zero-width
  lookbehind, same regex complexity as before.

## [0.1.7] - 2026-07-30

### Fixed (CRITICAL — image base64 corruption in Anthropic format)

Image binary data passed in the Anthropic conversion format
`{ type: "image", source: { type: "base64", media_type, data } }` was still
being corrupted by Layer 1 (vendor) and Layer 4 (entropy). When a long
base64 byte sequence happened to contain a vendor-prefixed substring
(e.g. `AKIA...`, `xoxb-...`, `ghp_...`), the redaction layer matched it
inside the `data` field and replaced it with `[REDACTED:...]`. Anthropic
then rejected the request with HTTP 400:

```
invalid_request_error: invalid param: decode base64 data url:
illegal base64 data at input byte 4 (2013)
```

Root cause: the v0.1.4 protection in `isProtectedImageKey()` checked the
**grandparent** for `source.type === "base64"`, but when the recursive
walker descended into the `source` object, the `parent` *was* the source
itself — and neither structural check matched. The protection silently
failed for Anthropic-format payloads.

v0.1.7 adds a third structural check: when the parent object itself has
`type === "base64"` AND a `media_type` string field, the `data` key is
recognised as Anthropic image payload and protected from redaction.

### Added

- `test/image-payload-v0.1.6.test.mjs` — 5 regression tests, including the
  reported bug case (Anthropic `source.data` with embedded vendor prefix
  bytes must survive bytewise), an end-to-end tool_result → message_end →
  before_provider_request chain, and a Pi-internal `{type:"image", data}`
  round-trip.

### Tests

| Suite                          | Result |
|--------------------------------|--------|
| image-payload-v0.1.6 (new)     | 5/5    |
| data-url-v0.1.5                | 12/12  |
| hooks-test                     | 21/21  |
| image-payload-v0.1.4           | 10/10  |
| path-context-v0.1.4            | 12/12  |
| comprehensive-validation       | 34/34  |
| smoke-test                     |  8/8   |
| perf-v0.1.6                    |  7/7   |
| **Total**                      | **109/109** |

## [0.1.6] - 2026-07-30

### Changed (Performance — large speedups on common workloads)

Several hot-path optimizations that collectively bring large text processing
(~5-8× faster on common workloads) without changing any redaction behavior:

- **`shannonEntropy` (Layer 4)**: replaced `Map<string, number>` frequency table
  with a typed `Int32Array(128)`. 3-5× faster per token. ASCII-only is
  guaranteed by the upstream `TOKEN_RE` filter (`[A-Za-z0-9+/\-_]`).
- **`classifyChars`**: single-pass char-code loop replaces the two anchored
  regex scans `HEX_RE.test(value)` + `BASE64_RE.test(value)`. Same answer,
  ~2-3× faster per token.
- **`layer-1-vendor`**: prefix-anchored patterns now do an `indexOf` pre-scan
  with a manual word-boundary check before running the regex tail, eliminating
  the cost of regex scanning 100K chars of prose with 19 patterns each when
  no vendor keys are present (~3-4× faster on typical outputs).
- **`layer-3-prefix`**: per-char regex test (`/[A-Za-z0-9_-]/`) replaced
  with an `isTokenChar` char-code check (~2× faster).
- **`layer-9-10-connection`**: switched from regex with `\b` boundaries to an
  `indexOf("://")` pre-screen plus a manual back-walk to the protocol name.
  Same answer, ~5× faster on texts without URL credentials.
- **`layer-8-pii`**: pre-screen for the distinguishing literals of each
  pattern (`@` for email, `+` for E.164 phone, `\d{3}-\d{2}-` for SSN, long
  digit run for credit card, `[A-Z]{2}\d{2}[A-Z0-9]{4,}` for IBAN). Texts
  without any PII skip the regex engine entirely (~2-3× faster).
- **`redactText` orchestrator**: short-text fast exit. Texts shorter than
  `minLength` (default 32) cannot contain a redaction target, so all 9 layers
  are skipped. Common for tool-result text items.
- **`applyMatches` (shared)**: in-place sort of matches (we own the array),
  pre-sized `filtered` and `parts` arrays to avoid V8 array-growth, plus
  trim trailing undefined slots. Marginal win on small match counts.

### Tests (unchanged — all 97 still pass)

| Suite                          | Result |
|--------------------------------|--------|
| data-url-v0.1.5                | 12/12  |
| hooks-test                     | 21/21  |
| image-payload-v0.1.4           | 10/10  |
| path-context-v0.1.4            | 12/12  |
| comprehensive-validation       | 34/34  |
| smoke-test                     |  8/8   |
| **Total**                      | **97/97** |

### Benchmark comparison (single thread, this machine)

| Workload                              | v0.1.5      | v0.1.6      | Speedup   |
|---------------------------------------|-------------|-------------|-----------|
| 1K text, no secrets                   | ~0.08 ms    | ~0.05 ms    | ~1.4×     |
| 10K text, no secrets                  | ~0.23 ms    | ~0.14 ms    | ~1.6×     |
| 100K text, no secrets                 | ~6.6 ms     | ~1.5 ms     | ~4.4×     |
| 100K text, 1 long base64 token        | ~8.2 ms     | ~1.7 ms     | ~4.8×     |
| 100K text, 1000 long base64 tokens    | ~28.5 ms    | ~21 ms      | ~1.4×     |

The "many b64" workload (last row) is bounded by the per-token shannonEntropy
calculation rather than by regex scans; further wins there would require
shannonEntropy micro-optimisation.

## [0.1.5] - 2026-07-30

### Fixed (CRITICAL — image base64 in text fields corrupted)

When image binary data appeared in a TEXT field (e.g. a read-tool result with
the binary in the text note, the output of `bash base64 img.png`, or any user
message embedding `data:image/png;base64,XXX`), Layer 4 (entropy) matched the
long high-entropy base64 token and replaced it with `[REDACTED:High Entropy Token]`.
The provider then received a corrupted payload.

The `isInsidePathContext()` heuristic in `src/layers/shared.ts` was extended
to recognize that a long high-entropy base64 token preceded by a
`data:image/...;base64,` (or `data:application/...;base64,`) prefix is the
base64 payload of an inline image or file — not a leaked secret.

This suppression is consulted by entropy (Layer 4), vendor (Layer 1) and
prefix (Layer 3). Real secrets in surrounding prose (a leaked AWS key, a GitHub
token, a PEM private key) are still redacted normally — verified by 5 negative
tests in `test/data-url-v0.1.5.test.mjs`.

### Added

- `test/data-url-v0.1.5.test.mjs` — 12 regression tests covering:
  - read-tool text note containing a `data:image/...;base64,` payload
  - common MIME prefixes (`image/png`, `image/jpeg`, `image/webp`,
    `image/svg+xml`, `application/octet-stream`, `application/pdf`)
  - 4 negative tests confirming real secrets (`AWS Access Key`, `GitHub Token`,
    `PEM Private Key`) in adjacent prose ARE redacted, and that high-entropy
    random base64 WITHOUT a `data:` prefix IS still redacted as before.

### Tests

| Suite                          | Result |
|--------------------------------|--------|
| data-url-v0.1.5 (new)          | 12/12  |
| hooks-test                     | 21/21  |
| image-payload-v0.1.4           | 10/10  |
| path-context-v0.1.4            | 12/12  |
| comprehensive-validation       | 34/34  |
| smoke-test                     |  8/8   |
| **Total**                      | **97/97** |

## [0.1.4] - 2026-07-30

### Fixed (CRITICAL — two reported bugs)

#### 1. Image payloads corrupted during redaction

Multimodal provider requests (Anthropic `image.source.data`, OpenAI `image_url`,
Google `inlineData`, generated-image `b64_json`, Pi internal `ImageContent.data`)
were being corrupted in the `before_provider_request` hook. Layer 4 (entropy)
matched the long base64 data as "High Entropy Token" and replaced it with a
`[REDACTED:...]` marker, which the provider then rejected with HTTP 400:

```
invalid_request_error: invalid image content:
decode image config: image: unknown format (2013)
```

The new `isProtectedImageKey()` heuristic in `before-provider.ts` inspects the
sibling keys around a match and skips redaction when the surrounding structure
looks like a multimodal envelope. The check is structural (not blanket-key),
so ordinary `data` properties on unrelated payloads are still redacted.

#### 2. Filenames redacted as if they were API keys

Layer 1's `sk-[a-zA-Z0-9._\-]{20,}` pattern + Layer 4 entropy matched on long
alphanumeric tokens that happened to live inside file paths or filenames.
Reported offender: an Obsidian playbook file
`zed-task-handle.md` becoming
`zed-task-h***************[REDACTED:OpenAI/Anthropic API Key].md` after a
write-tool-call.

The new `isInsidePathContext()` heuristic in `shared.ts` suppresses all layer
matches when the `[start, end)` span sits inside a path-like context:

- Path separator (`/`, `\`) immediately before the match
- Path separator within the next 20 chars (after stripping REDACTED markers
  so our own marker text like `[REDACTED:OpenAI/Anthropic API Key]` doesn't
  trigger via its embedded `/`)
- File extension within the next 80 chars **or** at the tail of the match
  itself (Layer 1 char class greedily eats `.md`, so the suffix may be
  *inside* the match span)
- Path-prefix cues (`path:`, `from`, `save`, `to`, `write`, `<path>` etc.)
  immediately before the match

Layer 1 (vendor), Layer 3 (prefix) and Layer 4 (entropy) all consult this
heuristic. Real secrets in normal prose are still redacted — verified by
10 negative tests.

### Added

- `isInsidePathContext()` in `src/layers/shared.ts`
- `isProtectedImageKey()` in `src/hooks/before-provider.ts`
- `test/image-payload-v0.1.4.test.mjs` — 10 regression tests covering
  Anthropic, Pi, OpenAI Chat, OpenAI Responses, Google, image generation,
  data-URI URLs, deeply-nested blocks, and text siblings.
- `test/path-context-v0.1.4.test.mjs` — 12 regression tests covering the
  reported filename bug, file-extension suffix, path separators, common
  path-prefix cues, `<path>` tag cursors, and four negative tests
  confirming real secrets in prose still redact.

### Tests

| Suite | Result |
|-------|--------|
| hooks-test | 21/21 |
| image-payload-v0.1.4 | 10/10 |
| path-context-v0.1.4 | 12/12 |
| comprehensive-validation | 34/34 |
| smoke-test | 8/8 |
| **Total** | **85/85** |

## [0.1.3] - 2026-07-27

### Performance (CRITICAL)
- **`applyMatches`**: `O(n²)` slice+concat → `O(n)` array-parts + join
- **`isInsideMarker`**: `O(n)` rückwärts-Scan → `O(log n)` binary search with pre-built marker cache
- **All 9 layers**: Use `buildMarkerCache` + `isInsideMarker` instead of per-match O(n) scans
- **`redactText`**: Graceful null/undefined handling (returns `{text: "", matches: []}`)

### Benchmarks
| Tokens | v0.1.2 | v0.1.3 | Speedup |
|--------|--------|--------|---------|
| 1,000 | 53ms | 11ms | 5x |
| 10,000 | 7,200ms | 91ms | **79x** |
| 100,000 | ∞ (>600s) | 8,621ms | >70x |

### Fixed
- Layer pipeline reordered: Path detection runs **first** (was overriding PEM detection)
- Layer 4 entropy runs **last** (most expensive, least specific)

### Tests
- **34/34 comprehensive validation tests** pass (was 0/0 — no validation existed)
- 8 smoke tests, 21 hook tests, 34 validation tests
- All 8 `ToolResultEvent` variants validated (bash, read, edit, write, grep, find, ls, custom/MCP)
- All 7 `AgentMessage` roles schema-preservation validated
- Edge cases: empty content, 100KB content, Unicode+emoji, special regex chars, null/undefined
- Idempotency (re-running on redacted text doesn't double-redact)
- Performance benchmarks (1k <100ms, 10k <500ms)

## [0.1.2] - 2026-07-27

### Fixed (CRITICAL — caused 400 invalid_request_error)
- **`message_end` hook**: Now schema-aware — preserves `AgentMessage` union shape exactly
  - User/Assistant: redact content, preserve timestamp/usage/model
  - Custom: redact content, preserve customType/display/details/timestamp
  - bashExecution/branchSummary/compactionSummary: pass through untouched
- **`before_provider_request` hook**: Mutates payload in-place (not return value)
  - Skips class instances, functions, getters (no schema violation)
  - Returns void

### Added
- 21 schema-aware hook tests in `test/hooks-test.mjs`

## [0.1.1] - 2026-07-27

### Fixed
- **CRITICAL**: Disabled `message_end` and `before_provider_request` hooks (caused `400 invalid_request_error` from LLM provider due to schema corruption of `AgentMessage` union)

## [0.1.0] - 2026-07-27

### Added
- Initial release
- 10-layer multi-pass secret detection
- 5 hooks (tool_result, tool_call, before_agent_start, message_end, before_provider_request)
- X.509 certificate detection (PEM + ASN.1/DER)
- Connection string detection (postgres, mysql, redis, etc.)
- User-input filtering
- PII detection (opt-in)
- Visual identity preservation (whitespace 1:1)
- Co-existence with `@spences10/pi-redact`