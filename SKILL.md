---
name: rea-build-guard
description: Reverse-engineering and security self-audit gate for your own production build artifacts (web dist/ bundles, .wasm modules, Electron apps, and macOS .app bundles) using deterministic static scanners plus REA (Reverse Engineer Anything). Use this skill whenever the user wants to audit a built dist/ or .app before shipping, check if AI-generated ("vibe-coded") or multi-agent builds leaked API keys, local /Users paths, localhost URLs, or .map source maps, inspect WASM exports or Mach-O dylib links, compare bundle bloat and new network endpoints between two builds, or says "发版前自检", "检查打包产物", "审计 dist", "看看构建包有没有漏密钥", "rea 审计构建", "pre-release bundle check", or "audit build output". Strictly for auditing the user's own builds—never third-party binaries or external sites.
---

# REA Build Guard

Pre-release inspection gate that looks at **what you are actually about to ship** (`dist/`, `build/`, `.next/static/`, `.wasm`, or `MyApp.app`) from a reverse engineer's perspective—catching vibe-coding and bundler mistakes that source-level linters miss.

## Ground Rules

1. **Audit your own artifacts only.** Never run this skill or `rea` against third-party apps, commercial `.dmg` binaries, or external websites. If asked to reverse-engineer someone else's proprietary software, decline and offer to audit the user's own build output instead.
2. **Read-only & redacted.** `scripts/guard.py` never modifies or executes the target artifact, and secret matches are always redacted (`sk-ant… (51 chars)`) in both Markdown and JSON reports so audit logs themselves never leak credentials.
3. **REA + zero-dependency fallback.** When `rea` CLI (`rea-agents`) is installed, `guard.py` runs deep JS semantic-graph extraction (`analyze-javascript-application`), WASM symbol inspection (`inspect-wasm-artifact` with automatic `REA_WABT_BIN_DIRECTORY` resolution), and macOS Mach-O/plist/dyld/signature verification. When `rea` is absent or `--skip-rea` is passed, deterministic Python + system-tool checks (`plutil`, `otool`, `codesign`) still run in under a second.

## Workflow

### 1. Build the production artifact first

Ensure the build output is fresh before auditing so you do not inspect stale chunks:

```bash
# Web / Vite / Next / Electron renderer
npm run build

# Or macOS SwiftPM / AppKit bundle
Scripts/build-app.sh
```

### 2. Run `guard.py`

```bash
python3 ~/.agents/skills/rea-build-guard/scripts/guard.py <artifact-path> \
  [--out reports/build-guard] \
  [--compare reports/build-guard-prev] \
  [--budget-total-kb 1024] \
  [--budget-asset-kb 5120] \
  [--allow-origin https://cdn.example.com] \
  [--fail-on-warn] \
  [--skip-rea]
```

Supported `<artifact-path>` types (auto-detected):
- **Directory** (`dist/`, `build/`, `out/`) — Web / SPA / static bundle audit.
- **macOS `.app` bundle** (`build/MyApp.app`) — Mach-O slices, `Info.plist`, non-system `dyld` link leaks (e.g. accidental `/opt/homebrew` links that crash on user Macs), code signature, plus embedded web/JS resources if hybrid (`WKWebView` / Electron).
- **Single `.wasm` file** (`pkg/engine_bg.wasm`) — Raw/gzip size + WASM exports/imports surface.

### 3. Interpret results & exit codes

`guard.py` writes `<out>/summary.md` and `<out>/audit.json` (plus REA evidence JSON files when `rea` runs) and exits with:
- `0` — All checks `PASS` (or `WARN` without `--fail-on-warn`).
- `1` — Warnings triggered `--fail-on-warn`.
- `2` — One or more `FAIL` checks triggered:
  - `SEC-001` Shipped credential / private key / high-entropy token literal
  - `SEC-002` `.env` or credential file copied into static output
  - `MAC-001` Missing `CFBundleExecutable` binary inside `.app/Contents/MacOS`
  - `MAC-003` Non-system dynamic library link (`/opt/homebrew/...`, `/Users/...`) without `@rpath` bundling
  - `MAC-004` Broken or missing code signature on `.app`
  - `BDG-001` Explicit `--budget-total-kb` or `--budget-chunk-kb` exceeded

Read `references/rea-checks.md` for the full check catalog and exact framework-specific remediation snippets (Vite, Next.js, esbuild, SwiftPM, Rust `wasm-pack`).

### 4. Compare against a previous build (optional regression gate)

Pass `--compare <previous-report-dir>` to diff content-hashed chunks (`index-a1b2c3d4.js` → `index.js`) and highlight:
- Total raw & gzip delta
- Newly added external network endpoints (from REA semantic graph + URL scan)
- Newly introduced source maps or warnings

### 5. Report concisely to the user

Summarize:
1. Overall verdict (`PASS` / `WARN` / `FAIL`) and artifact footprint (file count, raw & gzip size).
2. Blocking `FAIL` items first (file, line, redacted rule name—never raw secrets) with exact fix instructions.
3. Notable `WARN` items (shipped `.map` files, leaked `/Users/<name>` paths, `localhost` endpoints, `eval`/`new Function` sinks, oversized uncompressed assets).
