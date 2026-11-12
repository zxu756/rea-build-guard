# rea-build-guard

**Reverse-engineering & security self-audit gate for your own production builds** (`dist/`, `.wasm`, Electron, and macOS `.app` bundles)—powered by deterministic static scanners and [REA (`rea-agents`)](https://github.com/morluto/rea).

Source-level linters inspect what you *wrote*. `rea-build-guard` inspects **what your bundler or compiler actually emitted** before you upload a release or deploy to production—catching the exact failure modes common in fast multi-agent and vibe-coded shipping workflows:

- **`VITE_` / `NEXT_PUBLIC_` API keys & high-entropy secrets** inlined into minified JS chunks (`SEC-001`, always redacted in output)
- **`.env.production` or credential files** accidentally copied out of `public/` (`SEC-002`)
- **Developer `/Users/<name>` paths**, `http://localhost:*` endpoints, `debugger;`, and `eval()`/`new Function()` sinks (`SEC-003`–`SEC-005`, `BND-003`)
- **Production `.map` source maps** leaking internal TypeScript/JSX sources and system prompts (`BND-001`)
- **macOS `.app` portability traps**: `/opt/homebrew` dynamic library links that crash on user Macs (`MAC-003`), broken signatures (`MAC-004`), high `LSMinimumSystemVersion` floors (`MAC-002`), and `Info.plist` vs Mach-O `LC_BUILD_VERSION` drift (`MAC-005`)
- **Deep REA binary & AST enrichment** (optional, automatic when `rea` CLI is on `PATH`): JS semantic endpoint/storage graph (`analyze-javascript-application`), WASM export/import surface (`inspect-wasm-artifact`), and Mach-O load-command provenance (`inspect-macho`)
- **Build-to-build regression diffs (`--compare`)**: pairs content-hashed chunks (`index-a1b2c3d4.js` → `index.js`) and flags newly introduced external network origins

> **Scope**: Strictly for auditing **your own** build artifacts before release. Never use against third-party software or external websites.

---

## Install as an Agent Skill

Works with **Claude Code**, **Codex**, **OpenCode**, and **Antigravity**:

```bash
# Via skills CLI
npx skills add zxu756/rea-build-guard -g

# Or clone directly into ~/.agents/skills
git clone https://github.com/zxu756/rea-build-guard.git ~/.agents/skills/rea-build-guard
```

Optional deep binary/AST enrichment (zero-dependency static checks still run in `<100ms` without it):

```bash
npm install -g rea-agents
brew install wabt   # optional: enables WASM export/import inspection
```

---

## Standalone CLI Usage

`scripts/guard.py` uses **only the Python 3.10+ standard library** (+ macOS built-in `otool`/`lipo`/`codesign` for `.app` bundles, and `rea` when installed).

```bash
# 1. Audit a web / Vite / Next static bundle with a 500 KB gzip budget
python3 ~/.agents/skills/rea-build-guard/scripts/guard.py dist/ \
  --budget-total-kb 500 \
  --budget-chunk-kb 250 \
  --out reports/build-guard

# 2. Audit a native macOS .app bundle before cutting a GitHub Release
python3 ~/.agents/skills/rea-build-guard/scripts/guard.py build/MyApp.app \
  --out reports/build-guard

# 3. Regression gate against a previous release's audit.json
python3 ~/.agents/skills/rea-build-guard/scripts/guard.py dist/ \
  --compare reports/build-guard-prev \
  --fail-on-warn
```

### Exit Codes (CI-Ready)

| Exit Code | Meaning |
|---|---|
| `0` | All checks `PASS` (or `WARN` without `--fail-on-warn`) |
| `1` | One or more `WARN` checks triggered with `--fail-on-warn` |
| `2` | Blocking `FAIL` check (`SEC-001`, `SEC-002`, `MAC-001`, `MAC-003`, `MAC-004`, `BDG-001`, `BDG-002`) |

---

## Check Catalog

| ID | Default | Surface | Description |
|---|---|---|---|
| `SEC-001` | `FAIL` | Web / Hybrid | Embedded API keys, private keys, JWTs, or high-entropy secret assignments (always redacted) |
| `SEC-002` | `FAIL` | All | `.env*`, `.npmrc`, `id_rsa`, `credentials.json` shipped inside artifact |
| `SEC-003` | `WARN` | All | Developer machine paths (`/Users/<name>/`, `/home/<name>/`, `C:\Users\`) |
| `SEC-004` | `WARN` | Web / Hybrid | Hardcoded `localhost` / `127.0.0.1` / `0.0.0.0` endpoints |
| `SEC-005` | `WARN` | JS / HTML | `eval()`, `new Function()`, or `document.write()` dynamic execution sinks |
| `BND-001` | `WARN` | Web / Hybrid | `.map` source-map files or `sourceMappingURL` directives |
| `BND-002` | `WARN` | All | `.DS_Store`, `Thumbs.db`, or `.git/` metadata inside output |
| `BND-003` | `WARN` | JS / HTML | Leftover `debugger;` statements |
| `BND-004` | `WARN` | All | Single non-executable asset larger than `--budget-asset-kb` (default `5120` KB) |
| `BDG-001` | `FAIL` | Web / WASM | Total compressible gzip size exceeds `--budget-total-kb` |
| `BDG-002` | `FAIL` | Web | Single JS chunk gzip size exceeds `--budget-chunk-kb` |
| `MAC-001` | `FAIL` | macOS `.app` | `Info.plist` readable & `CFBundleExecutable` binary present + executable |
| `MAC-002` | `WARN` | macOS `.app` | `LSMinimumSystemVersion` sanity check (warns when locked to macOS `26.0+`) |
| `MAC-003` | `FAIL` | macOS `.app` | `otool -L` portability check (blocks `/opt/homebrew` or `/Users` dylib leaks) |
| `MAC-004` | `FAIL` | macOS `.app` | `codesign --verify --deep --strict` integrity check |
| `MAC-005` | `WARN` | macOS `.app` | `Info.plist` `LSMinimumSystemVersion` vs Mach-O `LC_BUILD_VERSION` `minos` alignment |

See [`references/rea-checks.md`](references/rea-checks.md) for framework-specific remediation snippets.

---

## GitHub Actions Gate

```yaml
- name: Build & Self-Audit Artifact
  run: |
    npm run build
    python3 scripts/guard.py dist/ --budget-total-kb 512 --fail-on-warn
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT
