# REA Build Guard — Check Catalog & Remediation Guide

## Table of Contents
1. [Security & Privacy Checks (`SEC-*`)](#1-security--privacy-checks-sec-)
2. [Bundle Hygiene & Bloat Checks (`BND-*` / `BDG-*`)](#2-bundle-hygiene--bloat-checks-bnd---bdg-)
3. [macOS `.app` Native Checks (`MAC-*`)](#3-macos-app-native-checks-mac-)
4. [REA Deep Static Analysis (`REA-*`)](#4-rea-deep-static-analysis-rea-)

---

## 1. Security & Privacy Checks (`SEC-*`)

| ID | Default Severity | What It Detects | Remediation |
|---|---|---|---|
| `SEC-001` | `FAIL` | API keys, private keys, GitHub/Slack/Stripe/Google/OpenAI/Anthropic tokens, JWTs, or high-entropy `apiKey`/`secret` literals inside shipped text assets. | Move secrets to server-side environment variables. Remove `NEXT_PUBLIC_` / `VITE_` prefixes from secret variables and rotate the exposed key immediately. |
| `SEC-002` | `FAIL` | `.env`, `.env.production`, `.npmrc`, `id_rsa`, or `*.pem` files copied verbatim into the output directory. | Restrict your static `publicDir` so it never points at the project root, and exclude dotfiles in your bundler copy plugin. |
| `SEC-003` | `WARN` | Local developer filesystem paths (`/Users/<name>/...`, `/home/<name>/...`, `C:\Users\...`) baked into JS/HTML/binary strings. | Disable inline source paths in production builds or replace `__dirname` compile-time constants with relative paths. |
| `SEC-004` | `WARN` | Hardcoded loopback endpoints (`http://localhost:3000`, `127.0.0.1`, `0.0.0.0`) outside allowlisted local bridges. | Configure production `VITE_API_BASE_URL` / relative `/api` paths before running `npm run build`. |
| `SEC-005` | `WARN` | Dangerous dynamic code-execution sinks (`eval(...)`, `new Function(...)`) in shipped JS. | Replace dynamic evaluation with static dispatch tables or JSON parsers so CSP `script-src 'self'` can be enforced. |

---

## 2. Bundle Hygiene & Bloat Checks (`BND-*` / `BDG-*`)

| ID | Default Severity | What It Detects | Remediation |
|---|---|---|---|
| `BND-001` | `WARN` | Shipped `.map` source maps or `//# sourceMappingURL=` comments exposing full TypeScript/JSX sources and internal prompts. | Set `build: { sourcemap: false }` (Vite) or `productionBrowserSourceMaps: false` (Next.js), or upload `.map` files privately to Sentry and delete them from `dist/`. |
| `BND-002` | `WARN` | OS/VCS junk shipped in production (`Thumbs.db`, `.DS_Store`, `.git/`). | Strip `.DS_Store` in your packaging script (`find dist -name .DS_Store -delete`). |
| `BND-003` | `WARN` | Leftover `debugger;` statements in production JS chunks. | Enable minifier `drop_debugger: true` (Terser / esbuild `drop: ['debugger']`). |
| `BND-004` | `WARN` | Single uncompressed asset exceeding `--budget-asset-kb` (default `5120` KB / 5 MB). | Compress textures/images (WebP/AVIF, `sips -Z`), decimate `.glb` meshes, or stream large media from a CDN. |
| `BDG-001` | `FAIL` | Total gzipped text/WASM payload or largest JS chunk exceeds explicit `--budget-total-kb` / `--budget-chunk-kb`. | Code-split heavy libraries (`import()`) or swap bloated dependencies. |

---

## 3. macOS `.app` Native Checks (`MAC-*`)

| ID | Default Severity | What It Detects | Remediation |
|---|---|---|---|
| `MAC-001` | `FAIL` | `Info.plist` missing or `CFBundleExecutable` binary absent from `Contents/MacOS/`. | Verify `Scripts/build-app.sh` copies the release binary and `plutil -lint Contents/Info.plist` passes. |
| `MAC-002` | `WARN` | `LSMinimumSystemVersion` in `Info.plist` mismatches Mach-O `LC_BUILD_VERSION` `minos` or locks out older macOS releases unnecessarily (e.g. `27.0`). | Align `platforms: [.macOS("14.0")]` in `Package.swift` (or `-target arm64-apple-macos14.0`) with `LSMinimumSystemVersion`. |
| `MAC-003` | `FAIL` | Mach-O links directly against `/opt/homebrew/...`, `/usr/local/...`, or `/Users/...` instead of `/usr/lib`, `/System/Library`, or bundled `@executable_path` / `@rpath`. | Bundle third-party `.dylib` inside `Contents/Frameworks` and rewrite install names with `install_name_tool`, or link statically. |
| `MAC-004` | `FAIL` | `.app` bundle has an invalid or missing code signature (`codesign --verify --deep --strict` fails). | Ad-hoc sign local/open-source builds (`codesign --force --sign - MyApp.app`) or sign with `Developer ID Application` for notarization. |

---

## 4. REA Deep Static Analysis (`REA-*`)

When `rea` (`rea-agents`) is installed on `PATH`:
- **`rea analyze-javascript-application`**: Parses bundled JS ASTs into a normalized semantic graph, extracting literal vs computed network endpoints, `localStorage`/`IndexedDB` keys, and module exports even across minified chunks.
- **`rea inspect-wasm-artifact`**: Inspects `.wasm` binaries (automatically setting `REA_WABT_BIN_DIRECTORY` from `wasm-objdump`) to list exported functions, memory/table exports, and host imports so unexpected FFI surface is visible.
- **`rea inspect-macho` / `trace-dylib-resolution` / `inspect-signature`**: Structured binary evidence for macOS `.app` bundles.
