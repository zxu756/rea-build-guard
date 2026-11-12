#!/usr/bin/env python3
"""REA Build Guard — Pre-release reverse-engineering & security audit for your own build artifacts.

Supports:
  - Web / SPA / static output directories (dist/, build/, out/, .next/static/)
  - macOS .app bundles (pure SwiftUI/AppKit, Electron, or WKWebView hybrid)
  - Standalone .wasm modules

Read-only with respect to the target artifact. Secret matches are always redacted.
Exit codes:
  0  All checks PASS (or WARN without --fail-on-warn)
  1  WARN present and --fail-on-warn set
  2  One or more FAIL checks triggered, or invalid arguments
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import math
import os
import plistlib
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

TEXT_EXT = {".js", ".mjs", ".cjs", ".css", ".html", ".htm", ".json", ".svg", ".txt", ".xml", ".toml", ".yaml", ".yml"}
CODE_EXT = {".js", ".mjs", ".cjs", ".html", ".htm"}

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("OpenAI/Anthropic key", re.compile(r"\bsk-(?:ant|proj|svcacct|admin)-[A-Za-z0-9_-]{20,}\b")),
    ("sk- secret key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("Stripe live key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    ("JWT token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]

KEY_ASSIGN_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key|secret[_-]?key)\b"
    r"\s*[:=]\s*[\"']([A-Za-z0-9_+/\-]{16,}=*)[\"']"
)
PLACEHOLDER_RE = re.compile(
    r"(?i)your[_-]|example|changeme|change_me|redacted|placeholder|dummy|xxxx|test|mock|sample|public|anon"
)

SENSITIVE_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.development",
    ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "credentials.json",
}
JUNK_NAMES = {".DS_Store", "Thumbs.db"}

HOME_PATH_RE = re.compile(r"(?:/Users/[A-Za-z0-9._-]{2,}/|/home/[A-Za-z0-9._-]{2,}/|[A-Za-z]:\\Users\\[A-Za-z0-9._-]{2,}\\)")
LOCALHOST_RE = re.compile(r"\bhttps?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?[^\s\"'`<>)]*")
DEBUGGER_RE = re.compile(r"(?<![.\w$])debugger\s*;")
SINK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("eval()", re.compile(r"(?<![.\w$])eval\s*\(")),
    ("new Function()", re.compile(r"\bnew\s+Function\s*\(")),
    ("document.write()", re.compile(r"\bdocument\.write\s*\(")),
]
SOURCE_MAP_REF_RE = re.compile(r"[#@]\s*sourceMappingURL=([^\s*\"']+)")
EXTERNAL_URL_RE = re.compile(r"\b(?:https?|wss?)://([A-Za-z0-9.-]+(?::\d+)?)(/[^\s\"'`<>)]*)?")
BENIGN_HOSTS = {
    "www.w3.org", "schemas.openxmlformats.org", "ns.adobe.com",
    "www.apple.com", "apple.com", "localhost", "127.0.0.1", "0.0.0.0",
}
SYSTEM_LIB_PREFIXES = ("/usr/lib/", "/System/Library/", "@executable_path/", "@loader_path/", "@rpath/")


def redact(secret: str) -> str:
    clean = secret.strip()
    if len(clean) <= 10:
        return "***"
    return f"{clean[:6]}… ({len(clean)} chars)"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_high_entropy_secret(value: str) -> bool:
    if PLACEHOLDER_RE.search(value):
        return False
    classes = sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    return classes >= 3 and shannon_entropy(value) >= 3.3


def fmt_size(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes / (1024 * 1024):.2f} MB"


def gz_len(data: bytes) -> int:
    return len(gzip.compress(data, compresslevel=6))


def run_cmd(cmd: list[str], timeout: int = 180, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"


def rea_env() -> dict[str, str]:
    env = dict(os.environ)
    objdump = shutil.which("wasm-objdump")
    if objdump and "REA_WABT_BIN_DIRECTORY" not in env:
        env["REA_WABT_BIN_DIRECTORY"] = str(Path(objdump).resolve().parent)
    return env


class AuditReport:
    def __init__(self, target: Path, kind: str) -> None:
        self.target = str(target)
        self.kind = kind
        self.generated_at = dt.datetime.now(dt.timezone.utc).isoformat()
        self.checks: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self.files: list[dict[str, Any]] = []
        self.external_origins: list[str] = []
        self.rea: dict[str, Any] = {}
        self.macos: dict[str, Any] = {}
        self.comparison: dict[str, Any] | None = None

    def add_check(self, check_id: str, status: str, title: str, detail: str) -> None:
        self.checks.append({"id": check_id, "status": status, "title": title, "detail": detail})

    def add_finding(self, check_id: str, severity: str, label: str, file: str, line: int | None, match: str) -> None:
        self.findings.append({
            "id": check_id,
            "severity": severity,
            "label": label,
            "file": file,
            "line": line,
            "match": match[:160],
        })

    @property
    def verdict(self) -> str:
        statuses = {c["status"] for c in self.checks}
        if "FAIL" in statuses:
            return "FAIL"
        if "WARN" in statuses:
            return "WARN"
        return "PASS"

    @property
    def totals(self) -> dict[str, int]:
        raw = sum(f["bytes"] for f in self.files)
        gz = sum(f["gzip"] for f in self.files if f["gzip"] is not None)
        return {"file_count": len(self.files), "bytes": raw, "gzip": gz}


def detect_kind(target: Path) -> str:
    if target.is_file() and target.suffix.lower() == ".wasm":
        return "wasm"
    if target.is_dir() and target.suffix.lower() == ".app" and (target / "Contents" / "Info.plist").exists():
        return "macos-app"
    if target.is_dir():
        return "directory"
    return "file"


def collect_files(target: Path, kind: str) -> list[tuple[Path, str]]:
    if kind in ("file", "wasm"):
        return [(target, target.name)]
    entries: list[tuple[Path, str]] = []
    for p in sorted(target.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        rel = p.relative_to(target).as_posix()
        entries.append((p, rel))
    return entries


def scan_bundle_files(
    target: Path,
    kind: str,
    report: AuditReport,
    asset_budget_kb: int,
    allowed_origins: set[str],
) -> None:
    entries = collect_files(target, kind)
    secret_hits = 0
    env_files: list[str] = []
    home_hits = 0
    localhost_hits = 0
    sink_hits = 0
    sourcemap_files: list[str] = []
    sourcemap_refs = 0
    junk_files: list[str] = []
    debugger_hits = 0
    oversized_assets: list[str] = []
    origins: set[str] = set()

    for full_path, rel in entries:
        name = full_path.name
        ext = full_path.suffix.lower()
        data = full_path.read_bytes()
        size = len(data)
        is_compressible = ext in (TEXT_EXT | {".wasm", ".map"})
        gz = gz_len(data) if is_compressible and size <= 25_000_000 else None
        report.files.append({"path": rel, "ext": ext, "bytes": size, "gzip": gz})

        if name in JUNK_NAMES or "/.git/" in f"/{rel}":
            junk_files.append(rel)

        if name.lower() in SENSITIVE_FILENAMES or (name.startswith(".env.") and not name.endswith(".example")):
            env_files.append(rel)
            report.add_finding("SEC-002", "FAIL", "Sensitive config/credential file shipped", rel, None, name)

        if ext == ".map":
            sourcemap_files.append(rel)
            continue

        if size > asset_budget_kb * 1024 and not rel.startswith("Contents/MacOS/"):
            oversized_assets.append(f"{rel} ({fmt_size(size)})")

        if ext not in TEXT_EXT or size > 10_000_000:
            continue

        text = data.decode("utf-8", errors="replace")

        for label, rx in SECRET_PATTERNS:
            for m in rx.finditer(text):
                val = m.group(0)
                if label == "sk- secret key" and not re.search(r"\d", val):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                secret_hits += 1
                report.add_finding("SEC-001", "FAIL", label, rel, line, redact(val))

        for m in KEY_ASSIGN_RE.finditer(text):
            val = m.group(1)
            if looks_high_entropy_secret(val):
                line = text.count("\n", 0, m.start()) + 1
                secret_hits += 1
                report.add_finding("SEC-001", "FAIL", "High-entropy secret assignment", rel, line, redact(val))

        for m in HOME_PATH_RE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            home_hits += 1
            report.add_finding("SEC-003", "WARN", "Developer machine path", rel, line, m.group(0))

        for m in LOCALHOST_RE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            localhost_hits += 1
            report.add_finding("SEC-004", "WARN", "Localhost endpoint", rel, line, m.group(0))

        for m in SOURCE_MAP_REF_RE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            sourcemap_refs += 1
            report.add_finding("BND-001", "WARN", "sourceMappingURL reference", rel, line, m.group(1))

        if ext in CODE_EXT:
            for m in DEBUGGER_RE.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                debugger_hits += 1
                report.add_finding("BND-003", "WARN", "debugger statement", rel, line, "debugger;")
            for sink_label, rx in SINK_PATTERNS:
                for m in rx.finditer(text):
                    line = text.count("\n", 0, m.start()) + 1
                    sink_hits += 1
                    report.add_finding("SEC-005", "WARN", f"Dynamic code sink {sink_label}", rel, line, sink_label)

        for m in EXTERNAL_URL_RE.finditer(text):
            host = m.group(1).lower()
            full_origin = m.group(0).split("/")[0] + "//" + host
            if host not in BENIGN_HOSTS and full_origin not in allowed_origins and host not in allowed_origins:
                origins.add(full_origin)

    report.external_origins = sorted(origins)

    report.add_check(
        "SEC-001",
        "FAIL" if secret_hits else "PASS",
        "Embedded credentials & API keys",
        f"{secret_hits} redacted secret match(es) found" if secret_hits else "none detected across text/code assets",
    )
    report.add_check(
        "SEC-002",
        "FAIL" if env_files else "PASS",
        "Shipped .env / credential files",
        f"shipped: {', '.join(env_files)}" if env_files else "no .env or credential files in output",
    )
    report.add_check(
        "SEC-003",
        "WARN" if home_hits else "PASS",
        "Developer home-directory paths",
        f"{home_hits} local path string(s) leaked" if home_hits else "no /Users or /home paths found",
    )
    report.add_check(
        "SEC-004",
        "WARN" if localhost_hits else "PASS",
        "Hardcoded localhost URLs",
        f"{localhost_hits} loopback URL(s) found" if localhost_hits else "none",
    )
    report.add_check(
        "SEC-005",
        "WARN" if sink_hits else "PASS",
        "Dynamic JS execution sinks",
        f"{sink_hits} eval/Function/document.write call(s)" if sink_hits else "none",
    )
    has_maps = bool(sourcemap_files or sourcemap_refs)
    report.add_check(
        "BND-001",
        "WARN" if has_maps else "PASS",
        "Production source maps",
        f"{len(sourcemap_files)} .map file(s), {sourcemap_refs} sourceMappingURL ref(s)"
        if has_maps else "no .map files or sourceMappingURL comments",
    )
    report.add_check(
        "BND-002",
        "WARN" if junk_files else "PASS",
        "OS / VCS junk files",
        f"{len(junk_files)} junk file(s): {', '.join(junk_files[:5])}" if junk_files else "clean",
    )
    report.add_check(
        "BND-003",
        "WARN" if debugger_hits else "PASS",
        "Leftover debugger statements",
        f"{debugger_hits} statement(s)" if debugger_hits else "none",
    )
    report.add_check(
        "BND-004",
        "WARN" if oversized_assets else "PASS",
        f"Single-asset size threshold (>{asset_budget_kb} KB)",
        "; ".join(oversized_assets[:5]) if oversized_assets else f"all assets <= {asset_budget_kb} KB",
    )


def audit_macos_app(app_path: Path, report: AuditReport) -> None:
    plist_path = app_path / "Contents" / "Info.plist"
    try:
        with plist_path.open("rb") as fp:
            plist = plistlib.load(fp)
    except Exception as exc:
        report.add_check("MAC-001", "FAIL", "Info.plist & executable", f"unreadable Info.plist: {exc}")
        return

    exe_name = plist.get("CFBundleExecutable", "")
    exe_path = app_path / "Contents" / "MacOS" / exe_name if exe_name else Path()
    exe_ok = bool(exe_name) and exe_path.is_file() and os.access(exe_path, os.X_OK)
    min_os = str(plist.get("LSMinimumSystemVersion", "unspecified"))
    bundle_id = str(plist.get("CFBundleIdentifier", "unspecified"))
    short_ver = str(plist.get("CFBundleShortVersionString", "0"))
    report.macos["bundle_id"] = bundle_id
    report.macos["version"] = short_ver
    report.macos["minimum_macos"] = min_os
    report.macos["executable"] = exe_name

    report.add_check(
        "MAC-001",
        "PASS" if exe_ok else "FAIL",
        "Info.plist & CFBundleExecutable",
        f"{bundle_id} v{short_ver}, executable '{exe_name}' present" if exe_ok
        else f"CFBundleExecutable '{exe_name}' missing or not executable in Contents/MacOS",
    )

    try:
        major = int(min_os.split(".")[0])
    except ValueError:
        major = 0
    report.add_check(
        "MAC-002",
        "WARN" if major >= 26 else "PASS",
        "macOS deployment target",
        f"LSMinimumSystemVersion={min_os} (very high floor; older Macs cannot launch)" if major >= 26
        else f"LSMinimumSystemVersion={min_os}",
    )

    if exe_ok and sys.platform == "darwin":
        rc, out, _ = run_cmd(["lipo", "-archs", str(exe_path)], timeout=15)
        if rc == 0:
            report.macos["architectures"] = out.strip().split()

        rc, out, _ = run_cmd(["otool", "-L", str(exe_path)], timeout=15)
        if rc == 0:
            libs = []
            leaked_libs = []
            for line in out.splitlines()[1:]:
                lib = line.strip().split(" (", 1)[0].strip()
                if not lib:
                    continue
                libs.append(lib)
                if not lib.startswith(SYSTEM_LIB_PREFIXES):
                    leaked_libs.append(lib)
            report.macos["linked_libraries"] = libs
            report.add_check(
                "MAC-003",
                "FAIL" if leaked_libs else "PASS",
                "Dynamic library portability (otool -L)",
                f"non-portable links: {', '.join(leaked_libs)}" if leaked_libs
                else f"{len(libs)} linked libraries, all system or @rpath/@executable_path",
            )

        rc, _, err = run_cmd(["codesign", "--verify", "--deep", "--strict", str(app_path)], timeout=30)
        report.add_check(
            "MAC-004",
            "PASS" if rc == 0 else "FAIL",
            "Code signature integrity",
            "valid signature on disk" if rc == 0 else f"codesign failed: {err.strip()[:200]}",
        )


def run_rea_enrichment(target: Path, kind: str, out_dir: Path, report: AuditReport) -> None:
    rea_bin = shutil.which("rea")
    if not rea_bin:
        report.rea = {"available": False, "reason": "rea CLI not installed on PATH"}
        return

    env = rea_env()
    rea_info: dict[str, Any] = {"available": True}

    js_root: Path | None = None
    if kind == "directory" and any(f["ext"] in {".js", ".mjs", ".cjs"} for f in report.files):
        js_root = target
    elif kind == "macos-app":
        web_res = target / "Contents" / "Resources" / "web"
        if web_res.is_dir():
            js_root = web_res

    if js_root is not None:
        ev_path = out_dir / "rea-js.evidence.json"
        rc, _, err = run_cmd(
            [
                rea_bin, "analyze-javascript-application", str(js_root),
                "--artifact-format", "directory", "--detail", "summary",
                "--evidence_output", str(ev_path), "--format", "json",
            ],
            timeout=300,
            env=env,
        )
        if rc == 0 and ev_path.is_file():
            try:
                raw = json.loads(ev_path.read_text(encoding="utf-8"))
                nr = raw["records"][0]["normalized_result"]
                nodes = nr.get("graph", {}).get("nodes", [])
                endpoints = sorted({
                    n.get("identity", {}).get("key", "")
                    for n in nodes if n.get("kind") == "endpoint"
                })
                storage = sorted({
                    n.get("identity", {}).get("key", "")
                    for n in nodes if n.get("kind") == "storage"
                })
                rea_info["javascript"] = {
                    "ok": True,
                    "statistics": nr.get("statistics", {}),
                    "endpoint_count": len(endpoints),
                    "endpoints": endpoints[:40],
                    "storage_keys": storage[:40],
                    "source_map_nodes": sum(1 for n in nodes if n.get("kind") == "source-map"),
                }
            except Exception as exc:
                rea_info["javascript"] = {"ok": False, "error": str(exc)[:200]}
        else:
            rea_info["javascript"] = {"ok": False, "error": (err.strip().splitlines() or [f"exit {rc}"])[-1][:200]}

    wasm_paths = [target] if kind == "wasm" else sorted(target.rglob("*.wasm"))
    if wasm_paths:
        wasm_reports = []
        for wp in wasm_paths[:10]:
            rc, stdout, err = run_cmd(
                [rea_bin, "inspect-wasm-artifact", str(wp), "--format", "json"],
                timeout=180,
                env=env,
            )
            if rc == 0:
                clean_lines = [l for l in stdout.splitlines() if "rea_progress" not in l]
                try:
                    nr = json.loads("\n".join(clean_lines))["normalized_result"]
                    wasm_reports.append({
                        "file": wp.name if kind == "wasm" else wp.relative_to(target).as_posix(),
                        "ok": True,
                        "export_count": len(nr.get("exports", [])),
                        "import_count": len(nr.get("imports", [])),
                        "exports": nr.get("exports", [])[:30],
                    })
                except Exception as exc:
                    wasm_reports.append({"file": wp.name, "ok": False, "error": str(exc)[:200]})
            else:
                wasm_reports.append({
                    "file": wp.name,
                    "ok": False,
                    "error": (err.strip().splitlines() or [f"exit {rc}"])[-1][:200],
                })
        rea_info["wasm"] = wasm_reports

    if kind == "macos-app":
        rc, stdout, err = run_cmd([rea_bin, "inspect-macho", str(target), "--format", "json"], timeout=120, env=env)
        if rc == 0:
            clean_lines = [l for l in stdout.splitlines() if "rea_progress" not in l]
            try:
                parsed = json.loads("\n".join(clean_lines))
                nr = parsed.get("normalized_result", {})
                build_items = nr.get("build_metadata", {}).get("items", [])
                archs = [a.get("name") for a in nr.get("architectures", {}).get("items", []) if a.get("name")]
                macho_min_os = build_items[0].get("minimum_os") if build_items else None
                rea_info["macho"] = {
                    "ok": True,
                    "sha256": parsed.get("subject", {}).get("digest", {}).get("sha256"),
                    "uuid": nr.get("uuid"),
                    "architectures": archs,
                    "minimum_os": macho_min_os,
                    "sdk": build_items[0].get("sdk") if build_items else None,
                    "load_commands": nr.get("load_commands", {}).get("total"),
                }
                plist_min = report.macos.get("minimum_macos")
                if macho_min_os and plist_min and plist_min != "unspecified" and macho_min_os != plist_min:
                    report.add_check(
                        "MAC-005",
                        "WARN",
                        "Plist vs Mach-O minimum OS alignment",
                        f"Info.plist={plist_min} != LC_BUILD_VERSION minos={macho_min_os}",
                    )
            except Exception as exc:
                rea_info["macho"] = {"ok": False, "error": str(exc)[:200]}
        else:
            rea_info["macho"] = {"ok": False, "error": (err.strip().splitlines() or [f"exit {rc}"])[-1][:200]}

    report.rea = rea_info


def apply_budgets(report: AuditReport, total_kb: int | None, chunk_kb: int | None) -> None:
    if total_kb is not None:
        gz_bytes = report.totals["gzip"]
        ok = gz_bytes <= total_kb * 1024
        report.add_check(
            "BDG-001",
            "PASS" if ok else "FAIL",
            f"Total gzip budget (<={total_kb} KB)",
            f"total gzip={fmt_size(gz_bytes)} (limit {total_kb} KB)",
        )
    if chunk_kb is not None:
        js_chunks = [f for f in report.files if f["ext"] in {".js", ".mjs", ".cjs"}]
        over = [
            f"{f['path']} ({fmt_size(f['gzip'] or f['bytes'])})"
            for f in js_chunks if (f["gzip"] or f["bytes"]) > chunk_kb * 1024
        ]
        report.add_check(
            "BDG-002",
            "FAIL" if over else "PASS",
            f"Per-chunk gzip budget (<={chunk_kb} KB)",
            "; ".join(over[:5]) if over else f"all {len(js_chunks)} JS chunks within {chunk_kb} KB",
        )


def strip_chunk_hash(path: str) -> str:
    return re.sub(r"[-.][A-Za-z0-9_]{8,}(?=\.[a-z0-9]+$)", "", path)


def compare_previous(prev_dir_or_file: Path, report: AuditReport) -> dict[str, Any]:
    prev_json = prev_dir_or_file / "audit.json" if prev_dir_or_file.is_dir() else prev_dir_or_file
    if not prev_json.is_file():
        return {"error": f"previous report not found: {prev_json}"}
    prev = json.loads(prev_json.read_text(encoding="utf-8"))

    def normalize_map(file_list: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        counts = Counter(strip_chunk_hash(f["path"]) for f in file_list)
        return {
            (strip_chunk_hash(f["path"]) if counts[strip_chunk_hash(f["path"])] == 1 else f["path"]): f
            for f in file_list
        }

    before = normalize_map(prev.get("files", []))
    after = normalize_map(report.files)
    deltas = []
    for key in sorted(set(before) | set(after)):
        b, a = before.get(key), after.get(key)
        b_sz = (b or {}).get("gzip") or (b or {}).get("bytes", 0)
        a_sz = (a or {}).get("gzip") or (a or {}).get("bytes", 0)
        if b is None or a is None or b_sz != a_sz:
            deltas.append({
                "file": key,
                "before_bytes": b_sz if b is not None else None,
                "after_bytes": a_sz if a is not None else None,
                "delta_bytes": a_sz - b_sz,
            })

    prev_origins = set(prev.get("external_origins", []))
    cur_origins = set(report.external_origins)
    return {
        "previous": str(prev_json),
        "raw_delta_bytes": report.totals["bytes"] - prev.get("totals", {}).get("bytes", 0),
        "gzip_delta_bytes": report.totals["gzip"] - prev.get("totals", {}).get("gzip", 0),
        "origins_added": sorted(cur_origins - prev_origins),
        "origins_removed": sorted(prev_origins - cur_origins),
        "changed_files": deltas[:30],
    }


def render_markdown(report: AuditReport) -> str:
    t = report.totals
    lines = [
        f"# Build Guard Report — `{report.verdict}`",
        "",
        f"- **Target**: `{report.target}` (`{report.kind}`)",
        f"- **Generated**: `{report.generated_at}`",
        f"- **Footprint**: {t['file_count']} files · {fmt_size(t['bytes'])} raw · {fmt_size(t['gzip'])} compressible gzip",
        "",
        "## Checks",
        "",
        "| ID | Status | Check | Detail |",
        "|---|---|---|---|",
    ]
    for c in report.checks:
        lines.append(f"| `{c['id']}` | **{c['status']}** | {c['title']} | {c['detail']} |")

    if report.findings:
        lines += [
            "",
            "## Findings (Redacted)",
            "",
            "| ID | Severity | File | Line | Rule | Snippet |",
            "|---|---|---|---|---|---|",
        ]
        for f in report.findings[:50]:
            ln = str(f["line"]) if f["line"] is not None else "-"
            snip = str(f["match"]).replace("|", "\\|")
            lines.append(f"| `{f['id']}` | **{f['severity']}** | `{f['file']}` | {ln} | {f['label']} | `{snip}` |")

    largest = sorted(report.files, key=lambda x: x["bytes"], reverse=True)[:10]
    if largest:
        lines += [
            "",
            "## Largest Bundled Files",
            "",
            "| File | Raw | Gzip |",
            "|---|---|---|",
        ]
        for f in largest:
            gz_s = fmt_size(f["gzip"]) if f["gzip"] is not None else "-"
            lines.append(f"| `{f['path']}` | {fmt_size(f['bytes'])} | {gz_s} |")

    if report.external_origins:
        lines += ["", "## External Network Origins Referenced", ""]
        for orig in report.external_origins:
            lines.append(f"- `{orig}`")

    if report.rea.get("available"):
        lines += ["", "## REA Deep Analysis", ""]
        if "macho" in report.rea and report.rea["macho"].get("ok"):
            m = report.rea["macho"]
            lines.append(
                f"- **Mach-O (`rea inspect-macho`)**: archs `{','.join(m.get('architectures') or [])}` · "
                f"`minos={m.get('minimum_os')}` · `sdk={m.get('sdk')}` · `{m.get('load_commands')}` load commands · "
                f"UUID `{m.get('uuid')}`"
            )
        if "javascript" in report.rea and report.rea["javascript"].get("ok"):
            js = report.rea["javascript"]
            lines.append(
                f"- **JS Semantic Graph (`rea analyze-javascript-application`)**: "
                f"{js.get('endpoint_count', 0)} endpoints · {len(js.get('storage_keys', []))} storage keys · "
                f"{js.get('source_map_nodes', 0)} source-map nodes"
            )
        if "wasm" in report.rea:
            for w in report.rea["wasm"]:
                if w.get("ok"):
                    lines.append(
                        f"- **WASM (`rea inspect-wasm-artifact`) `{w['file']}`**: "
                        f"{w['export_count']} exports · {w['import_count']} imports"
                    )

    if report.comparison and "error" not in report.comparison:
        cmp = report.comparison
        sign = "+" if cmp["gzip_delta_bytes"] >= 0 else "-"
        lines += [
            "",
            "## Comparison vs Previous Build",
            "",
            f"- **Gzip delta**: `{sign}{fmt_size(abs(cmp['gzip_delta_bytes']))}`",
        ]
        if cmp["origins_added"]:
            lines.append(f"- **New external origins**: {', '.join(f'`{o}`' for o in cmp['origins_added'])}")
        if cmp["origins_removed"]:
            lines.append(f"- **Removed external origins**: {', '.join(f'`{o}`' for o in cmp['origins_removed'])}")

    lines.append("")
    return "\n".join(lines)


def audit_target(
    target: Path,
    out_dir: Path,
    *,
    compare_path: Path | None = None,
    budget_total_kb: int | None = None,
    budget_chunk_kb: int | None = None,
    budget_asset_kb: int = 5120,
    allowed_origins: set[str] | None = None,
    skip_rea: bool = False,
) -> AuditReport:
    kind = detect_kind(target)
    report = AuditReport(target, kind)
    out_dir.mkdir(parents=True, exist_ok=True)

    scan_bundle_files(target, kind, report, budget_asset_kb, allowed_origins or set())
    if kind == "macos-app":
        audit_macos_app(target, report)
    if not skip_rea:
        run_rea_enrichment(target, kind, out_dir, report)
    else:
        report.rea = {"available": False, "reason": "skipped via --skip-rea"}

    apply_budgets(report, budget_total_kb, budget_chunk_kb)
    if compare_path is not None:
        report.comparison = compare_previous(compare_path, report)

    payload = {
        "verdict": report.verdict,
        "target": report.target,
        "kind": report.kind,
        "generated_at": report.generated_at,
        "totals": report.totals,
        "checks": report.checks,
        "findings": report.findings,
        "external_origins": report.external_origins,
        "macos": report.macos,
        "rea": report.rea,
        "comparison": report.comparison,
        "files": report.files,
    }
    (out_dir / "audit.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out_dir / "summary.md").write_text(render_markdown(report), encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Audit your own production build artifact for leaks, bloat, and portability.")
    ap.add_argument("target", help="Path to built directory (e.g. dist/), .app bundle, or .wasm file")
    ap.add_argument("--out", help="Output report directory (default: reports/build-guard)")
    ap.add_argument("--compare", help="Previous report directory or audit.json for delta comparison")
    ap.add_argument("--budget-total-kb", type=int, help="Fail if total gzipped payload exceeds KB")
    ap.add_argument("--budget-chunk-kb", type=int, help="Fail if any JS chunk gzip exceeds KB")
    ap.add_argument("--budget-asset-kb", type=int, default=5120, help="Warn if any single asset exceeds KB (default: 5120)")
    ap.add_argument("--allow-origin", action="append", default=[], help="Allowlist expected external origin")
    ap.add_argument("--fail-on-warn", action="store_true", help="Exit 1 when WARN checks exist")
    ap.add_argument("--skip-rea", action="store_true", help="Skip calling rea CLI even if installed")
    ap.add_argument("--json", action="store_true", help="Print JSON summary to stdout")
    args = ap.parse_args(argv)

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"error: target does not exist: {target}", file=sys.stderr)
        return 2

    out_dir = Path(args.out).resolve() if args.out else Path.cwd() / "reports" / "build-guard"
    compare_path = Path(args.compare).resolve() if args.compare else None
    report = audit_target(
        target,
        out_dir,
        compare_path=compare_path,
        budget_total_kb=args.budget_total_kb,
        budget_chunk_kb=args.budget_chunk_kb,
        budget_asset_kb=args.budget_asset_kb,
        allowed_origins=set(args.allow_origin),
        skip_rea=args.skip_rea,
    )

    if args.json:
        print(json.dumps({
            "verdict": report.verdict,
            "totals": report.totals,
            "checks": report.checks,
            "report_dir": str(out_dir),
        }, indent=2))
    else:
        t = report.totals
        print(f"[{report.verdict}] {target.name} ({report.kind}): {t['file_count']} files, {fmt_size(t['bytes'])} raw, {fmt_size(t['gzip'])} gzip")
        for c in report.checks:
            if c["status"] != "PASS":
                print(f"  {c['status']:4s} {c['id']} {c['title']}: {c['detail']}")
        print(f"Report written to {out_dir / 'summary.md'}")

    if report.verdict == "FAIL":
        return 2
    if report.verdict == "WARN" and args.fail_on_warn:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
