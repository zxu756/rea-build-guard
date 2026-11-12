import json
import os
import plistlib
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import guard  # noqa: E402


class BuildGuardTests(unittest.TestCase):
    def test_clean_web_bundle_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            out = Path(tmp) / "report"
            dist.mkdir()
            (dist / "index.html").write_text("<!doctype html><script src='app-1234abcd.js'></script>", encoding="utf-8")
            (dist / "app-1234abcd.js").write_text("export function add(a, b) { return a + b; }\n", encoding="utf-8")

            report = guard.audit_target(dist, out, skip_rea=True)
            self.assertEqual(report.verdict, "PASS")
            self.assertEqual(guard.main([str(dist), "--out", str(out), "--skip-rea"]), 0)
            self.assertTrue((out / "summary.md").is_file())
            self.assertTrue((out / "audit.json").is_file())

    def test_detects_and_redacts_leaked_secret_and_dotenv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            out = Path(tmp) / "report"
            dist.mkdir()
            # Synthetic test key constructed dynamically so repo scanners stay quiet
            fake_key = "sk-ant-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"
            (dist / "bundle.js").write_text(f'const k = "{fake_key}";\n', encoding="utf-8")
            (dist / ".env.production").write_text("DATABASE_URL=postgres://localhost/db\n", encoding="utf-8")

            rc = guard.main([str(dist), "--out", str(out), "--skip-rea"])
            self.assertEqual(rc, 2)

            summary_md = (out / "summary.md").read_text(encoding="utf-8")
            audit_json = (out / "audit.json").read_text(encoding="utf-8")
            # Raw secret must NEVER appear in either report artifact
            self.assertNotIn(fake_key, summary_md)
            self.assertNotIn(fake_key, audit_json)
            data = json.loads(audit_json)
            check_map = {c["id"]: c["status"] for c in data["checks"]}
            self.assertEqual(check_map["SEC-001"], "FAIL")
            self.assertEqual(check_map["SEC-002"], "FAIL")

    def test_warns_on_sourcemaps_home_paths_localhost_and_eval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            out = Path(tmp) / "report"
            dist.mkdir()
            js = (
                'const src = "/Users/alice/secret-project/src/index.ts";\n'
                'fetch("http://localhost:8787/api");\n'
                'eval("1 + 1");\n'
                'debugger;\n'
                '//# sourceMappingURL=app.js.map\n'
            )
            (dist / "app.js").write_text(js, encoding="utf-8")
            (dist / "app.js.map").write_text('{"version":3}', encoding="utf-8")

            self.assertEqual(guard.main([str(dist), "--out", str(out), "--skip-rea"]), 0)
            self.assertEqual(guard.main([str(dist), "--out", str(out), "--skip-rea", "--fail-on-warn"]), 1)

            data = json.loads((out / "audit.json").read_text(encoding="utf-8"))
            check_map = {c["id"]: c["status"] for c in data["checks"]}
            self.assertEqual(check_map["SEC-003"], "WARN")
            self.assertEqual(check_map["SEC-004"], "WARN")
            self.assertEqual(check_map["SEC-005"], "WARN")
            self.assertEqual(check_map["BND-001"], "WARN")
            self.assertEqual(check_map["BND-003"], "WARN")

    def test_compare_pairs_hashed_chunks_and_tracks_new_origins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d1, d2 = Path(tmp) / "dist1", Path(tmp) / "dist2"
            o1, o2 = Path(tmp) / "out1", Path(tmp) / "out2"
            d1.mkdir()
            d2.mkdir()
            (d1 / "index-aaaa1111.js").write_text("console.log('v1');", encoding="utf-8")
            (d2 / "index-bbbb2222.js").write_text(
                "console.log('v2'); fetch('https://telemetry.example.org/collect');",
                encoding="utf-8",
            )

            guard.audit_target(d1, o1, skip_rea=True)
            rep2 = guard.audit_target(d2, o2, compare_path=o1, skip_rea=True)
            assert rep2.comparison is not None
            self.assertEqual(rep2.comparison["origins_added"], ["https://telemetry.example.org"])
            self.assertEqual(len(rep2.comparison["changed_files"]), 1)
            self.assertEqual(rep2.comparison["changed_files"][0]["file"], "index.js")

    def test_budget_gate_fails_when_exceeded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            out = Path(tmp) / "out"
            dist.mkdir()
            # Generate incompressible-ish pseudo-random text > 4 KB
            payload = "".join(f"var x{i} = '{os.urandom(16).hex()}';\n" for i in range(400))
            (dist / "heavy.js").write_text(payload, encoding="utf-8")
            rc = guard.main([str(dist), "--out", str(out), "--budget-chunk-kb", "2", "--skip-rea"])
            self.assertEqual(rc, 2)

    def test_macos_app_missing_executable_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "Broken.app"
            (app / "Contents" / "MacOS").mkdir(parents=True)
            with (app / "Contents" / "Info.plist").open("wb") as fp:
                plistlib.dump({
                    "CFBundleIdentifier": "local.test.Broken",
                    "CFBundleExecutable": "MissingBinary",
                    "CFBundleShortVersionString": "0.1.0",
                    "LSMinimumSystemVersion": "14.0",
                }, fp)
            out = Path(tmp) / "out"
            rep = guard.audit_target(app, out, skip_rea=True)
            self.assertEqual(rep.verdict, "FAIL")
            check_map = {c["id"]: c["status"] for c in rep.checks}
            self.assertEqual(check_map["MAC-001"], "FAIL")


if __name__ == "__main__":
    unittest.main()
