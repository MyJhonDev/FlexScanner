import unittest

from flexscanner.models import CoverageItem, Finding
from flexscanner.report import calculate_verdict
from flexscanner.package import _classify_install_source


class VerdictTests(unittest.TestCase):
    def test_single_low_is_not_ban(self):
        verdict = calculate_verdict(
            [Finding("LOW", 10, "Lua analyzer", "Single indicator")],
            [],
        )
        self.assertEqual(verdict["code"], "NO_STRONG_EVIDENCE")

    def test_two_independent_highs_trigger_review(self):
        verdict = calculate_verdict(
            [
                Finding("HIGH", 50, "Storage", "Autoexec"),
                Finding("HIGH", 60, "Lua analyzer", "Exploit APIs"),
            ],
            [],
        )
        self.assertEqual(verdict["code"], "STRONG_EVIDENCE_REVIEW_FOR_BAN")

    def test_inaccessible_area_keeps_warning(self):
        verdict = calculate_verdict(
            [],
            [CoverageItem("Android/data", "/x", "not-verified", "blocked")],
        )
        self.assertEqual(verdict["coverage_warnings"], 1)

    def test_install_source_classification(self):
        trusted = {"com.android.vending"}
        self.assertEqual(
            _classify_install_source("com.android.vending", None, trusted)[0],
            "play-store",
        )
        self.assertEqual(
            _classify_install_source("com.example.installer", None, trusted)[0],
            "external",
        )
        self.assertEqual(
            _classify_install_source(None, "com.android.shell", trusted)[0],
            "adb-shell",
        )


if __name__ == "__main__":
    unittest.main()

class DeltaEvidenceTests(unittest.TestCase):
    def test_delta_saved_script_without_extension_is_analyzed(self):
        import tempfile
        from pathlib import Path
        from flexscanner.delta import _scan_saved_scripts
        from flexscanner.rules import Rules

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Delta"
            scripts = root / "Scripts"
            scripts.mkdir(parents=True)
            (scripts / "FUTEBOL PROIBIDO").write_text(
                'loadstring(readfile("futebol_proibido.lua"))()',
                encoding="utf-8",
            )
            rules = Rules(Path(__file__).resolve().parents[1] / "config" / "signatures.json")
            findings, info = _scan_saved_scripts(root, rules)
            self.assertEqual(info["saved_count"], 1)
            self.assertEqual(info["analyzed_count"], 1)
            self.assertTrue(any(f.risk == "HIGH" for f in findings))

    def test_delta_crash_log_confirms_execution(self):
        import tempfile
        from pathlib import Path
        from flexscanner.delta import _scan_crash_logs

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Delta"
            crashes = root / "Crashes"
            crashes.mkdir(parents=True)
            (crashes / "Crash-test.txt").write_text(
                """Basic Info:\nScripts Ran: true\nLast Action: EXECUTE SCRIPT\nGame ID: 123\nPlace ID: 456\nCrash Info:\nTimestamp (Unix): 1791615733\nScript Log:\n#0: loadstring(game:HttpGet(\"https://example.com/a\"))()\nStacktrace:\n#0: example\n""",
                encoding="utf-8",
            )
            findings, info = _scan_crash_logs(root)
            self.assertEqual(info["execution_logs"], 1)
            self.assertTrue(any(f.category == "Execução confirmada" for f in findings))
            self.assertTrue(any("Script Log: 1 entrada(s)" in f.evidence for f in findings))
