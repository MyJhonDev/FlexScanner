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
