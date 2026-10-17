import copy
import json
import unittest
from pathlib import Path

from ward_detector import (
    INCIDENT_START, analyze, at_or_after, contains_credentials_change,
    markdown_report, utc_timestamp,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic_compromise.json"


def data():
    return json.loads(FIXTURE.read_text())


class DetectorTests(unittest.TestCase):
    def test_fixture_detects_attack_chain(self):
        report = analyze(data())
        rules = {finding["rule"] for finding in report["findings"]}
        expected = {
            "EXPOSED_VENDOR_APP", "IOC_SIGNIN", "VENDOR_ROLE_ESCALATION",
            "VENDOR_CREDENTIAL_MODIFICATION", "SCRIPTED_CREDENTIAL_MODIFICATION",
            "VENDOR_DIRECTORY_ROLE", "RECENT_CREDENTIAL", "MULTI_STAGE_SUSPICION",
        }
        self.assertEqual(expected, rules)
        self.assertTrue(report["complete"])
        self.assertGreaterEqual(report["summary"].get("critical", 0), 3)

    def test_no_secret_values_leak_in_summary(self):
        sample = data()
        sample["applications"][0]["passwordCredentials"][0]["secretText"] = "SIMULATED_SECRET_DO_NOT_OUTPUT"
        report = analyze(sample)
        self.assertNotIn("SIMULATED_SECRET_DO_NOT_OUTPUT", json.dumps(report))
        self.assertNotIn("SIMULATED_SECRET_DO_NOT_OUTPUT", markdown_report(report))

    def test_benign_complete_fixture_no_findings(self):
        sample = data()
        sample["servicePrincipals"] = []
        sample["applications"] = []
        sample["signIns"] = []
        sample["directoryAudits"] = []
        sample["roleAssignments"] = []
        sample["roleDefinitions"] = []
        report = analyze(sample)
        self.assertEqual(report["totalFindings"], 0)
        self.assertTrue(report["complete"])

    def test_disabled_app_not_exposure(self):
        sample = data()
        sample["servicePrincipals"][0]["accountEnabled"] = False
        sample["servicePrincipals"][1]["accountEnabled"] = False
        sample["directoryAudits"] = []
        sample["signIns"] = []
        sample["applications"] = []
        sample["roleAssignments"] = []
        sample["roleDefinitions"] = []
        self.assertEqual(analyze(sample)["totalFindings"], 0)

    def test_failed_ioc_signin_not_claimed_success(self):
        sample = data()
        sample["signIns"][0]["status"]["errorCode"] = 50053
        finding = next(f for f in analyze(sample)["findings"] if f["rule"] == "IOC_SIGNIN")
        self.assertEqual(finding["evidence"]["result"], "failed-or-unverified")
        self.assertEqual(finding["severity"], "high")

    def test_coverage_gap_is_a_finding(self):
        sample = data()
        sample["coverage"]["signIns"] = {"complete": False, "error": "License not available"}
        report = analyze(sample)
        self.assertFalse(report["complete"])
        self.assertTrue(any(f["rule"] == "COVERAGE_GAP" and f["evidence"]["dataset"] == "signIns" for f in report["findings"]))

    def test_missing_coverage_is_not_clean(self):
        sample = data()
        sample["coverage"] = {}
        sample["servicePrincipals"] = []
        sample["applications"] = []
        sample["directoryAudits"] = []
        sample["signIns"] = []
        sample["roleAssignments"] = []
        sample["roleDefinitions"] = []
        self.assertEqual(analyze(sample)["totalFindings"], 6)

    def test_recent_credential_boundary_and_timestamp_validation(self):
        self.assertTrue(at_or_after(INCIDENT_START))
        self.assertFalse(at_or_after("2026-10-12T23:59:59Z"))
        self.assertFalse(at_or_after("not-a-timestamp"))
        self.assertIsNone(utc_timestamp(None))

    def test_update_without_credential_change_not_special_cased(self):
        entry = {"activityDisplayName": "Update application", "targetResources": [
            {"modifiedProperties": [{"displayName": "DisplayName"}]}]}
        self.assertFalse(contains_credentials_change(entry))

    def test_report_contains_tenant_and_no_markup_break(self):
        sample = data()
        sample["servicePrincipals"][0]["displayName"] = "Application\nInjected Header"
        report = analyze(sample)
        markdown = markdown_report(report)
        self.assertIn(report["tenantId"], markdown)
        self.assertNotIn("Application\nInjected Header", markdown)

    def test_delta_detects_new_credential_and_role(self):
        current = data()
        old = copy.deepcopy(current)
        old["collectedAt"] = "2026-10-14T01:00:00Z"
        old["applications"][0]["passwordCredentials"] = []
        old["roleAssignments"] = []
        report = analyze(current, old)
        rules = {f["rule"] for f in report["findings"]}
        self.assertIn("NEW_CREDENTIAL_DELTA", rules)
        self.assertIn("NEW_ROLE_ASSIGNMENT_DELTA", rules)

    def test_baseline_cross_tenant_fails_closed(self):
        current, old = data(), data()
        old["tenantId"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        old["collectedAt"] = "2026-10-14T01:00:00Z"
        with self.assertRaises(ValueError):
            analyze(current, old)

    def test_baseline_bad_order_fails_closed(self):
        current, old = data(), data()
        with self.assertRaises(ValueError):
            analyze(current, old)

    def test_invalid_tenant_fails_closed(self):
        with self.assertRaises(ValueError):
            analyze({"coverage": {}})


if __name__ == "__main__":
    unittest.main()