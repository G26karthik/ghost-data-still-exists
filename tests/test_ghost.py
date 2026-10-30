"""Participant-created controls for identity, time, copies, policy, and authorization."""

import hashlib
import unittest
from unittest.mock import patch

from ghost.activity import correlate, earliest_activity_tiebreak, policy_offset, second_distance
from ghost.evidence import Observation, activity_links, pdf_observations, vision_observations
from ghost.identity import IdentityIndex
from ghost.intake import classify
from ghost.planner import is_deletion_request, plan
from ghost.policy import load_rules, treatment
from ghost.state import resources
from ghost.validate import validate
from pathlib import Path

DATASET = Path("dataset")
RULES = Path(__file__).resolve().parents[1] / "evaluation" / "custom_cases" / "after_audit"


def obs(rid, at, fields, scope, tokens):
    return Observation("evidence_01", at, at, rid, "account_service", fields,
                       frozenset(tokens), "record", scope)


class GhostControls(unittest.TestCase):
    def test_intake_disagreement_keeps_guard_and_flags_case(self):
        row = {"case_id": "case_a", "request_text": "Do not delete my account."}
        answer = {"results": [{"case_id": "case_a", "authorizes_deletion": True,
                               "request_type": "deletion", "evidence_phrase": "delete my account"}]}
        with patch("ghost.intake.ask", return_value=(answer, None, False)):
            decisions, conflicts, bad = classify([row], Path("runs/final"), offline=True)
        self.assertFalse(decisions["case_a"])
        self.assertEqual([x["case_id"] for x in conflicts], ["case_a"])
        self.assertFalse(bad)

    @unittest.skipUnless(DATASET.exists(), "competition dataset is not redistributed")
    def test_catalog_aliases_link_pdf_and_object_image(self):
        links = activity_links(Path("dataset"))
        statement = pdf_observations("evidence_18", "2026-07-18T11:00:00Z",
                                     Path("dataset/evidence/documents/account_history_report_20260718.pdf"), links)
        self.assertIn("export_1842", {x.resource_id for x in statement})
        objects = vision_observations("evidence_46", "2026-02-13T08:00:00Z",
                                      [{"resource_id": "delivery_confirmation_19.pdf",
                                        "file_name": "delivery_confirmation_19.pdf"}], links)
        self.assertEqual(objects[0].resource_id, "object_19")

    def test_worker_seconds_resolve_account_and_policy_without_state_claim(self):
        class Identity:
            owner = {"user_1": "user_1", "user_2": "user_2"}

            def resolve(self, email):
                return "user_1", {"user_1"}

        request = {"case_id": "case_a", "email": "one@example.com",
                   "request_text": "Delete my account", "requested_at": "2026-09-01T10:00:00Z",
                   "reported_at": "2026-09-02T10:00:00Z", "audit_at": "2026-09-03T10:00:00Z",
                   "reported_status": "COMPLETE"}
        actions = [
            {"activity_id": "a1", "event_time": "2026-09-02T09:30:10Z", "event_type": "DELETE_RECORD",
             "source_system": "deletion_worker", "target_system": "account_service",
             "resource_id": "account_1", "reported_result": "SUCCESS", "details": ""},
            {"activity_id": "a2", "event_time": "2026-09-02T09:31:20Z", "event_type": "DELETE_RECORD",
             "source_system": "deletion_worker", "target_system": "account_service",
             "resource_id": "account_2", "reported_result": "SUCCESS", "details": ""},
            {"activity_id": "a3", "event_time": "2026-09-02T09:35:51Z", "event_type": "ANONYMIZE_RECORD",
             "source_system": "deletion_worker", "target_system": "analytics_platform",
             "resource_id": "analytics_1", "reported_result": "SUCCESS",
             "details": "Policy action completed for analytics_1."},
        ]
        observations = [Observation("evidence_1", "2026-09-02T09:00:00Z", "2026-09-02T09:00:00Z",
                                    "analytics_1", "analytics_platform", {}, frozenset({"user_1"}),
                                    "record", "snapshot")]
        linked = correlate([request], Identity(), observations, actions)
        self.assertEqual(linked.account["case_a"]["resource_id"], "account_1")
        self.assertEqual([x["activity_id"] for x in linked.policy["case_a"]], ["a3"])
        self.assertEqual(policy_offset(actions[2]), 19.5)
        self.assertEqual(second_distance(59, 0), 1)

    def test_account_checkpoint_precedes_later_linked_followup(self):
        class Identity:
            owner = {"user_1": "user_1"}

            def resolve(self, _email):
                return "user_1", {"user_1"}

        request = {"case_id": "case_a", "email": "one@example.test",
                   "request_text": "Delete my account", "requested_at": "2026-09-01T10:00:00Z",
                   "reported_at": "2026-09-02T10:00:00Z", "audit_at": "2026-09-03T10:00:00Z",
                   "reported_status": "COMPLETE"}

        def action(identifier, when, event, system, rid, details=""):
            return {"activity_id": identifier, "event_time": when, "event_type": event,
                    "source_system": "deletion_worker", "target_system": system,
                    "resource_id": rid, "reported_result": "SUCCESS", "details": details}

        actions = [
            action("a1", "2026-09-02T09:00:40Z", "DELETE_RECORD", "account_service", "account_false"),
            action("a2", "2026-09-02T09:05:10Z", "DELETE_RECORD", "account_service", "account_true"),
            action("a3", "2026-09-02T09:10:02Z", "SYNC_RECORD", "account_replication_cluster",
                   "account_true", "Replication worker reported its final checkpoint for account_true."),
            action("a4", "2026-09-02T09:31:49Z", "DISABLE_DATA_FLOW", "integration_service",
                   "data_flow_1", "Policy action completed for data_flow_1."),
            action("a5", "2026-09-02T09:40:31Z", "CHECK_DATA_FLOW", "integration_service",
                   "data_flow_1", "Connector check completed."),
        ]
        linked = [Observation("evidence_1", "2026-09-02T09:00:00Z", "2026-09-02T09:00:00Z",
                              "data_flow_1", "integration_service", {}, frozenset({"user_1"}),
                              "record", "snapshot")]
        assigned = correlate([request], Identity(), linked, actions)
        self.assertEqual(assigned.account["case_a"]["resource_id"], "account_true")
        self.assertEqual(policy_offset(actions[3]), 20.5)

    def test_tie_break_is_earliest_activity_only(self):
        candidates = [{"activity_id": "later", "event_time": "2026-09-02T09:10:00Z"},
                      {"activity_id": "earlier", "event_time": "2026-09-02T09:00:00Z"}]
        self.assertEqual(earliest_activity_tiebreak(candidates)["activity_id"], "earlier")

    def test_corrected_support_and_restore_centers(self):
        support = {"details": "Policy action completed for support_1.", "event_type": "REDACT_RECORD",
                   "target_system": "support_platform"}
        restore = {"details": "Policy action completed for backup_1.", "event_type": "BLOCK_RESTORE",
                   "target_system": "backup_service"}
        self.assertEqual(policy_offset(support), 49.5)
        self.assertEqual(policy_offset(restore), 50.5)

    def test_future_only_search_does_not_enter_audit_plan(self):
        request = {"requested_at": "2026-09-01T00:00:00Z", "audit_at": "2026-09-10T00:00:00Z"}
        late = Observation("evidence_1", "2026-09-11T00:00:00Z", "2026-09-09T00:00:00Z",
                           "search_1", "search_service", {"result": "FOUND"},
                           frozenset({"user_1"}), "record", "snapshot")
        decisions, _gaps, unresolved = resources(request, {"user_1"}, [late])
        self.assertEqual((decisions, unresolved), ([], []))

    def test_absent_analytics_verifies_absence(self):
        rules = load_rules(RULES)
        self.assertEqual(treatment("ANALYTICS_PROFILE", "ABSENT", {}, rules)[2],
                         ("VERIFY_RECORD_ABSENT", "ABSENT"))

    def test_historical_email_hash_is_subject_token(self):
        email = "new@example.com"
        users = [{"user_id": "user_1", "email": email, "phone": "+1 202 555 0101",
                  "email_hash": hashlib.sha256(email.encode()).hexdigest()}]
        audit = [{"user_id": "user_1", "old_value": "old@example.com", "new_value": email}]
        uid, values = IdentityIndex(users, audit).resolve("OLD@example.com")
        self.assertEqual(uid, "user_1")
        self.assertIn(hashlib.sha256(b"old@example.com").hexdigest(), values)

    def test_replica_survivor_and_future_absence(self):
        request = {"requested_at": "2026-09-01T00:00:00Z", "audit_at": "2026-09-10T00:00:00Z"}
        records = [
            obs("account_9", "2026-09-08T00:00:00Z", {"resource_id": "account_9", "result": "NOT_FOUND",
                 "table": "customer_profiles_primary"}, "p", {"user_9"}),
            obs("account_9", "2026-09-07T00:00:00Z", {"resource_id": "account_9", "account_status": "ACTIVE",
                 "table": "customer_profiles_failover_replica"}, "r", {"user_9"}),
            obs("account_9", "2026-09-11T00:00:00Z", {"resource_id": "account_9", "result": "NOT_FOUND",
                 "table": "customer_profiles_failover_replica"}, "r", {"user_9"}),
        ]
        decisions, gaps, unresolved = resources(request, {"user_9"}, records)
        self.assertEqual(decisions[0][3], "PRESENT")
        self.assertFalse(unresolved)

    def test_tombstone_requires_redaction_of_direct_email(self):
        rules = load_rules(RULES)
        finding, repair, check, note = treatment("ACCOUNT_TOMBSTONE", "IDENTIFIABLE",
                                                  {"subject_reference": "user_9", "email": "x@example.com"}, rules)
        self.assertEqual(finding[0], "REPORT_EXPOSED_PII")
        self.assertEqual(repair[0], "REDACT_RECORD")
        self.assertEqual(check[0], "VERIFY_RECORD_REDACTED")

    def test_non_deletion_and_positive_request(self):
        self.assertFalse(is_deletion_request("I am not asking for deletion; stop marketing only."))
        self.assertFalse(is_deletion_request("Correct my surname without removing records."))
        self.assertTrue(is_deletion_request("Please delete my account and personal data."))

    def test_future_citation_is_rejected(self):
        request = {"case_id": "case_a", "audit_at": "2026-09-10T00:00:00Z"}
        row = {"case_id": "case_a", "deletion_status": "COMPLETE", "steps_json": [
            {"step_no": 1, "phase": "VERIFICATION", "system_id": "account_service",
             "resource_id": "account_1", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT",
             "evidence_id": "evidence_01"}]}
        manifest = [{"file_id": "evidence_01", "captured_at": "2026-09-11T00:00:00Z"}]
        self.assertTrue(any("after cutoff" in error for error in validate([row], [request], manifest)))

    def test_shared_report_time_cannot_claim_one_account(self):
        first = {"case_id": "case_a", "email": "one@example.test",
                 "request_text": "Delete my account", "requested_at": "2026-09-09T12:00:00Z",
                 "reported_at": "2026-09-10T12:00:00Z", "audit_at": "2026-09-11T00:00:00Z",
                 "reported_status": "COMPLETE"}
        second = {**first, "case_id": "case_b"}
        action = {"activity_id": "a9", "event_type": "DELETE_RECORD",
                  "source_system": "deletion_worker", "target_system": "account_service",
                  "reported_result": "SUCCESS", "details": "", "resource_id": "account_9",
                  "event_time": "2026-09-10T11:00:00Z"}
        users = [{"user_id": "user_1", "email": "one@example.test",
                  "email_hash": hashlib.sha256(b"one@example.test").hexdigest()}]
        assigned = correlate([first, second], IdentityIndex(users, []), [], [action])
        self.assertEqual(len(assigned.account), 1)


if __name__ == "__main__":
    unittest.main()
