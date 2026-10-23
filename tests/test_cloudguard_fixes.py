"""Tests for the two root-cause fixes in CloudGuard AI.

Bug 1: _extract_resource_name returned "lambda" or "s3" instead of "reports-bucket"
        for the input "My Lambda function needs to upload reports to the reports-bucket S3 bucket only."

Bug 2: The Strands Decider 2B hook was never called because the old monkey-patch targeted
        analyse_permission_request.func / __wrapped__, but Strands stores the callable at
        ._tool_func. So reviewer.log stayed empty, out["decisions"] was [], and the browser
        showed outcome="unknown" and confidence=0%.

These tests verify the fixes without calling real AWS or the live Decider API.
All Decider calls use FakeDecider.
"""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from fakes import FakeDecider


# ---------------------------------------------------------------------------
# Bug 1: _extract_resource_name
# ---------------------------------------------------------------------------

class TestExtractResourceName:
    """The regex must extract the actual bucket/table name, not a service keyword."""

    def _fn(self, request: str):
        from agent.tools import _extract_resource_name
        return _extract_resource_name(request)

    def test_reports_bucket_from_canonical_request(self):
        """The motivating example from the bug report."""
        result = self._fn(
            "My Lambda function needs to upload reports to the reports-bucket S3 bucket only."
        )
        assert result == "reports-bucket", (
            f"Expected 'reports-bucket', got {result!r}. "
            "The regex must not capture 's3' or 'lambda' as the resource name."
        )

    def test_does_not_return_service_keyword_s3(self):
        result = self._fn("Upload files to the data-lake S3 bucket.")
        assert result == "data-lake"

    def test_does_not_return_service_keyword_lambda(self):
        result = self._fn("My Lambda function needs to read from the orders DynamoDB table.")
        # "orders" is the table name, not "lambda" or "dynamodb"
        assert result == "orders"

    def test_hyphenated_bucket_name(self):
        result = self._fn("Allow the function to write to the finance-reports bucket.")
        assert result == "finance-reports"

    def test_quoted_name_takes_priority(self):
        result = self._fn('Upload to the "analytics-data" S3 bucket.')
        assert result == "analytics-data"

    def test_plain_bucket_name(self):
        result = self._fn("Read from the uploads bucket and write to the results bucket.")
        # "uploads" is the first bucket-adjacent word that is not a service keyword
        assert result == "uploads"

    def test_dynamodb_table_name(self):
        result = self._fn("Query items in the catalog-table DynamoDB table.")
        assert result == "catalog-table"

    def test_no_resource_name_returns_none(self):
        result = self._fn("Give me permission to access the data.")
        # No clear resource name -- acceptable to return None or a non-service word
        # The important invariant is it should NOT return a bare service keyword
        service_words = {"s3", "lambda", "dynamodb", "ec2", "iam", "kms"}
        if result is not None:
            assert result.lower() not in service_words, (
                f"Returned bare service keyword {result!r}"
            )

    def test_finance_reports_bucket(self):
        result = self._fn(
            "Allow the scheduled Lambda to upload the nightly sales report CSV "
            "to the finance-reports S3 bucket."
        )
        assert result == "finance-reports"


# ---------------------------------------------------------------------------
# Bug 2: Decider hook actually fires and decisions[] is populated
# ---------------------------------------------------------------------------

class TestDeciderHookFires:
    """After the fix, reviewer.log must be populated and out['decisions'] must be non-empty."""

    def _make_agent(self, fake_decider=None):
        from agent.agent import HackathonAgent
        d = fake_decider or FakeDecider()
        return HackathonAgent(decider=d, model_id="us.amazon.nova-lite-v1:0")

    def test_decisions_not_empty_after_safe_request(self):
        """out['decisions'] must have at least one entry for a permission review request."""
        a = self._make_agent()
        out = a.chat(
            "My Lambda function needs to upload reports to the reports-bucket S3 bucket only."
        )
        assert isinstance(out["decisions"], list), "decisions must be a list"
        assert len(out["decisions"]) > 0, (
            "decisions[] is empty -- the Decider hook did not fire. "
            "This was the original bug: monkey-patch targeted .func but Strands uses ._tool_func."
        )

    def test_decision_has_outcome_field(self):
        """Each decision entry must have 'outcome' (not 'decider_outcome')."""
        a = self._make_agent()
        out = a.chat(
            "My Lambda function needs to upload reports to the reports-bucket S3 bucket only."
        )
        if out["decisions"]:
            d = out["decisions"][0]
            assert "outcome" in d, (
                f"Decision entry missing 'outcome'. Keys present: {list(d.keys())}. "
                "The browser's submitReview() reads d.outcome to set the colored pill."
            )

    def test_decision_has_confidence_field(self):
        """Each decision entry must have 'confidence' as a float 0-1."""
        a = self._make_agent()
        out = a.chat(
            "My Lambda function needs to upload reports to the reports-bucket S3 bucket only."
        )
        if out["decisions"]:
            d = out["decisions"][0]
            assert "confidence" in d, f"Missing 'confidence'. Keys: {list(d.keys())}"
            assert isinstance(d["confidence"], (int, float)), "confidence must be numeric"
            assert 0.0 <= d["confidence"] <= 1.0, f"confidence out of range: {d['confidence']}"

    def test_decision_outcome_is_not_unknown(self):
        """outcome must be one of the three valid values, never the fallback 'unknown'."""
        a = self._make_agent()
        out = a.chat(
            "My Lambda function needs to upload reports to the reports-bucket S3 bucket only."
        )
        if out["decisions"]:
            outcome = out["decisions"][0].get("outcome", "unknown")
            assert outcome in {"allow", "clarify", "human_review"}, (
                f"Got outcome={outcome!r}. Expected allow/clarify/human_review. "
                "If 'unknown', decisions[] was empty and the browser defaulted to unknown."
            )

    def test_decision_confidence_is_not_zero_when_decider_runs(self):
        """When FakeDecider runs, confidence must be > 0 (not the default 0 from empty decisions)."""
        a = self._make_agent()
        out = a.chat(
            "My Lambda function needs to upload reports to the reports-bucket S3 bucket only."
        )
        if out["decisions"]:
            conf = out["decisions"][0].get("confidence", 0)
            assert conf > 0, (
                f"confidence={conf}. If 0, the Decider hook did not fire "
                "and the browser would show 0% confidence."
            )

    def test_decision_has_probability_bars(self):
        """The four noul questions must appear as float fields (rendered as bars in the UI)."""
        a = self._make_agent()
        out = a.chat(
            "My Lambda function needs to upload reports to the reports-bucket S3 bucket only."
        )
        if out["decisions"]:
            d = out["decisions"][0]
            bar_fields = [k for k, v in d.items()
                          if isinstance(v, float) and 0 <= v <= 1 and not k.endswith("_ms")
                          and k != "confidence"]
            assert len(bar_fields) > 0, (
                f"No probability bar fields found in decision. Keys: {list(d.keys())}. "
                "The browser renders floats 0-1 (excluding confidence and *_ms) as bars."
            )


# ---------------------------------------------------------------------------
# Resource mismatch flagging (requirement 6)
# ---------------------------------------------------------------------------

class TestResourceMismatch:
    """When the extracted resource does not match the bucket in the request,
    the result must not be labelled safe to apply."""

    def test_correct_resource_for_reports_bucket(self):
        """For the canonical request, proposed_action must contain 'reports-bucket', not 'lambda' or 's3'."""
        from agent.agent import _build_proposed_action
        proposed, resource = _build_proposed_action(
            "My Lambda function needs to upload reports to the reports-bucket S3 bucket only."
        )
        assert "reports-bucket" in proposed, (
            f"proposed_action={proposed!r} does not contain 'reports-bucket'. "
            "The wrong resource would cause a mismatched permission recommendation."
        )
        assert "lambda" not in resource.lower() or "reports-bucket" in resource, (
            f"resource={resource!r} looks wrong -- contains 'lambda' but not 'reports-bucket'."
        )

    def test_finance_reports_bucket_resource(self):
        from agent.agent import _build_proposed_action
        proposed, _ = _build_proposed_action(
            "Allow the scheduled Lambda to upload the nightly CSV to the finance-reports S3 bucket."
        )
        assert "finance-reports" in proposed, f"Got {proposed!r}"

    def test_prohibited_request_goes_to_human_review(self):
        """A request with AdministratorAccess must produce human_review (deterministic, no Decider)."""
        from agent.decision import PermissionReviewer
        rev = PermissionReviewer(FakeDecider())
        result = rev.review(
            "Give this Lambda administrator access.",
            "AdministratorAccess on *",
        )
        assert result.outcome == "human_review", f"Got {result.outcome!r}"
        assert result.decider_ms == 0, "Deterministic block must not call the Decider"

    def test_wildcard_action_goes_to_human_review(self):
        from agent.decision import PermissionReviewer
        rev = PermissionReviewer(FakeDecider())
        result = rev.review("Allow s3:* on every S3 resource.", "s3:* on *")
        assert result.outcome == "human_review"
        assert result.decider_ms == 0

    def test_vague_request_goes_to_clarify_without_decider(self):
        from agent.decision import PermissionReviewer
        rev = PermissionReviewer(FakeDecider())
        result = rev.review("Give me permission to access the data.", "unknown action on unknown resource")
        assert result.outcome == "clarify"
        assert result.decider_ms == 0, "Vague request must not call the Decider"


# ---------------------------------------------------------------------------
# Missing decision / missing confidence edge cases
# ---------------------------------------------------------------------------

class TestMissingDecisionHandling:
    """Verify that Decider errors result in explicit human_review, not silent success."""

    def test_decider_error_gives_human_review(self):
        """If the Decider raises DeciderError, the result must be human_review (fail-closed)."""
        from decider_kit import DeciderError
        from agent.decision import PermissionReviewer

        class ErrorDecider:
            last_latency_ms = 0
            def ask(self, *a, **kw):
                raise DeciderError("test error")

        rev = PermissionReviewer(ErrorDecider())
        result = rev.review(
            "My Lambda needs to upload to the reports-bucket.",
            "s3:PutObject on arn:aws:s3:::reports-bucket/*",
        )
        assert result.outcome == "human_review", (
            f"Decider error must produce human_review (fail-closed), got {result.outcome!r}"
        )
        assert result.confidence == 0.0
        assert result.decider_ms == 0

    def test_log_entry_always_has_outcome_and_confidence(self):
        """Every _log() call must produce an entry with both 'outcome' and 'confidence'."""
        from agent.decision import PermissionReviewer
        rev = PermissionReviewer(FakeDecider())
        # Use a request that passes deterministic checks and goes to the Decider
        rev.review(
            "My Lambda needs to upload to the reports-bucket.",
            "s3:PutObject on arn:aws:s3:::reports-bucket/*",
        )
        assert len(rev.log) == 1
        entry = rev.log[0]
        assert "outcome" in entry, f"Missing 'outcome' in log entry: {entry}"
        assert "confidence" in entry, f"Missing 'confidence' in log entry: {entry}"
        assert "verdict" in entry, f"Missing 'verdict' in log entry: {entry}"
        assert entry["outcome"] == entry["verdict"], "outcome and verdict must always match"
        assert isinstance(entry["confidence"], (int, float))
        assert 0.0 <= entry["confidence"] <= 1.0

    def test_full_chat_response_shape(self):
        """out from HackathonAgent.chat() must have all required keys with correct types."""
        from agent.agent import HackathonAgent
        a = HackathonAgent(decider=FakeDecider(), model_id="us.amazon.nova-lite-v1:0")
        out = a.chat("Show me an example safe request.")
        assert "reply" in out and isinstance(out["reply"], str)
        assert "decisions" in out and isinstance(out["decisions"], list)
        assert "model_id" in out and isinstance(out["model_id"], str)
        assert "latency_ms" in out and isinstance(out["latency_ms"], int)
        assert "agent" in out and out["agent"] == "CloudGuard AI - AWS Permission Review Agent"
