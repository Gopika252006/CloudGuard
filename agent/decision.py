"""REUSABLE DECISION PATTERN: AWS IAM permission scope review  (#policy)

What it does
    Before an AWS permission recommendation is shown to a developer, Strands Decider 2B
    reviews the natural-language request and the proposed IAM action to decide whether it is
    safe to allow, needs clarification, or must be escalated for human review.

    This is a #policy classification: the decider reads the request text and applies
    least-privilege principles. The large LLM handles the conversation and proposes an initial
    action; Strands Decider 2B makes the structured policy judgement - faster (under 2 s per
    review), cheaper, and with an explicit confidence score the code can branch on.

    The final outcome is determined by combining the Decider's output with deterministic
    Python validation. A high model confidence can never override a prohibited permission or
    a failed safety check (fail-closed design).

Typed questions and options (4 questions sent to Strands Decider 2B per review)
    scope_appropriate (noul): Is the resource scope appropriately narrow?
        true: the resource is scoped to a specific named bucket, table, function, or ARN
        false: the resource is a wildcard (*), "all", every bucket/table/function, or unnamed

    action_matches_task (noul): Does the proposed IAM action match only what the stated task requires?
        true: the action is the minimal set needed - e.g. s3:PutObject for uploading files
        false: the action is broader than needed - e.g. s3:* when only upload is required

    contains_prohibited (noul): Does the request ask for a dangerous or prohibited permission class?
        true: administrator access, IAM admin, wildcard actions (*), root, or "full access" to a service
        false: the request is for a specific, scoped, non-admin permission

    missing_info (noul): Is critical information missing that prevents a safe review?
        true: no resource name, no service, no specific action, or the intent cannot be determined
        false: enough information is present to evaluate the permission request

    Note: request clarity (action_clear) is handled deterministically before the Decider
    is called, keeping the request count to 4 to stay within the API tier limit.

Wiring
    `PermissionReviewer.review(request, proposed_action, task_context)` is called directly
    from `HackathonAgent.chat()` after the LLM proposes an IAM action via the
    `analyse_permission_request` tool. The result is stored in `self.decisions` and returned
    in every `chat()` response for the demo UI and benchmark.

    Outcome logic (deterministic layer runs first; Decider cannot override it):
        1. Deterministic safety check: wildcard/admin/prohibited patterns -> human_review
        2. Deterministic clarity check: vague/empty request -> clarify (no Decider call)
        3. missing_info.yes (Decider) -> clarify
        4. contains_prohibited.yes (Decider) -> human_review
        5. scope_appropriate.no AND action_matches_task.no -> human_review
        6. scope_appropriate.no OR action_matches_task.no (confident) -> clarify
        7. All checks pass and Decider confident -> allow
        8. Decider error, low confidence, or unhandled edge case -> human_review (fail-closed)

How to reuse it
    Copy this file. Replace PERMISSION_POLICY and QUESTIONS for your domain.
    Keep PermissionReviewer.review() -- only the questions and policy text change.
    The four-question structure works for any policy classification that needs to check
    scope, action alignment, prohibited patterns, and information completeness.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from decider_kit import Decider, DeciderError

PATTERN_TAG = "#policy"

# ---------------------------------------------------------------------------
# Deterministic safety constants -- Decider cannot override these
# ---------------------------------------------------------------------------

PROHIBITED_ACTIONS = {
    "iam:*", "sts:*", "organizations:*",
    "s3:*", "ec2:*", "lambda:*", "dynamodb:*", "rds:*",
    "cloudformation:*", "sagemaker:*", "bedrock:*",
    "*",
}
PROHIBITED_KEYWORDS = {
    "administratoraccess", "fulladministrator", "fullaccess", "root", "iam:passrole",
    "poweruseraccess",
}

# Phrases that indicate a vague request -- handled deterministically, no Decider call needed
_VAGUE_PHRASES = {
    "give me access", "all permissions", "all the permissions", "everything it needs",
    "full access", "any permissions", "access to everything", "all services",
    "all aws", "give it access", "give access", "all resources",
}

PERMISSION_POLICY = (
    "Least-privilege AWS IAM policy: every permission must be as narrow as possible. "
    "Wildcard actions (s3:*, iam:*, *) are prohibited unless explicitly justified. "
    "Wildcard resources (*) are prohibited unless a resource ARN cannot be known at design time. "
    "Administrator access, IAM admin, PowerUser, and root are prohibited for application roles. "
    "Each permission must match the stated task - no broader action than necessary is allowed. "
    "Missing resource names, service names, or task descriptions prevent a safe review."
)


def deterministic_check(proposed_action: str, request: str) -> tuple[str, str] | None:
    """Returns (outcome, reason) if immediately prohibited; None if safe to proceed to Decider.

    Matches whole action tokens only (not substrings), so 'arn:aws:s3:::bucket/*' does not
    trigger the '*' wildcard rule.
    """
    action_lower = proposed_action.lower().strip()
    request_lower = request.lower()
    tokens = set(re.split(r'[\s,]+', action_lower))

    # Wildcard / broad actions as whole tokens
    for pat in PROHIBITED_ACTIONS:
        if pat.lower() in tokens:
            return (
                "human_review",
                f"Prohibited: '{pat}' grants access far beyond any single task. "
                "Use specific action names (e.g. s3:PutObject) scoped to a named resource.",
            )

    # Prohibited keywords in action or request text
    for kw in PROHIBITED_KEYWORDS:
        if kw in request_lower or kw in action_lower:
            return (
                "human_review",
                f"Prohibited: '{kw}' access detected. "
                "Application roles must never receive admin, root, or full-service access.",
            )

    # Bare wildcard resource: ends with "on *" or "on * " (not "on arn:.../bucket/*")
    if re.search(r'\bon\s+\*\s*$', action_lower) or re.search(r'\bon\s+\*[,\s]', action_lower):
        return (
            "human_review",
            "Prohibited: wildcard resource (*) applies this permission to every resource in your account.",
        )

    return None


def is_vague_request(request: str, proposed_action: str) -> bool:
    """True when the request is clearly too vague to review without asking for more detail."""
    r = request.lower()
    a = proposed_action.lower()
    # Catch explicit vague phrases
    if any(phrase in r for phrase in _VAGUE_PHRASES):
        return True
    # Proposed action carries no real information
    if "unknown action" in a or "unknown resource" in a:
        return True
    # Very short request with no service or action keyword
    if len(request.split()) < 4 and not any(
        svc in r for svc in ("s3", "dynamodb", "lambda", "sns", "sqs", "iam", "kms",
                              "secretsmanager", "ssm", "cloudwatch", "bedrock", "ec2", "rds")
    ):
        return True
    return False


@dataclass
class ReviewResult:
    request: str
    proposed_action: str
    outcome: str            # allow | clarify | human_review
    reason: str             # plain-English explanation for the user
    recommendation: str     # the safer permission (or what information is needed)
    deterministic_flags: list[str]  # findings from rule-based checks
    confidence: float       # Decider's confidence on the most certain question (0 if deterministic)
    decider_ms: int
    answers: dict[str, Any] = field(repr=False, default_factory=dict)

    @property
    def verdict(self) -> str:
        return self.outcome


# 4 questions -- within the hosted API tier limit
QUESTIONS: dict[str, dict[str, Any]] = {
    "scope_appropriate": Decider.noul(
        "Is the proposed IAM resource a specific, named resource (not a wildcard or account-wide scope)?",
        {
            "true": (
                "the resource is an explicit named ARN or resource name: "
                "e.g. arn:aws:s3:::reports-bucket/*, arn:aws:dynamodb:us-east-1:123:table/orders, "
                "or a named function -- the permission applies to that one resource only"
            ),
            "false": (
                "the resource is '*' (all resources), 'arn:aws:*:*:*:*', an account-wide wildcard, "
                "or no specific resource name is given at all"
            ),
        },
    ),
    "action_matches_task": Decider.noul(
        "Does the proposed IAM action list contain only the specific permissions the stated task requires?",
        {
            "true": (
                "every action in the list is needed for the task -- for example s3:PutObject "
                "for 'upload files', or dynamodb:GetItem,dynamodb:Query for 'read from a table'; "
                "no extra or unrelated permissions are included"
            ),
            "false": (
                "the action list is broader than the task needs -- for example s3:* or dynamodb:* "
                "when only one or two specific operations are required, or actions unrelated to the task"
            ),
        },
    ),
    "contains_prohibited": Decider.noul(
        "Does the proposed action include a wildcard service action (like s3:*, dynamodb:*, iam:*, "
        "or the bare '*'), AdministratorAccess, PowerUserAccess, or any other full-service or "
        "account-admin grant?",
        {
            "true": (
                "yes -- the action is a service wildcard (s3:*, ec2:*, dynamodb:*, lambda:*, iam:*, "
                "bedrock:*, or '*'), or the name 'AdministratorAccess', 'PowerUserAccess', "
                "'FullAccess', or similar managed policy that grants broad control"
            ),
            "false": (
                "no -- the action is a list of specific named operations such as s3:PutObject, "
                "dynamodb:GetItem, lambda:InvokeFunction; no wildcards or admin policies present"
            ),
        },
    ),
    "missing_info": Decider.noul(
        "After reading the request and the proposed action, is there still missing information "
        "that makes it impossible to confirm the permission is safe?",
        {
            "true": (
                "the request gives no specific AWS service, no specific operation, and no resource name "
                "-- for example 'give me access to the data' or 'all the permissions it needs'"
            ),
            "false": (
                "the request and action together identify the service (e.g. S3, DynamoDB), "
                "the operation (e.g. PutObject, GetItem), and at least a resource name or ARN -- "
                "enough to evaluate whether the permission is appropriate"
            ),
        },
    ),
}


class PermissionReviewer:
    """Reviews AWS IAM permission requests using Strands Decider 2B + deterministic safety checks."""

    def __init__(self, decider: Decider, confidence_threshold: float = 0.65):
        self.decider = decider
        self.confidence_threshold = confidence_threshold
        self.log: list[dict[str, Any]] = []

    def review(
        self,
        request: str,
        proposed_action: str,
        task_context: str = "",
    ) -> ReviewResult:
        """Review a permission request. Returns a ReviewResult with outcome, reason, recommendation."""
        flags: list[str] = []

        # --- Layer 1: deterministic prohibited-action check ---
        det = deterministic_check(proposed_action, request)
        if det:
            outcome, reason = det
            flags.append(f"BLOCKED by safety rule: {reason}")
            result = ReviewResult(
                request=request,
                proposed_action=proposed_action,
                outcome=outcome,
                reason=reason,
                recommendation=(
                    "Specify the exact action (e.g. s3:PutObject) and the exact resource ARN."
                ),
                deterministic_flags=flags,
                confidence=1.0,
                decider_ms=0,
                answers={},
            )
            self._log(result)
            return result

        # --- Layer 2: deterministic vagueness check (skip Decider for obvious cases) ---
        if is_vague_request(request, proposed_action):
            flags.append("Request is too vague to review safely (deterministic check)")
            result = ReviewResult(
                request=request,
                proposed_action=proposed_action,
                outcome="clarify",
                reason="The request is too vague to review safely.",
                recommendation=(
                    "Please specify: (1) which AWS service, (2) what exact action is needed "
                    "(e.g. s3:PutObject), and (3) the specific resource name or ARN."
                ),
                deterministic_flags=flags,
                confidence=1.0,
                decider_ms=0,
                answers={},
            )
            self._log(result)
            return result

        # --- Layer 3: Strands Decider 2B (4 questions) ---
        state = (
            f"AWS permission request from a developer:\n{request}\n\n"
            f"Proposed IAM action: {proposed_action}\n"
            + (f"Task context: {task_context}\n\n" if task_context else "\n")
            + f"Permission policy:\n{PERMISSION_POLICY}"
        )
        try:
            answers = self.decider.ask(state, QUESTIONS)
        except DeciderError as exc:
            # Fail-closed: any Decider error -> human_review
            result = ReviewResult(
                request=request,
                proposed_action=proposed_action,
                outcome="human_review",
                reason=f"Decider unavailable - fail-closed: {exc}",
                recommendation="Retry once the decision service is available.",
                deterministic_flags=["Decider error - defaulted to human_review"],
                confidence=0.0,
                decider_ms=0,
                answers={},
            )
            self._log(result)
            return result

        decider_ms = round(self.decider.last_latency_ms or 0)
        conf = max(a.confidence for a in answers.values())

        # Collect Decider flags
        if answers["contains_prohibited"].yes:
            flags.append("Decider flagged a prohibited permission class")
        if not answers["scope_appropriate"].yes:
            flags.append("Decider: resource scope is too broad")
        if not answers["action_matches_task"].yes:
            flags.append("Decider: action is broader than the task requires")
        if answers["missing_info"].yes:
            flags.append("Decider: critical information is missing")

        # --- Layer 4: outcome logic ---
        outcome, reason, recommendation = self._decide(answers, conf, proposed_action, request)

        result = ReviewResult(
            request=request,
            proposed_action=proposed_action,
            outcome=outcome,
            reason=reason,
            recommendation=recommendation,
            deterministic_flags=flags,
            confidence=round(conf, 3),
            decider_ms=decider_ms,
            answers={
                k: {
                    "p_yes": round(v.p_yes, 3) if v.p_yes is not None else None,
                    "label": v.label,
                    "confidence": round(v.confidence, 3),
                }
                for k, v in answers.items()
            },
        )
        self._log(result)
        return result

    def _decide(
        self,
        a: dict[str, Any],
        conf: float,
        proposed_action: str,
        request: str,
    ) -> tuple[str, str, str]:
        t = self.confidence_threshold

        if a["missing_info"].yes:
            return (
                "clarify",
                "The request lacks enough detail to safely evaluate the permission.",
                "Please specify: (1) which AWS service, (2) what exact action is needed, "
                "and (3) the specific resource name or ARN.",
            )

        if a["contains_prohibited"].yes and a["contains_prohibited"].confidence >= t:
            return (
                "human_review",
                "The request asks for a permission class that requires human review "
                "(admin, wildcard, or full-service access).",
                "Replace with the minimum specific action: for example, "
                "s3:PutObject on arn:aws:s3:::bucket-name/* instead of s3:*.",
            )

        if not a["scope_appropriate"].yes and not a["action_matches_task"].yes:
            return (
                "human_review",
                "Both the resource scope and the action are broader than necessary. "
                "This combination creates significant over-permissioning risk.",
                "Scope the resource to a specific ARN and narrow the action to only "
                "what the task requires.",
            )

        if not a["scope_appropriate"].yes:
            if conf < t:
                return (
                    "human_review",
                    "The resource scope appears too broad and the Decider is uncertain. "
                    "Escalating for human review.",
                    "Name the specific resource (bucket, table, or ARN) instead of a wildcard.",
                )
            return (
                "clarify",
                "The resource scope is broader than necessary for the stated task.",
                "Specify the exact resource ARN (e.g. arn:aws:s3:::reports-bucket/*) "
                "rather than applying this to all resources.",
            )

        if not a["action_matches_task"].yes:
            if conf < t:
                return (
                    "human_review",
                    "The proposed action may be broader than the task requires, "
                    "and the Decider is not confident enough to approve it.",
                    "Review the specific action needed and remove permissions not required.",
                )
            return (
                "clarify",
                "The proposed IAM action grants more access than the stated task requires.",
                "Use only the specific action needed "
                "(e.g. s3:PutObject instead of s3:PutObject + s3:GetObject + s3:DeleteObject).",
            )

        if conf < t:
            return (
                "human_review",
                f"Decider confidence ({conf:.0%}) is below the threshold ({t:.0%}). "
                "Escalating for human review.",
                "Provide more detail about the task and resource to allow a confident review.",
            )

        return (
            "allow",
            "The request is specific, appropriately scoped, and matches the stated task.",
            f"Recommended: {proposed_action} - least-privilege permission for the described task.",
        )

    def _log(self, r: ReviewResult) -> None:
        entry: dict[str, Any] = {
            "pattern": PATTERN_TAG,
            "outcome": r.outcome,
            "verdict": r.verdict,
            "confidence": r.confidence,
            "decider_ms": r.decider_ms,
            "proposed_action": r.proposed_action,
        }
        for k, v in r.answers.items():
            if v.get("p_yes") is not None:
                entry[k] = v["p_yes"]
        self.log.append(entry)
