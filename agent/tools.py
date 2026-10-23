"""CloudGuard AI tools - simulated AWS permission analysis, no real IAM API calls.

Four tools:
  analyse_permission_request  - interpret a natural-language request into an IAM action + resource
  validate_policy_json        - check a simulated IAM policy document for obvious issues
  get_example_request         - return a canned example scenario by name
  list_review_history         - list recent permission reviews from the in-process history store

All IAM actions and resources are SIMULATED. This agent never calls AWS IAM write APIs,
creates real policies, or attaches permissions. Every result is a recommendation only.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from strands import tool

# ---------------------------------------------------------------------------
# In-process review history (cleared on agent reset)
# ---------------------------------------------------------------------------

REVIEW_HISTORY: list[dict[str, Any]] = []

# Mapping of common task descriptions to least-privilege IAM actions
_TASK_TO_ACTION: dict[str, tuple[str, str]] = {
    "upload":    ("s3:PutObject",                 "arn:aws:s3:::BUCKET_NAME/*"),
    "read":      ("s3:GetObject",                 "arn:aws:s3:::BUCKET_NAME/*"),
    "download":  ("s3:GetObject",                 "arn:aws:s3:::BUCKET_NAME/*"),
    "list":      ("s3:ListBucket",                "arn:aws:s3:::BUCKET_NAME"),
    "put":       ("s3:PutObject",                 "arn:aws:s3:::BUCKET_NAME/*"),
    "delete":    ("s3:DeleteObject",              "arn:aws:s3:::BUCKET_NAME/*"),
    "invoke":    ("lambda:InvokeFunction",        "arn:aws:lambda:REGION:ACCOUNT:function:FUNCTION_NAME"),
    "write":     ("dynamodb:PutItem",             "arn:aws:dynamodb:REGION:ACCOUNT:table/TABLE_NAME"),
    "query":     ("dynamodb:Query",               "arn:aws:dynamodb:REGION:ACCOUNT:table/TABLE_NAME"),
    "scan":      ("dynamodb:Scan",                "arn:aws:dynamodb:REGION:ACCOUNT:table/TABLE_NAME"),
    "publish":   ("sns:Publish",                  "arn:aws:sns:REGION:ACCOUNT:TOPIC_NAME"),
    "send":      ("sqs:SendMessage",              "arn:aws:sqs:REGION:ACCOUNT:QUEUE_NAME"),
    "receive":   ("sqs:ReceiveMessage",           "arn:aws:sqs:REGION:ACCOUNT:QUEUE_NAME"),
    "log":       ("logs:CreateLogGroup,logs:CreateLogStream,logs:PutLogEvents",
                  "arn:aws:logs:REGION:ACCOUNT:log-group:/aws/lambda/FUNCTION_NAME:*"),
    "secrets":   ("secretsmanager:GetSecretValue","arn:aws:secretsmanager:REGION:ACCOUNT:secret:SECRET_NAME"),
    "parameter": ("ssm:GetParameter",             "arn:aws:ssm:REGION:ACCOUNT:parameter/PARAM_PATH"),
    "kms":       ("kms:Decrypt,kms:GenerateDataKey","arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"),
    "bedrock":   ("bedrock:InvokeModel",          "arn:aws:bedrock:REGION::foundation-model/MODEL_ID"),
}

_EXAMPLE_REQUESTS: dict[str, dict[str, str]] = {
    "safe": {
        "request": "My Lambda function needs to upload reports to the reports-bucket S3 bucket only.",
        "proposed_action": "s3:PutObject on arn:aws:s3:::reports-bucket/*",
        "task_context": "Lambda function writing monthly PDF reports to a dedicated bucket",
    },
    "ambiguous": {
        "request": "Give my application all the permissions it needs.",
        "proposed_action": "s3:*,ec2:*,lambda:*,dynamodb:* on *",
        "task_context": "Application - exact requirements unknown",
    },
    "admin": {
        "request": "Give this Lambda administrator access to every AWS service.",
        "proposed_action": "AdministratorAccess on *",
        "task_context": "Lambda function - administrative tasks",
    },
    "wildcard": {
        "request": "Allow s3:* on every S3 resource.",
        "proposed_action": "s3:* on *",
        "task_context": "S3 access - no specific task described",
    },
    "missing": {
        "request": "Give me permission to access the data.",
        "proposed_action": "unknown action on unknown resource",
        "task_context": "Data access - no service or resource specified",
    },
}


@tool
def analyse_permission_request(
    request: str,
    task_context: str = "",
) -> dict[str, Any]:
    """Interpret a natural-language AWS permission request and propose the least-privilege IAM action.
    Returns the interpreted task, the proposed action, the resource, and a SIMULATED policy JSON.
    This never calls AWS APIs or creates real policies - all output is for review only."""
    request_lower = request.lower()

    # Find the best matching action keyword
    proposed_action = "unknown"
    proposed_resource = "*"
    matched_task = "unknown task"
    for keyword, (action, resource) in _TASK_TO_ACTION.items():
        if keyword in request_lower:
            proposed_action = action
            proposed_resource = resource
            matched_task = keyword
            break

    # Try to extract a resource name from the request
    resource_name = _extract_resource_name(request)
    if resource_name and proposed_resource != "*":
        proposed_resource = (proposed_resource
            .replace("BUCKET_NAME", resource_name)
            .replace("TABLE_NAME", resource_name)
            .replace("FUNCTION_NAME", resource_name)
            .replace("TOPIC_NAME", resource_name)
            .replace("QUEUE_NAME", resource_name)
            .replace("SECRET_NAME", resource_name)
            .replace("PARAM_PATH", resource_name)
            .replace("KEY_ID", resource_name)
            .replace("MODEL_ID", resource_name)
            .replace("REGION", "us-east-1")
            .replace("ACCOUNT", "123456789012"))

    # Build simulated policy document
    simulated_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CloudGuardAISimulatedReview",
                "Effect": "Allow",
                "Action": [a.strip() for a in proposed_action.split(",")],
                "Resource": proposed_resource,
                "_note": "SIMULATED - recommendation only. Review with your security team before applying.",
            }
        ],
    }

    action_display = f"{proposed_action} on {proposed_resource}"
    return {
        "request": request,
        "task_context": task_context or matched_task,
        "proposed_action": action_display,
        "simulated_policy": json.dumps(simulated_policy, indent=2),
        "warning": (
            "SIMULATION ONLY - CloudGuard AI never creates, attaches, or modifies "
            "real AWS IAM permissions. This recommendation must be reviewed by your "
            "security team before applying."
        ),
    }


@tool
def validate_policy_json(policy_json: str) -> dict[str, Any]:
    """Check a simulated IAM policy JSON string for obvious security issues.
    Returns a list of findings. Does not call AWS APIs - deterministic rule-based check only."""
    findings: list[str] = []
    risk_level = "low"

    try:
        policy = json.loads(policy_json)
    except json.JSONDecodeError as e:
        return {
            "valid_json": False,
            "error": str(e),
            "findings": ["Malformed JSON - cannot validate"],
            "risk_level": "unknown",
        }

    statements = policy.get("Statement", [])
    if not statements:
        findings.append("No Statement block found in policy")
        return {"valid_json": True, "findings": findings, "risk_level": "unknown"}

    for stmt in statements:
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        effect = stmt.get("Effect", "")

        if effect == "Allow":
            for action in actions:
                if action == "*" or action.endswith(":*"):
                    findings.append(
                        f"[WARNING] Wildcard action '{action}' grants all actions for this service"
                    )
                    risk_level = "critical"
                if any(kw in action.lower() for kw in ("iam:", "sts:assumerole", "organizations:")):
                    findings.append(
                        f"[CRITICAL] High-risk action '{action}' can escalate privileges or affect org structure"
                    )
                    risk_level = "critical"

            for resource in resources:
                if resource == "*":
                    findings.append(
                        "[WARNING] Wildcard resource '*' applies to every resource in your account"
                    )
                    if risk_level != "critical":
                        risk_level = "high"

            if "*" in actions:
                findings.append(
                    "[CRITICAL] Action '*' with Allow Effect grants ALL permissions - this is AdministratorAccess"
                )
                risk_level = "critical"

    if not findings:
        findings.append(
            "[OK] No obvious high-risk patterns detected. Review with your security team before applying."
        )
        risk_level = "low"

    return {
        "valid_json": True,
        "findings": findings,
        "risk_level": risk_level,
        "warning": (
            "Rule-based check only - does not guarantee policy safety. "
            "Verify with AWS IAM Access Analyzer."
        ),
    }


@tool
def get_example_request(scenario: str = "safe") -> dict[str, str]:
    """Return an example permission scenario by name for demonstration.
    Valid scenarios: safe, ambiguous, admin, wildcard, missing."""
    scenario = scenario.lower().strip()
    ex = _EXAMPLE_REQUESTS.get(scenario)
    if not ex:
        available = ", ".join(_EXAMPLE_REQUESTS)
        return {"error": f"Unknown scenario '{scenario}'. Available: {available}"}
    return {
        **ex,
        "scenario": scenario,
        "note": "This is a demonstration scenario. No real AWS permissions are involved.",
    }


@tool
def list_review_history(limit: int = 10) -> dict[str, Any]:
    """List the most recent permission reviews from this session (local demo history only).
    Returns up to `limit` recent reviews with their outcomes."""
    recent = REVIEW_HISTORY[-limit:][::-1]  # newest first
    return {
        "count": len(REVIEW_HISTORY),
        "showing": len(recent),
        "reviews": recent,
        "note": "Local demo session history only - not production data.",
    }


def add_to_history(
    request: str, outcome: str, proposed_action: str, recommendation: str
) -> None:
    """Called by HackathonAgent after each review to record the result."""
    REVIEW_HISTORY.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request": request[:120] + ("..." if len(request) > 120 else ""),
        "outcome": outcome,
        "proposed_action": proposed_action,
        "recommendation": recommendation[:120] + ("..." if len(recommendation) > 120 else ""),
    })


def _extract_resource_name(request: str) -> str | None:
    """Extract the resource name from a natural-language permission request.

    Tries five strategies in order:
    1. A quoted name: "reports-bucket" or 'my-table'
    2. "the X-name <optional-svc> type" -- e.g. "the reports-bucket S3 bucket"
    3. "to/from (the) X-name <optional-svc> type" -- with or without "the"
    4. Hyphenated word immediately before (optional svc +) resource-type word
    5. Any non-service word immediately before (optional svc +) resource-type word

    A "bare service word" is a single token that is itself a known AWS service
    name (s3, lambda, dynamodb, ...) rather than a user-chosen resource name.

    The optional service abbreviation pattern (e.g. "S3", "DynamoDB") between the
    resource name and the type word handles inputs like:
        "reports-bucket S3 bucket" -- resource name is "reports-bucket", not "S3"
        "orders DynamoDB table" -- resource name is "orders", not "dynamodb"
    """
    import re

    # AWS service keywords that are NOT resource names
    _SERVICE_WORDS = {
        "s3", "lambda", "dynamodb", "rds", "sns", "sqs", "iam",
        "kms", "ssm", "ec2", "ecs", "eks", "cloudwatch", "cloudformation",
        "bedrock", "secretsmanager", "sagemaker", "glue", "athena",
    }
    # Resource-type words that follow resource names in natural language
    _RESOURCE_TYPES = r"(?:bucket|table|function|topic|queue|database|db|stream|cluster|role|key|secret|parameter)"
    # Optional service abbreviation that may appear between resource name and type
    # e.g. "reports-bucket S3 bucket", "orders DynamoDB table"
    _OPT_SVC = r"(?:[A-Za-z0-9]+\s+)?"

    def _is_service_word(word: str) -> bool:
        return word.lower() in _SERVICE_WORDS

    # 1. Quoted name takes highest priority
    m = re.search(r'["\']([^"\']{3,60})["\']', request)
    if m:
        return m.group(1).replace(" ", "-").lower()

    # 2. "the X-name [svc] type" -- captures the word after "the", skips bare service words
    #    Handles: "the reports-bucket S3 bucket", "the data-lake S3 bucket",
    #             "the orders DynamoDB table", "the catalog-table DynamoDB table"
    m = re.search(
        r'\bthe\s+([\w][\w-]{1,59})\s+' + _OPT_SVC + _RESOURCE_TYPES + r'\b',
        request, re.I,
    )
    if m and not _is_service_word(m.group(1)):
        return m.group(1).lower()

    # 3. "to/from (the) X-name [svc] type" -- with or without "the"
    #    Handles: "to the reports-bucket S3 bucket", "to the finance-reports S3 bucket"
    for prep in (r'\bto\s+(?:the\s+)?', r'\bfrom\s+(?:the\s+)?'):
        m = re.search(
            prep + r'([\w][\w-]{1,59})\s+' + _OPT_SVC + _RESOURCE_TYPES + r'\b',
            request, re.I,
        )
        if m and not _is_service_word(m.group(1)):
            return m.group(1).lower()

    # 4. Hyphenated word (at least one dash) before [svc] type -- e.g. "finance-reports S3 bucket"
    m = re.search(
        r'\b([\w]+-[\w][\w-]*)\s+' + _OPT_SVC + _RESOURCE_TYPES + r'\b',
        request, re.I,
    )
    if m:
        return m.group(1).lower()

    # 5. Any non-service word immediately before [svc] type
    m = re.search(
        r'\b([\w]{3,60})\s+' + _OPT_SVC + _RESOURCE_TYPES + r'\b',
        request, re.I,
    )
    if m and not _is_service_word(m.group(1)):
        return m.group(1).lower()

    return None


TOOLS = [analyse_permission_request, validate_policy_json, get_example_request, list_review_history]
