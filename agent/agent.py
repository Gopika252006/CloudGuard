"""CloudGuard AI - Intelligent AWS Permission Review Agent.

The LLM (Amazon Bedrock or the user-group cloud) handles the conversation and interprets the
developer's request. Strands Decider 2B makes the structured policy decision - is this
permission safe to allow, does it need clarification, or must it go to a human reviewer?

    from agent.agent import HackathonAgent
    out = HackathonAgent().chat(
        "My Lambda needs to upload reports to the reports-bucket S3 bucket."
    )
    out["reply"], out["decisions"]

The standard HackathonAgent interface is preserved so the demo UI, benchmark, video and
AgentCore deployment all work without changes.
"""

from __future__ import annotations

import time
from typing import Any

from strands import Agent
from strands.hooks import AfterToolCallEvent, HookProvider, HookRegistry

from decider_kit import Decider
from decider_kit.llm import agent_model, default_model_id, strip_thinking

from .decision import PermissionReviewer
from .tools import TOOLS, add_to_history, _TASK_TO_ACTION, _extract_resource_name

NAME = "CloudGuard AI - AWS Permission Review Agent"

SYSTEM_PROMPT = """You are CloudGuard AI, an expert assistant that helps developers review AWS IAM permission requests.

IMPORTANT RULES:
- You NEVER create, attach, or modify real AWS IAM permissions. Everything is a recommendation only.
- Always remind users that recommendations must be reviewed by their security team.
- Use least-privilege principles in every recommendation.

What you can do:
- analyse_permission_request(request, task_context)
    Interpret a natural-language request into a proposed IAM action and simulated policy.
    Call this FIRST whenever a user asks about permissions.

- validate_policy_json(policy_json)
    Check a simulated IAM policy for obvious security issues.

- get_example_request(scenario)
    Show a demonstration scenario. Scenarios: safe, ambiguous, admin, wildcard, missing.

- list_review_history(limit)
    Show recent reviews from this session.

Workflow for permission reviews:
1. Call analyse_permission_request to interpret the request.
2. The system will automatically run a Strands Decider 2B review on the result.
3. Report the outcome (allow / clarify / human_review), the confidence, the reason,
   and the recommendation clearly.
4. If the outcome is clarify, ask the user for the missing information.
5. If the outcome is human_review, explain the risk and recommend their security team review it.

Always be concise, use plain language, and highlight security risks clearly.
Never fabricate AWS account IDs, ARNs, or real resource names in recommendations.
"""

def _build_proposed_action(request: str, task_context: str = "") -> tuple[str, str]:
    """Return (proposed_action_string, proposed_resource) for a plain-text request.

    Shared by _DeciderHookProvider so the Decider always receives the same
    action/resource that the analyse_permission_request tool computed.
    """
    request_lower = request.lower()
    proposed_action_base = "unknown action"
    proposed_resource = "*"

    for keyword, (action, resource) in _TASK_TO_ACTION.items():
        if keyword in request_lower:
            resource_name = _extract_resource_name(request)
            if resource_name and resource != "*":
                resource = (resource
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
            proposed_action_base = action
            proposed_resource = resource
            break

    # Detect obviously dangerous patterns in the raw request
    request_combined = request.lower() + " " + task_context.lower()
    if any(kw in request_combined for kw in [
        "s3:*", "ec2:*", "lambda:*", "dynamodb:*", "iam:*", "*:*",
        "administratoraccess", "full access", "full s3", "all services",
        "all permissions", "everything",
    ]):
        proposed_action_base = request.strip()
        proposed_resource = "*"

    return f"{proposed_action_base} on {proposed_resource}", proposed_resource


class _DeciderHookProvider(HookProvider):
    """Strands HookProvider that intercepts analyse_permission_request results and runs
    Strands Decider 2B via PermissionReviewer. Replaces the previous monkey-patch."""

    def __init__(self, reviewer: PermissionReviewer, original_request: str):
        self._reviewer = reviewer
        self._original_request = original_request

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(AfterToolCallEvent, self._after_tool_call)

    def _after_tool_call(self, event: AfterToolCallEvent) -> None:
        """Called by Strands after any tool finishes. Only processes analyse_permission_request."""
        # Resolve tool name from event attributes
        tool_name = ""
        for attr in ("tool_name", "name"):
            val = getattr(event, attr, None)
            if val:
                tool_name = str(val)
                break
        if not tool_name:
            tool_use = getattr(event, "tool_use", None) or {}
            tool_name = str(tool_use.get("name") or "")

        if tool_name != "analyse_permission_request":
            return

        # Get the inputs that were passed to the tool
        tool_use = getattr(event, "tool_use", None) or {}
        inputs = tool_use.get("input") or {}
        request = str(inputs.get("request") or self._original_request)
        task_context = str(inputs.get("task_context") or "")

        proposed_action, _ = _build_proposed_action(request, task_context)

        review = self._reviewer.review(
            request=request,
            proposed_action=proposed_action,
            task_context=task_context,
        )
        add_to_history(request, review.outcome, review.proposed_action, review.recommendation)


class HackathonAgent:
    """CloudGuard AI: LLM conversation + Strands Decider 2B policy review."""

    def __init__(
        self,
        decider: Decider | None = None,
        model_id: str | None = None,
        eager: bool | None = None,  # unused, kept for interface compatibility
    ):
        self.decider = decider or Decider()
        self.reviewer = PermissionReviewer(self.decider)
        self.model_id = model_id or default_model_id()

    def _make_agent(self, original_request: str) -> Agent:
        """Create a fresh Strands Agent with a new HookProvider bound to this turn's request."""
        hook = _DeciderHookProvider(self.reviewer, original_request)
        return Agent(
            model=agent_model(self.model_id),
            system_prompt=SYSTEM_PROMPT,
            tools=TOOLS,
            callback_handler=None,
            hooks=[hook],
        )

    def chat(
        self,
        message: str,
        session_id: str = "default",
        images: list[Any] | None = None,
    ) -> dict[str, Any]:
        """Process a permission review request end-to-end.

        The Strands Agent calls analyse_permission_request; the _DeciderHookProvider
        intercepts the AfterToolCallEvent and runs Strands Decider 2B inline via
        PermissionReviewer. The reviewer.log entry is then included in decisions[].
        """
        before = len(self.reviewer.log)
        t0 = time.perf_counter()

        a = self._make_agent(message)
        result = a(message)
        reply = strip_thinking(str(result))
        new_decisions = self.reviewer.log[before:]

        return {
            "reply": reply,
            "decisions": new_decisions,
            "model_id": self.model_id,
            "latency_ms": round((time.perf_counter() - t0) * 1000),
            "agent": NAME,
            "eager": False,
        }


if __name__ == "__main__":
    import json
    import sys

    a = HackathonAgent()
    msgs = sys.argv[1:] or [
        "My Lambda function needs to upload reports to the reports-bucket S3 bucket only.",
        "Give this Lambda administrator access to every AWS service.",
        "Give me permission to access the data.",
    ]
    for msg in msgs:
        print(f"\n>>> {msg}")
        out = a.chat(msg)
        print(out["reply"])
        if out["decisions"]:
            print("Decisions:", json.dumps(out["decisions"], indent=2))
