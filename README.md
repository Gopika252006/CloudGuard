# CloudGuard AI - AWS Permission Review Agent

**CloudGuard AI helps developers review AWS IAM permission requests before applying them — catching wildcard access, over-permissioned roles, and missing details using a fast, cheap specialized decision model instead of a large LLM.**

An agent on AWS that hands one decision to **Strands Decider 2B** and the conversation to **Amazon Bedrock**. Decision pattern: `#policy`. Tags: `#strands-decider-2b` `#policy`.

- Video: (add the YouTube/Vimeo link)
- Article: (add the AWS Builder Center link)
- Deployed: run `./kit deploy`

## The project

- **Pitch:** CloudGuard AI helps developers review AWS IAM permission requests before applying them — catching wildcard access, over-permissioned roles, and missing details using a fast, cheap specialized decision model instead of a large LLM.
- **Who it is for:** developers and DevOps engineers who want a second opinion on AWS permissions before applying them, without waiting for a full security review.
- **Features:**
  - review natural-language permission requests against least-privilege principles;
  - detect wildcard actions, admin access, and over-scoped resources with deterministic rules;
  - use Strands Decider 2B to classify requests as allow, clarify, or human_review with a confidence score;
  - explain why each decision was made, with a specific safer recommendation;
  - validate simulated IAM policy JSON for obvious security issues;
  - all actions are simulated — CloudGuard AI never creates or modifies real AWS permissions;
  - deployed on Amazon Bedrock AgentCore Runtime.
- **The decision handed to Strands Decider 2B:** given a developer's permission request and the proposed IAM action, is it safe to allow, does it need clarification, or must it go to a human reviewer? (`#policy`)
- **Why a decision model:** every request must be classified against least-privilege principles. Strands Decider 2B makes this classification in under 2 seconds with an explicit confidence score, without the latency or cost of a full LLM call for each structured judgement. Deterministic safety rules run first; the Decider handles the nuanced language understanding.
- **Amazon Bedrock:** the conversation and tool use (Amazon Nova Pro by default).



## How it is built

Strands Agents with Amazon Bedrock for the generative part, the tools in `agent/tools.py`, deployed to Amazon Bedrock AgentCore Runtime, and one decision handed to Strands Decider 2B at a clear seam in the agent's path.

Every Amazon Bedrock model id is set in `.env` (`BEDROCK_MODEL_ID`, and `BEDROCK_SMALL/MEDIUM/LARGE_MODEL_ID` for routing), Amazon Nova by default.



## Reusable decision pattern: AWS IAM permission scope review  (#policy)

The pattern lives in [`agent/decision.py`](agent/decision.py), labelled `REUSABLE DECISION PATTERN`. It contains the typed questions and their options, the wiring that puts the decision in the agent's path, and a note on how to reuse it:

```text
REUSABLE DECISION PATTERN: AWS IAM permission scope review  (#policy)

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
```

Typed questions:

```python
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
```

## Measured

Decider: strands-decider-2b-hobson-v19 (ugmdu). 14 labelled cases, 53 decisions.

| | Strands Decider 2B | qwen3.5-4b |
|---|---|---|
| Accuracy | 75.5% | 98.1% |
| Latency p50 per decision | 5539 ms | 22759 ms |
| Latency p95 | 6054 ms | 23145 ms |
| Cost per 1,000 decisions | $0.0350 | $0.0000 |
| Answered alone at confidence >= 0.7 | 57% | 100% |
| Accuracy when confident | 86.7% | 98.1% |

At the median the decider was 4.1x faster than the LLM.

Reproduce with `./kit bench` (cases in `agent/eval_cases.jsonl`; charts in `submission/bench/`).

## Run it

```bash
./kit setup        # checks your machine and AWS, sets up Strands Decider 2B (local model or hosted API)
./kit demo         # web UI at http://localhost:8501
./kit bench        # the decision vs an Amazon Bedrock LLM
./kit deploy       # Amazon Bedrock AgentCore Runtime
```

Requirements: Python 3.10+, AWS credentials with Amazon Bedrock access, and for deploying, Node 20+ with the AgentCore CLI (`./kit agentcore-cli`).

## Credits

Built with the AWS User Group Madurai Strands Decider hackathon kit (https://github.com/awsugmdu). The kit's reusable library (`decider_kit/`, the demo UI, the video and article tooling, and the Kiro steering, skills and hooks) is the user group's; the agent in `agent/` is mine. Strands Decider: https://github.com/strands-labs/strands-decider (Apache-2.0).

Licence: Apache-2.0 (see LICENSE).
