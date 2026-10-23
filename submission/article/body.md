# CloudGuard AI: Catching Over-Permissioned AWS IAM Requests Before They Reach Production

By Gopika

Developers request overly broad AWS permissions every day, not out of carelessness but because it is the path of least resistance when you just need something to work. "Give it full S3 access" is faster than figuring out whether `s3:PutObject` is the right action. That shortcut quietly becomes a security vulnerability that sits in production for years.

CloudGuard AI fixes that gap. Describe your permission request in plain English, and the agent tells you whether it is safe to apply, what is wrong with it, or what information is missing to review it safely. It uses Strands Decider 2B to make that classification in under two seconds, with an explicit confidence score, instead of waiting for a full LLM call or a security team review. On 53 labelled decisions, Strands Decider 2B ran 4.1 times faster than the LLM asked the same questions.

## The project

CloudGuard AI is for developers and DevOps engineers who want a quick second opinion on an IAM permission before applying it. The agent:

- interprets any natural-language permission request and proposes the least-privilege IAM action and resource ARN
- runs deterministic safety checks first: wildcard actions like `s3:*`, admin access, and bare wildcard resources are blocked before the decision model is even called
- sends specific, scoped requests to Strands Decider 2B, which returns one of three outcomes: allow, clarify, or human_review, each with a confidence score
- explains exactly why each decision was made and gives a specific safer alternative
- never creates, modifies, or applies real AWS permissions; all output is a recommendation only
- runs on Amazon Bedrock AgentCore Runtime

Here is what a real session looks like. A developer asks:

> My Lambda function needs to upload reports to the reports-bucket S3 bucket only.

The agent proposes `s3:PutObject on arn:aws:s3:::reports-bucket/*`. Strands Decider 2B reviews the proposed action against four typed questions, scores the request at 93% confidence, and returns allow. The full review takes under eight seconds end to end.

A different request:

> Give this Lambda administrator access to every AWS service.

The deterministic safety rule catches `AdministratorAccess` before the Decider is called. The outcome is human_review instantly, at zero additional cost.

< FIGURE 1 of 6: upload submission/article/img/demo.png here >
Alt text: CloudGuard AI permission review UI showing an allow decision with confidence score and proposed IAM action

## How I built it

The agent is built with the Strands Agents SDK. Amazon Bedrock (Nova Pro) handles the conversation and calls the `analyse_permission_request` tool, which extracts the intended IAM action and resource ARN from the developer's plain-English request. Once the tool runs, a Strands `HookProvider` intercepts the `AfterToolCallEvent` and calls `PermissionReviewer.review()`, which runs the deterministic checks and then sends the request to Strands Decider 2B.

The decision result, proposed action, confidence score, and explanation are returned to the UI in every response. The UI is a single-page FastAPI and vanilla JavaScript app with a two-column layout: the review form and result on the left, the live Strands Decider 2B probability bars on the right.

The whole agent is deployed to Amazon Bedrock AgentCore Runtime with `./kit deploy`. AgentCore handles session management and scaling; the agent itself is stateless because each permission review is independent.

I built and iterated on this using Kiro, which let me describe the use case, generate the initial structure, and refine the decision questions and outcome logic through spec-driven development.

< FIGURE 2 of 6: upload submission/article/img/architecture.png here >
Alt text: Architecture diagram: developer request flows through Amazon Bedrock Nova Pro to the analyse_permission_request tool, then to deterministic checks, then to Strands Decider 2B, returning allow, clarify, or human_review

## The decision I handed to Strands Decider 2B

Every IAM permission request needs to be checked against least-privilege principles. That check requires reading language: understanding what "upload reports to the reports-bucket" means versus "full S3 access", and whether `s3:PutObject` on a named bucket is the right action for that task. A rule-based system cannot do this reliably for arbitrary natural language. A large LLM can, but using a full generative call for every structured classification adds latency and cost to something that needs to be fast enough to fit in a developer's workflow.

Strands Decider 2B makes the classification in one forward pass with calibrated probabilities. The agent sends the developer's request, the proposed IAM action, and a policy statement to the Decider as a single state, with four typed yes/no questions:

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

The outcome logic combines all four answers with a confidence threshold of 65%:

- `missing_info` is yes: clarify (ask for the service, action, and resource name)
- `contains_prohibited` is yes with high confidence: human_review
- both `scope_appropriate` and `action_matches_task` are no: human_review
- either one is no: clarify (or human_review if the Decider is uncertain)
- all pass and confidence is above 65%: allow
- any error or low confidence: human_review (fail-closed)

Deterministic safety rules run before the Decider is called at all. Wildcard actions, admin access, and bare wildcard resources are blocked instantly without a model call. A high Decider confidence can never override a deterministic block.

When the Decider is uncertain (below the confidence threshold), the outcome escalates to human_review instead of guessing. In the benchmark, 43% of decisions fell below the threshold, all of which were correctly escalated rather than given a wrong answer.

## Measured

The benchmark runs the same four typed questions through both Strands Decider 2B and a large language model, on 14 held-out test cases (53 individual question answers) from `agent/eval_cases.jsonl`.

Decider: strands-decider-2b-hobson-v19, running on the AWS User Group Madurai hosted API. LLM baseline: qwen3.5-4b on the same hosted API.

| | Strands Decider 2B | qwen3.5-4b LLM |
|---|---|---|
| Accuracy | 75.5% | 98.1% |
| Latency p50 per decision | 5,539 ms | 22,759 ms |
| Latency p95 | 6,054 ms | 23,145 ms |
| Cost per 1,000 decisions | $0.035 | $0.00 |
| Answered alone at confidence >= 0.7 | 57% | 100% |
| Accuracy when confident | 86.7% | 98.1% |

At the median, Strands Decider 2B was 4.1 times faster than the LLM.

The LLM is more accurate overall, which is expected: qwen3.5-4b is a much larger model. But Strands Decider 2B returns calibrated confidence scores that the code can act on. When the Decider is confident (57% of cases), it answers correctly 86.7% of the time and costs $0.035 per 1,000 decisions. The remaining 43% are escalated to human_review rather than guessed. The hosted API adds network latency; a local or GPU-hosted Decider would be significantly faster.

< FIGURE 3 of 6: upload submission/article/img/bench-accuracy.png here >
Alt text: Bar chart comparing accuracy of Strands Decider 2B and the LLM on the four policy questions

< FIGURE 4 of 6: upload submission/article/img/bench-latency.png here >
Alt text: Latency comparison showing Strands Decider 2B at 5.5 seconds median versus 22.8 seconds for the LLM

< FIGURE 5 of 6: upload submission/article/img/bench-cost.png here >
Alt text: Cost per 1,000 decisions: $0.035 for Strands Decider 2B versus $0.00 for the local LLM

< FIGURE 6 of 6: upload submission/article/img/bench-confidence.png here >
Alt text: Accuracy at each confidence threshold, showing how escalating low-confidence cases improves overall reliability

## The reusable decision pattern

The pattern lives in `agent/decision.py`, labelled `REUSABLE DECISION PATTERN: AWS IAM permission scope review (#policy)`. It contains the typed questions and options, the outcome logic, and a note on how to adapt it.

To reuse it for a different domain: copy `agent/decision.py`, replace `PERMISSION_POLICY` with the rules that apply to your domain, rewrite the four questions and their option descriptions to match what you are classifying, and keep `PermissionReviewer.review()` as the wiring. The four-question structure (scope, action alignment, prohibited patterns, completeness) maps to many policy classification problems beyond IAM: data access requests, infrastructure change reviews, compliance checklist evaluation.

The Decider client, the benchmark runner, and the five reusable patterns are all in `decider_kit/`, which is part of the AWS User Group Madurai hackathon kit.

## What I learned and what is next

The most important thing I learned is that deterministic pre-checks and a decision model work better together than either does alone. The rules catch the obvious cases instantly and cheaply; the Decider handles the language understanding for the nuanced middle ground; and the fail-closed design means uncertainty always escalates rather than approves. The LLM only does what it is actually good at: the conversation and the natural-language interpretation.

The confidence-based escalation is what makes the system trustworthy. Showing a 93% confidence allow is a very different signal to a developer than a flat yes. They know when to double-check.

Next steps would be connecting CloudGuard AI to a real IAM policy simulator, so the tool can validate that the proposed action actually grants only the access it claims, and adding memory to track which requests a team has reviewed before so repeat patterns can be flagged automatically.

---

Code: https://github.com/Gopika252006/CloudGuard . Video: https://youtu.be/mB0Hovumlvo . Tags: #strands-decider-2b #policy

Built with the AWS User Group Madurai Strands Decider hackathon kit
