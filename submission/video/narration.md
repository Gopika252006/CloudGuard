0. CloudGuard AI uses Amazon Bedrock for the conversation and Strands Decider for every permission classification. Watch how it handles a safe request, a dangerous wildcard, and an ambiguous one — each with a different outcome.

1. Helps developers review AWS IAM permissions before applying them, catching wildcard access and over-permissioned roles using Strands Decider. What it does: Review natural-language permission requests against least-privilege principles. Detect wildcard actions, admin access, and missing details with deterministic safety rules. Strands Decider classifies each request as allow, clarify, or human_review with a confidence score. Specific safer recommendations — never just 'denied', always explains why.

2. A well-scoped, specific request. The decider should classify it as allow. The decider scored confidence 0.93, scope appropriate 0.62, action matches task 0.69, so the verdict was allow, in 6.0 seconds.

3. A request for admin access — the deterministic safety rule blocks this before the Decider even runs. No decision was needed on this turn.

4. An ambiguous request with no service, action, or resource specified. The decider should return clarify. No decision was needed on this turn.

5. Another safe request. The decider identifies s3:PutObject on a named bucket as allow. The decider scored confidence 0.91, scope appropriate 0.70, action matches task 0.65, so the verdict was allow, in 5.8 seconds.

6. On 53 labelled decisions, with the decider on the AWS User Group Madurai hosted API, Strands Decider was 75% accurate at a median of 5539 milliseconds, against 98% and 22759 milliseconds for a hosted open LLM asked the same questions.

7. One Decider call per review, a typed outcome with a confidence score, and deterministic safety rules that cannot be overridden. Strands Decider makes permission classification fast, cheap, and auditable.