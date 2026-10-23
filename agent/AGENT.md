# Use case

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
