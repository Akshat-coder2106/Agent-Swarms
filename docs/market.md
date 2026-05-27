# Market Understanding

## Target User

The first buyer is a DevSecOps or application security lead responsible for shrinking vulnerability remediation time across many repositories. The daily user is a senior engineer or security reviewer who needs validated patches, not another static report.

## Competitive Landscape

| Tool | Strength | Sentinel Differentiator |
| --- | --- | --- |
| Snyk | Dependency and container vulnerability intelligence | Sentinel moves beyond detection into patch generation, sandbox validation, and rollback-ready approval. |
| SonarQube | Code quality and static analysis governance | Sentinel adds multi-agent remediation and live evidence trails for each patch decision. |
| GitHub Advanced Security | Native code scanning and secret scanning in GitHub | Sentinel is repo-host agnostic and can orchestrate agentic remediation across scanner findings. |
| Semgrep CLI | Fast customizable static analysis | Sentinel can consume Semgrep-style findings, generate fixes, validate them, and escalate stalled tasks. |

## Why Now

Security teams are overwhelmed by alert volume. The bottleneck has shifted from finding issues to safely fixing them without breaking production. LLMs can draft patches, but enterprises need evidence, isolation, approval gates, and rollback controls before trusting autonomous remediation.

## Product Positioning

Sentinel is an autonomous remediation control plane. It combines code memory, agent roles, secure execution, validation matrices, human escalation, and rollback into one reviewable workflow.

## Go-To-Market Wedge

1. Start with pull-request security remediation for Python and JavaScript services.
2. Integrate with existing scanners instead of replacing them.
3. Expand into nightly autonomous audit sessions with team-level telemetry and compliance reports.
