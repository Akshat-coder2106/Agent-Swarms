# Project Sentinel — 10 Slide Presentation Script
## Microsoft Build AI Hackathon
### Instructions for AI slide builder: Each slide has a HEADLINE, BODY COPY, VISUAL DIRECTION, and SPEAKER NOTE. Use the exact numbers given — do not round or embellish.

---

## SLIDE 1 — TITLE

**HEADLINE:**
Project Sentinel
Autonomous DevSecOps Swarm

**SUB-HEADLINE:**
From vulnerability alert to validated, human-approved fix — automatically.

**BODY COPY:**
Built on: Azure AI Foundry · Semantic Kernel · AutoGen · Azure OpenAI · GitHub Actions

**VISUAL DIRECTION:**
Clean dark background. Microsoft logo family (Azure, GitHub, SK) shown as small icons in a row at bottom. No AI-generated art. Show the live dashboard URL prominently.

**SPEAKER NOTE:**
One sentence pitch if asked: "Sentinel is the remediation layer that security scanners don't have — it finds a vulnerability, writes a patch, proves it works in an isolated sandbox, and hands humans a single approve/rollback decision."

---

## SLIDE 2 — THE PROBLEM

**HEADLINE:**
Finding vulnerabilities is solved.
Fixing them safely is not.

**BODY COPY (3 panels, no bullets — use cards):**

Panel 1 — Alert Overload
SAST and DAST tools generate thousands of findings per week. Security teams triage, not fix.

Panel 2 — Remediation Bottleneck
Every alert requires a human engineer to analyse the code, write a fix, test it, and submit a PR. That loop takes days, not minutes.

Panel 3 — Business Impact
Blocked CI/CD pipelines. Delayed releases. Alert fatigue where critical issues get ignored alongside low-priority noise.

**VISUAL DIRECTION:**
Three equal-width cards. No stock photos. Use a simple timeline bar showing "Alert raised → Engineer assigned → Fix reviewed → Merged" with realistic multi-day gaps marked.

**SPEAKER NOTE:**
Do not say "thousands of vulnerabilities." Say "thousands of alerts" — the distinction matters to security judges. The problem is alert volume overwhelming human capacity, not the scanners themselves.

---

## SLIDE 3 — THE SOLUTION

**HEADLINE:**
Sentinel closes the loop.

**BODY COPY:**
Sentinel ingests your repository, generates a context-aware patch using Azure OpenAI, validates it inside a process-isolated sandbox, and surfaces one decision to a human engineer: Approve or Rollback.

Four agents work in sequence:
— Architect maps the repository data flow before any patch is written
— Scout retrieves semantic context and CVE history for the finding
— Engineer generates the patch with full code context
— Critic compiles, runs tests, and adversarially challenges the fix in the sandbox

Nothing reaches a human until the sandbox approves it.

**VISUAL DIRECTION:**
Four connected circles: Architect → Scout → Engineer → Critic → [Human: 1-click]. Use the actual flow diagram from the codebase, not AI art. Each circle gets one icon (map, search, code, shield).

**SPEAKER NOTE:**
Emphasise that humans are NOT removed — they are upgraded. They go from writing patches to reviewing validated diffs. That is the human-in-the-loop story Microsoft cares about.

---

## SLIDE 4 — MICROSOFT STACK

**HEADLINE:**
Built natively on the Microsoft AI stack.

**BODY COPY (use a 2-column layout):**

LEFT COLUMN — What we use:
· Azure OpenAI (gpt-4o) — patch generation and Critic adversarial analysis
· Azure AI Foundry — semantic code search via text-embedding-3-small
· Semantic Kernel — 4 agent functions registered as @kernel_function plugin
· AutoGen GroupChat — 4-agent audit conversation transcript per session
· GitHub Actions — one-file CI integration via action.yml
· SARIF 2.1 — findings export to GitHub Advanced Security
· Azure DevOps — findings exported as work items via REST API

RIGHT COLUMN — Live endpoints judges can call:
GET  /api/system/sk_status        → Semantic Kernel kernel state
GET  /api/sessions/{id}/autogen_transcript → AutoGen conversation log
GET  /api/sessions/{id}/export/sarif       → SARIF 2.1 output
POST /api/sessions/{id}/export/azure       → Azure DevOps work items

**VISUAL DIRECTION:**
Two-column card layout. Left column uses official Microsoft product icons. Right column shows a live terminal/JSON snippet of the sk_status response showing "semantic_kernel: active".

**SPEAKER NOTE:**
If a judge asks "why not just use GitHub Copilot Autofix?" — the answer is: "Copilot Autofix generates a patch and stops. Sentinel sandboxes it, adversarially challenges it with AutoGen, and gives you a rollback-safe approval gate. We close the loop Copilot leaves open."

---

## SLIDE 5 — LIVE ARCHITECTURE

**HEADLINE:**
Four agents. One convergence loop. Zero unvalidated patches in production.

**BODY COPY:**
The LangGraph state machine drives deterministic retry logic — if the Critic rejects a patch, the Engineer refactors and tries again, up to 7 iterations. Azure AI Foundry embeddings give every agent semantic context, not just keyword matching. Semantic Kernel exposes each agent as a callable plugin function.

**ARCHITECTURE (show as actual Mermaid diagram):**
```
Frontend (Vercel) → JWT Auth → FastAPI Backend (Render)
                               ↓
                    Semantic Kernel Kernel
                    [Architect | Scout | Engineer | Critic]
                               ↓
                    LangGraph State Machine (retry loop)
                               ↓
                    Process-Isolated Sandbox
                               ↓
                    Human Approval Gate → GitHub PR
```

**VISUAL DIRECTION:**
Render the actual architecture diagram. Include the live Render + Vercel deployment URLs as labels. Show "MVP adapter / Production seam" labels honestly on Firecracker and Qdrant components.

**SPEAKER NOTE:**
Be honest about the sandbox: "In production this would run Firecracker MicroVMs. Our deployed version uses a process-isolated sandbox with the same interface — the production seam is explicit in our capabilities panel at /api/system/capabilities."

---

## SLIDE 6 — AUTOGEN MULTI-AGENT TRANSCRIPT

**HEADLINE:**
The agents don't just act — they reason, debate, and sign off.

**BODY COPY:**
Every audit session produces an AutoGen GroupChat transcript — a readable record of how each agent assessed the vulnerability and the proposed fix. This is not a log file. It is four expert perspectives that a human reviewer can read in 30 seconds.

Example transcript (real output, internal test fixture):

Architect: "Repository analysis complete. SQL injection in users.py line 42 via f-string query construction. Data flow confirmed from untrusted HTTP parameter to database cursor."

Scout: "CWE-89 confirmed. Deterministic rule python.sql_injection.fstring matched. No encoding bypass possible via this code path — parameterisation required."

Engineer: "Patch applied: replaced f-string query with parameterised cursor.execute(). Confidence 0.91. Minimal footprint — one line changed."

Critic: "Sandbox result: APPROVE. Tests pass. Encoding bypass and second-order injection vectors tested — both blocked by parameterisation. Human review recommended before merge."

**VISUAL DIRECTION:**
Show the actual AutoGen transcript panel from the live UI. Four agent speech bubbles with distinct colours matching the agent roles. This should be a real screenshot, not an illustration.

**SPEAKER NOTE:**
This is the feature that differentiates Sentinel from every other DevSecOps tool in this hackathon. No competing tool produces a human-readable multi-agent deliberation record.

---

## SLIDE 7 — BENCHMARK RESULTS

**HEADLINE:**
Tested against 5 real vulnerable repositories.
86% sandbox pass rate. 223 findings. 150 patches generated.

**BODY COPY (exact numbers — do not round):**

| Repository | Findings | Patches | Pass Rate | False Positives |
|---|---|---|---|---|
| examples/python-vulnerable-api | 14 | 14 | 100% | 0 |
| PyCQA/bandit test fixtures | 48 | 42 | 87% | 3 |
| trufflesecurity/trufflehog | 32 | 31 | 96% | 1 |
| juice-shop/juice-shop | 105 | 45 | 68% | 12 |
| appsecco/dvna | 24 | 18 | 80% | 2 |
| **Overall** | **223** | **150** | **~86%** | **18** |

Note below table:
"18 of 223 findings were flagged as false positives and escalated for human review — consistent with our policy gate design. The sandbox rejected 15% of LLM-generated patches before they could reach production."

**VISUAL DIRECTION:**
Clean table. Highlight the overall row. Add a secondary donut chart showing 85.15% passed first attempt / 14.85% rejected by sandbox — this is accurate from the benchmark data. No inflated claims.

**SPEAKER NOTE:**
If a judge challenges the 18 false positives: "We surface them for human review rather than suppressing them. Our policy gate is designed so engineers make the final call on edge cases — that is by design, not a failure mode."

---

## SLIDE 8 — RESPONSIBLE AI & POLICY GATE

**HEADLINE:**
Autonomous patching with hard guardrails.
No patch merges without passing three policy checks.

**BODY COPY:**
Sentinel's policy gate enforces three conditions before any patch is eligible for auto-approval:

1. Sandbox verdict must be APPROVE — the patch compiled and all tests passed
2. Engineer confidence must be ≥ 0.92 — below this threshold, human review is mandatory
3. Risk level must be below CRITICAL or HIGH — high-risk patches always require a human

If any condition fails, the patch is escalated — never silently dropped or auto-merged.

Rollback is always available: Sentinel stores the original file content and verifies it before restoring, so engineers can revert with one click even after approval.

**VISUAL DIRECTION:**
Three-step gate visual. Green checkmarks for passing conditions, red escalation arrow for failing ones. Show the actual /api/sessions/{id}/policy JSON response as a sidebar snippet — it's real and readable.

**SPEAKER NOTE:**
This slide matters for Microsoft judges because Responsible AI is a named evaluation area. Lead with: "Human oversight is not a feature we added — it is the architecture. The system is designed to escalate, not to auto-merge."

---

## SLIDE 9 — DETECTION COVERAGE

**HEADLINE:**
11 deterministic detection rules.
CWE-mapped. OWASP Top 10 tagged. NIST SP 800-53 aligned.

**BODY COPY:**

| Rule | Language | CWE | OWASP | Severity |
|---|---|---|---|---|
| SQL injection via f-string | Python | CWE-89 | A03:2021 | HIGH |
| Code injection via eval()/exec() | Python | CWE-94 | A03:2021 | CRITICAL |
| Path traversal | Python | CWE-22 | A01:2021 | HIGH |
| Insecure deserialization (pickle) | Python | CWE-502 | A08:2021 | CRITICAL |
| Unsafe YAML load | Python | CWE-502 | A08:2021 | HIGH |
| Weak PRNG for security | Python | CWE-338 | A02:2021 | MEDIUM |
| SQL injection via template literal | JavaScript | CWE-89 | A03:2021 | HIGH |
| XSS via innerHTML | JavaScript | CWE-79 | A03:2021 | HIGH |
| Code injection via eval() | JavaScript | CWE-94 | A03:2021 | CRITICAL |
| Hardcoded credentials | Multi | CWE-798 | A07:2021 | CRITICAL |
| Git merge conflict markers | Multi | CWE-116 | A05:2021 | LOW |

Plus: optional Semgrep, Trivy, Checkov, and Gitleaks integration when installed.

**VISUAL DIRECTION:**
Clean table. Colour-code severity column (CRITICAL = red, HIGH = orange, MEDIUM = yellow, LOW = grey). Add a small OWASP Top 10 logo in the corner. This is enterprise security vocabulary — it signals credibility.

**SPEAKER NOTE:**
The NIST alignment matters if any judge is from a government or compliance background. You can add: "SARIF export means findings flow directly into GitHub Advanced Security's code scanning dashboard — no integration work required."

---

## SLIDE 10 — WHAT'S NEXT & CLOSE

**HEADLINE:**
The foundation is in place.
Three phases to production scale.

**BODY COPY:**

Phase 1 — Fleet Scanning (buildable on current architecture)
Extend the session model to scan multiple repositories in one operation. Useful for organisations auditing 50+ microservices.

Phase 2 — Expanded Rule Coverage
Broader deterministic rules covering complex injection chains, auth bypass patterns, and infrastructure-as-code misconfigurations via Checkov integration.

Phase 3 — Natural Language Policy Engine
Let security teams define policies in plain English: "Always escalate CRITICAL findings in payment services." No YAML. No DSL. Powered by Azure OpenAI.

---

CLOSING STATEMENT (display as a single bold line):

"Sentinel turns security alerts into reviewed, validated, rollback-safe fixes — with full human control at every gate."

Live demo: [your Vercel URL]
GitHub: [your repo URL]
API health: [your Render URL]/api/health

**VISUAL DIRECTION:**
Three-column roadmap cards for phases. Clean closing statement in large type. QR codes for live demo and repo. No stock photos. Real screenshots of the working UI in the background.

**SPEAKER NOTE:**
End with the differentiator question judges are thinking: "Why not just use GitHub Copilot Autofix?" Answer it before they ask: "Copilot Autofix generates a suggestion. Sentinel generates a patch, sandboxes it, gets four agents to adversarially challenge it, enforces a three-condition policy gate, and gives you a rollback button. That is a fundamentally different product."
