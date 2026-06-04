# Judge Submission Pack (2-Minute Video + Live Demo)

Use this script when recording. Total runtime: **120 seconds**.

## 0:00–0:15 — Hook

> "Security teams find thousands of vulnerabilities. The bottleneck is **safe remediation**. Project Sentinel is an autonomous agent swarm that finds issues, generates patches, **validates them in an isolated sandbox**, and only then asks a human to approve—or rollback."

Show: Live URL + logo.

## 0:15–0:35 — Problem + Microsoft fit

> "Static scanners report problems; they don't close the loop. Sentinel integrates with **GitHub Actions** and can export findings to **Azure DevOps** work items—fitting enterprise DevSecOps workflows teams already use."

Show: GitHub Action badge + "Export to Azure" (or capabilities panel).

## 0:35–1:25 — Demo (no narration lag)

1. Open live app → **Watch Live Demo** (or start audit on `/app/examples/python-vulnerable-api`).
2. Point to **Active runtime** sidebar: sandbox engine + LLM mode (honest, not oversold).
3. Show findings → Engineer patch diff → sandbox validation axes.
4. Click **Approve** → brief **Rollback** to prove safety.

## 1:25–1:50 — Technical credibility

> "Four agents—Architect, Scout, Engineer, Critic—with typed contracts, convergence scoring, and a reproducible benchmark in CI. Built as an MVP with production seams for Firecracker, Temporal, and Kubernetes."

Show: Capability panel (`IMPLEMENTED` vs `MVP_ADAPTER`).

## 1:50–2:00 — Close

> "Sentinel turns alerts into **reviewed, validated fixes**—reducing MTTR without sacrificing control. Try the live demo and GitHub Action on our repo."

Show: QR or URL + repo link.

---

## Pre-submit checklist

- [ ] Render health check green (`/api/health`)
- [ ] Vercel `VITE_SENTINEL_API_URL` = Render backend URL
- [ ] CORS includes your exact Vercel hostname
- [ ] Demo path on cloud: `examples/python-vulnerable-api` or public GitHub URL
- [ ] `ANTHROPIC_API_KEY` set on Render (optional; deterministic path works offline)
- [ ] README Live Demo link matches deployed URL
- [ ] 2-min video uploaded; first frame shows working UI
