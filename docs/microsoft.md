# Microsoft Stack Integration

Project Sentinel is built for **Microsoft hackathon / enterprise DevSecOps** workflows.

## Azure OpenAI

```env
AZURE_OPENAI_ENDPOINT=https://<resource>.openai.azure.com
AZURE_OPENAI_KEY=<key>
AZURE_OPENAI_DEPLOYMENT=gpt-4o
SENTINEL_LLM_PROVIDER=azure
```

Engineer and Critic agents use your Azure deployment when configured (preferred over Anthropic when `SENTINEL_LLM_PROVIDER=azure` or `auto`).

## Azure DevOps

```env
AZURE_DEVOPS_ORG=your-org
AZURE_DEVOPS_PROJECT=YourProject
AZURE_DEVOPS_PAT=<pat>
```

`POST /api/sessions/{session_id}/export/azure` creates work items from findings.

## GitHub Advanced Security (SARIF)

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://<api>/api/sessions/<session_id>/export/sarif \
  -o results.sarif.json
```

Upload to GitHub: **Security → Code scanning → Upload SARIF**.

## GitHub Actions

See root `action.yml` and README workflow snippet.

## Responsible AI policy

`GET /api/sessions/{id}/policy` — patches need sandbox APPROVE, confidence ≥ 0.92, and non-critical risk before auto-approve eligibility. Humans approve in the UI by default.

## Session persistence (SQLite)

Production and `SENTINEL_SESSION_DB=/path/to/sentinel.db` persist sessions across API restarts.
