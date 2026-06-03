import base64
import os
from typing import Any

import httpx

from .models import AuditSession


class AzureIntegrationError(Exception):
    pass

async def export_to_azure_devops(session: AuditSession) -> dict[str, Any]:
    """Export Sentinel findings as Azure DevOps work items."""
    organization = os.getenv("AZURE_DEVOPS_ORG", "demo-org")
    project = os.getenv("AZURE_DEVOPS_PROJECT", "ProjectSentinel")
    pat = os.getenv("AZURE_DEVOPS_PAT")
    
    if not pat:
        # Mock success for demo purposes if not configured
        return {"status": "success", "work_items_created": len(session.findings), "mocked": True}
        
    url = f"https://dev.azure.com/{organization}/{project}/_apis/wit/workitems/$Issue?api-version=7.0"
    
    auth_header = "Basic " + base64.b64encode(f":{pat}".encode()).decode("utf-8")
    headers = {
        "Authorization": auth_header,
        "Content-Type": "application/json-patch+json"
    }
    
    created_ids = []
    
    async with httpx.AsyncClient() as client:
        for finding in session.findings:
            document = [
                {
                    "op": "add",
                    "path": "/fields/System.Title",
                    "value": f"[Sentinel] Security Vulnerability: {finding.title}"
                },
                {
                    "op": "add",
                    "path": "/fields/System.Description",
                    "value": f"Sentinel has identified a {finding.severity} severity finding (CWE-{finding.cwe or 'Unknown'}).<br><br><b>File:</b> {finding.file_path}:{finding.line}<br><b>Snippet:</b><pre>{finding.snippet}</pre><br><b>Remediation:</b> {finding.remediation}"
                }
            ]
            
            resp = await client.post(url, headers=headers, json=document)
            if resp.status_code in (200, 201):
                created_ids.append(resp.json().get("id"))
            else:
                print(f"Failed to create ADO work item: {resp.text}", flush=True)
                
    return {"status": "success", "work_items_created": len(created_ids), "mocked": False, "ids": created_ids}
