"""
Webhook Handler for GitHub App.

Verifies webhook signatures, parses GitHub events,
and triggers Sentinel workflows.
"""
import hashlib
import hmac
import logging
from typing import Any, Callable

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)


class WebhookHandler:
    def __init__(self, webhook_secret: str, workflow_trigger_callback: Callable):
        self.webhook_secret = webhook_secret.encode("utf-8")
        self.workflow_trigger_callback = workflow_trigger_callback

    async def verify_signature(self, request: Request) -> bytes:
        """Verify the GitHub webhook signature to prevent spoofing."""
        signature_header = request.headers.get("x-hub-signature-256")
        if not signature_header:
            raise HTTPException(status_code=401, detail="Missing signature header")
            
        try:
            signature = signature_header.split("=")[1]
        except IndexError:
            raise HTTPException(status_code=401, detail="Invalid signature format")

        payload_body = await request.body()
        expected_signature = hmac.new(
            self.webhook_secret,
            payload_body,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            raise HTTPException(status_code=401, detail="Signature mismatch")
            
        return payload_body

    async def handle_event(self, request: Request, payload: dict[str, Any]):
        """Handle incoming GitHub events."""
        event_type = request.headers.get("x-github-event")
        
        if event_type == "pull_request":
            action = payload.get("action")
            if action in ("opened", "synchronize"):
                repo_url = payload["repository"]["clone_url"]
                pr_number = payload["pull_request"]["number"]
                installation_id = str(payload.get("installation", {}).get("id", ""))
                
                logger.info(f"Triggering workflow for PR #{pr_number} in {repo_url}")
                
                # Trigger the deterministic workflow asynchronously
                await self.workflow_trigger_callback({
                    "repo_url": repo_url,
                    "pr_number": pr_number,
                    "installation_id": installation_id,
                    "trigger_source": "webhook"
                })
                return {"status": "workflow_triggered"}
                
        return {"status": "ignored"}
