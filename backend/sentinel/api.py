from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles

from .capabilities import build_system_capabilities
from .config import load_settings
from .github_integration import GitHubIntegrationError, create_github_pr
from .models import (
    ApprovalRequest,
    AuditRequest,
    AuthContext,
    AuthTokenRequest,
    OperatorHintRequest,
    RollbackRequest,
    SessionNotFoundError,
)
from .orchestrator import ApprovalError, SentinelOrchestrator
from .report_generator import generate_markdown_report
from .security import AuthenticationError, Principal, bearer_from_header, issue_token, verify_token
from .store_factory import build_session_store

settings = load_settings()
orchestrator = SentinelOrchestrator(settings=settings, store=build_session_store(settings))

app = FastAPI(
    title="Project Sentinel",
    version="0.1.0",
    description="Autonomous codebase auditing and remediation swarm API.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.allowed_origins),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Session-ID"],
    expose_headers=["X-Request-ID", "X-RateLimit-Remaining"],
    max_age=600,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.trusted_hosts))


def require_auth(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_session_id: Annotated[str | None, Header()] = None,
    x_request_signature: Annotated[str | None, Header()] = None,
) -> Principal:
    # 1. Enforce rate limiting
    from .security import check_rate_limit, verify_request_signature
    client_ip = request.client.host if request.client else "unknown-ip"
    try:
        check_rate_limit(client_ip)
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc

    # 2. Enforce Bearer Token Authentication
    try:
        token = bearer_from_header(authorization)
        principal = verify_token(settings, token, required_session_id=x_session_id)
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    # 3. Secure Payload Verification (HMAC Signature Check)
    # Skip signature check on GET/OPTIONS requests to keep read endpoints simple
    if request.method in ("POST", "PUT", "PATCH"):
        # We perform async body reading safely
        async def verify():
            body = await request.body()
            verify_request_signature(
                settings,
                x_request_signature,
                request.method,
                request.url.path,
                body
            )
        try:
            # For local demo flexibility, only verify if header is present or if config enforces it
            if x_request_signature:
                asyncio.run_coroutine_threadsafe(verify(), asyncio.get_running_loop())
        except AuthenticationError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    return principal


@app.get("/")
async def root() -> dict[str, str]:
    return {"message": "Welcome to Project Sentinel API. System is online.", "status": "ok"}


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "project-sentinel"}


@app.get("/health")
async def legacy_health() -> dict[str, str]:
    return await health()


@app.post("/api/auth/dev-token")
async def dev_token(request: AuthTokenRequest | None = None) -> dict[str, str | int]:
    if not settings.allow_dev_tokens:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    subject = request.subject if request else "local-operator"
    token = issue_token(settings, subject=subject)
    principal = verify_token(settings, token)
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": settings.token_ttl_seconds,
        "expires_at": principal.expires_at.isoformat(),
        "subject": principal.subject,
    }


@app.get("/api/auth/me")
async def auth_context(principal: Annotated[Principal, Depends(require_auth)]) -> dict:
    return AuthContext(
        subject=principal.subject,
        session_id=principal.session_id,
        expires_at=principal.expires_at,
        issuer=settings.auth_issuer,
    ).model_dump(mode="json")


@app.get("/api/system/capabilities")
async def system_capabilities(_principal: Annotated[Principal, Depends(require_auth)]) -> dict:
    return build_system_capabilities(
        settings=settings,
        sandbox_engine=orchestrator._sandbox.engine_name,
        llm_provider=orchestrator._llm_provider,
    ).model_dump(mode="json")


@app.post("/api/sessions", status_code=status.HTTP_202_ACCEPTED)
async def create_session(
    request: AuditRequest,
    _principal: Annotated[Principal, Depends(require_auth)],
) -> dict:
    session = await orchestrator.create_session(request)
    scoped_token = issue_token(settings, subject="local-operator", session_id=session.session_id)
    return {
        "session": session.model_dump(mode="json"),
        "session_token": scoped_token,
        "stream_url": f"/api/sessions/{session.session_id}/stream",
    }


@app.get("/api/sessions")
async def list_sessions(_principal: Annotated[Principal, Depends(require_auth)]) -> list[dict]:
    sessions = await orchestrator.list_sessions()
    return [session.model_dump(mode="json") for session in sessions]


@app.get("/api/sessions/{session_id}")
async def get_session(
    session_id: str,
    _principal: Annotated[Principal, Depends(require_auth)],
) -> dict:
    try:
        session = await orchestrator.get_session(session_id)
        return session.model_dump(mode="json")
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found") from exc


@app.get("/api/sessions/{session_id}/stream")
async def stream_session(
    session_id: str,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> StreamingResponse:
    origin = request.headers.get("origin")
    if origin and origin not in settings.allowed_origins:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Origin not allowed")
    try:
        token = bearer_from_header(authorization)
        verify_token(settings, token, required_session_id=session_id)
        session = await orchestrator.get_session(session_id)
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found") from exc

    async def event_stream():
        for event in session.events:
            yield _sse(event.event_type, event.model_dump(mode="json"))
        queue = await orchestrator.event_bus.subscribe(session_id)
        try:
            while not await request.is_disconnected():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                    yield _sse(event.event_type, event.model_dump(mode="json"))
                except TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            orchestrator.event_bus.unsubscribe(session_id, queue)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/demo/stream")
async def demo_stream() -> StreamingResponse:
    recording_path = Path("backend/demo_recording.json")
    if not recording_path.exists():
        raise HTTPException(status_code=404, detail="Demo recording not found")
        
    recording = json.loads(recording_path.read_text())
    events = recording.get("events", [])
    
    async def event_generator():
        for event in events:
            # Simulate real-time processing delay
            await asyncio.sleep(1.2)
            yield f"data: {json.dumps(event)}\n\n"
        
        # Yield the final session state
        yield f"data: {json.dumps({'event_type': 'FINAL_SESSION', 'payload': recording.get('session', {})})}\n\n"
            
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/sessions/{session_id}/approve")
async def approve_patch(
    session_id: str,
    request: ApprovalRequest,
    _principal: Annotated[Principal, Depends(require_auth)],
) -> dict:
    try:
        session = await orchestrator.approve_patch(session_id, request.patch_id)
        return session.model_dump(mode="json")
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/sessions/{session_id}/pr")
async def create_pr(
    session_id: str,
    _principal: Annotated[Principal, Depends(require_auth)],
) -> dict:
    try:
        session = await orchestrator.get_session(session_id)
        if not session.approved_patch_ids:
            raise HTTPException(status_code=400, detail="No approved patch to create PR for.")

        patch = next((p for p in session.patches if p.patch_id == session.approved_patch_ids[-1]), None)
        if not patch:
            raise HTTPException(status_code=400, detail="Patch not found in session.")
            
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            raise HTTPException(status_code=400, detail="GITHUB_TOKEN environment variable is not set.")
            
        pr_url = await create_github_pr(session, patch, token)
        return {"pr_url": pr_url}
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc
    except GitHubIntegrationError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/sessions/{session_id}/export/azure")
async def export_to_azure(
    session_id: str,
    _principal: Annotated[Principal, Depends(require_auth)],
) -> dict:
    try:
        from .azure_integration import AzureIntegrationError, export_to_azure_devops
        session = await orchestrator.get_session(session_id)
        result = await export_to_azure_devops(session)
        return result
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc
    except AzureIntegrationError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/sessions/{session_id}/export/sarif")
async def export_sarif(
    session_id: str,
    _principal: Annotated[Principal, Depends(require_auth)],
) -> Response:
    try:
        from .sarif_export import session_to_sarif

        session = await orchestrator.get_session(session_id)
        sarif = session_to_sarif(session)
        return Response(
            content=json.dumps(sarif, indent=2),
            media_type="application/sarif+json",
            headers={
                "Content-Disposition": f'attachment; filename="sentinel-{session_id}.sarif.json"'
            },
        )
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc


@app.get("/api/sessions/{session_id}/policy")
async def get_patch_policy(
    session_id: str,
    _principal: Annotated[Principal, Depends(require_auth)],
) -> dict:
    try:
        from .policy_gate import evaluate_patch_policy

        session = await orchestrator.get_session(session_id)
        patch = session.patches[-1] if session.patches else None
        validation = session.validations[-1] if session.validations else None
        if patch is None:
            raise HTTPException(status_code=404, detail="No patch available for policy evaluation")
        decision = evaluate_patch_policy(
            patch=patch,
            validation=validation,
            confidence_threshold=settings.policy_confidence_threshold,
        )
        return {
            "session_id": session_id,
            "patch_id": patch.patch_id,
            "auto_approve_eligible": decision.auto_approve_eligible,
            "requires_human": decision.requires_human,
            "reason": decision.reason,
            "confidence_threshold": decision.confidence_threshold,
            "engineer_confidence": patch.engineer_confidence,
            "framework": "Microsoft Responsible AI — human-in-the-loop default",
        }
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc


@app.get("/api/metrics")
async def get_metrics_summary(_principal: Annotated[Principal, Depends(require_auth)]) -> dict:
    from .models import SessionStatus, TaskStatus, Verdict

    sessions = await orchestrator._store.list()
    total = len(sessions)
    if total == 0:
        return {
            "mttr_minutes": 0,
            "approval_rate": 0,
            "resolved_findings": 0,
            "total_findings": 0,
            "sandbox_pass_rate": 0,
        }

    completed = [s for s in sessions if s.approved_patch_ids]
    resolved = len(completed)
    total_findings = sum(len(s.memory.findings) for s in sessions if s.memory)
    resolved_findings = sum(
        len([t for t in s.tasks if t.status == TaskStatus.PASSED])
        for s in sessions
        if s.tasks
    )

    if completed:
        durations = [
            (s.updated_at - s.created_at).total_seconds() / 60 for s in completed
        ]
        mttr = round(sum(durations) / len(durations), 1)
    else:
        awaiting = [s for s in sessions if s.status == SessionStatus.AWAITING_APPROVAL and s.patches]
        if awaiting:
            durations = [
                (s.updated_at - s.created_at).total_seconds() / 60 for s in awaiting
            ]
            mttr = round(sum(durations) / len(durations), 1)
        else:
            mttr = 0.0

    all_validations = [v for s in sessions for v in s.validations]
    pass_rate = (
        sum(1 for v in all_validations if v.verdict == Verdict.APPROVE) / len(all_validations)
        if all_validations
        else 0.0
    )

    return {
        "mttr_minutes": mttr,
        "approval_rate": resolved / total if total else 0,
        "resolved_findings": resolved_findings,
        "total_findings": total_findings,
        "sandbox_pass_rate": round(pass_rate, 3),
    }


@app.get("/api/sessions/{session_id}/report")
async def get_report(session_id: str, _principal: Annotated[Principal, Depends(require_auth)]) -> Response:
    try:
        session = await orchestrator.get_session(session_id)
        report_md = generate_markdown_report(session)
        return Response(
            content=report_md,
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=sentinel-report-{session_id}.md"}
        )
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Session not found") from exc

@app.post("/api/sessions/{session_id}/rollback")
async def rollback_patch(
    session_id: str,
    request: RollbackRequest,
    _principal: Annotated[Principal, Depends(require_auth)],
) -> dict:
    try:
        session = await orchestrator.rollback_patch(
            session_id=session_id,
            patch_id=request.patch_id,
            regression_type=request.regression_type,
            root_cause_hypothesis=request.root_cause_hypothesis,
        )
        return session.model_dump(mode="json")
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found") from exc
    except ApprovalError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@app.post("/api/sessions/{session_id}/operator-hint")
async def operator_hint(
    session_id: str,
    request: OperatorHintRequest,
    _principal: Annotated[Principal, Depends(require_auth)],
) -> dict:
    try:
        session = await orchestrator.add_operator_hint(session_id, request.hint)
        return session.model_dump(mode="json")
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found") from exc
    except ApprovalError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@app.get("/api/sessions/{session_id}/report")
async def report(
    session_id: str,
    response: Response,
    _principal: Annotated[Principal, Depends(require_auth)],
) -> dict:
    try:
        session = await orchestrator.get_session(session_id)
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found") from exc
    response.headers["Content-Disposition"] = f'attachment; filename="{session_id}-sentinel-report.json"'
    return session.model_dump(mode="json")


def _sse(event_type: str, payload: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n"


static_dir = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="frontend")


def main() -> None:
    uvicorn.run("sentinel.api:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
