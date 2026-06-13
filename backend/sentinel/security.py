from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from .config import Settings


class AuthenticationError(ValueError):
    pass


@dataclass(frozen=True)
class Principal:
    subject: str
    session_id: str | None
    expires_at: datetime
    role: str


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _json_b64(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _b64url_encode(encoded)


def issue_token(
    settings: Settings,
    *,
    subject: str,
    session_id: str | None = None,
    role: str = "Admin",
    ttl_seconds: int | None = None,
) -> str:
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=ttl_seconds or settings.token_ttl_seconds)
    header = {"alg": "HS256", "typ": "JWT"}
    payload: dict[str, Any] = {
        "iss": settings.auth_issuer,
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": uuid4().hex,
        "role": role,
    }
    if session_id:
        payload["session_id"] = session_id
    signing_input = f"{_json_b64(header)}.{_json_b64(payload)}"
    signature = hmac.new(
        settings.auth_secret.encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def verify_token(
    settings: Settings,
    token: str,
    *,
    required_session_id: str | None = None,
) -> Principal:
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthenticationError("Malformed bearer token")
    signing_input = f"{parts[0]}.{parts[1]}"
    expected_signature = hmac.new(
        settings.auth_secret.encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    supplied_signature = _b64url_decode(parts[2])
    if not hmac.compare_digest(expected_signature, supplied_signature):
        raise AuthenticationError("Bearer token signature is invalid")
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except (json.JSONDecodeError, ValueError) as exc:
        raise AuthenticationError("Bearer token payload is invalid") from exc
    if payload.get("iss") != settings.auth_issuer:
        raise AuthenticationError("Bearer token issuer is invalid")
    expires_at = datetime.fromtimestamp(int(payload["exp"]), UTC)
    if expires_at <= datetime.now(UTC):
        raise AuthenticationError("Bearer token has expired")
    session_id = payload.get("session_id")
    if required_session_id and session_id not in (required_session_id, None):
        raise AuthenticationError("Bearer token is not scoped to this session")
    subject = str(payload.get("sub") or "")
    if not subject:
        raise AuthenticationError("Bearer token subject is missing")
    return Principal(
        subject=subject,
        session_id=session_id,
        expires_at=expires_at,
        role=str(payload.get("role") or "ReadOnly"),
    )


def bearer_from_header(value: str | None) -> str:
    if not value:
        raise AuthenticationError("Authorization header is required")
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise AuthenticationError("Authorization header must use Bearer authentication")
    return token.strip()


def sign_request(settings: Settings, method: str, path: str, body: bytes) -> str:
    """Generate a secure cryptographic signature to verify payload integrity."""
    signing_input = f"{method.upper()}:{path}:".encode() + body
    return hmac.new(
        settings.auth_secret.encode("utf-8"),
        signing_input,
        hashlib.sha256
    ).hexdigest()


def verify_request_signature(
    settings: Settings,
    signature: str | None,
    method: str,
    path: str,
    body: bytes,
) -> None:
    """Validate request signature using constant-time comparison."""
    if not signature:
        raise AuthenticationError("X-Request-Signature header is required")
    expected = sign_request(settings, method, path, body)
    if not hmac.compare_digest(expected.encode("utf-8"), signature.encode("utf-8")):
        raise AuthenticationError("X-Request-Signature verification failed")


# Simple in-memory rate-limiter for secure API endpoints
RATE_LIMIT_CACHE: dict[str, list[float]] = {}

def check_rate_limit(client_ip: str, max_requests: int = 100, window_sec: int = 60) -> None:
    """Prevent automated denial of service attacks against sandbox orchestrators."""
    import time
    
    # Prevent memory leak from distributed uptime checkers with rotating IPs
    if len(RATE_LIMIT_CACHE) > 10000:
        RATE_LIMIT_CACHE.clear()
        
    now = time.time()
    history = RATE_LIMIT_CACHE.setdefault(client_ip, [])
    # Evict expired events
    history[:] = [t for t in history if now - t < window_sec]
    if len(history) >= max_requests:
        raise AuthenticationError("API rate limit exceeded. Please try again shortly.")
    history.append(now)
