"""
JWT Manager for Authentication.

Handles token creation, validation, expiration, and claims.
"""
import time

import jwt
from pydantic import BaseModel


class TokenPayload(BaseModel):
    sub: str
    role: str
    exp: int


class JWTManager:
    def __init__(self, secret: str, algorithm: str = "HS256", expiration_seconds: int = 3600):
        self.secret = secret
        self.algorithm = algorithm
        self.expiration_seconds = expiration_seconds

    def create_token(self, subject: str, role: str) -> str:
        """Create a new JWT token for a subject and role."""
        expiration = int(time.time()) + self.expiration_seconds
        payload = {"sub": subject, "role": role, "exp": expiration}
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def verify_token(self, token: str) -> TokenPayload | None:
        """Verify a JWT token and return its payload. Returns None if invalid or expired."""
        try:
            payload_dict = jwt.decode(token, self.secret, algorithms=[self.algorithm])
            return TokenPayload(**payload_dict)
        except jwt.PyJWTError:
            return None
