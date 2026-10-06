"""Security primitives: password hashing, JWT, RBAC, encrypted key vault, rate limiter, IP privacy."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from collections import defaultdict

import jwt
from cryptography.fernet import Fernet

ROLES = {"viewer": 1, "analyst": 2, "admin": 3}


def hash_password(password: str, iterations: int = 120_000) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt, digest = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), digest)
    except Exception:
        return False


def create_token(secret: str, sub: str, role: str, ttl_minutes: int = 480) -> str:
    now = int(time.time())
    return jwt.encode({"sub": sub, "role": role, "iat": now, "exp": now + ttl_minutes * 60}, secret, algorithm="HS256")


def decode_token(secret: str, token: str) -> dict:
    """Raises jwt.PyJWTError on invalid/expired token."""
    return jwt.decode(token, secret, algorithms=["HS256"])


def has_role(role: str, required: str) -> bool:
    return ROLES.get(role, 0) >= ROLES[required]


class KeyVault:
    """Encrypts third-party secrets (LLM API keys) at rest with Fernet (AES-128-CBC + HMAC-SHA256)."""

    def __init__(self, master_key: str):
        self._f = Fernet(base64.urlsafe_b64encode(hashlib.sha256(master_key.encode()).digest()))

    def encrypt(self, plain: str) -> str:
        return self._f.encrypt(plain.encode()).decode()

    def decrypt(self, token: str) -> str:
        return self._f.decrypt(token.encode()).decode()


class RateLimiter:
    """Token bucket per client key."""

    def __init__(self, per_minute: int = 600, burst: int | None = None):
        self.rate = per_minute / 60.0
        self.burst = burst or max(10, per_minute // 4)
        self.state: dict[str, list[float]] = defaultdict(lambda: [float(self.burst), time.monotonic()])

    def allow(self, key: str, cost: float = 1.0) -> bool:
        st = self.state[key]
        now = time.monotonic()
        st[0] = min(self.burst, st[0] + (now - st[1]) * self.rate)
        st[1] = now
        if st[0] >= cost:
            st[0] -= cost
            return True
        return False


def hash_ip(ip: str, salt: str) -> str:
    return hashlib.sha256((salt + ip).encode()).hexdigest()[:16]


def mask_ip(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.x.x"
    return ip[:9] + "…" if len(ip) > 9 else ip
