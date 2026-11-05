"""Local web users and roles.

Roles: analyst (run reports, give feedback, record tests), approver (+ approve rules), admin (+ all).
Passwords are stored as salted PBKDF2-SHA256 hashes in <state_dir>/users.json. For production,
put the web UI behind your SSO reverse proxy and keep this as a break-glass list.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path

ROLES = ("analyst", "approver", "admin")
_ITER = 310_000
# Basic auth resends the password on every request (static files, 1.5s job polling); remembering recent
# successful checks keeps PBKDF2 to about one per user per TTL. The key covers the stored hash, so a
# password change or removal invalidates it.
_OK_TTL_S = 300
_OK_MAX = 256


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITER)
    return f"pbkdf2_sha256${_ITER}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt, digest = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(iters))
        return algo == "pbkdf2_sha256" and hmac.compare_digest(base64.b64encode(dk).decode(), digest)
    except (ValueError, TypeError):
        return False


class Users:
    def __init__(self, state_dir: str | Path):
        self.path = Path(state_dir) / "users.json"
        self._ok: dict[bytes, float] = {}   # sha256(name, password, stored hash) -> expiry
        self._ok_lock = threading.Lock()

    def _read(self) -> dict:
        return json.loads(self.path.read_text()) if self.path.is_file() else {}

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1))
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    def any(self) -> bool:
        return bool(self._read())

    def add(self, name: str, password: str, role: str) -> None:
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        if len(password) < 12:
            raise ValueError("password must be at least 12 characters")
        data = self._read()
        data[name] = {"hash": hash_password(password), "role": role}
        self._write(data)

    def remove(self, name: str) -> bool:
        data = self._read()
        if data.pop(name, None) is None:
            return False
        self._write(data)
        return True

    def list(self) -> dict[str, str]:
        return {n: u["role"] for n, u in self._read().items()}

    def authenticate(self, name: str, password: str) -> str | None:
        """Role on success, else None (constant-time on the password check)."""
        u = self._read().get(name)
        if u is None:
            hash_password(password, b"\0" * 16)   # equalise timing for unknown users
            return None
        key = hashlib.sha256("\0".join((name, password, u["hash"])).encode()).digest()
        now = time.monotonic()
        with self._ok_lock:
            if self._ok.get(key, 0) > now:
                return u["role"]
        if not verify_password(password, u["hash"]):
            return None
        with self._ok_lock:
            if len(self._ok) >= _OK_MAX:
                self._ok = {k: t for k, t in self._ok.items() if t > now}
                while len(self._ok) >= _OK_MAX:
                    self._ok.pop(next(iter(self._ok)))   # oldest first
            self._ok[key] = now + _OK_TTL_S
        return u["role"]
