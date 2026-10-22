"""Credential vault and small security helpers for the web app.

Device credentials are encrypted with Fernet (AES-128-CBC + HMAC) before they
touch the database. The key lives in data/secret.key (file mode 600), never in
the database, so a copy of the database alone reveals nothing. Lose the key and
the stored credentials cannot be recovered (add the network again).
"""
import ipaddress
import json
import os
import secrets
import time

from cryptography.fernet import Fernet, InvalidToken


def _read_or_create(path, make):
    """Read a secret file, creating it with owner-only permissions the first time."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read().strip()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    value = make()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(value)
    return value


def flask_secret(data_dir):
    return _read_or_create(os.path.join(data_dir, "flask_secret"),
                           lambda: secrets.token_hex(32).encode()).decode()


class Vault:
    def __init__(self, data_dir):
        self._fernet = Fernet(_read_or_create(os.path.join(data_dir, "secret.key"),
                                              Fernet.generate_key))

    def seal(self, obj):
        return self._fernet.encrypt(json.dumps(obj).encode()).decode()

    def unseal(self, token):
        try:
            return json.loads(self._fernet.decrypt(token.encode()))
        except (InvalidToken, ValueError):
            return None


class LoginThrottle:
    """Five failed logins from one address lock it out for a minute."""

    def __init__(self, max_fails=5, lock_s=60):
        self.max_fails, self.lock_s = max_fails, lock_s
        self._state = {}

    def locked_for(self, who):
        fails, until = self._state.get(who, (0, 0))
        left = until - time.time()
        return int(left) + 1 if left > 0 else 0

    def failed(self, who):
        fails, until = self._state.get(who, (0, 0))
        if until and time.time() > until:
            fails = 0
        fails += 1
        self._state[who] = (fails, time.time() + self.lock_s if fails >= self.max_fails else 0)

    def ok(self, who):
        self._state.pop(who, None)


def is_local_path(target):
    """Only follow a `next` redirect that stays on this site."""
    return bool(target) and target.startswith("/") and not target.startswith("//") \
        and "\\" not in target


def parse_devices(text, max_devices=256):
    """'10.0.1.11 h1' per line -> [(ip, name)]. Raises ValueError with a readable message."""
    out, seen = [], set()
    for n, line in enumerate((text or "").splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        try:
            ip = str(ipaddress.ip_address(parts[0]))
        except ValueError:
            raise ValueError(f"line {n}: '{parts[0]}' is not a valid IP address")
        if ip in seen:
            raise ValueError(f"line {n}: {ip} is listed twice")
        seen.add(ip)
        out.append((ip, (parts[1] if len(parts) > 1 else "")[:40]))
        if len(out) > max_devices:
            raise ValueError(f"at most {max_devices} devices")
    return out
