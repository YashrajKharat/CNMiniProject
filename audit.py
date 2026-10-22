"""Audit log: one JSON object per line for every step the healer takes.

Every detection that was acted on, every command, approval, verification
result, rollback and release is written here, so an administrator can see
exactly what the system did and why. The Week 4 dashboard reads this file.
"""
import json
import os
import time
from datetime import datetime

from collector import fix_owner
from config import AUDIT_LOG


class AuditLog:
    def __init__(self, path=AUDIT_LOG):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def write(self, event, **fields):
        now = time.time()
        record = {"time": datetime.fromtimestamp(now).isoformat(timespec="milliseconds"),
                  "epoch": round(now, 3), "event": event}
        record.update(fields)
        with open(self.path, "a") as f:
            f.write(json.dumps(record, default=str) + "\n")
        fix_owner(self.path)
        return record
