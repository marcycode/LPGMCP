from __future__ import annotations
from pathlib import Path
import json, hashlib, time
from typing import Optional

class Auditor:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _sha256(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    def _last_hash(self) -> Optional[str]:
        if not self.path.exists():
            return None
        try:
            *_, last = self.path.read_text(encoding="utf-8").splitlines()
            return json.loads(last).get("hash")
        except Exception:
            return None

    def log(self, event: dict) -> None:
        event = dict(event)
        event["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        prev = self._last_hash()
        payload = json.dumps({k:v for k,v in event.items() if k != "hash"}, ensure_ascii=False)
        event["prev_hash"] = prev
        event["hash"] = self._sha256((prev or "") + payload)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
