from __future__ import annotations
from pathlib import Path
import json

DEFAULT_POLICY = {
    "root_dir": str(Path("demo/sandbox").resolve()),
    "allow_globs": ["**/*.txt", "**/*.md", "**/*.json"],
    "deny_globs": ["**/.env", "**/.git/**", "**/node_modules/**"],
    "allow_extensions": [".txt", ".md", ".json"],
    "deny_extensions": [".pem", ".key", ".pfx", ".crt"],
    "max_bytes": 2_000_000,
    "redact_on_read": True,
    "use_presidio": False,
    "presidio_entities": ["PERSON","EMAIL_ADDRESS","PHONE_NUMBER","CREDIT_CARD","LOCATION"],
    "redaction_token": "█",
}

class Policy:
    def __init__(self, path: Path):
        self.path = path
        self._data = DEFAULT_POLICY.copy()
        if path.exists():
            self._data.update(json.loads(path.read_text(encoding="utf-8")))

    @property
    def data(self) -> dict:
        return self._data

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")

    def patch(self, patch: dict) -> dict:
        self._data.update(patch or {})
        self.save()
        return self._data
