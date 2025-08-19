from __future__ import annotations
from pathlib import Path, PurePosixPath
from fnmatch import fnmatch

def safe_resolve(relpath: str, root_dir: str) -> Path:
    root = Path(root_dir).resolve()
    p = (root / relpath).resolve()
    if not str(p).startswith(str(root)):
        raise PermissionError("Path escapes sandbox root")
    return p

def _matches_any(rel: PurePosixPath, patterns: list[str]) -> bool:
    s = rel.as_posix()
    return any(fnmatch(s, pat) for pat in patterns)

def allowed_by_policy(path: Path, policy: dict) -> bool:
    if path.suffix in policy.get("deny_extensions", []):
        return False
    allow_exts = policy.get("allow_extensions") or []
    if allow_exts and path.suffix not in allow_exts:
        return False
    rel = PurePosixPath(path.relative_to(policy["root_dir"]).as_posix())
    if _matches_any(rel, policy.get("deny_globs", [])):
        return False
    allow_globs = policy.get("allow_globs") or []
    return True if not allow_globs else _matches_any(rel, allow_globs)

def read_text_safely(path: Path, max_bytes: int) -> tuple[str, bool]:
    raw = path.read_bytes()
    snipped = False
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
        snipped = True
    return raw.decode("utf-8", errors="replace"), snipped
