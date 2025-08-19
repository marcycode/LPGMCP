from pathlib import Path
from privacy_mcp.core.sandbox import safe_resolve, allowed_by_policy
from privacy_mcp.core.policy import DEFAULT_POLICY as P

def test_safe_resolve():
    root = Path("demo/sandbox").resolve()
    p = safe_resolve("intake_1.txt", str(root))
    assert str(p).startswith(str(root))

def test_allowed():
    root = Path("demo/sandbox").resolve()
    f = (root / "intake_1.txt")
    pol = dict(P, **{"root_dir": str(root)})
    assert allowed_by_policy(f, pol)
