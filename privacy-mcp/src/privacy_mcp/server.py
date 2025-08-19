from __future__ import annotations
from pathlib import Path
from typing import Optional
import json
import typer

from fastmcp import FastMCP  # If the API version differs, adjust imports per fastmcp docs.

from privacy_mcp.core.policy import Policy
from privacy_mcp.core.sandbox import safe_resolve, allowed_by_policy, read_text_safely
from privacy_mcp.core.pii_detect import detect
from privacy_mcp.core.redact import apply_redactions
from privacy_mcp.core.audit import Auditor

app = FastMCP("local-privacy-guardian")
cli_app = typer.Typer(add_completion=False)

POLICY_FILE = Path("policy.json")
AUDIT_FILE = Path("logs/requests.jsonl")

policy = Policy(POLICY_FILE)
auditor = Auditor(AUDIT_FILE)

# ---------- Tools ----------

@app.tool
def get_policy() -> dict:
    """Return the current enforcement policy."""
    auditor.log({"tool": "get_policy"})
    return policy.data

@app.tool
def set_policy(patch: dict) -> dict:
    """Update policy with a partial patch; returns the new policy."""
    newp = policy.patch(patch or {})
    auditor.log({"tool": "set_policy", "keys": list((patch or {}).keys())})
    return newp

@app.tool
def list_dir(relpath: str = "") -> dict:
    """List files/dirs under the sandbox root (policy-filtered)."""
    pol = policy.data
    base = safe_resolve(relpath or ".", pol["root_dir"])
    if not base.is_dir():
        raise FileNotFoundError("Not a directory")
    items = []
    for child in sorted(base.iterdir()):
        if child.is_file() and allowed_by_policy(child, pol):
            rel = child.relative_to(pol["root_dir"]).as_posix()
            items.append({"name": child.name, "relpath": rel, "uri": f"privacy://{rel}"})
        elif child.is_dir():
            items.append({"name": child.name + "/", "relpath": child.relative_to(pol["root_dir"]).as_posix(), "dir": True})
    auditor.log({"tool": "list_dir", "relpath": relpath, "returned": len(items)})
    return {"root": pol["root_dir"], "items": items}

@app.tool
def scan_text(text: str) -> dict:
    """Scan raw text for likely PII and return findings with offsets."""
    pol = policy.data
    findings = detect(text, pol.get("use_presidio", False), pol.get("presidio_entities", []))
    auditor.log({"tool": "scan_text", "findings": len(findings)})
    return {"findings": findings}

@app.tool
def safe_read_file(relpath: str, max_bytes: Optional[int] = None, redact: Optional[bool] = None) -> dict:
    """
    Read a text file within the sandbox, enforcing policy and optional redaction.
    Returns: {content, snipped, findings, redactions}
    """
    pol = policy.data
    path = safe_resolve(relpath, pol["root_dir"])
    if not path.exists() or not path.is_file():
        raise FileNotFoundError("File not found")
    if not allowed_by_policy(path, pol):
        auditor.log({"tool": "safe_read_file", "relpath": relpath, "denied": True})
        raise PermissionError("Access denied by policy")

    content, snipped = read_text_safely(path, max_bytes or pol["max_bytes"])
    findings = detect(content, pol.get("use_presidio", False), pol.get("presidio_entities", []))
    do_redact = pol["redact_on_read"] if redact is None else redact
    redactions = 0
    if do_redact and findings:
        content, redactions = apply_redactions(content, findings, token=pol["redaction_token"])

    auditor.log({
        "tool": "safe_read_file",
        "relpath": relpath,
        "snipped": snipped,
        "findings": len(findings),
        "redactions": redactions
    })
    return {"content": content, "snipped": snipped, "findings": findings, "redactions": redactions}

@app.tool
def copy_redacted_file(relpath: str, out_relpath: Optional[str] = None) -> dict:
    """Create a redacted copy in ./redacted and return the new path + findings."""
    pol = policy.data
    src = safe_resolve(relpath, pol["root_dir"])
    if not src.exists() or not src.is_file():
        raise FileNotFoundError("Source not found")
    if not allowed_by_policy(src, pol):
        raise PermissionError("Access denied by policy")

    text, _ = read_text_safely(src, pol["max_bytes"])
    findings = detect(text, pol.get("use_presidio", False), pol.get("presidio_entities", []))
    redacted, count = apply_redactions(text, findings, token=pol["redaction_token"])
    out_dir = Path("redacted"); out_dir.mkdir(exist_ok=True)
    dest = out_dir / (out_relpath or (src.name + ".redacted.txt"))
    dest.write_text(redacted, encoding="utf-8")
    auditor.log({"tool": "copy_redacted_file", "src": relpath, "dest": str(dest), "redactions": count})
    return {"dest": str(dest), "redactions": count, "findings": findings}

# ---------- Resources ----------

@app.resource("privacy://{relpath}")
def resource_file(relpath: str) -> str:
    """Sanitized, read-only view of a file via resource URI."""
    data = safe_read_file(relpath)
    return data["content"]

# ---------- CLI ----------
def cli():
    """
    Runs the server. Flags:
      --demo       Use demo/policy.json (and create if missing)
      --http PORT  (optional) run HTTP transport instead of stdio
    """
    import sys
    import os
    
    # Set working directory to script location
    script_dir = Path(__file__).parent.parent.parent
    os.chdir(script_dir)
    
    if "--help" in sys.argv or "-h" in sys.argv:
        print(cli.__doc__)
        return

    demo = "--demo" in sys.argv
    if demo and not POLICY_FILE.exists():
        try:
            demo_policy = json.loads(Path("demo/policy.json").read_text(encoding="utf-8"))
            POLICY_FILE.write_text(json.dumps(demo_policy, indent=2), encoding="utf-8")
            data = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
            data["root_dir"] = str(Path(data["root_dir"]).resolve())
            POLICY_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"Error setting up demo policy: {e}", file=sys.stderr)

    # Always use stdio for MCP - ignore HTTP arguments
    try:
        app.run(transport="stdio")
    except Exception as e:
        print(f"Error running server: {e}", file=sys.stderr)
        raise

# Typer wrapper (exposes `privacy-mcp`)
def _main():
    cli()

if __name__ == "__main__":
    _main()
