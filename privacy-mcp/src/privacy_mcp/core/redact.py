from __future__ import annotations
from typing import List, Dict, Tuple

def apply_redactions(text: str, findings: List[Dict], token: str="█") -> Tuple[str, int]:
    # replace from end to start to preserve offsets
    sorted_f = sorted(findings, key=lambda f: f["start"], reverse=True)
    out = text
    for f in sorted_f:
        out = out[:f["start"]] + (token * (f["end"] - f["start"])) + out[f["end"]:]
    return out, len(sorted_f)
