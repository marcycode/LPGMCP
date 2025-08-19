from __future__ import annotations
import re
import presidio_analyzer
from typing import List, Dict

REGEXES = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "PHONE": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "CAN_SIN": re.compile(r"\b\d{3}[- ]?\d{3}[- ]?\d{3}\b"),
}

def detect_regex(text: str) -> List[Dict]:
    findings = []
    for label, rx in REGEXES.items():
        for m in rx.finditer(text):
            findings.append({"entity": label, "start": m.start(), "end": m.end(), "match": m.group(0)})
    return findings

def detect_presidio(text: str, entities: list[str]) -> List[Dict]:
    try:
        from presidio_analyzer import AnalyzerEngine
    except Exception:
        return []
    engine = AnalyzerEngine()
    res = engine.analyze(text=text, entities=entities, language="en")
    return [{"entity": r.entity_type, "start": r.start, "end": r.end, "match": text[r.start:r.end]} for r in res]

def detect(text: str, use_presidio: bool, entities: list[str]) -> List[Dict]:
    return detect_presidio(text, entities) if use_presidio else detect_regex(text)
