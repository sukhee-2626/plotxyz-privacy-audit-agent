"""Original deterministic implementation for Privacy Audit (plotxyz-privacy-audit-agent)."""
from __future__ import annotations

import ast
import csv
import io
import json
import math
import os
import re
import statistics
import time
from collections import Counter, defaultdict, deque


class LogicError(ValueError):
    """Raised when supplied input cannot be processed."""


def _text(payload, key, min_len=1, max_len=20000):
    value = payload.get(key)
    if not isinstance(value, str):
        raise LogicError(f"'{key}' must be a string")
    value = value.strip()
    if len(value) < min_len:
        raise LogicError(f"'{key}' is required")
    if len(value) > max_len:
        raise LogicError(f"'{key}' exceeds {max_len} characters")
    return value


def _num(payload, key, default=None, lo=None, hi=None):
    value = payload.get(key, default)
    if value is None or value == "":
        if default is None:
            raise LogicError(f"'{key}' is required")
        return default
    if isinstance(value, bool):
        raise LogicError(f"'{key}' must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise LogicError(f"'{key}' must be numeric")
    if lo is not None and number < lo:
        raise LogicError(f"'{key}' must be at least {lo}")
    if hi is not None and number > hi:
        raise LogicError(f"'{key}' must be at most {hi}")
    return number


def _json(payload, key, expected=None, max_len=200000):
    raw = payload.get(key)
    if isinstance(raw, (dict, list)):
        data = raw
    elif isinstance(raw, str):
        if len(raw) > max_len:
            raise LogicError(f"'{key}' exceeds {max_len} characters")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LogicError(f"'{key}' is not valid JSON: {exc.msg} at line {exc.lineno}")
    else:
        raise LogicError(f"'{key}' must be JSON")
    if expected is not None and not isinstance(data, expected):
        name = expected.__name__ if hasattr(expected, "__name__") else str(expected)
        raise LogicError(f"'{key}' must be a JSON {name}")
    return data


def _csv(payload, key, max_rows=5000):
    text = _text(payload, key, max_len=2000000)
    try:
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise LogicError(f"'{key}' must include a header row")
        columns = [str(c).strip() for c in reader.fieldnames if c and str(c).strip()]
        if not columns:
            raise LogicError(f"'{key}' must include named columns")
        rows = []
        for index, raw in enumerate(reader):
            if index >= max_rows:
                raise LogicError(f"'{key}' exceeds {max_rows} rows")
            rows.append({col: (raw.get(col) or "").strip() for col in columns})
    except csv.Error as exc:
        raise LogicError(f"'{key}' is not valid CSV: {exc}")
    if not rows:
        raise LogicError(f"'{key}' must include at least one data row")
    return columns, rows


STOPWORDS = {'will', 'they', 'was', 'your', 'than', 'that', 'on', 'be', 'then', 'do', 'our', 'with', 'he', 'is', 'about', 'had', 'were', 'as', 'may', 'we', 'their', 'are', 'did', 'at', 'she', 'a', 'by', 'the', 'if', 'might', 'it', 'into', 'have', 'from', 'should', 'not', 'over', 'can', 'for', 'and', 'an', 'you', 'does', 'to', 'this', 'could', 'would', 'under', 'of', 'no', 'its', 'in', 'i', 'or', 'has'}


def _tokens(text):
    return [w for w in re.findall(r"[a-z0-9][a-z0-9_+-]{1,}", text.lower()) if w not in STOPWORDS]


def _sentences(text):
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    return [p.strip(" -•\t") for p in parts if len(p.strip()) > 2]


def provider_status():
    """Report which optional model providers are configured (never exposes secrets)."""
    ollama = bool(os.getenv("OLLAMA_BASE_URL"))
    openai = bool(os.getenv("OPENAI_BASE_URL") and os.getenv("OPENAI_MODEL"))
    return {"ollama_compatible": ollama, "openai_compatible": openai}


def _llm(messages, temperature=0.2):
    """Call an explicitly configured OpenAI-compatible endpoint; return None when unavailable."""
    base = os.getenv("OPENAI_BASE_URL", "").rstrip("/")
    model = os.getenv("OPENAI_MODEL", "")
    if not base or not model:
        ollama = os.getenv("OLLAMA_BASE_URL", "").rstrip("/")
        if not ollama:
            return None
        base = f"{ollama}/v1"
        model = os.getenv("OLLAMA_MODEL", "")
    if not model:
        return None
    try:
        import httpx

        headers = {"Content-Type": "application/json"}
        key = os.getenv("OPENAI_API_KEY")
        if key:
            headers["Authorization"] = f"Bearer {key}"
        with httpx.Client(timeout=20) as client:
            response = client.post(
                f"{base}/chat/completions",
                headers=headers,
                json={"model": model, "messages": messages, "temperature": temperature},
            )
            response.raise_for_status()
            return str(response.json()["choices"][0]["message"]["content"]).strip()
    except Exception:
        return None


def _result(summary, result, warnings=None):
    return {"summary": summary, "result": result, "warnings": warnings or []}


def agent_privacy_audit(payload):
    config = _text(payload, "config", max_len=60000)
    flow = str(payload.get("data_flow", "")).strip()
    haystack = config + "\n" + flow
    patterns = [
        ("Email address", r"[\w.+-]+@[\w-]+\.[\w.]+", "high", "Personal identifiers may be stored or transmitted."),
        ("API key or cloud token", r"(sk-[A-Za-z0-9]{8,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})", "high", "A credential-like value is present in the supplied text."),
        ("Sensitive field name", r"\b(password|secret|token|ssn|credit_card|date_of_birth|dob)\b", "high", "Sensitive fields need encryption, minimization, and access control."),
        ("Plain HTTP endpoint", r"http://[^\s\"']+", "medium", "Traffic over plain HTTP can be intercepted."),
        ("Telemetry or analytics", r"\b(telemetry|analytics|tracking|sentry|segment|mixpanel)\b", "medium", "Telemetry can reveal usage patterns; confirm consent and retention."),
        ("Third-party endpoint", r"https?://([\w.-]+)", "low", "Review each external destination and its data-processing terms."),
        ("Logging of payloads", r"\b(log|logging|logger)\b[^\n]{0,40}\b(payload|body|request|response)\b", "medium", "Request logging may capture personal data."),
    ]
    findings, rows = [], []
    score = 100
    for label, pattern, severity, detail in patterns:
        matches = re.findall(pattern, haystack, re.I)
        count = len(matches)
        if count:
            examples = sorted({m if isinstance(m, str) else str(m) for m in matches})[:3]
            score -= {"high": 18, "medium": 9, "low": 3}[severity] * min(count, 3)
            findings.append({"title": label, "severity": severity, "detail": f"{detail} Found {count} match(es), e.g. {', '.join(examples)[:160]}."})
        rows.append([label, count, severity, "review" if count else "clear"])
    score = max(0, min(100, score))
    if not flow:
        findings.append({"title": "Data-flow description missing", "severity": "low", "detail": "Add sources, transforms, storage, and destinations for a fuller review."})
    return _result(
        f"Static privacy review found {len(findings)} item(s); heuristic score {score}/100.",
        {
            "metrics": {"score": score, "findings": len(findings), "high_severity": sum(1 for f in findings if f["severity"] == "high")},
            "findings": findings,
            "table": {"columns": ["Check", "Matches", "Severity", "Status"], "rows": rows},
        },
        ["This is a static text heuristic, not a compliance certification or legal advice."],
    )


run = agent_privacy_audit
