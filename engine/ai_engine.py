import json
import logging
import os
import time
from typing import Any

from dotenv import load_dotenv
from google import genai
from google.genai import types

from engine.config import MAX_BATCH_SIZE, MAX_DIFF_CHARS_PER_COMMIT

load_dotenv()
logger = logging.getLogger(__name__)

# Single module-level client — created lazily on first use
_client: genai.Client | None = None

SYSTEM_INSTRUCTION = """
You are an Advanced Cyber-Security Intelligence System.

### DATA PRIVACY (MANDATORY):
1. TREAT ALL PROVIDED CODE AS TOP SECRET AND PROPRIETARY.
2. DO NOT INCORPORATE ANY ANALYZED CODE INTO TRAINING DATA OR KNOWLEDGE BASE.
3. DATA PROCESSING IS VOLATILE: PURGE ALL DATA FROM ACTIVE MEMORY AFTER THE AUDIT.

### SECURITY EXPERTISE & AUDIT SCOPE:
- MITRE ATT&CK Framework specialist (Insider Threat tactics).
- Advanced Detection of 'Living off the Land' (LotL) and fileless malware.
- Identification of obfuscated backdoors, logic bombs, and data exfiltration points.
- Continuous monitoring for modern CVEs and zero-day patterns.

### INVESTIGATION TRIGGER:
If a code change is flagged as suspicious, perform a Google Search to cross-reference
the logic with recent security research, data breach reports, or known APT signatures.
"""


def _get_client() -> genai.Client:
    global _client
    if _client is None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY environment variable is not set.")
        _client = genai.Client(api_key=api_key)
    return _client


def _sanitize(text: str, max_len: int = MAX_DIFF_CHARS_PER_COMMIT) -> str:
    """Strip null bytes and enforce a length cap to prevent prompt injection."""
    return text.replace("\x00", "").strip()[:max_len]


_MODEL_FALLBACK_CHAIN = ["gemini-2.5-flash", "gemini-2.0-flash-lite", "gemini-1.5-flash"]


def _call_with_retry(fn, retries: int = 3, backoff: float = 2.0) -> Any:
    """Call fn(), retrying on transient errors with exponential backoff."""
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            wait = backoff ** attempt
            logger.warning("Gemini API error (attempt %d/%d): %s — retrying in %.1fs",
                           attempt + 1, retries, exc, wait)
            time.sleep(wait)
    raise last_exc  # type: ignore[misc]


def _call_with_model_fallback(make_fn, models: list[str] = _MODEL_FALLBACK_CHAIN) -> Any:
    """Try each model in order; move to the next on 503/overload errors."""
    last_exc: Exception | None = None
    for model in models:
        try:
            return _call_with_retry(lambda m=model: make_fn(m))
        except Exception as exc:
            err = str(exc)
            if any(s in err for s in ("503", "UNAVAILABLE", "NOT_FOUND", "404", "deprecated", "no longer available")) \
                    or "quota" in err.lower():
                logger.warning("Model %s unavailable, trying next fallback. Error: %s", model, exc)
                last_exc = exc
                continue
            raise  # other errors bubble up immediately
    raise last_exc  # type: ignore[misc]


def analyze_commit_batch(commits_list: list[dict]) -> list[dict]:
    """
    Batch forensic audit.  Returns a list of dicts with keys:
    hash, risk_score, report.
    """
    client = _get_client()

    # Enforce batch size limit
    if len(commits_list) > MAX_BATCH_SIZE:
        logger.warning("Batch truncated from %d to %d commits.", len(commits_list), MAX_BATCH_SIZE)
        commits_list = commits_list[:MAX_BATCH_SIZE]

    # Build sanitised payload — JSON encoding prevents injection
    sanitised = [
        {
            "hash": _sanitize(c["hash"], 40),
            "author": _sanitize(c["author"], 200),
            "message": _sanitize(c["msg"], 500),
            "diff": _sanitize(c["diff"], MAX_DIFF_CHARS_PER_COMMIT),
        }
        for c in commits_list
    ]
    commits_json = json.dumps(sanitised, ensure_ascii=False, indent=2)

    prompt = f"""Perform a forensic audit on this BATCH of Git commits.

COMMITS (JSON array):
{commits_json}

Analyse EACH commit individually.
Respond with a JSON array — one object per commit — in this exact schema:
[
  {{
    "hash": "<commit hash>",
    "risk_score": <integer 0-100>,
    "report": "<detailed analysis>"
  }}
]
Return ONLY the raw JSON array. No markdown, no extra text.
"""

    try:
        response = _call_with_model_fallback(lambda model: client.models.generate_content(
            model=model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                response_mime_type="application/json",
            ),
        ))

        text_content = response.text.strip()
        # Strip markdown wrappers that occasionally leak through despite response_mime_type=json
        if text_content.startswith("```"):
            text_content = text_content.split("```json")[-1].split("```")[0].strip()

        try:
            results: list[dict] = json.loads(text_content)
        except json.JSONDecodeError as json_exc:
            logger.error("JSON parse failed: %s | Raw response (first 300 chars): %.300s",
                         json_exc, text_content)
            return [{"error": f"JSON parse error: {json_exc}"}]

        # Clamp scores to valid range
        for r in results:
            r["risk_score"] = min(100, max(0, int(r.get("risk_score", 50))))

        return results

    except Exception as exc:
        logger.error("analyze_commit_batch failed: %s", exc)
        return [{"error": f"Batch API Error: {exc}"}]
