"""Structured, secret-redacting logging (coding spec §8: 无密钥入日志).

SECURITY: every logger returned by `get_logger` has a `RedactionFilter` attached.
Pass structured context via `extra={"context": {...}}` - sensitive keys in that
mapping are redacted, and secret-shaped substrings (bearer tokens, Authorization
headers) are scrubbed from the rendered message as defense in depth.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "authorization",
        "cookie",
        "api_key",
        "apikey",
        "private_key",
        "client_secret",
        "jwt",
        "code_verifier",
        "code_challenge",
    }
)
_REDACTED = "***REDACTED***"

_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_AUTH_HEADER_RE = re.compile(r"(?i)\bAuthorization:\s*.+")


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact sensitive keys in a mapping intended for logging."""
    result: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            result[key] = redact_mapping(value)
        elif key.lower() in _SENSITIVE_KEYS:
            result[key] = _REDACTED
        else:
            result[key] = value
    return result


def redact_text(text: str) -> str:
    """Redact secret-shaped substrings from free-form text before it's logged."""
    text = _BEARER_RE.sub(f"Bearer {_REDACTED}", text)
    text = _AUTH_HEADER_RE.sub(f"Authorization: {_REDACTED}", text)
    return text


class RedactionFilter(logging.Filter):
    """SECURITY: scrubs a LogRecord's plain-string msg and `context` extra before
    any handler emits it."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        context = getattr(record, "context", None)
        if isinstance(context, dict):
            record.context = redact_mapping(context)
        return True


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = redact_text(record.getMessage())
        payload: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": message,
        }
        context = getattr(record, "context", None)
        if context:
            payload["context"] = context
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not any(isinstance(f, RedactionFilter) for f in logger.filters):
        logger.addFilter(RedactionFilter())
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(_JsonFormatter())
        handler.addFilter(RedactionFilter())
        logger.addHandler(handler)
        logger.propagate = False
    return logger
