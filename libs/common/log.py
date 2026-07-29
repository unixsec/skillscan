"""Structured, secret-redacting logging (coding spec §8: 无密钥入日志).

SECURITY: every logger returned by `get_logger` has a `RedactionFilter` attached.
Pass structured context via `extra={"context": {...}}` - sensitive keys in that
mapping are redacted, and secret-shaped substrings (bearer tokens, Authorization
headers, `scheme://user:pass@host` URL credentials) are scrubbed from the
rendered message as defense in depth.

LEVEL (2026-07-29): `get_logger` sets an EXPLICIT level on every logger it
returns. Until this was fixed it attached the filter, attached a handler with
the JSON formatter and set `propagate = False` - but never called `setLevel`.
Python then resolved each logger's effective level by walking to the first
ancestor that had one, i.e. the root logger's default WARNING, so every
`.info(...)` call returned at `isEnabledFor` and the handler it had just been
given was never consulted. Nineteen INFO call sites across the monolith and the
engine-runner - OIDC/SAML/M2M/local-account auth outcomes, the background
worker loop, the per-engine `{scan_id, engine, status, finding_count}` record -
had therefore never emitted a single line in any deployment, with no signal
that a whole severity level was missing. Every individual line looked correct;
the level check upstream of all of them was the defect. Never inherit the level
here: set it, and make a bad setting say so out loud.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

# Read once per `get_logger` call (each module calls it once at import), so a
# process picks up whatever the env said at startup without any import-order
# dependency on a settings object. Deliberately NOT threaded through
# `apps/monolith/config.Settings` or `engine_runner.main._settings_from_env`:
# those are two separate processes with two separate settings objects, both
# constructed long after the module-level `_logger = get_logger(...)` lines
# have already run, so a settings-carried level could not reach the loggers
# that need it without making every logger lazy. One env var read at the single
# chokepoint both processes already share is simpler and cannot desynchronize.
_LEVEL_ENV_VAR = "SKILLSCAN_LOG_LEVEL"
_DEFAULT_LEVEL = logging.INFO

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
        # SECURITY (2026-07-29): `gate_outbox`'s `verdict_issued` payload carries
        # the signed verdict itself under the key `jws` (modules/gate/service.py),
        # and integration_relay's log-only branch logs that payload verbatim -
        # a branch that is taken for EVERY verdict whenever no marketplace
        # adapter is configured, not only for exotic event types. `jwt` was
        # already listed; this codebase spells it `jws`, so the key that
        # actually exists was the one not covered. `jws_signature` is the
        # `verdict` table's column name for the same value.
        "jws",
        "jws_signature",
        "signature",
        "code_verifier",
        "code_challenge",
    }
)
# Keys whose value is a URL/DSN: fully redacting them would destroy the
# diagnostic ("which Redis am I talking to?") that makes them worth logging, so
# only the `user:pass@` userinfo is stripped. See `_URL_USERINFO_RE`.
_URL_KEY_SUFFIXES = ("_url", "_dsn", "_uri", "_endpoint")
_REDACTED = "***REDACTED***"

_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_AUTH_HEADER_RE = re.compile(r"(?i)\bAuthorization:\s*.+")
# `scheme://` then anything up to an `@` that is still inside the authority
# component - the character class excludes `/?#`, so a path like
# `https://host/a@b` cannot match across the slash.
_URL_USERINFO_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/?#@]*@")


def redact_url_credentials(url: str) -> str:
    """Strip `user:pass@` userinfo from a URL, keeping scheme/host/path.

    SECURITY (2026-07-29): the Helm chart's own Redis requires auth and both
    Deployments splice the password into `SKILLSCAN_REDIS_URL` themselves
    (`redis://:$(REDIS_PASSWORD)@host/db`, see monolith-deployment.yaml). The
    engine-runner's startup line logs that setting, so on any real deployment
    the Redis password would land in `kubectl logs` in cleartext the moment
    INFO records started being emitted.
    """
    return _URL_USERINFO_RE.sub(rf"\g<1>{_REDACTED}@", url)


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact sensitive keys in a mapping intended for logging."""
    result: dict[str, Any] = {}
    for key, value in data.items():
        lowered = key.lower()
        if isinstance(value, dict):
            result[key] = redact_mapping(value)
        elif lowered in _SENSITIVE_KEYS:
            result[key] = _REDACTED
        elif isinstance(value, str) and (
            lowered.endswith(_URL_KEY_SUFFIXES) or lowered in ("url", "dsn", "uri", "endpoint")
        ):
            result[key] = redact_url_credentials(value)
        else:
            result[key] = value
    return result


def redact_text(text: str) -> str:
    """Redact secret-shaped substrings from free-form text before it's logged."""
    text = _BEARER_RE.sub(f"Bearer {_REDACTED}", text)
    text = _AUTH_HEADER_RE.sub(f"Authorization: {_REDACTED}", text)
    text = redact_url_credentials(text)
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


def _resolve_level() -> tuple[int, str | None]:
    """Returns `(level, rejected_raw_value)`; the second item is None when the
    env var was unset or valid.

    NOTSET is rejected rather than honoured: `setLevel(NOTSET)` means "defer to
    an ancestor", which combined with `propagate = False` is precisely the
    silent-drop this module's docstring describes. A logging setting must not
    be able to reintroduce that.
    """
    raw = os.environ.get(_LEVEL_ENV_VAR, "").strip()
    if not raw:
        return _DEFAULT_LEVEL, None
    level = logging.getLevelNamesMapping().get(raw.upper())
    if not isinstance(level, int) or level == logging.NOTSET:
        return _DEFAULT_LEVEL, raw
    return level, None


_bad_level_reported = False


def _report_bad_level_once(logger: logging.Logger, raw: str) -> None:
    """A misconfiguration must be LOUD - the whole point of this fix.

    Not a hard failure: a typo in a logging env var must not be able to stop a
    security gate from starting. Instead the fallback is INFO (never anything
    quieter than the default, so no severity can go missing as a side effect of
    a bad value) plus a WARNING that names the variable and the rejected value.
    WARNING outranks every level a deployment would plausibly set on purpose,
    so the complaint survives whatever the operator was trying to configure.
    """
    global _bad_level_reported
    if _bad_level_reported:
        return
    _bad_level_reported = True
    logger.warning(
        "invalid log level - falling back to INFO",
        extra={
            "context": {
                "metric": "log_level_invalid",
                "variable": _LEVEL_ENV_VAR,
                "rejected_value": raw,
                "valid_values": sorted(
                    name
                    for name, value in logging.getLevelNamesMapping().items()
                    if value != logging.NOTSET
                ),
            }
        },
    )


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
    # Unconditional, and after the handler exists: an explicit level is what
    # makes this logger independent of the root logger's default, and re-setting
    # it on every call keeps two get_logger callers for the same name from
    # depending on which one ran first.
    level, rejected = _resolve_level()
    logger.setLevel(level)
    if rejected is not None:
        _report_bad_level_once(logger, rejected)
    return logger
