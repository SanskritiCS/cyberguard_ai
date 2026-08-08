"""
Secure structured logging.

- Never prints the Gemini API key or anything that looks like one.
- Emits a consistent, greppable line format:
  timestamp | LEVEL | logger.name | event message | key=value ...
"""

from __future__ import annotations

import logging
import re
import sys

from config import settings

# Patterns that could leak secrets if a key ever ended up in a log message
# (e.g. via an exception's str(), a raw URL, etc.). We redact defensively
# even though the app is written to never log the key directly.
_SECRET_PATTERNS = [
    re.compile(r"(AIza[0-9A-Za-z\-_]{20,})"),           # Google API key shape
    re.compile(r"([?&]key=)([^&\s]+)", re.IGNORECASE),  # ?key=... in URLs
]


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        for pattern in _SECRET_PATTERNS:
            if pattern.groups == 2:
                message = pattern.sub(r"\1***REDACTED***", message)
            else:
                message = pattern.sub("***REDACTED***", message)
        return message


_CONFIGURED_LOGGERS: set[str] = set()


def get_logger(name: str) -> logging.Logger:
    """Return a module-level logger configured with redaction + level."""
    logger = logging.getLogger(name)
    if name not in _CONFIGURED_LOGGERS:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            RedactingFormatter(fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
        )
        logger.addHandler(handler)
        logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
        logger.propagate = False
        _CONFIGURED_LOGGERS.add(name)
    return logger
