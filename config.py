"""
Centralized application configuration.

Loads all runtime configuration from environment variables (via a local
.env file in development). No secrets are hard-coded anywhere in the
codebase — the Gemini API key lives ONLY in .env / real environment
variables and is never logged, returned in responses, or committed to
source control.
"""

from __future__ import annotations

import os
from typing import List

from dotenv import load_dotenv

# Load variables from a .env file if present. In production, real
# environment variables (set by the host/orchestrator) simply take
# precedence and .env is not required.
load_dotenv()


def _split_csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings:
    # --- Gemini AI ---------------------------------------------------
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
    GEMINI_TIMEOUT_SECONDS: float = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "20"))

    # --- App / environment --------------------------------------------
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")  # development | production

    # --- CORS -----------------------------------------------------------
    # Comma-separated list of allowed origins. Defaults cover local dev;
    # add your real production domain(s) in .env, e.g.:
    #   CORS_ORIGINS=https://cyberguard.example.com,https://www.cyberguard.example.com
    CORS_ORIGINS: List[str] = _split_csv(
        os.getenv(
            "CORS_ORIGINS",
            "http://localhost:3000,http://localhost:5173,http://localhost:8000,"
            "http://127.0.0.1:8000",
        )
    )

    # --- Rate limiting (applies to AI endpoints only) -------------------
    RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "10"))
    RATE_LIMIT_WINDOW_SECONDS: int = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

    # --- Logging ----------------------------------------------------------
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"


settings = Settings()
