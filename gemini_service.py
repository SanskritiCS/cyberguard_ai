
"""
Google Gemini integration — backend-only.
"""

from __future__ import annotations

import logging
import httpx
from dotenv import load_dotenv
from config import settings

load_dotenv()

logger = logging.getLogger(__name__)

GEMINI_ENDPOINT = ( 
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)

SYSTEM_INSTRUCTION = (
    "You are CyberGuard AI, the built-in assistant of a cybersecurity toolkit "
    "web app. The app also includes a URL scanner, QR scanner, camera scanner, "
    "voice fraud analyzer, email analyzer, and an IDS (Suricata-style) monitor. "
    "Answer questions about phishing, malware, passwords, VPNs, network safety, "
    "and how to use these tools. Keep responses clear, practical, and concise "
    "(a few short paragraphs at most). Never provide instructions that would "
    "help someone carry out an attack."
)


class GeminiServiceError(Exception):
    """Raised when the Gemini API is unavailable, misconfigured, or errors."""


async def generate_reply(message: str) -> str:
    """Send a message to Gemini and return the generated reply."""

    if not settings.GEMINI_API_KEY:
        raise GeminiServiceError("AI service is not configured.")

    url = GEMINI_ENDPOINT.format(model=settings.GEMINI_MODEL)
    params = {"key": settings.GEMINI_API_KEY}

    body = {
        "systemInstruction": {
            "parts": [
                {
                    "text": SYSTEM_INSTRUCTION
                }
            ]
        },
        "contents": [
            {
                "parts": [
                    {
                        "text": message
                    }
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.4,
            "maxOutputTokens": 4096
        }
    }

    try:
        async with httpx.AsyncClient( timeout=settings.GEMINI_TIMEOUT_SECONDS) as client:
            response = await client.post(url, params=params, json=body)

            # Debug output (terminal me dikhega)
            print("STATUS:", response.status_code)
            print("BODY:", response.text)

    except httpx.TimeoutException as exc:
        raise GeminiServiceError("The AI service timed out.") from exc

    except httpx.RequestError as exc:
        raise GeminiServiceError("Could not reach the AI service.") from exc

    # Google API error
    if response.status_code != 200:
        raise GeminiServiceError(
            f"Status {response.status_code}: {response.text}"
        )

    # Parse response
    try:
        data = response.json()
        candidates = data.get("candidates") or []

        if not candidates:
            raise GeminiServiceError("No candidates returned by Gemini.")

        parts = candidates[0]["content"]["parts"]
        text = "".join(part.get("text", "") for part in parts).strip()

    except Exception as exc:
        raise GeminiServiceError(
            f"Unexpected AI response format: {exc}"
        ) from exc

    if not text:
        raise GeminiServiceError("The AI service returned an empty response.")

    return text


async def analyze_image_with_gemini(image_bytes: bytes, mime_type: str = "image/jpeg") -> dict:
    """
    Send an actual image to Gemini Vision API for authenticity analysis.
    
    Returns a structured dict with classification, confidence, risk_level,
    explanation, and signals — all derived from actual image analysis.
    """
    import base64
    import json

    if not settings.GEMINI_API_KEY:
        raise GeminiServiceError("AI service is not configured (no API key).")

    image_b64 = base64.b64encode(image_bytes).decode("utf-8")

    url = GEMINI_ENDPOINT.format(model=settings.GEMINI_MODEL)
    params = {"key": settings.GEMINI_API_KEY}

    analysis_prompt = (
        "You are an image forensics expert. Analyze this image for signs of "
        "AI generation, manipulation, or editing.\n\n"
        "Examine:\n"
        "- Texture consistency and unnatural smoothness\n"
        "- Fine detail quality (hair, fingers, text, edges)\n"
        "- Lighting and shadow consistency\n"
        "- Background coherence and artifacts\n"
        "- Repeating patterns or symmetry anomalies\n"
        "- Compression artifacts and noise distribution\n"
        "- Whether this looks like a natural photograph or synthetic image\n\n"
        "Respond ONLY with valid JSON in exactly this format, no markdown:\n"
        '{"classification":"<one of: Likely Real, Likely AI-Generated, Likely Manipulated, Inconclusive>",'
        '"confidence":<integer 0-100>,'
        '"risk_level":"<one of: Low, Medium, High>",'
        '"explanation":"<1-2 sentence explanation>",'
        '"signals":["<signal 1>","<signal 2>","<signal 3>"]}\n\n'
        "IMPORTANT RULES:\n"
        "- confidence must reflect genuine uncertainty. Do NOT always say 90+.\n"
        "- If you truly cannot tell, use Inconclusive with confidence 40-60.\n"
        "- signals must describe what you actually observe in THIS specific image.\n"
        "- Do NOT invent signals you don't see. Be honest about uncertainty."
    )

    body = {
        "contents": [
            {
                "parts": [
                    {
                        "inlineData": {
                            "mimeType": mime_type,
                            "data": image_b64
                        }
                    },
                    {
                        "text": analysis_prompt
                    }
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 1024
        }
    }

    try:
        async with httpx.AsyncClient(timeout=settings.GEMINI_TIMEOUT_SECONDS) as client:
            response = await client.post(url, params=params, json=body)
    except httpx.TimeoutException as exc:
        raise GeminiServiceError("Image analysis timed out.") from exc
    except httpx.RequestError as exc:
        raise GeminiServiceError("Could not reach the AI service.") from exc

    if response.status_code != 200:
        raise GeminiServiceError(
            f"Gemini Vision error {response.status_code}: {response.text[:300]}"
        )

    try:
        data = response.json()
        candidates = data.get("candidates") or []
        if not candidates:
            raise GeminiServiceError("No candidates returned by Gemini Vision.")

        parts = candidates[0]["content"]["parts"]
        raw_text = "".join(part.get("text", "") for part in parts).strip()

        # Strip markdown code fences if present
        if raw_text.startswith("```"):
            raw_text = raw_text.split("\n", 1)[-1]
        if raw_text.endswith("```"):
            raw_text = raw_text.rsplit("```", 1)[0]
        raw_text = raw_text.strip()

        result = json.loads(raw_text)

        # Validate required fields
        classification = result.get("classification", "Inconclusive")
        valid_classifications = [
            "Likely Real", "Likely AI-Generated", 
            "Likely Manipulated", "Inconclusive"
        ]
        if classification not in valid_classifications:
            classification = "Inconclusive"

        confidence = int(result.get("confidence", 50))
        confidence = max(0, min(100, confidence))

        risk_level = result.get("risk_level", "Medium")
        if risk_level not in ("Low", "Medium", "High"):
            risk_level = "Medium"

        explanation = str(result.get("explanation", "Analysis complete."))
        signals = result.get("signals", [])
        if not isinstance(signals, list):
            signals = []
        signals = [str(s) for s in signals[:8]]

        return {
            "classification": classification,
            "confidence": confidence,
            "risk_level": risk_level,
            "explanation": explanation,
            "signals": signals,
        }

    except json.JSONDecodeError:
        # If Gemini didn't return valid JSON, try to extract what we can
        logger.warning("Gemini returned non-JSON for image analysis: %s", raw_text[:200])
        return {
            "classification": "Inconclusive",
            "confidence": 50,
            "risk_level": "Medium",
            "explanation": "The AI analysis returned an unparseable result.",
            "signals": ["Analysis could not be fully completed"],
        }
    except Exception as exc:
        raise GeminiServiceError(f"Failed to parse image analysis: {exc}") from exc

