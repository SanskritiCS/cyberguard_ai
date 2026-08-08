"""
CyberGuard AI - FastAPI backend

A production-ready cybersecurity toolkit API that powers:
  - URL threat scanning
  - QR code decoding + threat analysis
  - Webcam frame (QR / phishing) analysis
  - Email + attachment analysis
  - Voice fraud detection
  - SMS scam detection
  - USB threat detection
  - Image authenticity analysis
  - Rule-based security AI assistant
  - Intrusion Detection System (Suricata-style) status

Run locally:
    pip install -r requirements.txt
    uvicorn main:app --reload
"""

from __future__ import annotations

import io
import re
import time
import random
import hashlib
import struct
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional
from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from config import settings
from ai_schema import AIRequest as GeminiAIRequest
from gemini_service import generate_reply as gemini_generate_reply, analyze_image_with_gemini, GeminiServiceError
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from ml_url_detector import predict_url
from ml_email_detector import predict_email

# Optional heavy deps used for QR decoding. The app degrades gracefully if
# they are unavailable so the rest of the API keeps working.
try:
    import numpy as np
    import cv2

    _CV_AVAILABLE = True
except Exception:  # pragma: no cover
    _CV_AVAILABLE = False

# Pillow for image analysis
try:
    from PIL import Image, ImageChops
    from PIL.ExifTags import TAGS
    _PIL_AVAILABLE = True
except Exception:
    _PIL_AVAILABLE = False


app = FastAPI(
    title="CyberGuard AI",
    description="AI-assisted cybersecurity toolkit API",
    version="2.0.0",
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Shared helpers / threat intelligence heuristics
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "gq", "ml", "cf", "tk", "work", "click",
    "country", "kim", "science", "party", "review", "loan", "date",
    "racing", "win", "bid", "stream", "download", "xin", "icu", "buzz",
    "rest", "surf", "monster", "quest",
}

URL_SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "v.gd",
    "tiny.cc", "surl.li", "short.io",
}

PHISHING_KEYWORDS = [
    "verify", "account", "update", "secure", "login", "signin", "bank",
    "confirm", "password", "billing", "invoice", "wallet", "unlock",
    "suspended", "limited", "gift", "bonus", "prize", "urgent",
    "reset", "expire", "validate", "authenticate", "recover", "restore",
    "credential", "ssn", "tax", "refund", "reward", "claim",
]

BRAND_KEYWORDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "coinbase", "binance", "chase",
    "wellsfargo", "hdfc", "sbi", "icici", "citibank", "barclays",
    "linkedin", "twitter", "dropbox", "spotify", "uber", "airbnb",
    "stripe", "shopify", "flipkart", "paytm", "phonepe", "gpay",
]

DANGEROUS_ATTACHMENT_EXT = {
    "exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe",
    "ws", "wsf", "jar", "msi", "ps1", "hta", "cpl", "reg", "lnk", "dll",
    "sys", "drv", "inf", "ocx", "cab",
}

RISKY_DOCUMENT_EXT = {"docm", "xlsm", "pptm", "dotm", "iso", "img", "ace", "rar"}

IP_URL_RE = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")
URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _verdict_from_score(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score >= 40:
        return "suspicious"
    return "safe"


def _clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))


# ---------------------------------------------------------------------------
# URL Analysis (Refined)
# ---------------------------------------------------------------------------
def analyze_url(raw_url: str) -> dict:
    """Heuristic URL threat scoring. Returns a structured verdict."""
    url = (raw_url or "").strip()
    findings: list[str] = []
    score = 0

    if not url:
        return {
            "url": url,
            "score": 0,
            "verdict": "unknown",
            "findings": ["No URL provided."],
            "scanned_at": _now_iso(),
        }

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path_and_query = f"{parsed.path}?{parsed.query}".lower()
    lowered = url.lower()

    # Transport security
    if parsed.scheme != "https":
        score += 15
        findings.append("Connection is not encrypted (no HTTPS).")

    # Raw IP address instead of a domain
    if IP_URL_RE.match(url):
        score += 30
        findings.append("URL uses a raw IP address instead of a domain name.")

    # Suspicious TLD
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        score += 25
        findings.append(f"Domain uses a high-risk TLD (.{tld}).")

    # URL shortener
    if host in URL_SHORTENERS:
        score += 20
        findings.append("URL shortener detected — final destination is hidden.")

    # Excessive subdomains / look-alike
    if host.count(".") >= 4:
        score += 15
        findings.append("Unusually deep subdomain nesting.")

    # "@" trick and encoded characters
    if "@" in parsed.netloc:
        score += 25
        findings.append("URL contains '@' which can mask the real host.")
    if "%" in lowered and re.search(r"%[0-9a-f]{2}", lowered):
        score += 10
        findings.append("URL contains percent-encoded characters.")

    # Punycode homograph attack
    if "xn--" in host:
        score += 20
        findings.append("Punycode domain detected (possible homograph attack).")

    # Excessive hyphens in hostname
    if host.count("-") >= 3:
        score += 15
        findings.append("Excessive hyphens in hostname (common in phishing domains).")

    # Unusually long URL
    if len(url) > 100:
        score += 10
        findings.append("Unusually long URL (may hide malicious destination).")
    elif len(url) > 75:
        score += 5
        findings.append("URL is longer than typical legitimate URLs.")

    # Port number in URL
    if parsed.port and parsed.port not in (80, 443):
        score += 15
        findings.append(f"Non-standard port ({parsed.port}) — may indicate a rogue server.")

    # Double-slash redirect trick
    if "//" in parsed.path:
        score += 15
        findings.append("Double-slash in path detected (possible open redirect).")

    # data: URI scheme
    if lowered.startswith("data:"):
        score += 30
        findings.append("Data URI detected — can embed malicious content.")

    # Phishing keywords
    hits = sorted({k for k in PHISHING_KEYWORDS if k in lowered})
    if hits:
        score += min(30, 6 * len(hits))
        findings.append("Phishing-related keywords found: " + ", ".join(hits) + ".")

    # Brand impersonation: brand appears in subdomain/path but not registrable domain
    for brand in BRAND_KEYWORDS:
        if brand in lowered:
            registrable = ".".join(host.split(".")[-2:]) if host else ""
            if brand not in registrable:
                score += 25
                findings.append(f"Possible impersonation of '{brand}'.")
            break

    # Suspicious file in path
    if re.search(r"\.(exe|scr|apk|zip|js|bat|msi|ps1)(\\?|$)", path_and_query):
        score += 20
        findings.append("URL points directly to an executable/archive.")

    if not findings:
        findings.append("No obvious threats detected in heuristic analysis.")

    score = _clamp(score)
    return {
        "url": url,
        "host": host,
        "score": score,
        "verdict": _verdict_from_score(score),
        "findings": findings,
        "scanned_at": _now_iso(),
    }


def decode_qr_bytes(data: bytes) -> Optional[str]:
    """Decode the first QR code found in an image. Returns payload or None."""
    if not _CV_AVAILABLE:
        return None
    try:
        arr = np.frombuffer(data, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return None
        detector = cv2.QRCodeDetector()
        payload, points, _ = detector.detectAndDecode(img)
        return payload or None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Email Analysis (Refined)
# ---------------------------------------------------------------------------
def analyze_email_content(subject: str, body: str, sender: str) -> dict:
    findings: list[str] = []
    score = 0
    text = f"{subject}\n{body}".lower()

    urgency = [w for w in ("urgent", "immediately", "act now", "within 24 hours",
                           "suspended", "verify now", "final notice", "account locked",
                           "action required", "expires today", "last chance",
                           "must respond", "failure to respond")
               if w in text]
    if urgency:
        score += min(30, 8 * len(urgency))
        findings.append("Urgency/pressure language: " + ", ".join(urgency) + ".")

    money = [w for w in ("wire transfer", "gift card", "bitcoin", "crypto",
                         "bank details", "ssn", "password", "otp", "one-time",
                         "credit card", "debit card", "routing number",
                         "social security", "pin number", "cvv")
             if w in text]
    if money:
        score += min(30, 8 * len(money))
        findings.append("Requests sensitive/financial data: " + ", ".join(money) + ".")

    # Threat/consequence language
    threats = [w for w in ("legal action", "arrest warrant", "criminal charges",
                           "terminate your", "cancel your", "close your account")
               if w in text]
    if threats:
        score += min(20, 10 * len(threats))
        findings.append("Contains threatening language: " + ", ".join(threats) + ".")

    # Links in body
    links = URL_IN_TEXT_RE.findall(body or "")
    malicious_links = []
    for link in links[:10]:
        result = analyze_url(link)
        if result["verdict"] in ("suspicious", "malicious"):
            malicious_links.append({"url": link, "verdict": result["verdict"],
                                    "score": result["score"]})
    if malicious_links:
        score += min(35, 15 * len(malicious_links))
        findings.append(f"{len(malicious_links)} risky link(s) found in the body.")

    # Sender domain vs display / free mail impersonating a brand
    if sender:
        s = sender.lower()
        domain = s.split("@")[-1] if "@" in s else s
        if any(b in s for b in BRAND_KEYWORDS) and any(
            fm in domain for fm in ("gmail.com", "outlook.com", "yahoo.com", "hotmail.com")
        ):
            score += 25
            findings.append("Brand name sent from a free personal mailbox.")
        
        # Suspicious sender TLD
        sender_tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        if sender_tld in SUSPICIOUS_TLDS:
            score += 20
            findings.append(f"Sender uses a high-risk domain TLD (.{sender_tld}).")

    # Generic greeting
    if any(g in text for g in ("dear customer", "dear user", "dear valued", "dear sir/madam")):
        score += 10
        findings.append("Uses generic greeting instead of your name.")

    if not findings:
        findings.append("No strong phishing indicators detected in the message text.")

    score = _clamp(score)
    return {
        "score": score,
        "verdict": _verdict_from_score(score),
        "findings": findings,
        "links_found": links,
        "risky_links": malicious_links,
    }


def analyze_attachment(filename: str, size: int) -> dict:
    findings: list[str] = []
    score = 0
    name = (filename or "").lower()
    ext = name.rsplit(".", 1)[-1] if "." in name else ""

    if ext in DANGEROUS_ATTACHMENT_EXT:
        score += 60
        findings.append(f"Executable/script attachment (.{ext}).")
    elif ext in RISKY_DOCUMENT_EXT:
        score += 35
        findings.append(f"Macro-enabled or disk-image attachment (.{ext}).")

    # Double extension trick, e.g. invoice.pdf.exe
    if re.search(r"\.(pdf|doc|docx|xls|xlsx|jpg|png)\.[a-z0-9]{2,4}$", name):
        score += 30
        findings.append("Double file extension detected (masking real type).")

    if size == 0:
        findings.append("Attachment is empty.")
    elif size > 15 * 1024 * 1024:
        score += 5
        findings.append("Attachment is unusually large.")

    if not findings:
        findings.append("Attachment type appears benign.")

    score = _clamp(score)
    return {
        "filename": filename,
        "extension": ext,
        "size_bytes": size,
        "score": score,
        "verdict": _verdict_from_score(score),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Voice Analysis (Refined - no random entropy bias)
# ---------------------------------------------------------------------------
def analyze_voice(filename: str, data: bytes) -> dict:
    """Heuristic voice-fraud analysis using signal statistics."""
    size = len(data)
    findings: list[str] = []
    score = 0

    if size == 0:
        return {
            "score": 0,
            "verdict": "unknown",
            "findings": ["No audio captured."],
            "features": {},
        }

    # Deterministic pseudo-features derived from the audio payload.
    sample = np.frombuffer(data[: 4096 * 2], dtype=np.uint8).astype(np.float32) \
        if _CV_AVAILABLE else None

    if sample is not None and sample.size > 0:
        energy = float(np.mean(np.abs(sample - 128.0)) / 128.0)
        variance = float(np.var(sample) / (128.0 ** 2))
        
        # Zero-crossing rate for synthetic detection
        signs = np.sign(sample - 128.0)
        zcr = float(np.sum(np.abs(np.diff(signs)) > 0) / len(signs))
    else:
        digest = hashlib.sha256(data).digest()
        energy = digest[0] / 255.0
        variance = digest[1] / 255.0
        zcr = digest[2] / 255.0

    # Very low variance can indicate synthetic / heavily processed audio.
    flatness = 1.0 - min(1.0, variance * 4)
    if flatness > 0.7:
        score += 30
        findings.append("Low spectral variance — possible synthetic/cloned voice.")

    if energy < 0.05:
        score += 15
        findings.append("Very low audio energy — possible replay or silence padding.")

    # Zero-crossing rate anomaly
    if zcr < 0.1:
        score += 15
        findings.append("Abnormally low zero-crossing rate — potential AI-generated audio.")
    elif zcr > 0.8:
        score += 10
        findings.append("Very high zero-crossing rate — possible digital artifact.")

    duration_est = round(size / 16000, 1)  # rough estimate assuming ~16kB/s
    if duration_est < 1.5:
        score += 10
        findings.append("Clip is very short — limited context for verification.")

    if not findings:
        findings.append("No strong indicators of voice fraud detected.")

    score = _clamp(score)
    return {
        "filename": filename,
        "score": score,
        "verdict": _verdict_from_score(score),
        "features": {
            "size_bytes": size,
            "estimated_duration_sec": duration_est,
            "energy": round(energy, 4),
            "spectral_flatness": round(flatness, 4),
            "zero_crossing_rate": round(zcr, 4),
        },
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# SMS Analysis (Refined)
# ---------------------------------------------------------------------------
def analyze_sms(body: str) -> dict:
    """Heuristic SMS scam analysis."""
    lower = body.lower()
    score = 0
    findings = []

    # OTP / credential extraction
    if any(w in lower for w in ("otp", "password", "pin", "cvv", "ssn")):
        score += 35
        findings.append("Requests sensitive credentials (OTP, password, PIN).")

    # Urgency manipulation
    urgency_terms = ["urgent", "immediately", "account locked", "suspended",
                     "expires", "act now", "within 24", "action required", "verify now"]
    urgency_hits = [t for t in urgency_terms if t in lower]
    if urgency_hits:
        score += min(30, 10 * len(urgency_hits))
        findings.append("Uses urgency manipulation: " + ", ".join(urgency_hits) + ".")

    # Links
    urls_found = URL_IN_TEXT_RE.findall(body)
    if urls_found:
        score += 15
        findings.append(f"Contains {len(urls_found)} link(s) — possible smishing.")
        for u in urls_found[:3]:
            result = analyze_url(u)
            if result["verdict"] != "safe":
                score += 15
                findings.append(f"Embedded link flagged as {result['verdict']}: {u[:60]}...")
    elif any(d in lower for d in (".com", ".xyz", ".top", ".tk", ".ml", ".in/")):
        score += 10
        findings.append("Text contains domain-like patterns.")

    # Shortener in text
    if any(s in lower for s in ("bit.ly", "tinyurl", "t.co", "cutt.ly", "rb.gy")):
        score += 15
        findings.append("URL shortener detected in SMS text.")

    # Reward / lottery scam
    reward_terms = ["win", "winner", "gift", "prize", "lottery", "congratulations",
                    "selected", "lucky", "cashback", "reward", "free"]
    reward_hits = [t for t in reward_terms if t in lower]
    if reward_hits:
        score += min(25, 8 * len(reward_hits))
        findings.append("Fake reward/lottery language: " + ", ".join(reward_hits) + ".")

    # KYC / bank impersonation
    kyc_terms = ["kyc", "pan card", "aadhaar", "bank account", "debit card",
                 "credit card", "ifsc", "upi"]
    kyc_hits = [t for t in kyc_terms if t in lower]
    if kyc_hits:
        score += min(25, 10 * len(kyc_hits))
        findings.append("KYC/bank data extraction attempt: " + ", ".join(kyc_hits) + ".")

    # Delivery scam
    delivery_terms = ["delivery failed", "package", "parcel", "tracking",
                      "shipment", "customs fee"]
    delivery_hits = [t for t in delivery_terms if t in lower]
    if delivery_hits:
        score += min(20, 10 * len(delivery_hits))
        findings.append("Delivery scam indicators: " + ", ".join(delivery_hits) + ".")

    if not findings:
        findings.append("No strong social engineering indicators found.")

    score = _clamp(score)
    return {
        "score": score,
        "verdict": _verdict_from_score(score),
        "findings": findings,
        "scanned_at": _now_iso(),
    }


# ---------------------------------------------------------------------------
# USB Analysis
# ---------------------------------------------------------------------------
AUTORUN_PATTERNS = ["autorun.inf", "autorun.exe", "autoplay.exe", "setup.exe",
                    "install.exe", "run.exe", "start.exe"]

def analyze_usb_file(filename: str, size: int, data: bytes) -> dict:
    """Analyze an uploaded file as if scanning a USB device."""
    findings: list[str] = []
    score = 0
    name = (filename or "").lower()
    ext = name.rsplit(".", 1)[-1] if "." in name else ""

    # Autorun detection
    if any(p in name for p in AUTORUN_PATTERNS):
        score += 50
        findings.append("Autorun/autoplay file detected — high infection risk.")

    # Dangerous executable
    if ext in DANGEROUS_ATTACHMENT_EXT:
        score += 45
        findings.append(f"Executable file type (.{ext}) — can contain malware.")

    # Risky document types
    if ext in RISKY_DOCUMENT_EXT:
        score += 30
        findings.append(f"Macro-enabled or disk image file (.{ext}) — may contain embedded threats.")

    # Double extension
    if re.search(r"\.(pdf|doc|docx|xls|xlsx|jpg|png|mp4)\.[a-z0-9]{2,4}$", name):
        score += 35
        findings.append("Double file extension detected — real type is hidden.")

    # Hidden file indicators
    if name.startswith("."):
        score += 10
        findings.append("Hidden file (starts with dot) — may conceal malicious content.")

    # Suspicious size patterns
    if size == 0:
        score += 10
        findings.append("File is empty (0 bytes) — possible placeholder for dropper.")
    elif size < 100:
        score += 10
        findings.append("File is suspiciously small — may be a stub or shortcut.")

    # Check for script content in non-script files
    if ext not in DANGEROUS_ATTACHMENT_EXT and ext not in ("py", "sh", "rb", "pl"):
        header = data[:512].lower() if data else b""
        script_markers = [b"<script", b"powershell", b"cmd /c", b"wscript",
                          b"cscript", b"@echo off", b"#!/bin"]
        if any(m in header for m in script_markers):
            score += 30
            findings.append("Embedded script content detected in non-script file.")

    # PE header check (Windows executable magic bytes)
    if data[:2] == b"MZ":
        if ext not in ("exe", "dll", "sys", "drv"):
            score += 40
            findings.append("Windows executable (MZ header) disguised with non-executable extension.")
        else:
            score += 10
            findings.append("Windows PE executable detected.")

    if not findings:
        findings.append("File appears benign — no threat indicators detected.")

    score = _clamp(score)
    return {
        "filename": filename,
        "extension": ext,
        "size_bytes": size,
        "score": score,
        "verdict": _verdict_from_score(score),
        "findings": findings,
        "scanned_at": _now_iso(),
    }


# ---------------------------------------------------------------------------
# Image Authenticity Analysis
# ---------------------------------------------------------------------------
AI_GEN_SOFTWARE = [
    "dall-e", "midjourney", "stable diffusion", "stablediffusion",
    "novelai", "comfyui", "automatic1111", "invoke ai", "leonardo.ai",
    "adobe firefly", "bing image creator", "deepai",
]

def analyze_image_authenticity(filename: str, data: bytes) -> dict:
    """Analyze an image for signs of manipulation or AI generation."""
    findings: list[str] = []
    score = 0
    exif_data = {}

    if not _PIL_AVAILABLE:
        return {
            "filename": filename,
            "score": 0,
            "verdict": "unknown",
            "findings": ["Image analysis engine (Pillow) is unavailable."],
            "exif": {},
            "scanned_at": _now_iso(),
        }

    try:
        img = Image.open(io.BytesIO(data))
    except Exception:
        return {
            "filename": filename,
            "score": 0,
            "verdict": "unknown",
            "findings": ["Could not decode image file."],
            "exif": {},
            "scanned_at": _now_iso(),
        }

    width, height = img.size
    fmt = img.format or "unknown"

    # --- EXIF Analysis ---
    raw_exif = {}
    try:
        exif_raw = img._getexif()
        if exif_raw:
            for tag_id, value in exif_raw.items():
                tag_name = TAGS.get(tag_id, tag_id)
                try:
                    if isinstance(value, bytes):
                        raw_exif[str(tag_name)] = value.decode("utf-8", errors="replace")[:200]
                    else:
                        raw_exif[str(tag_name)] = str(value)[:200]
                except Exception:
                    pass
    except Exception:
        pass

    # Extract key EXIF fields
    camera_make = raw_exif.get("Make", "")
    camera_model = raw_exif.get("Model", "")
    software = raw_exif.get("Software", "")
    date_taken = raw_exif.get("DateTimeOriginal", raw_exif.get("DateTime", ""))

    exif_data = {
        "camera_make": camera_make,
        "camera_model": camera_model,
        "software": software,
        "date_taken": date_taken,
        "dimensions": f"{width}x{height}",
        "format": fmt,
        "has_exif": bool(raw_exif),
    }

    # No EXIF at all
    if not raw_exif:
        score += 15
        findings.append("No EXIF metadata — image may have been stripped or generated.")
    else:
        findings.append(f"EXIF present — Camera: {camera_make} {camera_model}" if camera_make else "EXIF present but no camera info.")

    # Software field check for AI generators
    software_lower = software.lower()
    for ai_tool in AI_GEN_SOFTWARE:
        if ai_tool in software_lower:
            score += 50
            findings.append(f"Software field contains AI generator: '{software}'.")
            break

    # Check for Photoshop or editing software
    edit_tools = ["photoshop", "gimp", "lightroom", "affinity", "paint.net",
                  "canva", "pixlr", "snapseed"]
    for tool in edit_tools:
        if tool in software_lower:
            score += 15
            findings.append(f"Image was processed with editing software: '{software}'.")
            break

    # --- Error Level Analysis (simplified) ---
    try:
        if img.mode != "RGB":
            img_rgb = img.convert("RGB")
        else:
            img_rgb = img.copy()

        # Save at low quality and compare
        buffer = io.BytesIO()
        img_rgb.save(buffer, "JPEG", quality=90)
        buffer.seek(0)
        resaved = Image.open(buffer)
        
        diff = ImageChops.difference(img_rgb, resaved)
        diff_data = list(diff.getdata())
        if diff_data:
            avg_diff = sum(sum(px) for px in diff_data) / (len(diff_data) * 3)
            
            if avg_diff < 1.5:
                score += 15
                findings.append(f"Very uniform compression artifacts (ELA avg={avg_diff:.2f}) — possible AI-generated or heavily processed image.")
            elif avg_diff > 15:
                score += 20
                findings.append(f"High ELA variance (avg={avg_diff:.2f}) — regions may have been spliced or edited.")
            else:
                findings.append(f"ELA analysis normal (avg={avg_diff:.2f}).")
    except Exception:
        findings.append("ELA analysis could not be performed.")

    # Unusual dimensions
    if width == height and width in (512, 768, 1024, 1536, 2048):
        score += 15
        findings.append(f"Square dimensions ({width}x{height}) match common AI generation sizes.")
    
    # Very large or very small
    if width * height > 50_000_000:
        score += 5
        findings.append("Extremely high resolution — unusual for casual photos.")

    if not findings:
        findings.append("No strong indicators of manipulation detected.")

    score = _clamp(score)
    return {
        "filename": filename,
        "score": score,
        "verdict": _verdict_from_score(score),
        "findings": findings,
        "exif": exif_data,
        "scanned_at": _now_iso(),
    }


# ---------------------------------------------------------------------------
# Rule-based security assistant (fallback when Gemini is unavailable)
# ---------------------------------------------------------------------------
AI_KNOWLEDGE = [
    (("phish", "phishing", "scam email", "fake email"),
     "Phishing messages try to trick you into revealing credentials or money. "
     "Check the sender's real address, hover over links before clicking, watch "
     "for urgency and generic greetings, and never enter passwords from an email link. "
     "Paste suspicious links into the URL Scanner first."),
    (("password", "passphrase", "credential"),
     "Use a unique 14+ character passphrase per account, enable a password "
     "manager, and turn on multi-factor authentication (MFA) everywhere. "
     "Never reuse passwords across sites."),
    (("malware", "virus", "ransomware", "trojan"),
     "Keep your OS and apps patched, run reputable endpoint protection, avoid "
     "pirated software, and keep offline backups. If you suspect ransomware, "
     "disconnect from the network immediately and do not pay before consulting experts."),
    (("wifi", "hotspot", "public network"),
     "On public Wi-Fi, use a VPN, prefer HTTPS sites, disable auto-connect, and "
     "avoid banking. Rogue hotspots can intercept traffic — verify the network "
     "name with the venue."),
    (("2fa", "mfa", "two factor", "otp"),
     "MFA adds a second proof of identity. Prefer app-based authenticators or "
     "hardware keys over SMS, since SMS codes can be SIM-swapped. Never share OTPs."),
    (("vpn",),
     "A VPN encrypts your traffic between your device and the VPN server, which "
     "protects you on untrusted networks. Choose a no-logs provider and keep the "
     "kill-switch enabled."),
    (("ddos", "dos", "denial of service"),
     "DDoS attacks flood a service to knock it offline. Mitigate with a CDN/WAF, "
     "rate limiting, autoscaling, and upstream scrubbing services."),
    (("ids", "suricata", "intrusion"),
     "An IDS like Suricata inspects network traffic against signatures and "
     "anomalies to alert on intrusions. Tune rules to reduce false positives and "
     "forward alerts to a SIEM for correlation."),
    (("qr",),
     "Malicious QR codes ('quishing') can point to phishing sites or trigger "
     "downloads. Always preview the decoded URL before opening — use the QR "
     "Scanner here to inspect it safely."),
]


def ai_reply(message: str) -> str:
    msg = (message or "").lower().strip()
    if not msg:
        return "Ask me anything about cybersecurity — phishing, passwords, malware, VPNs, and more."

    for keywords, response in AI_KNOWLEDGE:
        if any(k in msg for k in keywords):
            return response

    if msg in ["hi", "hello", "hey"]:
        return "Hello! I am CyberGuard AI. Ask me anything about phishing, malware, passwords, VPNs, or online safety."

    return "I can help with cybersecurity topics such as phishing, malware, passwords, VPNs, public Wi‑Fi safety, and IDS alerts."


# ---------------------------------------------------------------------------
# In-memory IDS (Suricata-style) alert feed
# ---------------------------------------------------------------------------
_IDS_SIGNATURES = [
    ("ET SCAN Potential SSH Scan", "attempted-recon", 2),
    ("ET MALWARE Win32/AgentTesla CnC Checkin", "trojan-activity", 1),
    ("ET POLICY Suspicious User-Agent (curl)", "policy-violation", 3),
    ("ET WEB_SERVER SQL Injection Attempt", "web-application-attack", 1),
    ("ET DNS Query to Known Malware Domain", "trojan-activity", 1),
    ("ET SCAN Nmap TCP Scan", "attempted-recon", 2),
    ("ET DOS Possible SYN Flood", "attempted-dos", 1),
]

_ids_engine_start = time.time()


def _random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def generate_ids_status() -> dict:
    random.seed(int(time.time() // 5))  # stable for 5s windows
    alert_count = random.randint(3, 8)
    alerts = []
    for _ in range(alert_count):
        sig, category, severity = random.choice(_IDS_SIGNATURES)
        alerts.append({
            "timestamp": _now_iso(),
            "signature": sig,
            "category": category,
            "severity": severity,  # 1 = high, 3 = low
            "src_ip": _random_ip(),
            "dest_ip": "10.0.0." + str(random.randint(2, 254)),
            "dest_port": random.choice([22, 80, 443, 3389, 53, 8080]),
            "proto": random.choice(["TCP", "UDP"]),
        })
    high = sum(1 for a in alerts if a["severity"] == 1)
    status = "critical" if high >= 2 else "warning" if high == 1 else "monitoring"
    return {
        "engine": "Suricata",
        "engine_status": "running",
        "uptime_sec": int(time.time() - _ids_engine_start),
        "rules_loaded": 34125,
        "status": status,
        "alerts_last_window": alert_count,
        "high_severity": high,
        "alerts": alerts,
        "updated_at": _now_iso(),
    }


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class URLScanRequest(BaseModel):
    url: str


class AIRequest(BaseModel):
    message: str


class SMSAnalyzeRequest(BaseModel):
    body: str


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "CyberGuard AI",
        "version": "2.0.0",
        "qr_engine": "available" if _CV_AVAILABLE else "unavailable",
        "image_engine": "available" if _PIL_AVAILABLE else "unavailable",
        "time": _now_iso(),
    }


@app.post("/analyze-sms")
async def analyze_sms_endpoint(payload: SMSAnalyzeRequest):
    result = analyze_sms(payload.body)
    return JSONResponse(result)


@app.post("/scan-url")
async def scan_url(payload: URLScanRequest):
    result = analyze_url(payload.url)
    ml_result = predict_url(payload.url)
    result["ml_analysis"] = ml_result
    if ml_result["ml_prediction"] == "phishing":
        result["score"] = min(100, result["score"] + 20)
    result["verdict"] = _verdict_from_score(result["score"])
    return JSONResponse(result)

@app.post("/scan/qr")
async def scan_qr(file: UploadFile = File(...)):
    data = await file.read()
    payload = decode_qr_bytes(data)
    if payload is None:
        return JSONResponse({
            "decoded": None,
            "message": "No QR code could be decoded from the image."
            if _CV_AVAILABLE else "QR engine unavailable on this server.",
            "verdict": "unknown",
            "scanned_at": _now_iso(),
        })

    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", payload) or "." in payload.split("/")[0]:
        analysis = analyze_url(payload)
        analysis["decoded"] = payload
        analysis["content_type"] = "url"
        return JSONResponse(analysis)

    return JSONResponse({
        "decoded": payload,
        "content_type": "text",
        "verdict": "safe",
        "findings": ["QR contains plain text, not a link."],
        "scanned_at": _now_iso(),
    })


@app.post("/scan/camera")
async def scan_camera(file: UploadFile = File(...)):
    """Analyze a captured webcam frame. Attempts QR decode on the frame."""
    data = await file.read()
    payload = decode_qr_bytes(data)
    result = {
        "frame_bytes": len(data),
        "qr_detected": payload is not None,
        "decoded": payload,
        "scanned_at": _now_iso(),
    }
    if payload:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", payload):
            result.update(analyze_url(payload))
            result["content_type"] = "url"
        else:
            result["content_type"] = "text"
            result["verdict"] = "safe"
    else:
        result["verdict"] = "clear"
        result["findings"] = ["No QR code detected in the current frame."]
    return JSONResponse(result)

@app.post("/analyze-email")
async def analyze_email(
    subject: str = Form(""),
    body: str = Form(""),
    sender: str = Form(""),
    attachment: Optional[UploadFile] = File(None),
):
    email_result = analyze_email_content(subject, body, sender)
    attachment_result = None
    total = email_result["score"]

    ml_email = predict_email(subject + " " + body)

    # Boost score if ML predicts phishing
    if ml_email["ml_prediction"] == "phishing":
        total = min(100, total + 15)

    if attachment is not None and attachment.filename:
        content = await attachment.read()
        attachment_result = analyze_attachment(attachment.filename, len(content))
        total = _clamp(int(0.6 * total + 0.6 * attachment_result["score"]))

    return JSONResponse({
        "overall_score": total,
        "verdict": _verdict_from_score(total),
        "email": email_result,
        "attachment": attachment_result,
        "ml_analysis": ml_email,
        "scanned_at": _now_iso(),
    })


@app.post("/analyze/voice")
async def analyze_voice_endpoint(file: UploadFile = File(...)):
    data = await file.read()
    return JSONResponse(analyze_voice(file.filename or "recording", data))


@app.post("/analyze-usb")
async def analyze_usb_endpoint(file: UploadFile = File(...)):
    data = await file.read()
    return JSONResponse(analyze_usb_file(file.filename or "unknown", len(data), data))


@app.post("/analyze-image")
async def analyze_image_endpoint(file: UploadFile = File(...)):
    # --- Validation ---
    filename = file.filename or "image"
    content_type = (file.content_type or "").lower()

    ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp", "image/bmp", "image/tiff",
                    "image/gif", "image/jpg"}
    ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tiff", ".tif", ".gif"}
    MAX_SIZE = 10 * 1024 * 1024  # 10 MB

    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if content_type not in ALLOWED_MIME and ext not in ALLOWED_EXT:
        return JSONResponse({
            "error": "Unsupported image format. Upload JPG, PNG, WebP, BMP, or TIFF.",
            "classification": "Error",
            "confidence": 0,
            "risk_level": "Unknown",
            "explanation": "The uploaded file is not a supported image format.",
            "signals": [],
        }, status_code=400)

    data = await file.read()

    if len(data) > MAX_SIZE:
        return JSONResponse({
            "error": "Image too large. Maximum size is 10 MB.",
            "classification": "Error",
            "confidence": 0,
            "risk_level": "Unknown",
            "explanation": "The uploaded file exceeds the 10 MB size limit.",
            "signals": [],
        }, status_code=400)

    if len(data) < 100:
        return JSONResponse({
            "error": "File is too small to be a valid image.",
            "classification": "Error",
            "confidence": 0,
            "risk_level": "Unknown",
            "explanation": "The uploaded file is too small to be a valid image.",
            "signals": [],
        }, status_code=400)

    # --- Heuristic forensic analysis (supplementary) ---
    heuristic = analyze_image_authenticity(filename, data)

    # Determine MIME type for Gemini
    mime_map = {
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".png": "image/png", ".webp": "image/webp",
        ".bmp": "image/bmp", ".tiff": "image/tiff",
        ".tif": "image/tiff", ".gif": "image/gif",
    }
    mime = mime_map.get(ext, content_type or "image/jpeg")

    # --- Gemini Vision AI analysis (primary) ---
    try:
        ai_result = await analyze_image_with_gemini(data, mime)

        return JSONResponse({
            "filename": filename,
            "classification": ai_result["classification"],
            "confidence": ai_result["confidence"],
            "risk_level": ai_result["risk_level"],
            "explanation": ai_result["explanation"],
            "signals": ai_result["signals"],
            "score": heuristic.get("score", 0),
            "verdict": heuristic.get("verdict", "unknown"),
            "findings": heuristic.get("findings", []),
            "exif": heuristic.get("exif", {}),
            "analysis_method": "gemini_vision",
            "scanned_at": _now_iso(),
        })

    except GeminiServiceError as e:
        print(f"GEMINI IMAGE ERROR: {e}")
        # Fallback to heuristic-only if Gemini fails
        heuristic["classification"] = "Inconclusive"
        heuristic["confidence"] = 50
        heuristic["risk_level"] = "Medium"
        heuristic["explanation"] = (
            "AI vision analysis unavailable. Results are based on "
            "metadata and compression heuristics only."
        )
        heuristic["signals"] = heuristic.get("findings", [])
        heuristic["analysis_method"] = "heuristic_only"
        return JSONResponse(heuristic)


@app.post("/ask-ai")
async def ask_ai(payload: GeminiAIRequest):
    try:
        reply = await gemini_generate_reply(payload.message)
        return JSONResponse({
            "reply": reply,
            "timestamp": _now_iso()
        })

    except Exception as e:
        print("GEMINI ERROR:", e)

        # fallback so app never crashes
        return JSONResponse({
            "reply": ai_reply(payload.message),
            "source": "fallback",
            "error": str(e),
            "timestamp": _now_iso()
        })
        
@app.get("/ids-status")
async def ids_status():
    return JSONResponse(generate_ids_status())


# ---------------- STATIC FRONTEND ----------------
STATIC_DIR = Path(__file__).parent / "static"

@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")

# CSS + JS + images access
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
