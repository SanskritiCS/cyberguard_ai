# CyberGuard AI

An AI-assisted cybersecurity toolkit with a FastAPI backend and a premium, responsive vanilla HTML/CSS/JS frontend built as a **Cybersecurity Command Center** for a national-level hackathon.

**Tagline:** *"Every click can be a cyber attack. What if AI protected you before it happened?"*

## Philosophy

```
DETECT → EXPLAIN → WARN → PROTECT
```

Every threat score comes with an explanation of *why* it was flagged and a list of *what the user should do next*.

---

## Modules

| Module | Endpoint | Description |
|--------|----------|-------------|
| **URL Scanner** | `POST /scan-url` | Heuristic + ML analysis of URLs for phishing, brand impersonation, suspicious TLDs, shortener detection, excessive hyphens, port tricks, redirect exploits |
| **QR Scanner** | `POST /scan/qr` | Decodes QR code images and runs the decoded URL through the URL scanner |
| **QR Camera** | `POST /scan/camera` | Live webcam QR scanning with auto-detection |
| **Email Analyzer** | `POST /analyze-email` | Multipart form analysis of sender, subject, body, and attachments. Checks urgency language, credential extraction, threatening language, generic greetings, risky links, sender domain, and attachment double-extension tricks |
| **SMS Detector** | `POST /analyze-sms` | Detects smishing patterns: OTP requests, urgency manipulation, shortener links, KYC fraud, delivery scams, lottery/reward scams |
| **Voice Detector** | `POST /analyze/voice` | Analyzes audio for synthetic voice indicators using energy levels, spectral flatness, and zero-crossing rate |
| **USB Scanner** | `POST /analyze-usb` | Scans uploaded files for autorun exploits, dangerous extensions, disguised executables (MZ header detection), embedded scripts, double-extension tricks |
| **Image Authenticator** | `POST /analyze-image` | EXIF metadata extraction, Error Level Analysis (ELA), AI-generation software detection (DALL-E, Midjourney, etc.), compression artifact analysis |
| **AI Assistant** | `POST /ask-ai` | Powered by Google Gemini API with cybersecurity system instructions. Falls back to a rule-based knowledge base on failure |
| **Network IDS** | `GET /ids-status` | Simulated Suricata-style intrusion detection system with randomized alert feed |

---

## Tech Stack

- **Backend:** Python, FastAPI, Uvicorn
- **ML:** scikit-learn (URL phishing model + email spam model)
- **Image Analysis:** Pillow (EXIF, ELA)
- **QR Decoding:** OpenCV
- **AI:** Google Gemini API (v1beta)
- **Frontend:** Vanilla HTML/CSS/JS, Lucide Icons, Inter font

---

## Getting Started

### Prerequisites
- Python 3.10+
- A Google Gemini API key in `.env`

### Installation

```bash
# Clone and enter the project
cd cyberguard.ai

# Create virtual environment
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Create a `.env` file (already present) with:
```
GEMINI_API_KEY=your_api_key_here
```

### Run

```bash
uvicorn main:app --reload
```

Then open [http://localhost:8000](http://localhost:8000).

---

## Project Structure

```
cyberguard.ai/
├── main.py                 # FastAPI app — all endpoints and heuristic logic
├── gemini_service.py       # Google Gemini API integration
├── ai_schema.py            # Pydantic schemas for AI requests
├── config.py               # Settings and environment variable loader
├── ml_url_detector.py      # ML URL phishing model
├── ml_url_model.py         # URL model training script
├── ml_email_detector.py    # ML email phishing model
├── ml_email_model.py       # Email model training script
├── url_phishing_model.pkl  # Trained URL model
├── email_model.pkl         # Trained email model
├── email_vectorizer.pkl    # Email text vectorizer
├── logger.py               # Logging utilities
├── rate_limit.py           # Rate limiting middleware
├── requirements.txt        # Python dependencies
├── .env                    # API keys
├── static/
│   ├── index.html          # Premium frontend UI
│   ├── style.css           # Design system and styles
│   └── script.js           # Client-side logic
└── README.md
```

---

## API Quick Reference

```bash
# Health check
curl http://localhost:8000/health

# Scan a URL
curl -X POST http://localhost:8000/scan-url -H "Content-Type: application/json" -d '{"url":"http://example.com"}'

# Analyze SMS
curl -X POST http://localhost:8000/analyze-sms -H "Content-Type: application/json" -d '{"body":"Your OTP is 1234"}'

# Analyze email
curl -X POST http://localhost:8000/analyze-email -F "sender=test@example.com" -F "subject=Hello" -F "body=Test body"

# USB scan
curl -X POST http://localhost:8000/analyze-usb -F "file=@myfile.exe"

# Image authenticity
curl -X POST http://localhost:8000/analyze-image -F "file=@photo.jpg"

# AI assistant
curl -X POST http://localhost:8000/ask-ai -H "Content-Type: application/json" -d '{"message":"What is phishing?"}'
```

---

## License

Built for educational and hackathon purposes.
