# CyberGuard 2.0

A Flask-based educational website security assessment dashboard.

## Features
- Modern responsive security operations dashboard
- HTTP/HTTPS reachability and response-time check
- Basic security-header presence review
- DNS resolution display
- Common TCP port availability check
- Simple configuration score and assessment summary

## Run locally
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000.

## Render deployment
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app`

## Important safety notes
Use this tool only on websites and systems you own or have explicit permission to assess. A missing header or open port is not proof of an exploitable vulnerability. The score is a simple educational indicator, not a formal security rating. This project is not a penetration-testing tool.
