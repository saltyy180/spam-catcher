# Login Rate Limiter & Bot Detection Middleware

A lightweight Flask authentication demo built to test multi-layered defenses against automated credential-stuffing and rotating-proxy attacks.

## Defense Layers
- **Client & Header Inspection:** Flags automated HTTP clients (`python-requests`, `curl`, etc.) and requests missing standard browser `Sec-Fetch-*` and `Accept-Language` headers.
- **Single-Use CSRF / Nonce Tokens:** Generates short-lived tokens per page load to block direct API spam from proxy pools.
- **Honeypot Field:** Catches automated form-fillers using a hidden input field invisible to normal users.
- **Dual Sliding-Window Rate Limiting:** Tracks failed attempts across both client IP (`X-Forwarded-For`) and target username, applying silent temporary cooldowns (`HTTP 429`) without exposing lockout timers.

## Project Structure
- `app.py` - Flask server with bot detection, rate-limiting logic, and `/metrics` endpoint.
- `templates/loginpage.html` - Login UI with hidden honeypot field and automatic token refresh.
- `attacker.py` - Multi-stage test script simulating raw requests, header spoofing + proxy rotation, and token scraping.

## Running Locally
```bash
pip install -r requirements.txt
python app.py
```

In a second terminal, run the automated attack simulation:
```bash
python attacker.py
```
