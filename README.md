# Spam-Catcher

Login service made using flask designed to evaluate layered protection against bots performing credential stuffing attacks and proxy rotation.

## Working mechanism
- **Client & Header Verification**: Blocks default scripting agents like `python-requests` and `curl` and requests without required headers from browser (`Sec-Fetch-*` and `Accept-Language`).
- **One-Time Page Tokenization**: Adds one-time CSRF token for each new page load to prevent bots to just spam `/login` endpoint without opening the page.
- **Honeypot**: Hidden form input is used as a honeypot for bots filling out the form automatically.
- **Rate Limiting**: Failed login attempts per IP (`X-Forwarded-For`) and account name are tracked in sliding window and cause HTTP `429` response to be returned silently.

## Directory
- `app.py` - Flask service, bot detection, rate limiting implementation and `/metrics` endpoint.
- `templates/loginpage.html` - Login form with honeypot input and CSRF token refreshing.
- `attacker.py` - Bot with three stages of attack (raw requests, spoofed headers and proxies rotation, token extraction).

## Installation & execution
```bash
pip install -r requirements.txt
py app.py
```

And in other terminal run attacker script:
```bash
py attacker.py
```
