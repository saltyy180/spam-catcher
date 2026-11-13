import logging
import secrets
import time
from collections import defaultdict
from flask import Flask, jsonify, render_template, request

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

app = Flask(__name__)

max_tries = 3
window_sec = 15
lockout_sec = 30
token_ttl = 300

bad_agents = ("python", "curl", "wget", "scrapy", "httpclient")
browser_headers = ("Accept-Language", "Sec-Fetch-Site", "Sec-Fetch-Mode")

ip_hits = defaultdict(list)
user_hits = defaultdict(list)
cooldowns = {}
tokens = {}
stats = {"ok": 0, "fail": 0, "blocked": 0, "limited": 0}


def client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        first, _, _ = xff.partition(",")
        return first.strip()
    return request.remote_addr or "unknown"


def check_bot():
    ua = request.headers.get("User-Agent", "")
    if not ua or any(sig in ua.lower() for sig in bad_agents):
        return True, f"bad_ua:{ua or 'none'}"

    missing = [h for h in browser_headers if not request.headers.get(h)]
    if missing:
        return True, f"missing_headers:{','.join(missing)}"

    return False, ""


def valid_token(tok, now):
    if not tok or tok not in tokens:
        return False
    issued = tokens.pop(tok)
    return (now - issued) <= token_ttl


def over_limit(key, bucket, now):
    recent = [t for t in bucket[key] if now - t < window_sec]
    recent.append(now)
    bucket[key] = recent

    if len(recent) > max_tries:
        cooldowns[key] = now + lockout_sec
        bucket[key].clear()
        return True
    return False


@app.route("/")
def index():
    tok = secrets.token_urlsafe(24)
    tokens[tok] = time.monotonic()
    return render_template("loginpage.html", csrf_token=tok)


@app.route("/token")
def new_token():
    tok = secrets.token_urlsafe(24)
    tokens[tok] = time.monotonic()
    return jsonify({"token": tok})


@app.route("/metrics")
def metrics():
    return jsonify({"locked_keys": len(cooldowns), **stats})


@app.route("/login", methods=["POST"])
def login():
    ip = client_ip()
    now = time.monotonic()

    bot, reason = check_bot()
    if bot:
        stats["blocked"] += 1
        logger.warning(f"bot blocked | ip={ip} | {reason}")
        return jsonify({"message": "Unable to verify request. Please try again later."}), 403

    data = request.get_json(silent=True) or {}
    user = data.get("username", "").strip().lower()
    pw = data.get("password", "")
    tok = data.get("token", "")
    trap = data.get("website_url", "")

    # hidden input trap for auto-fill bots
    if trap:
        stats["blocked"] += 1
        logger.warning(f"honeypot hit | ip={ip} | user={user}")
        return jsonify({"message": "Unable to verify request. Please try again later."}), 403

    if not valid_token(tok, now):
        stats["blocked"] += 1
        logger.warning(f"bad token | ip={ip} | user={user}")
        return jsonify({"message": "Session expired. Please refresh and try again."}), 403

    for k in (f"ip:{ip}", f"user:{user}"):
        if k in cooldowns:
            if now < cooldowns[k]:
                stats["limited"] += 1
                left = int(cooldowns[k] - now) + 1
                logger.warning(f"cooldown active | {k} | {left}s left")
                return jsonify({"message": "Too many sign-in attempts. Please try again later."}), 429
            del cooldowns[k]

    if over_limit(f"ip:{ip}", ip_hits, now) or (user and over_limit(f"user:{user}", user_hits, now)):
        stats["limited"] += 1
        logger.warning(f"rate limit triggered | ip={ip} | user={user}")
        return jsonify({"message": "Too many sign-in attempts. Please try again later."}), 429

    if user == "admin" and pw == "secret123":
        stats["ok"] += 1
        ip_hits.pop(f"ip:{ip}", None)
        user_hits.pop(f"user:{user}", None)
        logger.info(f"login ok | ip={ip} | user={user}")
        return jsonify({"message": "Sign-in successful. Redirecting..."}), 200

    stats["fail"] += 1
    logger.info(f"login fail | ip={ip} | user={user}")
    return jsonify({"message": "The username or password you entered is incorrect."}), 401


if __name__ == "__main__":
    app.run(debug=True, port=5000)
