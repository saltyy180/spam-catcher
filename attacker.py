import re
import time
import requests

host = "http://localhost:5000"
passwords = ["123456", "password", "admin123", "qwerty", "letmein", "secret123"]

chrome_headers = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
}


def run_raw_test():
    print("\n--- test 1: raw python requests ---")
    for i, pw in enumerate(passwords[:2], 1):
        r = requests.post(
            f"{host}/login",
            json={"username": "admin", "password": pw},
            headers={"X-Forwarded-For": f"198.51.100.{i}"},
        )
        print(f"try {i}: {r.status_code} - {r.json().get('message')}")


def run_spoofed_test():
    print("\n--- test 2: spoofed headers + proxy rotation (no csrf token) ---")
    for i, pw in enumerate(passwords[:2], 1):
        hdrs = {**chrome_headers, "X-Forwarded-For": f"203.0.113.{i + 10}"}
        r = requests.post(
            f"{host}/login",
            json={"username": "admin", "password": pw, "token": "bad_tok"},
            headers=hdrs,
        )
        print(f"try {i}: {r.status_code} - {r.json().get('message')}")


def run_scraper_test():
    print("\n--- test 3: token scraper + proxy rotation ---")
    for i, pw in enumerate(passwords, 1):
        ip = f"192.0.2.{i + 20}"
        hdrs = {**chrome_headers, "X-Forwarded-For": ip}

        page = requests.get(host, headers=hdrs)
        m = re.search(r'id="csrfToken"\s+value="([^"]+)"', page.text)
        tok = m.group(1) if m else ""

        r = requests.post(
            f"{host}/login",
            json={"username": "admin", "password": pw, "token": tok},
            headers=hdrs,
        )
        print(f"try {i} ({ip}) [{pw}]: {r.status_code} - {r.json().get('message')}")
        time.sleep(0.25)


if __name__ == "__main__":
    run_raw_test()
    time.sleep(1)
    run_spoofed_test()
    time.sleep(1)
    run_scraper_test()

    stats = requests.get(f"{host}/metrics").json()
    print(f"\nmetrics: {stats}")
