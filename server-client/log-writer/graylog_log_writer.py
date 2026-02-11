"""
Graylog Log Writer - Reads logs from Graylog API and writes to file in real time.
Runs on the host machine (Windows) where Graylog is running.

Data flow:
    Docker (GELF driver) -> Graylog GELF UDP :12201 -> Graylog shows real-time logs
    This script polls the Graylog API every 2 seconds -> writes to file immediately (flush)

Each source (hostname) is written to a separate file:
    - Prod-BootstrapLP.log
    - Prod-ReactLP.log

Log output format matches the Prod-VideoPortal.log sample:
    <Month> <Day> <Time> <Hostname> <Process/Container>: <Message>

How to run:
    pip install requests
    python graylog_log_writer.py
"""

import requests
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# ============ CONFIGURATION ============
GRAYLOG_URL = "http://localhost:9000"
GRAYLOG_USER = "admin"
GRAYLOG_PASS = "10102003"  # Password set in server-centralized/.env

# Output log files directory
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "log-output")

# List of server hostnames to monitor
SERVERS = ["Prod-BootstrapLP", "Prod-ReactLP"]

# Polling interval (seconds) - REAL-TIME: poll every 2 seconds
POLL_INTERVAL = 2

# ============ END CONFIGURATION ============


def ensure_output_dir():
    """Create the output directory if it doesn't exist."""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    print(f"  Output directory: {os.path.abspath(OUTPUT_DIR)}")


def format_syslog_line(message: dict) -> str:
    """
    Convert a Graylog API message to syslog format, like the sample:
    Mar 11 16:22:02 Prod-VideoPortal syslog-ng[608]: Syslog connection broken...

    When Docker uses the GELF driver, Graylog receives these fields:
    - source: container hostname (Prod-BootstrapLP, Prod-ReactLP) from compose hostname
    - message: original log content
    - container_name: Docker container name (bootstrap-landing-page, react-landing-page...)
    - image_name: Docker image (nginx:alpine)
    - tag: custom tag set in compose (bootstrap-landing-page, react-landing-page)
    - timestamp: time when the log was generated
    """
    try:
        # Parse timestamp
        ts_str = message.get("timestamp", "")
        if ts_str:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            formatted_time = ts.strftime("%b %d %H:%M:%S")
        else:
            formatted_time = datetime.now().strftime("%b %d %H:%M:%S")

        source = message.get("source", "unknown")
        msg = message.get("message", "")

        # Get process name from container_name or tag (GELF fields).
        container_name = message.get("container_name", "")
        # Docker GELF sends container_name formatted as "/prod-wordpress".
        if container_name.startswith("/"):
            container_name = container_name[1:]

        tag = message.get("tag", "")
        # Determine process name: prioritize container_name, fallback to tag.
        process = container_name or tag or source

        # If the message already contains a syslog-style prefix, keep it.
        # Otherwise, build: <time> <host> <process>: <message>
        if msg.startswith(f"{source}") or "pam_unix" in msg or "CRON" in msg:
            # System log already has format.
            return f"{formatted_time} {source} {msg}"
        else:
            # App log from Docker GELF.
            return f"{formatted_time} {source} {process}: {msg}"

    except Exception as e:
        return f"{datetime.now().strftime('%b %d %H:%M:%S')} unknown error: {e}"


def query_graylog_messages(server_name: str, range_seconds: int = 10):
    """
    Query Graylog Search API to get recent log messages.
    Use relative search (simple and fast) with a short time range for real-time.
    """
    url = f"{GRAYLOG_URL}/api/search/universal/relative"
    params = {
        "query": f"source:{server_name}",
        "range": range_seconds,
        "limit": 200,
        "sort": "timestamp:asc",
        "decorate": "false"
    }

    try:
        response = requests.get(
            url,
            params=params,
            auth=(GRAYLOG_USER, GRAYLOG_PASS),
            headers={"Accept": "application/json"},
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        return data.get("messages", [])
    except requests.exceptions.ConnectionError:
        return []
    except requests.exceptions.HTTPError as e:
        if "503" in str(e):
            pass  # Graylog is starting up
        else:
            print(f"  [!] API error for {server_name}: {e}")
        return []
    except Exception:
        return []


class LogWriter:
    """Manages writing logs to file for each server in real time."""

    def __init__(self, server_name: str):
        self.server_name = server_name
        self.log_file = os.path.join(OUTPUT_DIR, f"{server_name}.log")
        self.seen_ids = set()
        self.total_lines = 0
        # If the file already exists, count current lines.
        if os.path.exists(self.log_file):
            with open(self.log_file, "r", encoding="utf-8") as f:
                self.total_lines = sum(1 for _ in f)
        print(f"  [{server_name}] -> {self.log_file} ({self.total_lines} existing lines)")

    def poll_and_write(self):
        """
        Read new logs from Graylog and write to file immediately.
        Use flush() to ensure data is written to disk in real time.
        """
        # Query last 10 seconds (covers the polling interval plus buffer).
        messages = query_graylog_messages(self.server_name, range_seconds=10)

        new_count = 0
        if messages:
            with open(self.log_file, "a", encoding="utf-8") as f:
                for msg_wrapper in messages:
                    msg = msg_wrapper.get("message", {})
                    msg_id = msg.get("_id", "")

                    if msg_id in self.seen_ids:
                        continue

                    self.seen_ids.add(msg_id)
                    line = format_syslog_line(msg)
                    f.write(line + "\n")
                    f.flush()  # Flush immediately to write to disk in real time.
                    new_count += 1
                    self.total_lines += 1

        # Limit seen_ids to avoid unbounded memory growth.
        if len(self.seen_ids) > 50000:
            self.seen_ids = set(list(self.seen_ids)[-25000:])

        return new_count


def check_graylog_connection():
    """Check connection to Graylog."""
    try:
        response = requests.get(
            f"{GRAYLOG_URL}/api/system",
            auth=(GRAYLOG_USER, GRAYLOG_PASS),
            headers={"Accept": "application/json"},
            timeout=10
        )
        response.raise_for_status()
        info = response.json()
        print(f"  Graylog version : {info.get('version', 'unknown')}")
        print(f"  Cluster ID      : {info.get('cluster_id', 'unknown')}")
        print(f"  Is processing   : {info.get('is_processing', 'unknown')}")
        return True
    except Exception as e:
        print(f"  [!] Cannot connect: {e}")
        return False


def check_gelf_input():
    """Check if Graylog has a GELF UDP input configured."""
    try:
        response = requests.get(
            f"{GRAYLOG_URL}/api/system/inputs",
            auth=(GRAYLOG_USER, GRAYLOG_PASS),
            headers={"Accept": "application/json"},
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        inputs = data.get("inputs", [])

        gelf_found = False
        for inp in inputs:
            inp_type = inp.get("type", "")
            title = inp.get("title", "")
            state = inp.get("state", "")
            if "gelf" in inp_type.lower():
                gelf_found = True
                port = inp.get("attributes", {}).get("port", "?")
                print(f"  [OK] GELF Input: \"{title}\" (port {port}) - {state}")

        if not gelf_found:
            print("  [!!] NO GELF INPUT FOUND!")
            print("  In Graylog: System -> Inputs -> Choose 'GELF UDP' -> Launch new input")
            print("  Bind address: 0.0.0.0, Port: 12201")

        return gelf_found
    except Exception:
        print("  [!] Unable to check inputs")
        return False


def main():
    print("=" * 60)
    print("  GRAYLOG LOG WRITER - Real-time Log to File (GELF)")
    print("=" * 60)
    print()

    # [1] Check connection
    print("[1] Checking Graylog connection...")
    if not check_graylog_connection():
        print()
        print("CANNOT CONNECT TO GRAYLOG!")
        print(f"Ensure Graylog is running at {GRAYLOG_URL}")
        print("Run: cd server-centralized && docker compose up -d")
        sys.exit(1)

    # [2] Check GELF input
    print()
    print("[2] Checking GELF input...")
    check_gelf_input()

    # [3] Create output directory
    print()
    print("[3] Preparing output directory...")
    ensure_output_dir()

    # [4] Create log writers
    print()
    print("[4] Initializing log writers...")
    writers = {}
    for server in SERVERS:
        writers[server] = LogWriter(server)

    # [5] Polling loop - real time
    print()
    print(f"[5] STARTING REAL-TIME POLLING (every {POLL_INTERVAL}s)")
    print(f"    Monitoring : {', '.join(SERVERS)}")
    print(f"    Output     : {os.path.abspath(OUTPUT_DIR)}")
    print("    GELF Input : UDP port 12201")
    print()
    print("    Press Ctrl+C to stop")
    print("-" * 60)

    try:
        cycle = 0
        while True:
            total_new = 0
            status_parts = []
            for server, writer in writers.items():
                new_count = writer.poll_and_write()
                total_new += new_count
                status_parts.append(f"{server}={writer.total_lines}")

            timestamp = datetime.now().strftime("%H:%M:%S")

            if total_new > 0:
                print(f"  [{timestamp}] +{total_new} new lines | Total: {' | '.join(status_parts)}")
            else:
                # Every 30 seconds (15 cycles * 2s), print heartbeat.
                cycle += 1
                if cycle % 15 == 0:
                    print(f"  [{timestamp}] Listening... Total: {' | '.join(status_parts)}")

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print()
        print("=" * 60)
        print("  STOPPED - Final stats:")
        print("=" * 60)
        for server in SERVERS:
            log_path = os.path.join(OUTPUT_DIR, f"{server}.log")
            if os.path.exists(log_path):
                size = os.path.getsize(log_path)
                lines = sum(1 for _ in open(log_path, encoding="utf-8"))
                print(f"  {server}.log : {lines:,} lines, {size:,} bytes")
            else:
                print(f"  {server}.log : not created yet (no logs)")
        print()


if __name__ == "__main__":
    main()
