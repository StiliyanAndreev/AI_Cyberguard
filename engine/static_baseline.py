"""
Rule-based static analysis baseline — represents the detection capability of
pattern-matching SAST tools such as Semgrep or Bandit.

Rules are applied to the added lines of each git diff (lines starting with '+').
No external tool dependencies are required; all matching is performed with
compiled regular expressions over the diff text stored in the database.

Each rule maps to a known MITRE ATT&CK technique to allow direct comparison
with CyberGuard's LLM-based findings.
"""

import re
from dataclasses import dataclass


@dataclass
class StaticFinding:
    rule_id: str
    description: str
    severity: str      # HIGH | MEDIUM
    mitre: str
    matched_text: str


# (rule_id, description, severity, mitre_id, compiled_pattern)
_RULES: list[tuple[str, str, str, str, re.Pattern]] = [
    (
        "HARDCODED_EXTERNAL_IP",
        "Hardcoded external IP address in code",
        "HIGH", "T1071",
        re.compile(r'\b(?:185|91|45|194)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
    ),
    (
        "EXEC_BASE64_DECODE",
        "exec() applied to base64-decoded data — arbitrary code execution",
        "HIGH", "T1027",
        re.compile(r'exec\s*\(\s*base64\.b64decode'),
    ),
    (
        "SUBPROCESS_EXECUTION",
        "subprocess call that executes system commands",
        "MEDIUM", "T1059",
        re.compile(r'subprocess\s*\.\s*(call|run|Popen|getoutput)\s*\('),
    ),
    (
        "RAW_SOCKET_CONNECT",
        "Direct TCP socket connection to a remote host",
        "MEDIUM", "T1095",
        re.compile(r'\bs\.connect\s*\(\s*\('),
    ),
    (
        "CREDENTIAL_FILE_READ",
        "Reading SSH keys or shell credential files",
        "HIGH", "T1552",
        re.compile(
            r'id_rsa|id_ed25519|authorized_keys|'
            r'\.bash_history|\.aws[/\\]credentials|\.netrc|git-credentials',
            re.IGNORECASE,
        ),
    ),
    (
        "ENV_VARS_DUMP",
        "Dumping all environment variables (may expose secrets)",
        "HIGH", "T1552",
        re.compile(r'os\.environ\.items\s*\(\s*\)'),
    ),
    (
        "SENSITIVE_PATH_GLOB",
        "Glob over /etc or /home — filesystem credential harvesting",
        "HIGH", "T1555",
        re.compile(r'glob\.glob\s*\(\s*["\']\/(?:etc|home|root|var)'),
    ),
    (
        "DNS_TUNNELING_INDICATOR",
        "Base32 encoding used for DNS subdomain data encoding",
        "HIGH", "T1071.004",
        re.compile(r'base64\.b32encode|b32encode'),
    ),
    (
        "SYSTEM_PATH_REMOVAL",
        "shutil.rmtree on a system or application path",
        "HIGH", "T1485",
        re.compile(r'shutil\.rmtree\s*\(\s*["\']\/(?:var|opt|home|etc)'),
    ),
    (
        "CRONTAB_WRITE",
        "Writing to a crontab file — persistence mechanism",
        "HIGH", "T1053",
        re.compile(r'crontabs|/cron\.d/|/cron\.daily/'),
    ),
    (
        "SUID_PRIVILEGE_ESCALATION",
        "Setting SUID bit — local privilege escalation",
        "HIGH", "T1548.001",
        re.compile(r'chmod\s+(?:u\+s|4755|4644|0o[0-9]*4[0-9]{3})'),
    ),
    (
        "CRYPTO_MINING_INDICATOR",
        "Cryptocurrency mining pool URL or wallet address",
        "HIGH", "T1496",
        re.compile(r'stratum\+tcp://|hashmine\.|[A-Z0-9]{95}'),
    ),
    (
        "HIDDEN_FILE_WRITE",
        "Writing to a hidden file in /tmp or system directory",
        "MEDIUM", "T1027",
        re.compile(r'/tmp/\.[a-zA-Z]|/tmp/\.config_cache'),
    ),
    (
        "SUDOERS_WRITE",
        "Writing to /etc/sudoers — privilege persistence",
        "HIGH", "T1548",
        re.compile(r'/etc/sudoers|sudoers\.d/'),
    ),
]


def analyze_diff(diff_text: str) -> list[StaticFinding]:
    """
    Apply all SAST rules to the added lines of a git diff.

    Only lines beginning with '+' (excluding the '+++' header) are scanned,
    matching the behaviour of real SAST tools that inspect new code only.
    """
    if not diff_text:
        return []

    added_lines = [
        line[1:]
        for line in diff_text.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    text = "\n".join(added_lines)

    findings: list[StaticFinding] = []
    seen_rules: set[str] = set()

    for rule_id, description, severity, mitre, pattern in _RULES:
        if rule_id in seen_rules:
            continue
        match = pattern.search(text)
        if match:
            findings.append(StaticFinding(
                rule_id=rule_id,
                description=description,
                severity=severity,
                mitre=mitre,
                matched_text=match.group(0)[:80],
            ))
            seen_rules.add(rule_id)

    return findings


def score_diff(diff_text: str) -> int:
    """
    Return the number of HIGH-severity rules triggered.
    Used as a simple comparable signal alongside CyberGuard's risk score.
    """
    return sum(1 for f in analyze_diff(diff_text) if f.severity == "HIGH")
