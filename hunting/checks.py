import re
import json
import os
from collections import defaultdict
from hunting.models import Finding

def load_rules():
    """Loads detection rules from the JSON file."""
    rules_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'rules.json')
    try:
        with open(rules_path, 'r', encoding='utf-8') as f:
            return json.load(f).get("rules", [])
    except Exception as e:
        print(f"[!] Warning: Could not load rules.json. {e}")
        return []

def run_all_checks(log_content: str, remote_log_path: str) -> list[Finding]:
    """Runs dynamic rules against the log content."""
    findings = []
    if not log_content:
        return findings

    rules = load_rules()
    lines = log_content.splitlines()

    for rule in rules:
        if remote_log_path not in rule.get("target_logs", []):
            continue

        pattern = re.compile(rule["pattern"])
        matches = [line.strip() for line in lines if pattern.search(line)]

        if len(matches) >= rule.get("threshold", 1):
            findings.append(Finding(
                severity=rule["severity"],
                rule_name=rule['name'],       # Rule name separated from MITRE metadata
                mitre_id=rule['id'],          # MITRE technique ID
                mitre_tactic=rule['tactic'],  # MITRE tactic associated with the technique
                description=rule["description"],
                evidence=matches[-5:],
                log_path=remote_log_path,
                recommendation=rule["recommendation"]
            ))

    return findings

def check_complex_correlation(log_content: str, remote_log_path: str) -> list[Finding]:
    """Correlation engine for multi-step attacks."""
    findings = []
    if remote_log_path not in ["/var/log/auth.log", "/var/log/secure"]:
        return findings

    failed_attempts = defaultdict(list)
    successful_logins = defaultdict(list)

    failed_pattern = re.compile(r"Failed password for (?:invalid user )?(.*?) from (.*?) port")
    accepted_pattern = re.compile(r"Accepted password for (.*?) from (.*?) port")

    for line in log_content.splitlines():
        failed_match = failed_pattern.search(line)
        if failed_match:
            user, ip = failed_match.groups()
            failed_attempts[ip].append(line.strip())

        accepted_match = accepted_pattern.search(line)
        if accepted_match:
            user, ip = accepted_match.groups()
            successful_logins[ip].append(line.strip())

    for ip in successful_logins:
        if ip in failed_attempts and len(failed_attempts[ip]) >= 3:
            findings.append(Finding(
                severity="CRITICAL",
                rule_name="Compromised Account - Brute Force Success",  # Detection rule name
                mitre_id="T1078",                                       # Valid Accounts
                mitre_tactic="Initial Access / Persistence",            # ATT&CK tactic category
                description=f"IP {ip} successfully logged in after multiple failed attempts. Confirmed breach.",
                evidence=failed_attempts[ip][-3:] + successful_logins[ip],
                log_path=remote_log_path,
                recommendation="Immediately rotate credentials, terminate active sessions from this IP, and run a full forensic scan."
            ))

    return findings