import re
import os
from collections import defaultdict

LOG_FILE = "logs/access.log"

# Threat scoring rules (you can tune these values)
THREAT_RULES = {
    "failed_request": 5,
    "suspicious_method": 7,
    "sensitive_path": 10,
    "high_frequency": 15,
}

SUSPICIOUS_METHODS = ["DELETE", "TRACE", "OPTIONS"]
SENSITIVE_PATHS = ["/admin", "/login", "/config", "/wp-admin", "/phpmyadmin"]
HIGH_FREQUENCY_THRESHOLD = 50  # requests from same IP


def analyze_logs(log_file: str):
    if not os.path.exists(log_file):
        print(f"[!] Log file not found: {log_file}")
        return {}, {}

    ip_requests = defaultdict(int)
    ip_scores = defaultdict(int)

    print(f"[+] Analyzing log file: {log_file}")

    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue

            # Extract IP (first token in common Apache/Nginx formats)
            ip = line.split(" ")[0]
            ip_requests[ip] += 1

            # Extract method and path => "GET /index.php HTTP/1.1"
            match = re.search(r'"(\w+)\s(/.*?)\s', line)
            if match:
                method, path = match.groups()

                # Suspicious HTTP methods
                if method in SUSPICIOUS_METHODS:
                    ip_scores[ip] += THREAT_RULES["suspicious_method"]

                # Sensitive paths
                for sp in SENSITIVE_PATHS:
                    if path.startswith(sp):
                        ip_scores[ip] += THREAT_RULES["sensitive_path"]

            # Failed / error responses
            if " 404 " in line or " 403 " in line or " 500 " in line:
                ip_scores[ip] += THREAT_RULES["failed_request"]

    # High frequency behavior
    for ip, count in ip_requests.items():
        if count > HIGH_FREQUENCY_THRESHOLD:
            ip_scores[ip] += THREAT_RULES["high_frequency"]

    return ip_requests, ip_scores


def write_reports(ip_requests, ip_scores):
    print("[+] Writing reports...")

    # Detailed report
    with open("report.txt", "w") as f:
        f.write("=== Log Analyzer Report ===\n\n")
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            f.write(f"IP: {ip} | Requests: {count} | Score: {ip_scores.get(ip, 0)}\n")

    # Suspicious IPs only
    with open("suspicious_ips.txt", "w") as f:
        for ip, score in sorted(ip_scores.items(), key=lambda x: x[1], reverse=True):
            if score > 20:
                f.write(f"{ip} - Score: {score}\n")

    print("[+] Done! Check 'report.txt' and 'suspicious_ips.txt'")


if __name__ == "__main__":
    ip_requests, ip_scores = analyze_logs(LOG_FILE)
    if ip_requests:
        write_reports(ip_requests, ip_scores)
