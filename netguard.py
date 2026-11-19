#!/usr/bin/env python3
"""
NetGuard Audit (netguard.py)
Zero-Dependency Security Auditor for Web/TLS Headers, Exposed Ports & Git Secret Leaks.
Generates A+ to F Security Scorecards in CLI, JSON, Markdown and Executive HTML.
Author: Wallison Araujo (@WallisonWS) | License: MIT
"""

from __future__ import annotations

import argparse
import concurrent.futures
import html
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple


SECURITY_HEADERS: List[Tuple[str, int, str]] = [
    ("strict-transport-security", 20, "Enable HSTS (max-age=63072000; includeSubDomains; preload)"),
    ("content-security-policy", 20, "Define a strict Content-Security-Policy (CSP) to prevent XSS"),
    ("x-content-type-options", 10, "Set 'X-Content-Type-Options: nosniff'"),
    ("x-frame-options", 10, "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' against Clickjacking"),
    ("referrer-policy", 10, "Set 'Referrer-Policy: strict-origin-when-cross-origin'"),
    ("permissions-policy", 10, "Restrict browser features via Permissions-Policy"),
    ("cross-origin-opener-policy", 10, "Set 'Cross-Origin-Opener-Policy: same-origin'"),
]

SECRET_RULES: List[Tuple[str, str, str]] = [
    ("AWS Access Key ID", "CRITICAL", r"\bAKIA[0-9A-Z]{16}\b"),
    ("GitHub Personal Access Token", "CRITICAL", r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"),
    ("OpenAI / Stripe Secret Key", "CRITICAL", r"\b(?:sk-[A-Za-z0-9]{20,}|sk_live_[A-Za-z0-9]{16,})\b"),
    ("Google API Key", "HIGH", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("Private Key Block", "CRITICAL", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("Database Connection URI w/ Password", "CRITICAL", r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^:\s/]+:[^@\s/]+@[^\s]+"),
    ("Slack Webhook URL", "HIGH", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("Hardcoded JWT Token", "MEDIUM", r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b"),
    ("Hardcoded Password Assignment", "HIGH", r"(?i)\b(?:db_pass|db_password|api_secret|jwt_secret|secret_key|password)\s*[:=]\s*['\"][^'\"$\s]{8,}['\"]"),
]

CRITICAL_PORTS: Dict[int, Tuple[str, str]] = {
    21: ("FTP", "HIGH"),
    22: ("SSH", "MEDIUM"),
    23: ("Telnet", "CRITICAL"),
    25: ("SMTP", "MEDIUM"),
    53: ("DNS", "LOW"),
    80: ("HTTP", "LOW"),
    443: ("HTTPS", "INFO"),
    445: ("SMB", "CRITICAL"),
    554: ("RTSP/CFTV", "HIGH"),
    1433: ("MSSQL", "CRITICAL"),
    3306: ("MySQL", "CRITICAL"),
    3389: ("RDP", "CRITICAL"),
    5432: ("PostgreSQL", "CRITICAL"),
    6379: ("Redis", "CRITICAL"),
    8080: ("HTTP-Alt", "MEDIUM"),
    27017: ("MongoDB", "CRITICAL"),
}

IGNORED_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next"}


def score_to_grade(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    return "F"


def audit_web(url: str, timeout: int = 8) -> Dict[str, Any]:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    tls_info: Dict[str, Any] = {"enabled": parsed.scheme == "https", "version": None, "days_left": None, "issuer": None}
    score = 0
    checks: List[Dict[str, Any]] = []

    # 1. TLS Certificate Inspection
    if parsed.scheme == "https" and host:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    tls_info["version"] = ssock.version()
                    not_after = cert.get("notAfter")
                    if not_after:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_left = (exp - datetime.now(tz=timezone.utc)).days
                        tls_info["days_left"] = days_left
                        tls_info["expires_at"] = exp.strftime("%Y-%m-%d")
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    tls_info["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
                    score += 10
                    checks.append({"check": "TLS Certificate & Protocol", "status": "PASS", "detail": f"{tls_info['version']} ({tls_info['days_left']} days left)"})
        except Exception as exc:
            checks.append({"check": "TLS Certificate & Protocol", "status": "FAIL", "detail": str(exc)})

    # 2. HTTP Security Headers Inspection
    req = urllib.request.Request(url, headers={"User-Agent": "NetGuard-Audit/1.0 (+https://github.com/WallisonWS/netguard-audit)"})
    resp_headers: Dict[str, str] = {}
    status_code = 0
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.status
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as err:
        status_code = err.code
        resp_headers = {k.lower(): v for k, v in err.headers.items()}
    except Exception as exc:
        return {"target": url, "error": str(exc), "score": 0, "grade": "F", "checks": checks}

    for header_name, weight, tip in SECURITY_HEADERS:
        val = resp_headers.get(header_name)
        if val:
            score += weight
            checks.append({"check": header_name, "status": "PASS", "detail": val[:120]})
        else:
            checks.append({"check": header_name, "status": "WARN", "detail": f"Missing — {tip}"})

    # Info leak check
    leaked = [h for h in ("x-powered-by", "server") if h in resp_headers and any(ch.isdigit() for ch in resp_headers[h])]
    if leaked:
        score = max(0, score - 5)
        checks.append({"check": "Server Banner Fingerprinting", "status": "WARN", "detail": f"Version exposed in: {', '.join(leaked)}"})
    else:
        checks.append({"check": "Server Banner Fingerprinting", "status": "PASS", "detail": "No software version leaked"})

    score = min(100, score)
    return {
        "mode": "audit-web",
        "target": url,
        "http_status": status_code,
        "tls": tls_info,
        "score": score,
        "grade": score_to_grade(score),
        "checks": checks,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }


def audit_repo(root_path: str) -> Dict[str, Any]:
    root = Path(root_path).resolve()
    findings: List[Dict[str, Any]] = []
    files_scanned = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.stat().st_size > 1_500_000:
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            files_scanned += 1
            rel = str(fpath.relative_to(root))
            for line_no, line in enumerate(content.splitlines(), start=1):
                for rule_name, severity, pattern in SECRET_RULES:
                    if re.search(pattern, line):
                        findings.append({
                            "file": rel,
                            "line": line_no,
                            "rule": rule_name,
                            "severity": severity,
                            "preview": line.strip()[:90],
                        })

    score = max(0, 100 - sum(25 if f["severity"] == "CRITICAL" else 15 if f["severity"] == "HIGH" else 5 for f in findings))
    return {
        "mode": "audit-repo",
        "target": str(root),
        "files_scanned": files_scanned,
        "findings_count": len(findings),
        "score": score,
        "grade": score_to_grade(score),
        "findings": findings,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }


def _probe_port(host: str, port: int, timeout: float) -> Tuple[int, bool]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except OSError:
        return port, False


def audit_ports(host: str, ports: List[int] | None = None, timeout: float = 1.2) -> Dict[str, Any]:
    target_ports = ports or list(CRITICAL_PORTS.keys())
    open_ports: List[Dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        futures = [pool.submit(_probe_port, host, p, timeout) for p in target_ports]
        for fut in concurrent.futures.as_completed(futures):
            port, is_open = fut.result()
            if is_open:
                svc, risk = CRITICAL_PORTS.get(port, ("Custom", "MEDIUM"))
                open_ports.append({"port": port, "service": svc, "risk": risk})

    open_ports.sort(key=lambda x: x["port"])
    penalty = sum(30 if p["risk"] == "CRITICAL" else 15 if p["risk"] == "HIGH" else 5 if p["risk"] == "MEDIUM" else 0 for p in open_ports)
    score = max(0, 100 - penalty)
    return {
        "mode": "audit-ports",
        "target": host,
        "scanned_ports": len(target_ports),
        "open_ports": open_ports,
        "score": score,
        "grade": score_to_grade(score),
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }


def render_html_report(report: Dict[str, Any]) -> str:
    grade = report.get("grade", "N/A")
    score = report.get("score", 0)
    color = "#10b981" if score >= 85 else "#f59e0b" if score >= 60 else "#ef4444"
    rows_html = ""
    for item in report.get("checks", []):
        st = item["status"]
        badge_bg = "#064e3b" if st == "PASS" else "#78350f" if st == "WARN" else "#7f1d1d"
        rows_html += f"<tr><td>{html.escape(item['check'])}</td><td><span style='background:{badge_bg};padding:3px 10px;border-radius:999px;font-weight:700;'>{st}</span></td><td>{html.escape(item['detail'])}</td></tr>"
    for item in report.get("findings", []):
        rows_html += f"<tr><td>{html.escape(item['rule'])}</td><td><span style='background:#7f1d1d;padding:3px 10px;border-radius:999px;font-weight:700;'>{item['severity']}</span></td><td>{html.escape(item['file'])}:{item['line']}</td></tr>"
    for item in report.get("open_ports", []):
        rows_html += f"<tr><td>Port {item['port']}/TCP ({item['service']})</td><td><span style='background:#78350f;padding:3px 10px;border-radius:999px;font-weight:700;'>{item['risk']}</span></td><td>Open Service Detected</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>NetGuard Security Audit Report</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;background:#070b14;color:#f1f5f9;margin:0;padding:32px;}}
.wrap{{max-width:960px;margin:0 auto;background:#111827;border:1px solid #26334d;border-radius:16px;padding:28px;}}
.hdr{{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #26334d;padding-bottom:18px;margin-bottom:22px;}}
.grade{{font-size:3rem;font-weight:900;color:{color};border:3px solid {color};border-radius:14px;padding:8px 22px;}}
table{{width:100%;border-collapse:collapse;font-size:0.9rem;}}
th,td{{padding:12px;border-bottom:1px solid #1f2937;text-align:left;}}
th{{color:#94a3b8;text-transform:uppercase;font-size:0.75rem;}}
</style></head>
<body><div class="wrap">
<div class="hdr"><div><h1>🛡️ NetGuard Executive Security Report</h1>
<p style="color:#94a3b8;">Target: <strong>{html.escape(str(report.get('target')))}</strong> • Mode: <code>{report.get('mode')}</code> • Score: <strong>{score}/100</strong></p></div>
<div class="grade">{grade}</div></div>
<table><thead><tr><th>Control / Finding</th><th>Status / Risk</th><th>Details</th></tr></thead><tbody>{rows_html or '<tr><td colspan="3">No issues found.</td></tr>'}</tbody></table>
<p style="margin-top:24px;font-size:0.8rem;color:#64748b;">Generated by NetGuard Audit (https://github.com/WallisonWS/netguard-audit) at {report.get('timestamp')}</p>
</div></body></html>"""


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netguard", description="NetGuard Audit — Zero-Dependency Web/TLS, Port & Git Secret Auditor")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_web = sub.add_parser("audit-web", help="Audit HTTPS TLS certificate and HTTP Security Headers (A+ to F)")
    p_web.add_argument("url", help="Target URL or domain (e.g. https://github.com)")
    p_web.add_argument("--html", help="Save standalone executive HTML report to file")

    p_repo = sub.add_parser("audit-repo", help="Scan directory/Git repo for leaked API keys, passwords and secrets")
    p_repo.add_argument("path", default=".", nargs="?", help="Directory path to scan")
    p_repo.add_argument("--html", help="Save standalone executive HTML report to file")

    p_ports = sub.add_parser("audit-ports", help="Fast concurrent TCP exposure scan of critical ports")
    p_ports.add_argument("host", help="Target IP or hostname")
    p_ports.add_argument("--html", help="Save standalone executive HTML report to file")

    args = parser.parse_args(argv)
    if args.cmd == "audit-web":
        result = audit_web(args.url)
    elif args.cmd == "audit-repo":
        result = audit_repo(args.path)
    else:
        result = audit_ports(args.host)

    print(json.dumps(result, indent=2, ensure_ascii=False))
    if getattr(args, "html", None):
        Path(args.html).write_text(render_html_report(result), encoding="utf-8")
        print(f"\n[OK] Executive HTML report saved to: {args.html}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
