#!/usr/bin/env python3
import re
import sys
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from urllib.parse import unquote

# Isolation Forest is optional: without scikit-learn the script
# still works with the rule-based checks only.
try:
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

MIN_IPS_FOR_ML = 20

log_pattern = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] '
    r'"(\S+) (.*?) \S+" (\d{3}) (\S+)'
)

suspicious_patterns = {
    "SQL injection pattern": re.compile(
        r"(\bunion\b.{0,30}\bselect\b|"
        r"\bor\b\s+\d+=\d+|sleep\s*\(|benchmark\s*\()",
        re.I
    ),
    "Path traversal": re.compile(r"\.\./|%2e%2e", re.I),
    "Sensitive file scan": re.compile(
        r"(/\.env\b|/wp-config\.php|/\.git\b|"
        r"/etc/passwd|/phpmyadmin\b)",
        re.I
    ),
    "Common exploit scan": re.compile(
        r"(wp-login\.php|xmlrpc\.php|/cgi-bin/|"
        r"\.phpunit|/vendor/phpunit)",
        re.I
    ),
}

dashboard_paths = {
    "/dashboard",
    "/dashboard/",
    "/dashboard/scan_dashboard.html",
    "/dashboard/ai_scan_report.json",
    "/favicon.ico",
}

requests_by_ip = Counter()
errors_by_ip = Counter()
rate_check_by_ip = Counter()
ip_stats = defaultdict(
    lambda: {"req": 0, "err": 0, "post": 0, "hits": 0, "paths": set()}
)
events = []
total = 0
valid = 0

for line in sys.stdin:
    total += 1
    match = log_pattern.match(line.strip())
    if not match:
        continue

    ip, timestamp, method, path, status, size = match.groups()
    status = int(status)
    valid += 1
    requests_by_ip[ip] += 1

    base_path = path.split("?", 1)[0]
    is_dashboard = base_path in dashboard_paths
    if not is_dashboard:
        rate_check_by_ip[ip] += 1

    if status >= 400:
        errors_by_ip[ip] += 1

    decoded_path = unquote(path)
    reasons = [
        name for name, pattern in suspicious_patterns.items()
        if pattern.search(path) or pattern.search(decoded_path)
    ]

    # --- ML: collect per-IP behaviour (dashboard traffic excluded) ---
    if not is_dashboard and ip not in ('127.0.0.1', '::1'):
        s = ip_stats[ip]
        s["req"] += 1
        if status >= 400:
            s["err"] += 1
        if method == "POST":
            s["post"] += 1
        if reasons:
            s["hits"] += 1
        if len(s["paths"]) < 1000:
            s["paths"].add(base_path)

    if reasons:
        events.append({
            "time": timestamp,
            "ip": ip,
            "method": method,
            "path": path[:300],
            "status": status,
            "risk": "high" if any(
                "SQL injection" in r or "Path traversal" in r
                for r in reasons
            ) else "medium",
            "reasons": reasons,
        })

for ip, count in rate_check_by_ip.items():
    if count >= 30:
        events.append({
            "ip": ip,
            "risk": "review",
            "reasons": [
                f"{count} non-dashboard requests in this scanned log; review activity"
            ],
        })

# --- ML: Isolation Forest on per-IP behaviour ---
ml_info = {
    "model": "IsolationForest",
    "status": "unavailable (scikit-learn not installed)",
    "ips_analyzed": 0,
    "min_ips_required": MIN_IPS_FOR_ML,
    "anomalies": [],
}

if ML_AVAILABLE:
    try:
        ips = [ip for ip, s in ip_stats.items() if s["req"] > 0]
        ml_info["ips_analyzed"] = len(ips)
        if len(ips) < MIN_IPS_FOR_ML:
            ml_info["status"] = (
                f"skipped (only {len(ips)} IPs, need at least {MIN_IPS_FOR_ML})"
            )
        else:
            rows = []
            for ip in ips:
                s = ip_stats[ip]
                n = s["req"]
                rows.append([
                    math.log1p(n),
                    s["err"] / n,
                    len(s["paths"]) / n,
                    s["post"] / n,
                    s["hits"] / n,
                ])
            model = IsolationForest(
                n_estimators=200, contamination="auto", random_state=42
            )
            model.fit(rows)
            labels = model.predict(rows)
            scores = model.score_samples(rows)
            ml_info["status"] = "ok"

            found = []
            for ip, label, score in zip(ips, labels, scores):
                if label == -1:
                    s = ip_stats[ip]
                    n = s["req"]
                    found.append({
                        "ip": ip,
                        "anomaly_score": round(float(-score), 3),
                        "requests": n,
                        "error_ratio": round(s["err"] / n, 2),
                        "unique_path_ratio": round(len(s["paths"]) / n, 2),
                        "post_ratio": round(s["post"] / n, 2),
                        "rule_hit_ratio": round(s["hits"] / n, 2),
                    })
            found.sort(key=lambda a: a["anomaly_score"], reverse=True)
            ml_info["anomalies"] = found[:20]
            for a in found[:20]:
                events.append({
                    "ip": a["ip"],
                    "risk": "review",
                    "reasons": [
                        f"ML anomaly (score {a['anomaly_score']}): "
                        f"{a['requests']} requests, "
                        f"{int(a['error_ratio'] * 100)}% errors, "
                        f"{int(a['unique_path_ratio'] * 100)}% unique paths"
                    ],
                })
    except Exception as exc:
        ml_info["status"] = f"error ({type(exc).__name__})"

report = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "scan_type": (
        "rules + Isolation Forest" if ml_info["status"] == "ok"
        else "rule-based preliminary log scan"
    ),
    "total_lines": total,
    "parsed_requests": valid,
    "unique_ips": len(requests_by_ip),
    "http_error_requests": sum(errors_by_ip.values()),
    "suspicious_event_count": len(events),
    "top_ips_by_request_count": [
        {"ip": ip, "requests": count}
        for ip, count in requests_by_ip.most_common(10)
    ],
    "ml": ml_info,
    "events": events[:200],
    "note": (
        "Findings require human review. "
        "A matching URL does not prove a successful attack, and an ML anomaly "
        "only means the behaviour differs from other visitors."
    ),
}

print(json.dumps(report, ensure_ascii=False, indent=2))
