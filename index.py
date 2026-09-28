import random
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def gen_web():
    domain = random.choice(["malicious-site.com", "data-stealer.net", "exfiltration.org",
                            "suspicious-domain.com", "data-theft.io"])
    size = round(random.uniform(1, 50), 1)
    return {"domain": domain, "url": f"https://{domain}/upload",
            "leaks": random.choice([["credentials", "documents"], ["documents"]]),
            "data_size": f"{size}MB",
            "severity": "high" if size > 20 else ("medium" if size > 10 else "low"),
            "timestamp": now()}


def gen_network():
    proto = random.choice(["HTTP", "HTTPS", "FTP", "SSH", "SMB", "SMTP", "DNS"])
    size = round(random.uniform(0.5, 100), 1)
    unusual = random.random() < 0.3
    factors = sum([size > 25, proto in ("FTP", "SMB"), unusual])
    sev = "high" if factors >= 2 else ("medium" if factors == 1 else "low")
    ports = {"HTTP": 80, "HTTPS": 443, "FTP": 21, "SSH": 22, "SMB": 445, "SMTP": 25, "DNS": 53}
    allow_p = {"high": 0.3, "medium": 0.6, "low": 0.9}[sev]
    prefix = random.choice(["203.0.113.", "198.51.100.", "192.0.2."])
    return {"process_name": random.choice(["chrome.exe", "python.exe", "java.exe", "cmd.exe", "powershell.exe"]),
            "pid": random.randint(1000, 9999),
            "remote_ip": f"{prefix}{random.randint(1, 254)}",
            "remote_port": random.randint(1024, 65535) if unusual else ports[proto],
            "protocol": proto, "data_size": f"{size}MB", "severity": sev,
            "timestamp": now(),
            "transfer_status": "ALLOWED" if random.random() < allow_p else "BLOCKED"}


def gen_log():
    user = random.choice(["admin", "system", "user", "guest", "attacker", "unknown"])
    sens = random.choice(["customer_data", "classified", "secret", "confidential", "internal", "database"])
    size = round(random.uniform(0.1, 30), 1)
    action = random.choice(["Read", "Copy", "Download", "Export", "Query"])
    ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
    if user in ("attacker", "unknown") or sens == "secret":
        sev = "high"
    else:
        sev = "medium" if size > 5 else "low"
    return {"log_path": f"/opt/data/{sens}_{random.randint(1, 1000)}.csv",
            "suspicious_line": f"{user}@{ip} {action} {size}MB of sensitive data to external location",
            "leaks": [{"type": sens}] if random.random() > 0.3 else [],
            "data_size": f"{size}MB", "severity": sev, "timestamp": now()}


@app.route('/api/generate', methods=['GET', 'POST'])
def generate():
    burst = request.args.get('burst') == '1'
    out = {"web_alerts": [], "network_alerts": [], "log_alerts": []}
    for key, fn, p in (("web_alerts", gen_web, 0.5),
                       ("network_alerts", gen_network, 0.6),
                       ("log_alerts", gen_log, 0.4)):
        if burst or random.random() < p:
            out[key].append(fn())
    return jsonify(out)
