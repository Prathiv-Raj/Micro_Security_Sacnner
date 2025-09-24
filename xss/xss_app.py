#!/usr/bin/env python3
"""
xss_app.py — Minimal XSS automation PoC (Flask + simple payload injection)

Usage:
    python3 xss_app.py

Requirements:
    pip install flask requests
Run inside a venv on a test VM. Only test authorized targets.
"""
import os
import re
import sqlite3
import datetime
import logging
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from flask import Flask, render_template_string, request, redirect, url_for, flash, send_from_directory
import requests

# -----------------------
# Config
# -----------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "xss_results")
DB_PATH = os.path.join(BASE_DIR, "xss_scans.db")
LOG_FILE = os.path.join(BASE_DIR, "xss_app.log")

# small set of test payloads (POC). These are detectable reflection payloads.
# Keep payloads minimal. Do NOT include advanced exploit chains.
PAYLOADS = [
    "\"'><script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "'\"><svg onload=alert('xss')>",
    "<b>INJECTION_TEST_12345</b>"
]

REQUEST_TIMEOUT = 20  # seconds
ALLOWED_SCHEMES = ("http://", "https://")

os.makedirs(RESULTS_DIR, exist_ok=True)

# Logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

# -----------------------
# DB helpers
# -----------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            param TEXT,
            payload TEXT,
            result TEXT,
            output_file TEXT,
            created_at TEXT
        )"""
    )
    conn.commit()
    conn.close()

def insert_scan(url, param, payload, result, output_file):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO scans (url, param, payload, result, output_file, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (url, param, payload, result, output_file, datetime.datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

# -----------------------
# Utility functions
# -----------------------
def simple_url_check(url):
    if not url:
        return False
    if not any(url.startswith(s) for s in ALLOWED_SCHEMES):
        return False
    parsed = urlparse(url)
    return bool(parsed.netloc)

def save_response(body, url, param, payload):
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe = url.replace("://", "_").replace("/", "_").replace("?", "_")
    filename = f"{ts}_{safe}_{param or 'no_param'}_{hash(payload) & 0xffff}.html"
    path = os.path.join(RESULTS_DIR, filename)
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write(body)
    return path

# naive DOM-like detection: check if payload appears inside <script> or as attribute-ish contexts
def is_possible_dom_reflection(response_text, payload):
    lower = response_text.lower()
    pl = payload.lower()
    # payload appears inside a script tag or inside event-attribute-ish patterns
    if pl in lower:
        # check surrounding context for script or attribute indicators
        idx = lower.find(pl)
        start = max(0, idx - 40)
        context = lower[start: idx + len(pl) + 40]
        if "<script" in context or "onerror" in context or "onload" in context or "svg" in context:
            return True
    return False

# -----------------------
# Scanner core
# -----------------------
def inject_payloads_and_scan(url):
    """
    For each query parameter in the URL, replace its value with each payload
    and request the page. Return list of findings.
    """
    parsed = urlparse(url)
    q = parse_qsl(parsed.query, keep_blank_values=True)

    findings = []
    # if no query params, add a fake param "q" to test reflection in templates that echo body
    if not q:
        q = [("q", "test")]

    for i, (param_name, original_value) in enumerate(q):
        for payload in PAYLOADS:
            # build new query with injected payload for this param
            new_q = q.copy()
            new_q[i] = (param_name, payload)
            new_query = urlencode(new_q, doseq=True, safe="/:?=&")
            new_parsed = parsed._replace(query=new_query)
            target = urlunparse(new_parsed)

            try:
                resp = requests.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=True, headers={"User-Agent":"XSS-POC-Scanner/1.0"})
                body = resp.text or ""
            except Exception as e:
                body = f"Request error: {e}"

            # detection: straightforward reflection (payload substring present)
            reflected = payload in body
            possible_dom = False
            if reflected:
                possible_dom = is_possible_dom_reflection(body, payload)

            # classify
            if reflected and possible_dom:
                result = "Reflected, possible DOM"
            elif reflected:
                result = "Reflected (likely)"
            else:
                result = "No obvious reflection"

            # save raw output file
            out_path = save_response(body, url, param_name, payload)
            insert_scan(url, param_name, payload, result, os.path.basename(out_path))

            findings.append({
                "param": param_name,
                "payload": payload,
                "result": result,
                "output": os.path.basename(out_path),
                "target": target
            })

    return findings

# -----------------------
# Flask app
# -----------------------
app = Flask(__name__)
app.secret_key = "replace-in-prod"

TEMPLATE = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>XSS Security Scanner</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;background:#f6f8fa;padding:20px}
.container{max-width:900px;margin:0 auto;background:#fff;padding:20px;border-radius:8px}
form{display:flex;gap:8px;margin-bottom:16px}
input[type=text]{flex:1;padding:8px;border:1px solid #ddd;border-radius:4px}
button{padding:8px 12px;border:none;border-radius:4px;background:#0a66c2;color:#fff;cursor:pointer}
pre{background:#111;color:#dfd;padding:12px;border-radius:6px;overflow:auto}
.table{width:100%;border-collapse:collapse}
.table th,.table td{padding:6px;border:1px solid #eee;text-align:left;font-size:13px}
.flash{padding:8px;background:#ffecec;color:#7a0b0b;margin-bottom:12px;border-radius:4px}
</style>
</head>
<body>
<div class="container">
<h1>XSS Security Scanner</h1>
<p><strong>Use only on authorized targets.</strong></p>
<form method="post">
<input type="text" name="url" placeholder="https://example.com/page.php?id=1" required>
<button type="submit">Scan</button>
</form>

{% if findings %}
<h2>Findings</h2>
<table class="table">
<thead><tr><th>Param</th><th>Payload</th><th>Result</th><th>Raw Output</th><th>Test URL</th></tr></thead>
<tbody>
{% for f in findings %}
<tr>
<td>{{ f.param }}</td>
<td><code>{{ f.payload }}</code></td>
<td>{{ f.result }}</td>
<td><a href="{{ url_for('get_result', filename=f.output) }}">{{ f.output }}</a></td>
<td><a href="{{ f.target }}" target="_blank">Open</a></td>
</tr>
{% endfor %}
</tbody>
</table>
{% endif %}

<h3>Recent scans</h3>
<ul>
{% for r in recent %}
<li>{{ r[5] }} — <b>{{ r[4] }}</b> — {{ r[1] }} (param: {{ r[2] }}) — <a href="{{ url_for('get_result', filename=r[5]) }}">{{ r[5] }}</a></li>
{% else %}
<li>No recent scans</li>
{% endfor %}
</ul>

</div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    findings = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not simple_url_check(url):
            flash("Invalid URL. Include http:// or https://", "danger")
            return redirect(url_for("index"))
        logging.info(f"Starting XSS scan for {url}")
        findings = inject_payloads_and_scan(url)
        logging.info(f"Completed XSS scan for {url}")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, url, param, payload, result, output_file, created_at FROM scans ORDER BY id DESC LIMIT 10")
    recent = c.fetchall()
    conn.close()
    return render_template_string(TEMPLATE, findings=findings, recent=recent)

@app.route("/results/<filename>")
def get_result(filename):
    return send_from_directory(RESULTS_DIR, filename, as_attachment=True)

# -----------------------
# Main
# -----------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=6000, debug=True)
