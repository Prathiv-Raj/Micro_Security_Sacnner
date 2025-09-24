import os
import subprocess
import re
import sqlite3
import datetime
import logging
from urllib.parse import urlparse
from flask import Flask, render_template_string, request, redirect, url_for, flash, send_from_directory

# -----------------------
# Config
# -----------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
DB_PATH = os.path.join(BASE_DIR, "scans.db")
LOG_FILE = os.path.join(BASE_DIR, "app.log")
SQLMAP_OPTIONS = ["--batch", "--random-agent", "--level=2", "--risk=2", "--banner", "--is-dba"]
SQLMAP_TIMEOUT = 300
ALLOWED_SCHEMES = ("http://", "https://")

os.makedirs(RESULTS_DIR, exist_ok=True)

# Logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

# -----------------------
# Database setup
# -----------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            severity TEXT,
            vulnerability TEXT,
            output_path TEXT,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_scan(url, severity, vulnerability, output_path):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO scans (url, severity, vulnerability, output_path, created_at) VALUES (?, ?, ?, ?, ?)",
              (url, severity, vulnerability, output_path, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

# -----------------------
# SQLMap runner & parser
# -----------------------
def run_sqlmap(url):
    cmd = ["sqlmap", "-u", url] + SQLMAP_OPTIONS
    try:
        result = subprocess.run(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                text=True,
                                timeout=SQLMAP_TIMEOUT)
        return result.stdout or ""
    except FileNotFoundError:
        return "[-] sqlmap not found. Install it: sudo apt install -y sqlmap"
    except subprocess.TimeoutExpired as e:
        return f"[-] sqlmap timed out after {SQLMAP_TIMEOUT} seconds.\nPartial output:\n{e.stdout or ''}"

def analyze_output(output):
    vulnerability = "No vulnerability found"
    severity = "None"

    out_lower = output.lower()
    if "is vulnerable" in out_lower or "parameter" in out_lower:
        matches = re.findall(r"Parameter:\s*([^\s,;]+)", output, flags=re.IGNORECASE)
        if matches:
            vulnerability = f"Parameter(s) vulnerable: {', '.join(matches)}"
        else:
            vulnerability = "SQL Injection vulnerability detected"

        if "union query" in out_lower or "dumped" in out_lower:
            severity = "High"
        elif "time-based" in out_lower or "boolean-based" in out_lower:
            severity = "Medium"
        else:
            severity = "Low"
    return vulnerability, severity

def save_output(output, url):
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_name = url.replace("://", "_").replace("/", "_")
    filename = f"{ts}_{safe_name}.txt"
    filepath = os.path.join(RESULTS_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(output)
    return filepath

# -----------------------
# Flask App
# -----------------------
app = Flask(__name__)
app.secret_key = "dev-secret-key"

def simple_url_check(url):
    if not url:
        return False
    if not any(url.startswith(s) for s in ALLOWED_SCHEMES):
        return False
    return bool(urlparse(url).netloc)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not simple_url_check(url):
            flash("Invalid URL. Include http:// or https://", "danger")
            return redirect(url_for("index"))

        logging.info(f"Scanning {url}")
        output = run_sqlmap(url)
        vulnerability, severity = analyze_output(output)
        output_path = save_output(output, url)
        insert_scan(url, severity, vulnerability, output_path)

        evidence = [line.strip() for line in output.splitlines()
                    if any(k in line.lower() for k in
                           ["parameter", "vulnerable", "technique", "union", "time-based", "boolean-based"])]

        result = {
            "url": url,
            "vulnerability": vulnerability,
            "severity": severity,
            "evidence": evidence,
            "output_path": os.path.basename(output_path)
        }

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, url, severity, created_at FROM scans ORDER BY id DESC LIMIT 10")
    recent = c.fetchall()
    conn.close()

    return render_template_string(TEMPLATE, result=result, recent=recent)

@app.route("/results/<filename>")
def results_file(filename):
    return send_from_directory(RESULTS_DIR, filename, as_attachment=True)

# -----------------------
# Inline HTML Template
# -----------------------
TEMPLATE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>SQL Security Scanner</title>
<style>
body { font-family: Arial,sans-serif; background:#f6f8fa; margin:0; padding:20px;}
.container { max-width:900px; margin:0 auto; background:white; padding:20px; border-radius:8px; box-shadow:0 2px 6px rgba(0,0,0,.08);}
h1 { margin-top:0; }
form { display:flex; gap:8px; margin-bottom:16px;}
input[type="text"] { flex:1; padding:8px; border:1px solid #ddd; border-radius:4px; }
button { padding:8px 14px; border:none; border-radius:4px; background:#0a66c2; color:white; cursor:pointer;}
pre { background:#111; color:#dff; padding:12px; border-radius:6px; overflow:auto; }
.flash { padding:8px; background:#ffecec; color:#7a0b0b; margin-bottom:10px; border-radius:4px; }
footer { margin-top:18px; color:#555; font-size:12px; }
</style>
</head>
<body>
<div class="container">
<h1>SQL Security Scanner</h1>

{% with messages = get_flashed_messages(with_categories=true) %}
{% if messages %}
    {% for category, message in messages %}
        <div class="flash">{{ message }}</div>
    {% endfor %}
{% endif %}
{% endwith %}

<form method="POST">
<input type="text" name="url" placeholder="https://example.com/page.php?id=1" required>
<button type="submit">Scan</button>
</form>

{% if result %}
<h2>Scan Result</h2>
<p><b>URL:</b> {{ result.url }}</p>
<p><b>Vulnerability:</b> {{ result.vulnerability }}</p>
<p><b>Severity:</b> {{ result.severity }}</p>
<p><a href="{{ url_for('results_file', filename=result.output_path) }}">Download raw output</a></p>
<h3>Evidence</h3>
<pre>
{% for line in result.evidence %}
{{ line }}
{% else %}
No evidence extracted.
{% endfor %}
</pre>
{% endif %}

<h3>Recent Scans</h3>
<ul>
{% for r in recent %}
<li>{{ r[3] }} — <b>{{ r[2] }}</b> — {{ r[1] }}</li>
{% else %}
<li>No recent scans</li>
{% endfor %}
</ul>

<footer><small>Use responsibly. For authorized testing only.</small></footer>
</div>
</body>
</html>
"""

# -----------------------
# Main
# -----------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
