import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from io import BytesIO

from flask import Flask, abort, jsonify, render_template, request, send_file
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from scanner import scan_target
from port_scanner import check_ports

app = Flask(__name__)
DB_PATH = os.environ.get("CYBERGUARD_DB", "cyberguard_history.db")
JOBS = {}
JOBS_LOCK = threading.Lock()


def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scanned_at TEXT NOT NULL, target TEXT NOT NULL, result_json TEXT NOT NULL
    )""")
    db.commit()
    return db


def save_scan(target, result):
    with get_db() as db:
        cur = db.execute("INSERT INTO scans(scanned_at,target,result_json) VALUES(?,?,?)",
                         (datetime.now(timezone.utc).isoformat(), target, json.dumps(result)))
        return cur.lastrowid


def run_job(job_id, target):
    def progress(message, percent):
        with JOBS_LOCK:
            JOBS[job_id]["progress"] = max(0, min(99, int(percent)))
            JOBS[job_id]["events"].append(message)

    try:
        progress("Validating target format", 5)
        result = scan_target(target, progress)
        if result.get("status") == "Website reachable":
            ip, ports = check_ports(result["hostname"], result.get("ip"), progress)
            result["ip"] = ip or result.get("ip", "Not available")
            result["ports"] = ports
        else:
            result["ports"] = ["Port check skipped: target was not reachable or valid."]
        result["scanned_at"] = datetime.now(timezone.utc).isoformat()
        scan_id = save_scan(target, result)
        result["scan_id"] = scan_id
        with JOBS_LOCK:
            JOBS[job_id].update({"status": "complete", "progress": 100, "result": result})
            JOBS[job_id]["events"].append("Assessment complete")
    except Exception as exc:
        with JOBS_LOCK:
            JOBS[job_id].update({"status": "error", "progress": 100, "error": str(exc)[:180]})
            JOBS[job_id]["events"].append("Scan failed")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json(silent=True) or request.form
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Enter a website or domain."}), 400
    job_id = uuid.uuid4().hex
    with JOBS_LOCK:
        JOBS[job_id] = {"status": "running", "progress": 2, "events": ["Scan request received"]}
    threading.Thread(target=run_job, args=(job_id, target), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/api/scan/<job_id>")
def scan_status(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return jsonify({"error": "Scan session not found. Please start a new scan."}), 404
        return jsonify(dict(job))


@app.route("/api/history")
def history():
    with get_db() as db:
        rows = db.execute("SELECT id,scanned_at,target,result_json FROM scans ORDER BY id DESC LIMIT 10").fetchall()
    return jsonify([{
        "id": row["id"], "scanned_at": row["scanned_at"], "target": row["target"],
        "score": json.loads(row["result_json"]).get("score", 0),
        "status": json.loads(row["result_json"]).get("security_status", "Unknown")
    } for row in rows])


@app.route("/report/<int:scan_id>")
def report(scan_id):
    with get_db() as db:
        row = db.execute("SELECT scanned_at,target,result_json FROM scans WHERE id=?", (scan_id,)).fetchone()
    if row is None:
        abort(404)
    result = json.loads(row["result_json"])
    output = BytesIO()
    pdf = canvas.Canvas(output, pagesize=A4)
    width, height = A4
    y = height - 55
    pdf.setTitle("CyberGuard Security Assessment")
    pdf.setFont("Helvetica-Bold", 19)
    pdf.drawString(48, y, "CYBERGUARD | SECURITY REPORT")
    y -= 38
    pdf.setFont("Helvetica", 9)
    pdf.drawString(48, y, "Basic automated assessment - educational use")
    y -= 30

    def line(label, value):
        nonlocal y
        if y < 65:
            pdf.showPage()
            y = height - 55
        pdf.setFont("Helvetica-Bold", 9)
        pdf.drawString(48, y, str(label)[:50])
        pdf.setFont("Helvetica", 9)
        pdf.drawString(205, y, str(value)[:90])
        y -= 20

    for label, value in [
        ("Target", row["target"]), ("Scanned at (UTC)", row["scanned_at"]),
        ("Hostname", result.get("hostname", "N/A")), ("Resolved IP", result.get("ip", "N/A")),
        ("HTTP status", result.get("http_status", "N/A")), ("Reachability", result.get("status", "N/A")),
        ("Response time", result.get("response_time", "N/A")),
        ("HTTPS", "Enabled" if result.get("https") else "Not detected"),
        ("Security score", f'{result.get("score", 0)}/100'),
        ("Assessment", result.get("security_status", "N/A"))
    ]:
        line(label, value)
    y -= 8
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(48, y, "Security headers")
    y -= 22
    for key, present in result.get("security_headers", {}).items():
        line(key, "Present" if present else "Missing")
    y -= 8
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(48, y, "Common TCP port checks")
    y -= 22
    for item in result.get("ports", []):
        line("Port result", item)
    pdf.setFont("Helvetica", 8)
    pdf.drawString(48, max(35, y - 8), "Limitations: Basic checks only. Not a penetration test or a guarantee of security.")
    pdf.save()
    output.seek(0)
    return send_file(output, mimetype="application/pdf", as_attachment=True,
                     download_name=f"cyberguard-report-{scan_id}.pdf")


@app.route("/scan", methods=["GET", "POST"])
def legacy_scan():
    if request.method == "GET":
        return render_template("index.html")
    return start_scan()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
