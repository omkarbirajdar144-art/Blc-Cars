import io
import json
import os
import sqlite3
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request, send_file, abort
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from scanner import scan_target
from port_scanner import check_ports

app = Flask(__name__)
DB_PATH = os.environ.get("CYBERGUARD_DB", "cyberguard_history.db")


def get_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            target TEXT NOT NULL,
            result_json TEXT NOT NULL
        )
    """)
    connection.commit()
    return connection


def save_scan(target, result):
    with get_db() as db:
        cursor = db.execute(
            "INSERT INTO scans (scanned_at, target, result_json) VALUES (?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), target, json.dumps(result))
        )
        return cursor.lastrowid


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/history")
def history():
    with get_db() as db:
        rows = db.execute(
            "SELECT id, scanned_at, target, result_json FROM scans ORDER BY id DESC LIMIT 8"
        ).fetchall()
    items = []
    for row in rows:
        result = json.loads(row["result_json"])
        items.append({
            "id": row["id"],
            "scanned_at": row["scanned_at"],
            "target": row["target"],
            "score": result.get("score", 0),
            "status": result.get("security_status", "Unknown")
        })
    return jsonify(items)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or request.form
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Enter a website or domain."}), 400

    events = []
    def progress(message, percent):
        events.append({"message": message, "percent": percent})

    result = scan_target(target, progress)
    if result.get("status") == "Website reachable":
        ip, ports = check_ports(result["hostname"], result.get("ip"), progress)
        result["ip"] = ip or result.get("ip", "Not available")
        result["ports"] = ports
    else:
        result["ports"] = ["Port check skipped: target was not reachable or valid."]

    result["events"] = events
    result["scanned_at"] = datetime.now(timezone.utc).isoformat()
    scan_id = save_scan(target, result)
    result["scan_id"] = scan_id
    return jsonify(result)


@app.route("/report/<int:scan_id>")
def report(scan_id):
    with get_db() as db:
        row = db.execute(
            "SELECT scanned_at, target, result_json FROM scans WHERE id = ?",
            (scan_id,)
        ).fetchone()
    if row is None:
        abort(404)

    result = json.loads(row["result_json"])
    output = io.BytesIO()
    pdf = canvas.Canvas(output, pagesize=A4)
    width, height = A4
    y = height - 55

    def line(label, value, gap=22):
        nonlocal y
        pdf.setFont("Helvetica-Bold", 10)
        pdf.drawString(48, y, str(label)[:90])
        pdf.setFont("Helvetica", 10)
        pdf.drawString(205, y, str(value)[:95])
        y -= gap
        if y < 65:
            pdf.showPage()
            y = height - 55

    pdf.setTitle("CyberGuard Security Assessment")
    pdf.setFont("Helvetica-Bold", 19)
    pdf.drawString(48, y, "CYBERGUARD | SECURITY REPORT")
    y -= 35
    pdf.setFont("Helvetica", 9)
    pdf.drawString(48, y, "Basic automated assessment - educational use")
    y -= 30
    line("Target", row["target"])
    line("Scanned at (UTC)", row["scanned_at"])
    line("Hostname", result.get("hostname", "N/A"))
    line("Resolved IP", result.get("ip", "N/A"))
    line("HTTP status", result.get("http_status", "N/A"))
    line("Reachability", result.get("status", "N/A"))
    line("Response time", result.get("response_time", "N/A"))
    line("HTTPS", "Enabled" if result.get("https") else "Not detected")
    line("Security score", f'{result.get("score", 0)}/100')
    line("Assessment", result.get("security_status", "N/A"))
    y -= 5
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(48, y, "Security headers")
    y -= 22
    for header, present in result.get("security_headers", {}).items():
        line(header, "Present" if present else "Missing")
    y -= 5
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(48, y, "Common TCP port checks")
    y -= 22
    for port in result.get("ports", []):
        line("Port result", port)
    y -= 5
    pdf.setFont("Helvetica", 8)
    pdf.drawString(48, max(y, 35), "Limitations: This report shows basic checks only. It is not a penetration test or a guarantee of security.")
    pdf.save()
    output.seek(0)
    return send_file(output, mimetype="application/pdf", as_attachment=True,
                     download_name=f"cyberguard-report-{scan_id}.pdf")


@app.route("/scan", methods=["GET", "POST"])
def legacy_scan():
    if request.method == "GET":
        return render_template("index.html")
    return api_scan()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
