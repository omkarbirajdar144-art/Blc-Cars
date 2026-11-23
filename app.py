import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from flask import Flask, abort, jsonify, render_template, request, send_file
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
)

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
    score = max(0, min(100, int(result.get("score", 0) or 0)))
    headers = result.get("security_headers") or {}
    ports = result.get("ports") or []
    output = BytesIO()

    navy = colors.HexColor("#101B2D")
    blue = colors.HexColor("#147D92")
    pale = colors.HexColor("#EAF3F6")
    light = colors.HexColor("#F3F6F9")
    ink = colors.HexColor("#263445")
    muted = colors.HexColor("#687789")
    green = colors.HexColor("#16845B")
    red = colors.HexColor("#B54747")
    amber = colors.HexColor("#A66A13")

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=20, leading=24, textColor=colors.white, alignment=TA_LEFT, spaceAfter=3
    ))
    styles.add(ParagraphStyle(
        name="SubTitle", parent=styles["Normal"], fontName="Helvetica",
        fontSize=9, leading=13, textColor=colors.HexColor("#D5E5EC")
    ))
    styles.add(ParagraphStyle(
        name="Section", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=12, leading=15, textColor=navy, spaceBefore=12, spaceAfter=7
    ))
    styles.add(ParagraphStyle(
        name="BodySmall", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=8.5, leading=12, textColor=ink
    ))
    styles.add(ParagraphStyle(
        name="MutedSmall", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=7.5, leading=10, textColor=muted
    ))
    styles.add(ParagraphStyle(
        name="Cell", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=8, leading=10, textColor=ink
    ))
    styles.add(ParagraphStyle(
        name="CellBold", parent=styles["BodyText"], fontName="Helvetica-Bold",
        fontSize=8, leading=10, textColor=navy
    ))

    def para(value, style="Cell"):
        return Paragraph(escape(str(value if value not in (None, "") else "N/A")), styles[style])

    def page_chrome(canvas_obj, doc):
        canvas_obj.saveState()
        w, h = A4
        canvas_obj.setFillColor(navy)
        canvas_obj.rect(0, h - 7 * mm, w, 7 * mm, fill=1, stroke=0)
        canvas_obj.setStrokeColor(colors.HexColor("#DCE5EB"))
        canvas_obj.line(18 * mm, 15 * mm, w - 18 * mm, 15 * mm)
        canvas_obj.setFont("Helvetica", 7)
        canvas_obj.setFillColor(muted)
        canvas_obj.drawString(18 * mm, 10 * mm, "CYBERGUARD  |  SECURITY ASSESSMENT")
        canvas_obj.drawRightString(w - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas_obj.restoreState()

    doc = SimpleDocTemplate(
        output, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=17 * mm, bottomMargin=21 * mm,
        title=f"CyberGuard Security Assessment - {row['target']}",
        author="CyberGuard"
    )
    story = []

    banner = Table([[
        [Paragraph("CYBERGUARD", styles["ReportTitle"]),
         Paragraph("WEBSITE SECURITY ASSESSMENT REPORT", styles["SubTitle"])]
    ]], colWidths=[174 * mm])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), navy),
        ("BOX", (0, 0), (-1, -1), 0, navy),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.extend([Spacer(1, 3 * mm), banner, Spacer(1, 5 * mm)])

    scanned_at = row["scanned_at"]
    try:
        scanned_at = datetime.fromisoformat(scanned_at.replace("Z", "+00:00")).strftime("%d %b %Y, %H:%M UTC")
    except (ValueError, TypeError):
        pass

    meta = Table([
        [para("TARGET", "CellBold"), para(row["target"]), para("REPORT ID", "CellBold"), para(f"CG-{scan_id:05d}")],
        [para("SCAN DATE", "CellBold"), para(scanned_at), para("HOSTNAME", "CellBold"), para(result.get("hostname", "N/A"))],
        [para("RESOLVED IP", "CellBold"), para(result.get("ip", "N/A")), para("HTTP STATUS", "CellBold"), para(result.get("http_status", "N/A"))],
    ], colWidths=[25 * mm, 61 * mm, 27 * mm, 61 * mm])
    meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), light),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DCE5EB")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([meta, Paragraph("OVERALL SECURITY SUMMARY", styles["Section"])])

    assessment = result.get("security_status", "Assessment unavailable")
    score_color = green if score >= 75 else amber if score >= 45 else red
    score_card = Table([[
        [Paragraph(f'<font color="{score_color.hexval()}"><b>{score}/100</b></font>',
                   ParagraphStyle("ScoreNumber", parent=styles["Title"], fontSize=25, leading=29, alignment=TA_CENTER)),
         Paragraph("SECURITY CONFIGURATION SCORE", ParagraphStyle(
             "ScoreLabel", parent=styles["MutedSmall"], alignment=TA_CENTER))],
        [Paragraph(f"<b>{escape(str(assessment))}</b>", ParagraphStyle(
            "AssessmentText", parent=styles["BodyText"], fontSize=11, leading=15,
            textColor=ink, alignment=TA_LEFT)),
         Paragraph(
             f"HTTPS: {'Enabled' if result.get('https') else 'Not detected'}<br/>"
             f"Website reachability: {escape(str(result.get('status', 'N/A')))}<br/>"
             f"Response time: {escape(str(result.get('response_time', 'N/A')))}",
             styles["BodySmall"])]
    ]], colWidths=[58 * mm, 116 * mm])
    score_card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), pale),
        ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#C9DDE4")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("SPAN", (0, 0), (0, 0)),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.extend([score_card, Paragraph("SECURITY HEADER ANALYSIS", styles["Section"])])

    header_rows = [[para("SECURITY HEADER", "CellBold"), para("RESULT", "CellBold"), para("WHAT IT HELPS WITH", "CellBold")]]
    header_help = {
        "Strict-Transport-Security": "Encourages secure HTTPS connections",
        "Content-Security-Policy": "Helps reduce certain content injection risks",
        "X-Content-Type-Options": "Reduces MIME type confusion",
        "X-Frame-Options": "Helps protect against clickjacking",
        "Referrer-Policy": "Controls referrer information shared by browsers",
        "Permissions-Policy": "Restricts selected browser capabilities",
    }
    for key, present in headers.items():
        label = "PRESENT" if present else "MISSING"
        header_rows.append([para(key), para(label), para(header_help.get(key, "Browser security configuration"))])
    if len(header_rows) == 1:
        header_rows.append([para("No header data returned"), para("N/A"), para("No header checks were recorded")])
    header_table = Table(header_rows, colWidths=[63 * mm, 25 * mm, 86 * mm], repeatRows=1)
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#DCE5EB")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, light]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(header_table)

    story.append(Paragraph("COMMON TCP PORT CHECKS", styles["Section"]))
    port_rows = [[para("CHECK RESULT", "CellBold"), para("INTERPRETATION", "CellBold")]]
    for item in ports:
        text_item = str(item)
        interpretation = "Review this service and confirm it is required." if "open" in text_item.lower() else "No further action indicated by this basic check."
        port_rows.append([para(text_item), para(interpretation)])
    if len(port_rows) == 1:
        port_rows.append([para("No port results available"), para("Port checks were not completed")])
    port_table = Table(port_rows, colWidths=[82 * mm, 92 * mm], repeatRows=1)
    port_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#DCE5EB")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, light]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(port_table)

    recommendations = []
    for key, present in headers.items():
        if not present:
            recommendations.append(f"Review and configure the {key} response header where appropriate.")
    if not result.get("https"):
        recommendations.append("Enable HTTPS with a valid TLS certificate and redirect HTTP traffic to HTTPS.")
    if not recommendations:
        recommendations.append("The checked configuration items were detected. Continue routine patching, monitoring, and periodic security reviews.")
    story.append(Paragraph("RECOMMENDATIONS", styles["Section"]))
    for item in recommendations:
        story.append(Paragraph("&#8226; " + escape(item), styles["BodySmall"]))
        story.append(Spacer(1, 2 * mm))

    story.append(Spacer(1, 4 * mm))
    note = Table([[Paragraph(
        "<b>IMPORTANT SCOPE NOTE</b><br/>This report summarizes a limited, automated educational assessment "
        "of HTTPS, selected HTTP response headers, and a small set of common TCP ports. The score is a "
        "basic configuration indicator, not an industry-standard risk rating. This check is not a penetration "
        "test, does not identify every vulnerability, and cannot guarantee that a website is secure. "
        "Only assess systems you own or are authorized to test.",
        styles["BodySmall"]
    )]], colWidths=[174 * mm])
    note.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF7E8")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#E7D5AE")),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))
    story.append(note)

    doc.build(story, onFirstPage=page_chrome, onLaterPages=page_chrome)
    output.seek(0)
    return send_file(output, mimetype="application/pdf", as_attachment=True,
                     download_name=f"cyberguard-professional-report-{scan_id}.pdf")


@app.route("/scan", methods=["GET", "POST"])
def legacy_scan():
    if request.method == "GET":
        return render_template("index.html")
    return start_scan()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
