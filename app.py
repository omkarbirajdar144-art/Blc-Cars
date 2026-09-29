import os

from flask import Flask, render_template, request

from scanner import scan_target
from port_scanner import check_ports


app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["GET", "POST"])
def scan():

    # Directly opening /scan
    if request.method == "GET":
        return render_template("index.html")

    target = request.form.get("target", "").strip()

    if not target:
        return render_template(
            "index.html",
            error="Please enter a website or domain."
        )

    try:
        # Website security scan
        result = scan_target(target)

        # Port scan
        ip, ports = check_ports(target)

        # Add port information
        result["ip"] = ip if ip else result.get("ip", "Not Found")
        result["ports"] = ports

        return render_template(
            "index.html",
            result=result
        )

    except Exception as e:

        return render_template(
            "index.html",
            error=f"Scan error: {str(e)}"
        )


if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )