
from flask import Flask, render_template, request

from scanner import scan_target
from port_scanner import check_ports


app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    target = request.form.get("target", "").strip()

    if not target:
        return render_template("index.html")

    # Website security scan
    result = scan_target(target)

    # Port scan
    ip, ports = check_ports(target)

    result["ports"] = ports

    return render_template(
        "index.html",
        result=result
    )


if __name__ == "__main__":
    app.run(debug=True)

