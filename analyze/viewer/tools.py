from flask import Blueprint, send_from_directory, render_template, request, current_app
from sqlalchemy.orm import Session
from modules import ipinfo, virustotal,threatfox
from lib.db import Checksum
from viewer.database import get_session
import os

tools_bp = Blueprint("tools", __name__, url_prefix="/tools")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CYBERCHEF_DIR = os.path.join(BASE_DIR, "static", "cyberchef")

@tools_bp.route("/")
def tool_index():
    return render_template("tools/tools.html")

@tools_bp.route("/cyberchef-ui")
def tool_cyberchef_ui():
    return render_template("tools/cyberchef_wrapper.html")

@tools_bp.route("/cyberchef")
def tool_cyberchef():
    return send_from_directory(CYBERCHEF_DIR, "cyberchef.html")

@tools_bp.route("/<path:filename>")
def tool_files(filename):
    return send_from_directory(CYBERCHEF_DIR, filename)

@tools_bp.route("/ipinfo", methods=["GET", "POST"])
def tool_ipinfo():
    result_ipinfo = None
    error = None
    api_key = current_app.config["API_KEYS"].get('ipinfo', '')
    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        if ip:
            result_ipinfo = ipinfo.fetch(ip, api_key)
        else:
            error = "Please enter an IP address."

    return render_template("tools/ipinfo.html", result_ipinfo=result_ipinfo, error=error)

@tools_bp.route("/threatfox", methods=["GET", "POST"])
def tool_threatfox():
    result = None
    error = None
    api_key = current_app.config["API_KEYS"].get('threatfox', '')
    if request.method == "POST":
        query = request.form.get("query", "").strip()
        if query:
            result = threatfox.fetch(query, api_key)
            if result['query_status'] != "ok":
                error = result['data']
        else:
            error = "Please enter search term."
    return render_template("tools/threatfox.html", result=result, error=error)

@tools_bp.route("/virustotal", methods=["GET", "POST"])
def tool_virustotal():
    result_virustotal = None
    error = None
    q_type = None
    api_key = current_app.config["API_KEYS"].get('virustotal', '')

    if request.method == "POST":
        q_data = request.form.get("query", "").strip()
        q_type = request.form.get("query_type", "").strip()
        if q_type == "filehash":
            result_virustotal = virustotal.fetch_filehash(q_data, api_key)
        elif q_type == "domain":
            result_virustotal = virustotal.fetch_domain(q_data, api_key)
        elif q_type == "ip":
            result_virustotal = virustotal.fetch_ip(q_data, api_key)
        else:
            error = "Invalid query option"
        if result_virustotal:
            if 'error' in result_virustotal:
                error = result_virustotal['error']['message']
    return render_template("tools/virustotal.html", result=result_virustotal, result_type=q_type, error=error)

@tools_bp.route("/checksum_search", methods=["GET", "POST"])
def tool_checksum_search():
    results = []
    errors = []

    if request.method == "POST":
        db = get_session()

        checksums = set()

        # ----------------------------
        # 1. Pasted checksums
        # ----------------------------
        pasted = request.form.get("checksums_text", "").strip()
        if pasted:
            for line in pasted.splitlines():
                val = line.split(' ')[0]
                if val:
                    checksums.add(val)

        # ----------------------------
        # 2. Uploaded file
        # ----------------------------
        uploaded = request.files.get("checksums_file")
        if uploaded and uploaded.filename:
            for line in uploaded.stream.read().decode("utf-8", errors="ignore").splitlines():
                val = line.split(' ')[0]
                if val:
                    checksums.add(val)

        # ----------------------------
        # Validation
        # ----------------------------
        if not checksums:
            errors.append("No checksums provided.")

        # ----------------------------
        # Database query
        # ----------------------------
        if not errors:
            results = (
                db.query(Checksum)
                .filter(Checksum.checksum.in_(checksums))
                .all()
            )

    return render_template(
        "tools/checksum_search.html",
        results=results,
        errors=errors
    )

