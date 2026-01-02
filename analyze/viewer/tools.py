from flask import Blueprint, send_from_directory, render_template
import os

tools_bp = Blueprint("tools", __name__, url_prefix="/tools")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CYBERCHEF_DIR = os.path.join(BASE_DIR, "static", "cyberchef")

@tools_bp.route("/")
def tool_index():
    return render_template("tools.html")

@tools_bp.route("/cyberchef-ui")
def tool_cyberchef_ui():
    return render_template("tools/cyberchef_wrapper.html")

@tools_bp.route("/cyberchef")
def tool_cyberchef():
    return send_from_directory(CYBERCHEF_DIR, "cyberchef.html")

@tools_bp.route("/<path:filename>")
def tool_files(filename):
    return send_from_directory(CYBERCHEF_DIR, filename)
