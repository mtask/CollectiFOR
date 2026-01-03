from flask import Flask, render_template, request, current_app, jsonify, session, redirect, abort, url_for, current_app
from viewer.cases import cases_bp
from viewer.timelines import timelines_bp
from viewer.findings import findings_bp
from viewer.tools import tools_bp
from viewer.filters import apply_collection_filter, apply_text_query
from flask import session as flask_session
from sqlalchemy import create_engine, or_, not_, insert
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from viewer.database import get_session
from viewer.timelines import get_timelines
import markdown
import bleach
from markupsafe import Markup
import os
import html
import secrets

from lib.db import (
    CommandOutput,
    Checksum,
    FilePermission,
    PcapPacket,
    NetworkFlow,
    Finding,
    FileEntry,
    ListenerEntry,
    Collections,
    FindingNotes,
    Cases,
)


app = Flask(__name__)
app.register_blueprint(cases_bp)
app.register_blueprint(timelines_bp)
app.register_blueprint(findings_bp)
app.register_blueprint(tools_bp)
app.secret_key = secrets.token_hex(64)

@app.template_filter("render_markdown")
def render_markdown(text):
    if not text:
        return ""

    html = markdown.markdown(
        text,
        extensions=["extra", "nl2br", "fenced_code"]
    )

    allowed_tags = bleach.sanitizer.ALLOWED_TAGS.union({
        "p", "pre", "code", "blockquote",
        "h1", "h2", "h3", "h4", "h5", "h6",
        "ul", "ol", "li", "strong", "em",
        "a", "br"
    })

    allowed_attrs = {
        "a": ["href", "title", "rel"]
    }

    clean_html = bleach.clean(
        html,
        tags=allowed_tags,
        attributes=allowed_attrs,
        strip=True
    )

    return Markup(clean_html)

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    try:
        return datetime.utcfromtimestamp(value).strftime(format)
    except:
        return value


@app.context_processor
def inject_collections():
    return {
        "all_collections": app.config["COLLECTIONS"] + ['extra'],
        "all_timelines": app.config["TIMELINES"]
    }


# ----------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------

@app.route("/")
def index():
    db = get_session()
    try:
        collections = db.query(Collections).all()
    finally:
        db.close()
    return render_template("index.html", collections=collections)

@app.route("/change_collection", methods=["POST"])
def change_collection():
    collection = request.form.get("collection")

    if collection:
        session["collection_name"] = collection
    else:
        session.pop("collection_name", None)  # All Collections

    return redirect(request.form.get("next", "/"))

@app.route("/change_timeline", methods=["POST"])
def change_timeline():
    timeline = request.form.get("timeline")

    if timeline:
        session["timeline_name"] = timeline
    else:
        session.pop("timeline_name", None)  # All Timelines

    return redirect(request.form.get("next", "/"))

@app.route("/listeners")
def listeners():
    db = get_session()
    try:
        query = db.query(ListenerEntry)
        query = apply_collection_filter(query, ListenerEntry)

        entries = query.order_by(ListenerEntry.protocol, ListenerEntry.port).all()
    finally:
        db.close()

    return render_template(
        "listeners.html",
        entries=entries,
    )

@app.route("/files/", defaults={"dir_path": ""})
@app.route("/files/<path:dir_path>")
def files(dir_path):
    db = get_session()

    q = request.args.get("q", "").strip()

    dir_path = dir_path.strip("/")
    current_dir = "/" + dir_path if dir_path else ""

    dirs = []
    files = []

    if q:
        # Global search ignoring current_dir
        query = db.query(FileEntry).filter(
            FileEntry.type == "file",
            FileEntry.path.ilike(f"%{q}%")
        )

        query = apply_collection_filter(query, FileEntry)

        files = query.all()
        files.sort(key=lambda f: f.path)

    else:
        current_depth = current_dir.count("/") if current_dir else 0
        like_pattern = f"{current_dir}/%" if current_dir else "/%"

        # Directories
        dir_query = db.query(FileEntry).filter(
            FileEntry.path.like(like_pattern),
            FileEntry.type == "dir"
        )
        dir_query = apply_collection_filter(dir_query, FileEntry)

        dirs = dir_query.all()
        dirs = [d for d in dirs if d.path.count("/") == current_depth + 1]

        # Files
        file_query = db.query(FileEntry).filter(
            FileEntry.path.like(like_pattern),
            FileEntry.type == "file"
        )
        file_query = apply_collection_filter(file_query, FileEntry)

        files = file_query.all()
        files = [f for f in files if f.path.count("/") == current_depth + 1]

    db.close()

    return render_template(
        "files.html",
        current_dir=current_dir,
        dirs=dirs,
        files=files,
        search_query=q
    )


@app.route("/files/view")
def view_file():
    rel_path = request.args.get("path")
    if not rel_path:
        return "Missing file path", 400
    # Determine parent directory
    parent_dir = "/" + "/".join(rel_path.strip("/").split("/")[:-1])
    db = get_session()
    current_collection = flask_session.get("collection_name")
    collection_dir = (
        db.query(Collections.collection_abs_path)
        .filter(Collections.collection_name == current_collection)
        .first()
    )
    collection_dir = collection_dir[0] if collection_dir else None
    if not collection_dir:
        return render_template("file_view.html", path=rel_path, content="Collection directory not found from the database", parent_dir=parent_dir)
    if not os.path.isdir(collection_dir):
        return render_template("file_view.html", path=rel_path, content=f"Collection directory {collection_dir} not found", parent_dir=parent_dir)
    fp1 = os.path.join(collection_dir, "files_and_dirs", rel_path.lstrip("/"))
    fp2 = os.path.join(collection_dir, rel_path.lstrip("/"))
    if os.path.isfile(fp1):
        file_path = fp1
    elif os.path.isfile(fp2):
        file_path = fp2
    else:
        return "File not found", 404
    with open(file_path, "r", errors="replace") as f:
        content = f.read()

    return render_template("file_view.html", path=rel_path, content=content, parent_dir=parent_dir)


@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    results = {}

    if q:
        db = get_session()

        results["commands"] = apply_collection_filter(
            apply_text_query(db.query(CommandOutput), CommandOutput.output, q),
            CommandOutput
        ).all()

        results["files"] = apply_collection_filter(
            apply_text_query(db.query(FileEntry), FileEntry.path, q),
            FileEntry
        ).all()

        results["packets"] = apply_collection_filter(
            apply_text_query(db.query(PcapPacket), PcapPacket.raw_content, q),
            PcapPacket
        ).all()

        results["checksums"] = apply_collection_filter(
            apply_text_query(
                db.query(Checksum),
                Checksum.checksum,
                q
            ).filter(
                or_(
                    Checksum.checksum.ilike(f"%{q}%"),
                    Checksum.filepath.ilike(f"%{q}%")
                )
            ),
            Checksum
        ).all()

        results["findings"] = apply_collection_filter(
            apply_text_query(db.query(Finding), Finding.message, q),
            Finding
        ).all()

        db.close()

    return render_template("search.html", q=q, results=results)

@app.route("/commands")
def commands():
    db = get_session()
    q = request.args.get("q", "").strip()

    if q:
        query = db.query(CommandOutput).filter(
            CommandOutput.category.ilike(f"%{q}%")
        )
    else:
        query = db.query(CommandOutput)

    query = apply_collection_filter(query, CommandOutput)

    entries = query.order_by(
        CommandOutput.category,
        CommandOutput.inserted_at
    ).all()

    db.close()

    return render_template("commands.html", entries=entries, search_query=q)

@app.route("/checksums")
def checksum_search():
    value = request.args.get("value", "").strip()
    results = []

    if value:
        db = get_session()

        base_query = db.query(Checksum)
        base_query = apply_collection_filter(base_query, Checksum)

        # Apply text search separately per column
        q_checksum = apply_text_query(
            base_query, Checksum.checksum, value
        )
        q_filepath = apply_text_query(
            base_query, Checksum.filepath, value
        )

        # OR the results together
        query = base_query.filter(
            or_(
                Checksum.id.in_(q_checksum.with_entities(Checksum.id)),
                Checksum.id.in_(q_filepath.with_entities(Checksum.id))
            )
        )

        results = query.all()
        db.close()

    return render_template("checksums.html", value=value, results=results)


@app.route("/network")
def network_search():
    q = request.args.get("q", "").strip()
    packets = []
    flows = []

    if q:
        db = get_session()

        # PcapPacket search
        packet_query = db.query(PcapPacket)
        packet_query = apply_collection_filter(packet_query, PcapPacket)
        packet_query = apply_text_query(
            packet_query,
            [PcapPacket.src, PcapPacket.dst, PcapPacket.protocol],
            q
        )
        packets = packet_query.limit(1000).all()

        # NetworkFlow search
        flow_query = db.query(NetworkFlow)
        flow_query = apply_collection_filter(flow_query, NetworkFlow)
        flow_query = apply_text_query(
            flow_query,
            [NetworkFlow.src, NetworkFlow.dst, NetworkFlow.protocol],
            q
        )
        flows = flow_query.all()

        db.close()

    return render_template(
        "network.html",
        q=q,
        packets=packets,
        flows=flows
    )


def get_collections():
    db = get_session()
    collection_names = [n[0] for n in db.query(Collections.collection_name).all()]
    return collection_names


def run_viewer(api_keys={}, duckdb_file="timeline.duckdb", host="127.0.0.1", port=5000, debug=True):
    with app.app_context():
        app.config["DUCKDB_FILE"] = duckdb_file
        app.config["COLLECTIONS"] = get_collections()
        app.config["TIMELINES"] = get_timelines()
        app.config["API_KEYS"] = api_keys
    print(f"[+] Viewer started")
    print(f"[+] URL: http://{host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False)
