from flask import Flask, render_template, request, current_app, jsonify, session, redirect, abort, url_for, current_app
from viewer.cases import cases_bp
from viewer.timelines import timelines_bp
from flask import session as flask_session
from sqlalchemy import create_engine, or_, not_, insert
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from viewer.database import get_session
from viewer.timelines import get_timelines
import os
import re
import json
import html

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
app.secret_key = "super-secret-key"


# ----------------------------------------------------------------------
# Database helpers
# ----------------------------------------------------------------------

def apply_collection_filter(query, model):
    collection = flask_session.get("collection_name")
    if collection:
        query = query.filter(model.collection_name == collection)
    return query

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
    file_path = os.path.join(collection_dir, "files_and_dirs", rel_path.lstrip("/"))

    if not os.path.isfile(file_path):
        return "File not found", 404

    with open(file_path, "r", errors="replace") as f:
        content = f.read()

    return render_template("file_view.html", path=rel_path, content=content, parent_dir=parent_dir)


def _apply_text_query(query, columns, q_text):
    """
    Search syntax:
      - space        → AND
      - |            → OR
      - -term        → NOT
      - "quoted phrase" → exact phrase
    Supports multiple columns.
    """
    if not q_text:
        return query

    if not isinstance(columns, (list, tuple)):
        columns = [columns]

    include_groups = []   # each group is OR-ed
    exclude_terms = []

    pattern = r'(-?)"(.*?)"|(-?\S+)'
    tokens = re.findall(pattern, q_text)

    for dash, quoted, unquoted in tokens:
        if quoted:
            raw = quoted.strip()
            is_exclude = dash == "-"
        else:
            raw = (unquoted or "").strip()
            is_exclude = raw.startswith("-")
            if is_exclude:
                raw = raw[1:]

        if not raw:
            continue

        # OR support within a group
        parts = raw.split("|")

        if is_exclude:
            exclude_terms.extend(parts)
        else:
            include_groups.append(parts)

    # AND between groups, OR within group, across all columns
    for group in include_groups:
        query = query.filter(
            or_(
                *(col.ilike(f"%{term}%") for col in columns for term in group)
            )
        )

    if exclude_terms:
        query = query.filter(
            ~or_(
                *(col.ilike(f"%{t}%") for t in exclude_terms for col in columns)
            )
        )

    return query


@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    results = {}

    if q:
        db = get_session()

        results["commands"] = apply_collection_filter(
            _apply_text_query(db.query(CommandOutput), CommandOutput.output, q),
            CommandOutput
        ).all()

        results["files"] = apply_collection_filter(
            _apply_text_query(db.query(FileEntry), FileEntry.path, q),
            FileEntry
        ).all()

        results["packets"] = apply_collection_filter(
            _apply_text_query(db.query(PcapPacket), PcapPacket.raw_content, q),
            PcapPacket
        ).all()

        results["checksums"] = apply_collection_filter(
            _apply_text_query(
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
            _apply_text_query(db.query(Finding), Finding.message, q),
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
        q_checksum = _apply_text_query(
            base_query, Checksum.checksum, value
        )
        q_filepath = _apply_text_query(
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
        packet_query = _apply_text_query(
            packet_query,
            [PcapPacket.src, PcapPacket.dst, PcapPacket.protocol],
            q
        )
        packets = packet_query.limit(1000).all()

        # NetworkFlow search
        flow_query = db.query(NetworkFlow)
        flow_query = apply_collection_filter(flow_query, NetworkFlow)
        flow_query = _apply_text_query(
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

@app.route("/findings", methods=["GET", "POST"])
def findings():
    db = get_session()

    # Manually added finding
    if request.method == "POST":
        data = request.get_json() or {}

        message = (data.get("message") or "").strip()
        if not message:
            db.close()
            return jsonify({"error": "message required"}), 400

        # Parse meta (already JSON from frontend)
        meta = data.get("meta")

        finding = Finding(
            collection_name=data.get("collection"),
            type="manual",
            message=message,
            meta=meta,
            artifact=data.get("artifact"),
            indicator=data.get("indicator"),
        )

        db.add(finding)
        db.commit()
        finding_id = finding.id
        db.close()

        return jsonify({"status": "ok", "id": finding_id})

    q = request.args.get("q", "").strip()
    type_filters = request.args.getlist("type")
    rule_filters = request.args.getlist("rule")
    ack_filters = request.args.getlist("ack")  # list of '0' and/or '1'

    query = db.query(Finding)
    query = apply_collection_filter(query, Finding)

    # Apply text search
    if q:
        query = _apply_text_query(query, Finding.message, q)

    # Apply type filters
    if type_filters:
        query = query.filter(Finding.type.in_(type_filters))

    # Apply rule filters
    if rule_filters:
        query = query.filter(Finding.rule.in_(rule_filters))

    # Apply ack/unack filter
    if ack_filters:
        # Convert to int and filter
        ack_values = [int(a) for a in ack_filters if a in ('0', '1')]
        if ack_values:
            query = query.filter(Finding.ack.in_(ack_values))
    # If no ack filter provided, do nothing → include both 0 and 1

    findings = query.order_by(Finding.type, Finding.inserted_at).all()

    # Fetch dropdown options
    all_types = [row[0] for row in db.query(Finding.type).distinct().order_by(Finding.type)]
    all_rules = [row[0] for row in db.query(Finding.rule).distinct().order_by(Finding.rule)]

    # For adding finding to a case
    all_cases = db.query(Cases).order_by(Cases.inserted_at.desc()).all()

    db.close()

    return render_template(
        "findings.html",
        findings=findings,
        search_query=q,
        type_filter=type_filters,
        rule_filter=rule_filters,
        ack_filter=ack_filters,  # pass current ack filter to template
        all_types=all_types,
        all_rules=all_rules,
        all_cases=all_cases
    )

@app.route("/findings/<int:finding_id>", methods=["GET", "POST"])
def finding_detail(finding_id):
    db = get_session()

    if request.method == "POST":
        data = request.get_json() or {}

        # CASE 1: Add comment (existing behavior)
        if "comment" in data:
            comment = data.get("comment", "").strip()
            if not comment:
                db.close()
                return jsonify({"error": "comment required"}), 400

            note = FindingNotes(
                finding_id=finding_id,
                finding_comment=comment
            )
            db.add(note)
            db.commit()
            db.close()
            return jsonify({"status": "ok"})

    # GET
    finding = db.query(Finding).get(finding_id)
    if not finding:
        db.close()
        return "Finding not found", 404

    comments = (
        db.query(FindingNotes)
        .filter(FindingNotes.finding_id == finding_id)
        .order_by(FindingNotes.inserted_at.asc())
        .all()
    )

    db.close()
    return render_template("finding_detail.html", finding=finding, comments=comments)

@app.route("/findings/<int:finding_id>/ack", methods=["POST"])
def update_ack(finding_id):
    db = get_session()

    try:
        finding = db.query(Finding).get(finding_id)
        if not finding:
            return jsonify({"error": "Finding not found"}), 404

        data = request.get_json() or {}

        if "ack" not in data:
            return jsonify({"error": "Missing ack value"}), 400

        ack_comment = data.get("ack_comment")
        if not ack_comment:
            return jsonify({"error": "ack_comment required"}), 400

        finding.ack = 1 if data["ack"] else 0

        note = FindingNotes(
            finding_id=finding_id,
            finding_comment=ack_comment
        )
        db.add(note)

        db.commit()

        return jsonify({
            "status": "ok",
            "ack": finding.ack
        })

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()

@app.route("/findings/bulk_ack", methods=["POST"])
def bulk_ack():
    data = request.get_json()
    if not data.get("ack_comment"):
        return jsonify({"error": "ack_comment required"}), 400
    ack_comment = data.get("ack_comment")
    db = get_session()
    ids = data.get("ids", [])
    ack_value = 1 if data.get("ack") else 0

    if not ids:
        db.close()
        return jsonify({"error": "No IDs provided"}), 400


    db.add_all([
        FindingNotes(
            finding_id=finding_id,
            finding_comment=ack_comment
        )
        for finding_id in ids
    ])
    db.query(Finding).filter(Finding.id.in_(ids)).update(
        {Finding.ack: ack_value}, synchronize_session=False
    )
    db.commit()
    db.close()
    return jsonify({"status": "ok", "ack": ack_value, "count": len(ids)})


def get_collections():
    db = get_session()
    collection_names = [n[0] for n in db.query(Collections.collection_name).all()]
    return collection_names


def run_viewer(duckdb_file="timeline.duckdb", host="127.0.0.1", port=5000, debug=True):
    with app.app_context():
        app.config["DUCKDB_FILE"] = duckdb_file
        app.config["COLLECTIONS"] = get_collections()
        app.config["TIMELINES"] = get_timelines()
    print(f"[+] Viewer started")
    print(f"[+] URL: http://{host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False)
