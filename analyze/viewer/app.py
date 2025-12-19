from flask import Flask, render_template, request, current_app, jsonify
from sqlalchemy import create_engine, or_
from sqlalchemy.orm import sessionmaker
from flask import abort
from datetime import datetime
import pandas as pd
import duckdb
import os
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
)


app = Flask(__name__)


# ----------------------------------------------------------------------
# Database helpers
# ----------------------------------------------------------------------

def get_session():
    engine = create_engine(
        f"sqlite:///{DB_FILE}",
        future=True
    )
    Session = sessionmaker(bind=engine)
    return Session()

def get_tl_session():
    engine = create_engine(
        f"sqlite:///{DB_TL_FILE}",
        future=True
    )
    Session = sessionmaker(bind=engine)
    return Session()


# ----------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/listeners")
def listeners():
    session = get_session()
    try:
        entries = (
            session.query(ListenerEntry)
            .order_by(ListenerEntry.protocol, ListenerEntry.port)
            .all()
        )
    finally:
        session.close()

    return render_template(
        "listeners.html",
        entries=entries,
    )

@app.route("/files/", defaults={"dir_path": ""})
@app.route("/files/<path:dir_path>")
def files(dir_path):
    session = get_session()

    # Get optional search query
    q = request.args.get("q", "").strip()

    # Normalize current directory
    dir_path = dir_path.strip("/")
    current_dir = "/" + dir_path if dir_path else ""

    dirs = []
    files = []

    if q:
        # Global search ignoring current_dir
        files = session.query(FileEntry).filter(
            FileEntry.type == "file",
            FileEntry.path.ilike(f"%{q}%")
        ).all()
        # Optionally, sort by path
        files.sort(key=lambda f: f.path)
    else:
        # Normal browsing mode
        current_depth = current_dir.count("/") if current_dir else 0
        like_pattern = f"{current_dir}/%" if current_dir else "/%"

        # Directories
        dirs = session.query(FileEntry).filter(
            FileEntry.path.like(like_pattern),
            FileEntry.type == "dir"
        ).all()
        dirs = [d for d in dirs if d.path.count("/") == current_depth + 1]

        # Files
        files = session.query(FileEntry).filter(
            FileEntry.path.like(like_pattern),
            FileEntry.type == "file"
        ).all()
        files = [f for f in files if f.path.count("/") == current_depth + 1]

    session.close()

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

    file_path = os.path.join(COLLECTION_DIR, "files_and_dirs", rel_path.lstrip("/"))

    if not os.path.isfile(file_path):
        return "File not found", 404

    with open(file_path, "r", errors="replace") as f:
        content = f.read()

    return render_template("file_view.html", path=rel_path, content=content, parent_dir=parent_dir)

@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    results = {}

    if q:
        session = get_session()

        results["commands"] = session.query(CommandOutput)\
            .filter(CommandOutput.output.contains(q)).all()

        results["files"] = session.query(FilePermission)\
            .filter(FilePermission.filepath.contains(q)).all()

        results["packets"] = session.query(PcapPacket)\
            .filter(PcapPacket.raw_content.contains(q)).limit(100).all()

        results["findings"] = session.query(Finding)\
            .filter(Finding.message.contains(q)).all()

        session.close()

    return render_template("search.html", q=q, results=results)

@app.route("/commands")
def commands():
    session = get_session()

    # Optional filter: command name (e.g. "lsmod", "docker", "ps")
    q = request.args.get("q", "").strip()

    query = session.query(CommandOutput)

    if q:
        # Match both stdout.<cmd> and stderr.<cmd>
        query = query.filter(
            CommandOutput.category.ilike(f"%{q}%")
        )

    entries = query.order_by(
        CommandOutput.category,
        CommandOutput.inserted_at
    ).all()

    session.close()

    return render_template(
        "commands.html",
        entries=entries,
        search_query=q,
    )

@app.route("/checksums")
def checksum_search():
    value = request.args.get("value", "").strip()
    results = []

    if value:
        session = get_session()
        results = session.query(Checksum)\
            .filter(or_(
                Checksum.checksum.contains(value),
                Checksum.filepath.contains(value)
            )).all()
        session.close()

    return render_template("checksums.html", value=value, results=results)


@app.route("/network")
def network_search():
    q = request.args.get("q", "").strip()
    packets = []
    flows = []

    if q:
        session = get_session()

        packets = session.query(PcapPacket).filter(
            or_(
                PcapPacket.src.contains(q),
                PcapPacket.dst.contains(q),
                PcapPacket.protocol.contains(q)
            )
        ).limit(200).all()

        flows = session.query(NetworkFlow).filter(
            or_(
                NetworkFlow.src.contains(q),
                NetworkFlow.dst.contains(q),
                NetworkFlow.protocol.contains(q)
            )
        ).all()

        session.close()

    return render_template(
        "network.html",
        q=q,
        packets=packets,
        flows=flows
    )


@app.route("/findings")
def findings():
    session = get_session()

    findings = session.query(Finding)\
        .order_by(Finding.type, Finding.inserted_at.desc())\
        .all()

    session.close()
    return render_template("findings.html", findings=findings)


@app.route("/findings/<int:finding_id>")
def finding_detail(finding_id):
    session = get_session()
    finding = session.query(Finding).get(finding_id)
    session.close()
    return render_template("finding_detail.html", finding=finding)



# ------------------------
# Timeline page
# ------------------------
@app.route("/timeline")
def timeline():
    return render_template("timeline.html")


@app.route("/api/timeline_data")
def timeline_data():
    start_time = request.args.get("start_time")
    end_time = request.args.get("end_time")
    sql_filter = request.args.get("sql_filter", "").strip()

    start = int(request.args.get("start", 0))
    length = int(request.args.get("length", 50))

    conn = duckdb.connect(DUCKDB_FILE)

    base_sql = """
        FROM timeline_events
        WHERE 1=1
    """

    if start_time:
        ts_start = int(start_time) * 1_000_000
        base_sql += f" AND timestamp >= {ts_start}"

    if end_time:
        ts_end = int(end_time) * 1_000_000
        base_sql += f" AND timestamp <= {ts_end}"

    if sql_filter:
        base_sql += f" AND ({sql_filter})"

    data_sql = f"""
        SELECT id, timestamp, timestamp_desc, data_type, message
        {base_sql}
        ORDER BY timestamp ASC
        LIMIT {length} OFFSET {start}
    """

    data = conn.execute(data_sql).df().to_dict(orient="records")

    total_count = conn.execute(
        "SELECT COUNT(*) FROM timeline_events"
    ).fetchone()[0]

    filtered_count = conn.execute(
        f"SELECT COUNT(*) {base_sql}"
    ).fetchone()[0]

    return jsonify({
        "draw": int(request.args.get("draw", 1)),
        "recordsTotal": total_count,
        "recordsFiltered": filtered_count,
        "data": data
    })

@app.route("/api/timeline_event/<int:event_id>")
def timeline_event(event_id):
    conn = duckdb.connect(DUCKDB_FILE)

    result = conn.execute(
        "SELECT * FROM timeline_events WHERE id = ?",
        [event_id]
    )

    row = result.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Not found"}), 404

    columns = [desc[0] for desc in result.description]
    event_dict = dict(zip(columns, row))

    # Directly parse JSON fields
    print(event_dict)
    event_dict["extra"] = json.loads(event_dict["extra"])
    event_dict["date_time"] = json.loads(event_dict["date_time"])
    if isinstance(event_dict.get('inserted_at'), datetime):
        event_dict['inserted_at'] = event_dict['inserted_at'].isoformat()
    conn.close()

    # Return pretty JSON
    return app.response_class(
        response=json.dumps(event_dict, indent=2),
        mimetype='application/json'
    )


def run_viewer(collection_dir, db_file="collectifor.db", duckdb_file="timeline.duckdb", host="127.0.0.1", port=5000, debug=True):
    global COLLECTION_DIR, DB_FILE, DUCKDB_FILE
    COLLECTION_DIR = os.path.realpath(collection_dir)
    DB_FILE = db_file
    DUCKDB_FILE = duckdb_file
    print(f"[+] Viewer started")
    print(f"[+] Collection: {COLLECTION_DIR}")
    print(f"[+] URL: http://{host}:{port}")

    app.run(host=host, port=port, debug=debug, use_reloader=False)
