from flask import Flask, render_template, request, current_app
from sqlalchemy import create_engine, or_
from sqlalchemy.orm import sessionmaker
from flask import abort
from datetime import datetime
import os
import json
import html

# Import models ONLY (no DB class)
from lib.db import (
    CommandOutput,
    Checksum,
    FilePermission,
    PcapPacket,
    NetworkFlow,
    Finding,
    FileEntry,
    ListenerEntry,
    TimelineEvent,
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


@app.route("/timeline")
def timeline():
    session = get_session()

    q = request.args.get("q", "").strip()
    source = request.args.get("source", "").strip()
    event_type = request.args.get("event_type", "").strip()
    start_time = request.args.get("start", "").strip()
    end_time = request.args.get("end", "").strip()

    MIN_TIMESTAMP = datetime(1980, 1, 1)  # exclude 1970/Not-a-time events

    query = session.query(TimelineEvent).filter(TimelineEvent.timestamp >= MIN_TIMESTAMP)

    # Filters
    if q:
        query = query.filter(TimelineEvent.summary.contains(q))

    if source:
        source_list = source.split(',')
        query = query.filter(TimelineEvent.source.in_(source_list))

    if event_type:
        type_list = event_type.split(',')
        query = query.filter(TimelineEvent.event_type.in_(type_list))

    if start_time:
        try:
            dt_start = datetime.fromisoformat(start_time)
            query = query.filter(TimelineEvent.timestamp >= dt_start)
        except ValueError:
            pass

    if end_time:
        try:
            dt_end = datetime.fromisoformat(end_time)
            query = query.filter(TimelineEvent.timestamp <= dt_end)
        except ValueError:
            pass

    limit = 2000
    offset = int(request.args.get("offset", 0))
    events = query.order_by(TimelineEvent.timestamp.asc()).offset(offset).limit(limit).all()

    # Distinct EventTypes and Sources for filters
    event_types = [et[0] for et in session.query(TimelineEvent.event_type).distinct().order_by(TimelineEvent.event_type)]
    sources = [s[0] for s in session.query(TimelineEvent.source).distinct().order_by(TimelineEvent.source) if s[0]]

    session.close()

    return render_template(
        "timeline.html",
        events=events,
        q=q,
        source=source,
        event_type=event_type,
        start_time=start_time,
        end_time=end_time,
        event_types=event_types,
        sources=sources,
        limit=limit,
        offset=offset
    )


@app.route("/timeline_viz")
def timeline_viz():
    session = get_session()
    events = session.query(TimelineEvent).order_by(TimelineEvent.timestamp.asc()).limit(5000).all()

    # Prepare events for vis-timeline
    items = []
    for e in events:
        items.append({
            "id": e.id,
            "content": e.summary[:50],  # short label
            "start": e.timestamp.isoformat(),
            "title": e.summary,         # full tooltip
            "group": e.event_type       # optional grouping by event type
        })

    session.close()
    return render_template("timeline_viz.html", events_json=json.dumps(items))

# ----------------------------------------------------------------------
# Entry point for collectifor.py
# ----------------------------------------------------------------------

def run_viewer(collection_dir, db_file="collectifor.db", host="127.0.0.1", port=5000, debug=True):
    global COLLECTION_DIR, DB_FILE
    COLLECTION_DIR = os.path.realpath(collection_dir)
    DB_FILE = db_file
    print(f"[+] Viewer started")
    print(f"[+] Collection: {COLLECTION_DIR}")
    print(f"[+] URL: http://{host}:{port}")

    app.run(host=host, port=port, debug=debug, use_reloader=False)
