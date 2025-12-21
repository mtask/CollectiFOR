from flask import Flask, render_template, request, current_app, jsonify, session, redirect, abort
from flask import session as flask_session
from sqlalchemy import create_engine, or_, not_
from sqlalchemy.orm import sessionmaker
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
    Collections,
)


app = Flask(__name__)
app.secret_key = "super-secret-key"


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

def apply_collection_filter(query, model):
    collection = flask_session.get("collection_name")
    if collection:
        query = query.filter(model.collection_name == collection)
    return query

@app.context_processor
def inject_collections():
    return {
        "all_collections": COLLECTIONS,
        "all_timelines": TIMELINES
    }


# ----------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")

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
        return render_template("file_view.html", path=rel_path, content="Collection directory {collection_dir} not found", parent_dir=parent_dir)
    file_path = os.path.join(collection_dir, "files_and_dirs", rel_path.lstrip("/"))

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
        db = get_session()

        results["commands"] = apply_collection_filter(
            db.query(CommandOutput).filter(CommandOutput.output.contains(q)),
            CommandOutput
        ).all()

        results["files"] = apply_collection_filter(
            db.query(FileEntry).filter(FileEntry.path.contains(q)),
            FileEntry
        ).all()

        results["packets"] = apply_collection_filter(
            db.query(PcapPacket).filter(PcapPacket.raw_content.contains(q)),
            PcapPacket
        ).all()

        results["checksums"] = apply_collection_filter(
            db.query(Checksum).filter(
                or_(
                    Checksum.checksum.contains(q),
                    Checksum.filepath.contains(q),
                )
            ),
            Checksum
        ).all()

        results["findings"] = apply_collection_filter(
            db.query(Finding).filter(Finding.message.contains(q)),
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

        query = db.query(Checksum).filter(
            or_(
                Checksum.checksum.contains(value),
                Checksum.filepath.contains(value)
            )
        )
        query = apply_collection_filter(query, Checksum)

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

        packet_query = db.query(PcapPacket).filter(
            or_(
                PcapPacket.src.contains(q),
                PcapPacket.dst.contains(q),
                PcapPacket.protocol.contains(q)
            )
        )
        packet_query = apply_collection_filter(packet_query, PcapPacket)

        packets = packet_query.limit(1000).all()

        flow_query = db.query(NetworkFlow).filter(
            or_(
                NetworkFlow.src.contains(q),
                NetworkFlow.dst.contains(q),
                NetworkFlow.protocol.contains(q)
            )
        )
        flow_query = apply_collection_filter(flow_query, NetworkFlow)

        flows = flow_query.all()

        db.close()

    return render_template(
        "network.html",
        q=q,
        packets=packets,
        flows=flows
    )

from flask import request, render_template
from sqlalchemy import or_

@app.route("/findings")
def findings():
    db = get_session()

    # Get query parameters
    q = request.args.get("q", "").strip()
    type_filters = request.args.getlist("type")
    rule_filters = request.args.getlist("rule")

    # Start base query
    query = db.query(Finding)
    query = apply_collection_filter(query, Finding)

    # --- Multi-term text search with negation ---
    if q:
        include_terms = []
        exclude_terms = []

        # Split by whitespace
        for term in q.split():
            term = term.strip()
            if not term:
                continue
            if term.startswith("-"):
                exclude_terms.append(term[1:])
            else:
                include_terms.append(term)

        # Include terms (AND logic)
        for term in include_terms:
            query = query.filter(Finding.message.ilike(f"%{term}%"))

        # Exclude terms (OR logic)
        if exclude_terms:
            query = query.filter(~or_(*(Finding.message.ilike(f"%{t}%") for t in exclude_terms)))

    # Filter by type(s)
    if type_filters:
        query = query.filter(Finding.type.in_(type_filters))

    # Filter by rule(s)
    if rule_filters:
        query = query.filter(Finding.rule.in_(rule_filters))

    # Order results
    findings = query.order_by(Finding.type, Finding.inserted_at).all()

    # For dropdowns: fetch all distinct types and rules
    all_types = [row[0] for row in db.query(Finding.type).distinct().order_by(Finding.type)]
    all_rules = [row[0] for row in db.query(Finding.rule).distinct().order_by(Finding.rule)]

    db.close()

    return render_template(
        "findings.html",
        findings=findings,
        search_query=q,
        type_filter=type_filters,
        rule_filter=rule_filters,
        all_types=all_types,
        all_rules=all_rules
    )


@app.route("/findings/<int:finding_id>")
def finding_detail(finding_id):
    db = get_session()
    finding = db.query(Finding).get(finding_id)
    db.close()
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

    # <-- NEW: filter by timeline_name if set in session
    timeline_name = flask_session.get("timeline_name")
    if timeline_name:
        base_sql += f" AND timeline_file = '{timeline_name}'"

    data_sql = f"""
        SELECT id, timestamp, timestamp_desc, data_type, message
        {base_sql}
        ORDER BY timestamp ASC
        LIMIT {length} OFFSET {start}
    """
    try:
        data = conn.execute(data_sql).df().to_dict(orient="records")
    except Exception as e:
        print(repr(e))
        data = {}

    total_count = conn.execute(
        "SELECT COUNT(*) FROM timeline_events"
    ).fetchone()[0]

    try:
        filtered_count = conn.execute(
            f"SELECT COUNT(*) {base_sql}"
        ).fetchone()[0]
    except Exception as e:
        print(repr(e))
        filtered_count = 0

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


def get_bucket_from_span(span_seconds):
    if span_seconds > 365*24*3600:      # multiple years
        return 'YEAR'
    elif span_seconds > 30*24*3600:     # multiple months
        return 'MONTH'
    elif span_seconds > 24*3600:        # multiple days
        return 'DAY'
    elif span_seconds > 3600:           # multiple hours
        return 'HOUR'
    else:
        return 'MINUTE'

@app.route('/timeline_chart')
def timeline_chart():
    return render_template('timeline_chart.html')

@app.route('/timeline_chart/data')
def timeline_chart_data():
    start_time = request.args.get('start_time')
    end_time = request.args.get('end_time')

    conn = duckdb.connect(DUCKDB_FILE)

    # Filters
    filters = []
    if start_time:
        ts = int(datetime.strptime(start_time, "%d/%m/%Y %H:%M").timestamp()*1_000_000)
        filters.append(f"timestamp >= {ts}")
    if end_time:
        ts = int(datetime.strptime(end_time, "%d/%m/%Y %H:%M").timestamp()*1_000_000)
        filters.append(f"timestamp <= {ts}")

    # <-- Minimal addition: filter by timeline_name if set
    timeline_name = flask_session.get("timeline_name")
    if timeline_name:
        filters.append(f"timeline_file = '{timeline_name}'")

    where_sql = f"WHERE {' AND '.join(filters)}" if filters else ""

    # Min/Max timestamps
    min_ts, max_ts = conn.execute(
        f"SELECT MIN(timestamp), MAX(timestamp) FROM timeline_events {where_sql}"
    ).fetchone()
    if min_ts is None or max_ts is None:
        return jsonify({"labels": [], "counts": []})

    span_seconds = (max_ts - min_ts)/1_000_000
    bucket = get_bucket_from_span(span_seconds)

    # Fixed aggregation: divide by 1_000_000.0 to make float for TO_TIMESTAMP
    data_sql = f"""
        SELECT
            DATE_TRUNC('{bucket}', TO_TIMESTAMP(timestamp / 1000000.0)) AS bucket,
            COUNT(*) AS count
        FROM timeline_events
        {where_sql}
        GROUP BY bucket
        ORDER BY bucket
    """
    rows = conn.execute(data_sql).fetchall()

    # Labels, counts
    labels = []
    counts = []
    for r in rows:
        dt = r[0]
        if bucket == 'YEAR':
            labels.append(dt.strftime("%Y"))
        elif bucket == 'MONTH':
            labels.append(dt.strftime("%b %Y"))
        elif bucket == 'DAY':
            labels.append(dt.strftime("%d %b %Y"))
        elif bucket == 'HOUR':
            labels.append(dt.strftime("%d %b %H:%M"))
        else:
            labels.append(dt.strftime("%d %b %H:%M"))
        counts.append(r[1])

    return jsonify({"labels": labels, "counts": counts})

def get_collections():
    db = get_session()
    collection_names = [n[0] for n in db.query(Collections.collection_name).all()]
    return collection_names

def get_timelines():
    conn = duckdb.connect(DUCKDB_FILE)
    timeline_files = [row[0] for row in conn.execute(
        "SELECT timeline_file FROM timeline_files"
    ).fetchall()]
    conn.close()
    return timeline_files

def run_viewer(db_file="collectifor.db", duckdb_file="timeline.duckdb", host="127.0.0.1", port=5000, debug=True):
    global DB_FILE, DUCKDB_FILE, COLLECTIONS, TIMELINES
    DB_FILE = db_file
    DUCKDB_FILE = duckdb_file
    COLLECTIONS = get_collections()
    TIMELINES = get_timelines()
    print(TIMELINES)
    print(f"[+] Viewer started")
    print(f"[+] URL: http://{host}:{port}")

    app.run(host=host, port=port, debug=debug, use_reloader=False)
