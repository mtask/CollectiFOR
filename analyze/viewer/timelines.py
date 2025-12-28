from flask import Blueprint, render_template, request, jsonify, current_app
from flask import session as flask_session
from datetime import datetime
import pandas as pd
import duckdb

timelines_bp = Blueprint("timelines", __name__, url_prefix="/timeline")

def get_timelines():
    conn =  duckdb.connect(current_app.config["DUCKDB_FILE"])

    table_exists = conn.execute("""
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_name = 'timeline_files'
    """).fetchone()[0] > 0

    if not table_exists:
        conn.close()
        return []

    timeline_files = [
        row[0] for row in conn.execute(
            "SELECT timeline_file FROM timeline_files"
        ).fetchall()
    ]

    conn.close()
    return timeline_files

# ------------------------
# Timeline page
# ------------------------
@timelines_bp.route("/")
def timeline():
    return render_template("timeline.html")


@timelines_bp.route("/data")
def timeline_data():
    sort_order = request.args.get("sort_order", "timestamp DESC")
    start_time = request.args.get("start_time")
    end_time = request.args.get("end_time")
    sql_filter = request.args.get("sql_filter", "").strip()

    start = int(request.args.get("start", 0))
    length = int(request.args.get("length", 50))

    conn = duckdb.connect(current_app.config["DUCKDB_FILE"])

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
        ORDER BY {sort_order}
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


@timelines_bp.route("/event/<int:event_id>")
def timeline_event(event_id):
    conn = duckdb.connect(current_app.config["DUCKDB_FILE"])

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

    event_dict["extra"] = json.loads(event_dict["extra"])
    event_dict["date_time"] = json.loads(event_dict["date_time"])
    if isinstance(event_dict.get('inserted_at'), datetime):
        event_dict['inserted_at'] = event_dict['inserted_at'].isoformat()
    conn.close()

    return app.response_class(
        response=json.dumps(event_dict, indent=2),
        mimetype='application/json'
    )


@timelines_bp.route('/query', methods=['GET', 'POST'])
def timeline_query():
    conn = duckdb.connect(current_app.config["DUCKDB_FILE"])

    conn.execute("""
        CREATE TABLE IF NOT EXISTS saved_queries (
            name TEXT PRIMARY KEY,
            query TEXT NOT NULL
        )
    """)

    # Handle "save query"
    if request.method == 'POST':
        name = request.form.get("query_name", "").strip()
        query = request.form.get("sql_filter", "").strip()

        if name and query:
            conn.execute(
                "INSERT OR REPLACE INTO saved_queries (name, query) VALUES (?, ?)",
                (name, query)
            )

        return redirect(url_for('timeline_query', sql_filter=query))

    sql_query = request.args.get("sql_filter", "").strip()

    result_df = pd.DataFrame()
    if sql_query:
        try:
            result_df = conn.execute(sql_query).df().head(5000)
        except Exception as e:
            result_df = pd.DataFrame([{"Error": str(e)}])
    else:
        result_df = conn.execute("PRAGMA table_info('timeline_events')").df()

    saved_queries = conn.execute(
        "SELECT name, query FROM saved_queries ORDER BY name"
    ).fetchall()

    return render_template(
        'timeline_query.html',
        sql_query=sql_query,
        result_df=result_df,
        saved_queries=saved_queries
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

@timelines_bp.route('/chart')
def timeline_chart():
    return render_template('timeline_chart.html')

@timelines_bp.route('/chart/data')
def timeline_chart_data():
    start_time = request.args.get('start_time')
    end_time = request.args.get('end_time')

    conn = duckdb.connect(current_app.config["DUCKDB_FILE"])

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
