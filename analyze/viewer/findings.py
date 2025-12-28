from flask import Blueprint, render_template, request, jsonify
from flask import session as flask_session
from sqlalchemy.orm import Session
from datetime import datetime
from lib.db import Cases, Finding, FindingNotes
from viewer.database import get_session
from viewer.filters import apply_collection_filter, apply_text_query

findings_bp = Blueprint("findings", __name__, url_prefix="/findings")


@findings_bp.route("/", methods=["GET", "POST"])
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
    case_filters = request.args.getlist("case")
    ack_filters = request.args.getlist("ack")  # list of '0' and/or '1'

    query = db.query(Finding)
    query = apply_collection_filter(query, Finding)

    # Apply text search
    if q:
        query = apply_text_query(query, Finding.message, q)

    # Apply type filters
    if type_filters:
        query = query.filter(Finding.type.in_(type_filters))

    # Apply rule filters
    if rule_filters:
        query = query.filter(Finding.rule.in_(rule_filters))

    # Apply case filters
    if case_filters:
        query = query.filter(Finding.case_name.in_(case_filters))

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
    all_cases_filter = [row[0] for row in db.query(Cases.case_name).distinct().order_by(Cases.case_name)]

    db.close()

    return render_template(
        "findings.html",
        findings=findings,
        search_query=q,
        type_filter=type_filters,
        rule_filter=rule_filters,
        case_filter=case_filters,
        ack_filter=ack_filters,  # pass current ack filter to template
        all_types=all_types,
        all_rules=all_rules,
        all_cases=all_cases,
        all_cases_filter=all_cases_filter
    )

@findings_bp.route("/<int:finding_id>", methods=["GET", "POST"])
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

    # For adding finding to a case
    all_cases = db.query(Cases).order_by(Cases.inserted_at.desc()).all()

    db.close()
    return render_template("finding_detail.html", finding=finding, comments=comments, all_cases=all_cases)

@findings_bp.route("/<int:finding_id>/ack", methods=["POST"])
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

@findings_bp.route("/bulk_ack", methods=["POST"])
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

