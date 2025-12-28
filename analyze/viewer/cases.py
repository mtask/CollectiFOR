from flask import Blueprint, render_template, request, jsonify
from sqlalchemy.orm import Session
from datetime import datetime
from lib.db import Cases, CaseNotes, Finding, FindingNotes
from viewer.database import get_session

cases_bp = Blueprint("cases", __name__, url_prefix="/cases")

@cases_bp.route("/")
def cases_index():
    db = get_session()
    all_cases = db.query(Cases).order_by(Cases.inserted_at.desc()).all()
    db.close()
    return render_template("cases.html", all_cases=all_cases)

@cases_bp.route("/case/<int:case_id>")
def case_detail(case_id):
    db = get_session()
    case = db.query(Cases).get(case_id)
    case_notes = db.query(CaseNotes).filter_by(case_id=case_id).order_by(CaseNotes.inserted_at.desc()).all()
    findings = db.query(Finding).filter_by(case_id=case_id).all()
    for f in findings:
        f.notes = db.query(FindingNotes).filter_by(finding_id=f.id).order_by(FindingNotes.inserted_at.desc()).all()
    db.close()
    return render_template("case_detail.html", case=case, case_notes=case_notes, findings=findings)

@cases_bp.route("/case/<int:case_id>/note/add", methods=["POST"])
def add_case_note(case_id):
    data = request.get_json()
    db = get_session()
    note = CaseNotes(case_id=case_id, case_comment=data['case_comment'])
    db.add(note)
    db.commit()
    db.refresh(note)
    db.close()
    return jsonify({
        "id": note.id,
        "case_comment": note.case_comment,
        "inserted_at": note.inserted_at.isoformat()
    })

@cases_bp.route("/case/add", methods=["POST"])
def new_case():
    data = request.get_json()
    db = get_session()
    c = Cases(case_name=data['case_name'])
    db.add(c)
    db.commit()
    db.refresh(c)
    db.close()
    return jsonify({"id": c.id, "case_name": c.case_name, "inserted_at": c.inserted_at.isoformat()})

@cases_bp.route('/assign', methods=['POST'])
def assign_finding_to_case():
    data = request.get_json()
    findings = data.get('findings')
    case_id = data.get('case_id')
    case_name = data.get('case_name')
    if not findings or not case_id or not case_name:
        return jsonify({"error": "findings, case_name, and case_id required"}), 400

    session = get_session()
    for finding_id in findings:
        finding = session.query(Finding).filter_by(id=finding_id).first()
        finding.case_id = int(case_id)
        finding.case_name = case_name
    session.commit()
    session.close()

    return jsonify({"success": True, "findings": findings, "case_id": case_id, "case_name": case_name})
