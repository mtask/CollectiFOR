import math
from collections import Counter
from prompt_toolkit.shortcuts import (
    radiolist_dialog,
    yes_no_dialog,
    input_dialog,
)

def string_entropy(s):
    """Shannon entropy for string"""
    if not s:
        return 0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((freq[c]/len(s)) * math.log2(freq[c]/len(s)) for c in freq)

def file_entropy(path, chunk_size=1024*1024):
    """Shannon entropy for a file"""
    freq = Counter()
    total = 0

    try:
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                freq.update(chunk)
                total += len(chunk)
    except Exception:
        return 0

    if total == 0:
        return 0

    return -sum((count / total) * math.log2(count / total) for count in freq.values())

def collection_selector(db_file):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from lib.db import Collections, Cases
    engine = create_engine(f"sqlite:///{db_file}", future=True)
    session = sessionmaker(bind=engine)
    db = session()
    try:
        collections = [
            {"name": n[0], "path": n[1]}
            for n in db.query(
                Collections.collection_name,
                Collections.collection_abs_path
            ).all()
        ]
    finally:
        db.close()

    CREATE_NEW = "__CREATE_NEW__"
    selected_collection = None

    # Build radio list values
    values = [(CREATE_NEW, "➕ Create new collection")]
    values += [(c, c["name"]) for c in collections]

    choice = radiolist_dialog(
        title="Select Collection",
        text="Choose a collection or create a new collection:",
        values=values,
    ).run()

    if choice == CREATE_NEW:
        new_collection_name = input_dialog(
            title="New Collection",
            text="Enter new collection name:",
        ).run()

        if new_collection_name:
            selected_collection = {
                "name": new_collection_name.lower().replace(" ", "_"),
                "path": "-",
                "new": True,
            }

    elif choice:
        selected_collection = choice
        selected_collection["new"] = False

    return selected_collection

def case_selector(session, Cases):
    CREATE_NEW = "__CREATE_NEW__"

    # Initial question
    if not yes_no_dialog(
        title="Case",
        text="Add all findings to a case?"
    ).run():
        return {"case_name": None, "case_id": None}


    # Load cases
    cases = session.query(Cases.case_name, Cases.id).order_by(Cases.id).all()

    values = [(CREATE_NEW, "➕ Create new case")]
    values += [((c.case_name, c.id), c.case_name) for c in cases]

    choice = radiolist_dialog(
        title="Select Case",
        text="Choose a case (Esc to cancel):",
        values=values,
    ).run()

    if choice is None:
        return {"case_name": None, "case_id": None}

    # Create new case
    if choice == CREATE_NEW:
        case_name = input_dialog(
            title="New Case",
            text="Enter new case name:",
        ).run()

        if not case_name:
            return {"case_name": None, "case_id": None}

        new_case = Cases(case_name=case_name)
        session.add(new_case)
        session.commit()
        session.refresh(new_case)

        return {
            "case_name": new_case.case_name,
            "case_id": new_case.id,
        }

    # Existing case selected
    case_name, case_id = choice
    return {
        "case_name": case_name,
        "case_id": case_id,
    }

