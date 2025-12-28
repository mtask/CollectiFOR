import re
from flask import session as flask_session
from sqlalchemy import create_engine, or_, not_, insert

def apply_collection_filter(query, model):
    collection = flask_session.get("collection_name")
    if collection:
        query = query.filter(model.collection_name == collection)
    return query

def apply_text_query(query, columns, q_text):
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
