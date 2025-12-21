import os
import json
import logging
from datetime import datetime, timezone
import pandas as pd

class PlasoTimelineParser:
    """Plaso JSONL parser using DuckDB with Pandas batches and live progress."""

    def __init__(self, db, table_name="timeline_events"):
        self.db = db
        self.table_name = table_name
        self.db.create_table(self.table_name)
        self.db.create_timeline_file_table()

    def _store_timeline_file(self, timeline_file):
        self.db.insert_timeline_file(timeline_file)

    def parse_file(self, jsonl_path, batch_size=100_000, progress_interval=10_000):
        if not os.path.isfile(jsonl_path):
            logging.error(f"Plaso JSONL file not found: {jsonl_path}")
            return

        batch = []
        total = 0
        self._store_timeline_file(os.path.basename(jsonl_path))
        with open(jsonl_path, "r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    logging.warning(f"Invalid JSON at line {line_no}")
                    continue

                ts = self._extract_timestamp(record)
                if not ts:
                    continue

                event = {
                    "timeline_file": os.path.basename(jsonl_path),
                    "timestamp": int(ts.timestamp() * 1_000_000),
                    "timestamp_desc": record.get("timestamp_desc"),
                    "date_time": json.dumps(record.get("date_time", {})),
                    "data_type": record.get("data_type", "plaso"),
                    "parser": record.get("parser"),
                    "filename": record.get("filename"),
                    "display_name": record.get("display_name"),
                    "file_entry_type": record.get("file_entry_type"),
                    "file_system_type": record.get("file_system_type"),
                    "inode": record.get("inode"),
                    "file_size": record.get("file_size"),
                    "number_of_links": record.get("number_of_links"),
                    "owner_identifier": record.get("owner_identifier"),
                    "group_identifier": record.get("group_identifier"),
                    "mode": record.get("mode"),
                    "is_allocated": record.get("is_allocated"),
                    "message": record.get("message"),
                    "extra": json.dumps(self._build_extra(record)),
                }

                batch.append(event)
                total += 1

                if len(batch) >= batch_size:
                    self.db.insert_batch(self.table_name, pd.DataFrame(batch))
                    batch.clear()

                if total % progress_interval == 0:
                    current_count = self.db.count_rows(self.table_name)
                    logging.info(f"Processed {total:,} events (DB count: {current_count:,})")

        if batch:
            self.db.insert_batch(self.table_name, pd.DataFrame(batch))

        logging.info(f"Finished processing {total:,} events. Total in DB: {self.db.count_rows(self.table_name):,}")

    # ------------------------
    # Helpers
    # ------------------------

    def _extract_timestamp(self, record):
        ts = record.get("timestamp")
        if ts is not None:
            try:
                ts = float(ts)
                if ts > 1e12:
                    return datetime.fromtimestamp(ts / 1_000_000, tz=timezone.utc)
                return datetime.fromtimestamp(ts, tz=timezone.utc)
            except Exception:
                pass

        dt = record.get("date_time", {})
        ts2 = dt.get("timestamp")
        if ts2 is not None:
            try:
                ts2 = float(ts2)
                return datetime.fromtimestamp(ts2, tz=timezone.utc)
            except Exception:
                pass

        return None

    def _build_extra(self, record):
        skip_keys = {
            "__container_type__",
            "__type__",
            "timestamp",
            "timestamp_desc",
            "date_time",
            "message",
        }
        return {k: v for k, v in record.items() if k not in skip_keys}
