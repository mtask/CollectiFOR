import os
import json
import logging
from datetime import datetime, timezone

class PlasoTimelineParser:
    """
    Parser for Plaso JSONL timeline output.
    Compatible with raw psort -o json_line output.
    """

    def __init__(self, db):
        self.db = db

    def parse_file(self, jsonl_path, batch_size=1000):
        if not os.path.isfile(jsonl_path):
            logging.error(f'[-] Plaso JSONL file not found: {jsonl_path}')
            return

        events = []
        total = 0

        with open(jsonl_path, "r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    logging.warning(f"[!] Invalid JSON at line {line_no}")
                    continue

                ts = self._extract_timestamp(record)
                if not ts:
                    continue

                event = {
                    "timestamp": ts,
                    "source": record.get("data_type", "plaso"),
                    "event_type": record.get("timestamp_desc", "event"),
                    "summary": self._build_summary(record),
                    "meta": self._build_meta(record),
                }

                events.append(event)
                total += 1

                if len(events) >= batch_size:
                    self.db.add_timeline_events(events)
                    events.clear()

        if events:
            self.db.add_timeline_events(events)

        logging.info(f"[+] Ingested {total} Plaso timeline events")

    # ------------------------
    # Helpers
    # ------------------------

    def _extract_timestamp(self, record):
        """
        Handles Plaso timestamp variants:
        - 'timestamp': can be seconds or microseconds since epoch
        - 'date_time.timestamp': seconds since epoch
        Returns a datetime object in UTC, or None if unavailable.
        """
        ts = record.get("timestamp")
        if ts is not None:
            try:
                ts = float(ts)
                # Auto-detect unit
                if ts > 1e12:
                    # likely microseconds
                    return datetime.fromtimestamp(ts / 1_000_000, tz=timezone.utc)
                else:
                    # likely seconds
                    return datetime.fromtimestamp(ts, tz=timezone.utc)
            except Exception:
                pass

        # Fallback: date_time.timestamp
        dt = record.get("date_time", {})
        ts2 = dt.get("timestamp")
        if ts2 is not None:
            try:
                ts2 = float(ts2)
                return datetime.fromtimestamp(ts2, tz=timezone.utc)
            except Exception:
                pass

        return None

    def _build_summary(self, record):
        """
        Human-readable event summary.
        """
        msg = record.get("message")
        if msg:
            return msg.strip()

        return record.get("display_name", "(no message)")

    def _build_meta(self, record):
        """
        Preserve useful metadata, drop noisy internals.
        """
        skip_keys = {
            "__container_type__",
            "__type__",
            "timestamp",
            "timestamp_desc",
            "date_time",
            "message",
        }

        meta = {}
        for key, value in record.items():
            if key in skip_keys:
                continue

            # JSON-safe normalization
            if isinstance(value, (dict, list)):
                meta[key] = value
            else:
                meta[key] = str(value)

        return meta
