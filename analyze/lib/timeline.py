import os
import json
import logging
import time


class PlasoTimelineParser:
    """
    High-volume parser for psort -o json_line output.
    """

    DB_COLUMNS = {
        "timestamp",
        "timestamp_desc",
        "date_time",
        "data_type",
        "parser",
        "__container_type__",
        "__type__",
        "filename",
        "display_name",
        "file_entry_type",
        "file_system_type",
        "inode",
        "file_size",
        "number_of_links",
        "owner_identifier",
        "group_identifier",
        "mode",
        "is_allocated",
        "message",
    }

    def __init__(self, db):
        self.db = db

    # ----------------------------
    # Public API
    # ----------------------------

    def parse_file(self, jsonl_path, batch_size=10_000):
        if not os.path.isfile(jsonl_path):
            logging.error(f"[-] File not found: {jsonl_path}")
            return

        batch = []
        total = 0
        start = time.monotonic()
        last_report = start

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

                event = self._map_record(record)
                if event is None:
                    continue

                batch.append(event)
                total += 1

                if len(batch) >= batch_size:
                    self.db.add_timeline_events(batch)
                    batch.clear()

                # Progress every ~5 seconds
                now = time.monotonic()
                if now - last_report >= 5:
                    rate = total / (now - start)
                    logging.info(
                        "[+] Processed %s events (%.1f events/sec)",
                        f"{total:,}",
                        rate,
                    )
                    last_report = now

        if batch:
            self.db.add_timeline_events(batch)

        elapsed = time.monotonic() - start
        logging.info(
            "[✓] Finished: %s events in %.1fs (avg %.1f events/sec)",
            f"{total:,}",
            elapsed,
            total / elapsed if elapsed else 0,
        )

    # ----------------------------
    # Internal helpers
    # ----------------------------

    def _map_record(self, record):
        ts = record.get("timestamp")
        if ts is None:
            return None

        event = {"timestamp": int(ts)}
        extra = {}

        for key, value in record.items():
            if key == "timestamp":
                continue
            if key in self.DB_COLUMNS:
                event[key] = value
            else:
                extra[key] = self._json_safe(value)

        if extra:
            event["extra"] = extra

        return event

    def _json_safe(self, value):
        if value is None:
            return None
        if isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, dict):
            return {k: self._json_safe(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._json_safe(v) for v in value]
        return str(value)
