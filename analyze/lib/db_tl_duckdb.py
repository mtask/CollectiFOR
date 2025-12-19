import duckdb
import pandas as pd

class DB:
    """DuckDB wrapper for fast ingestion with sequence-based auto-increment ID."""

    def __init__(self, db_file: str):
        self.db_file = db_file
        self.conn = duckdb.connect(db_file)

    def create_table(self, table_name="timeline_events"):
        """Create sequence and table with sequence-based auto-increment primary key."""
        # Create sequence if it does not exist
        self.conn.execute(f"""
        CREATE SEQUENCE IF NOT EXISTS seq_{table_name}_id START 1;
        """)

        # Create table with default nextval from sequence
        self.conn.execute(f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id BIGINT PRIMARY KEY DEFAULT nextval('seq_{table_name}_id'),
            timestamp BIGINT NOT NULL,
            timestamp_desc VARCHAR,
            date_time JSON,
            data_type VARCHAR NOT NULL,
            parser VARCHAR,
            filename TEXT,
            display_name TEXT,
            file_entry_type VARCHAR,
            file_system_type VARCHAR,
            inode VARCHAR,
            file_size BIGINT,
            number_of_links INTEGER,
            owner_identifier INTEGER,
            group_identifier INTEGER,
            mode INTEGER,
            is_allocated BOOLEAN,
            message TEXT,
            extra JSON,
            inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

    def insert_batch(self, table_name, df: pd.DataFrame):
        """Insert a Pandas DataFrame into DuckDB table, only the DataFrame columns."""
        columns = ", ".join(df.columns)
        self.conn.register("df_batch", df)
        self.conn.execute(f"INSERT INTO {table_name} ({columns}) SELECT * FROM df_batch")

    def count_rows(self, table_name="timeline_events"):
        """Return number of rows in table."""
        return self.conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
