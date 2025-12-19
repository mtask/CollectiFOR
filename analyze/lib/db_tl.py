from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    BigInteger,
    String,
    Boolean,
    Text,
    DateTime,
    JSON,
    Index,
)
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

Base = declarative_base()


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Plaso canonical timestamp (microseconds since epoch)
    timestamp = Column(BigInteger, nullable=False, index=True)
    timestamp_desc = Column(String)

    date_time = Column(JSON)

    data_type = Column(String, nullable=False, index=True)
    parser = Column(String, index=True)

    __container_type__ = Column(String)
    __type__ = Column(String)

    filename = Column(Text, index=True)
    display_name = Column(Text)

    file_entry_type = Column(String)
    file_system_type = Column(String)
    inode = Column(String)

    file_size = Column(BigInteger)
    number_of_links = Column(Integer)

    owner_identifier = Column(Integer)
    group_identifier = Column(Integer)
    mode = Column(Integer)

    is_allocated = Column(Boolean)

    message = Column(Text)

    # Unknown / future Plaso fields
    extra = Column(JSON)

    inserted_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("idx_type_time", "data_type", "timestamp"),
    )


class DB:
    def __init__(self, db_file):
        self.engine = create_engine(
            f"sqlite:///{db_file}",
            echo=False,
            future=True,
        )
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, future=True)

    def tune_sqlite(self):
        with self.engine.connect() as conn:
            conn.exec_driver_sql("PRAGMA journal_mode = WAL;")
            conn.exec_driver_sql("PRAGMA synchronous = NORMAL;")
            conn.exec_driver_sql("PRAGMA temp_store = MEMORY;")
            conn.exec_driver_sql("PRAGMA cache_size = -200000;")

    def add_timeline_events(self, events):
        session = self.Session()
        try:
            session.bulk_insert_mappings(TimelineEvent, events)
            session.commit()
        finally:
            session.close()
