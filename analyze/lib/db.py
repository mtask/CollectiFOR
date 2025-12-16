from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class CommandOutput(Base):
    __tablename__ = "command_output"
    id = Column(Integer, primary_key=True, autoincrement=True)
    category = Column(String, nullable=False)
    commandline = Column(Text, nullable=False)
    output = Column(Text, nullable=False)
    inserted_at = Column(DateTime, default=datetime.utcnow)

class FilePermission(Base):
    __tablename__ = "file_permissions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    filepath = Column(Text, nullable=False)
    mode = Column(String, nullable=False)           # numeric mode, e.g., "644"
    perm_string = Column(String, nullable=False)   # symbolic, e.g., "-rw-r--r--"
    owner = Column(String, nullable=False)         # e.g., "root"
    group = Column(String, nullable=False)         # e.g., "shadow"
    size = Column(Integer, nullable=False)
    timestamp = Column(DateTime, nullable=False)   # last modification
    inserted_at = Column(DateTime, default=datetime.utcnow)


class Checksum(Base):
    __tablename__ = "checksums"
    id = Column(Integer, primary_key=True, autoincrement=True)
    filepath = Column(Text, nullable=False)
    checksum = Column(String, nullable=False)
    algorithm = Column(String, nullable=False)  # md5, sha1, sha256
    inserted_at = Column(DateTime, default=datetime.utcnow)


class PcapPacket(Base):
    __tablename__ = "pcap_packets"

    id = Column(Integer, primary_key=True)
    interface = Column(String, nullable=False)
    packet_number = Column(Integer, nullable=False)

    protocol = Column(String, nullable=False)
    src = Column(String)
    src_port = Column(Integer)
    dst = Column(String)
    dst_port = Column(Integer)

    raw_content = Column(Text)
    inserted_at = Column(DateTime, default=datetime.utcnow)

class DB:
    def __init__(self, db_file="commands.db"):
        self.engine = create_engine(f"sqlite:///{db_file}", echo=False, future=True)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def add_command_outputs(self, commands_dict):
        session = self.Session()
        for category, entries in commands_dict.items():
            for entry in entries:
                session.add(CommandOutput(
                    category=category,
                    commandline=entry.get("commandline", ""),
                    output=entry.get("output", "")
                ))
        session.commit()
        session.close()

    def add_checksums(self, checksum_entries):
        """
        checksum_entries: list of dicts with keys filepath, checksum, algorithm
        """
        session = self.Session()
        for entry in checksum_entries:
            session.add(Checksum(
                filepath=entry["filepath"],
                checksum=entry["checksum"],
                algorithm=entry["algorithm"]
            ))
        session.commit()
        session.close()

    def add_file_permissions(self, permission_entries):
        """
        permission_entries: list of dicts with keys filepath, mode, perm_string, owner, group, size, timestamp
        """
        session = self.Session()
        for entry in permission_entries:
            session.add(FilePermission(
                filepath=entry["filepath"],
                mode=entry["mode"],
                perm_string=entry["perm_string"],
                owner=entry["owner"],
                group=entry["group"],
                size=entry["size"],
                timestamp=entry["timestamp"]
            ))
        session.commit()
        session.close()

    def add_pcap_packets(self, packets):
        session = self.Session()
        try:
            for pkt in packets:
                session.add(PcapPacket(**pkt))
            session.commit()
        finally:
            session.close()
