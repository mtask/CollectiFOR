from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, JSON
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

    timestamp = Column(DateTime, nullable=False)   # NEW

    protocol = Column(String, nullable=False)
    src = Column(String)
    src_port = Column(Integer)
    dst = Column(String)
    dst_port = Column(Integer)

    icmp_type = Column(Integer)
    icmp_code = Column(Integer)

    dns_qname = Column(String)
    dns_qtype = Column(String)

    raw_content = Column(Text)
    inserted_at = Column(DateTime, default=datetime.utcnow)

class NetworkFlow(Base):
    __tablename__ = "network_flows"

    id = Column(Integer, primary_key=True)

    protocol = Column(String, nullable=False)
    src = Column(String, nullable=False)
    src_port = Column(Integer)
    dst = Column(String, nullable=False)
    dst_port = Column(Integer)

    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False)

    packet_count = Column(Integer, default=0)

    inserted_at = Column(DateTime, default=datetime.utcnow)

class FileEntry(Base):
    __tablename__ = "files_and_dirs"

    id = Column(Integer, primary_key=True)

    collection_path = Column(String, nullable=False)
    path = Column(String, nullable=False)
    type = Column(String, nullable=False)

    inserted_at = Column(DateTime, default=datetime.utcnow)

class ListenerEntry(Base):
    __tablename__ = "listeners"

    id = Column(Integer, primary_key=True)

    pid = Column(Integer)
    protocol = Column(String, nullable=False)
    port = Column(Integer)
    bind = Column(String, nullable=False)
    exec = Column(String, nullable=False)
    process = Column(String, nullable=False)
    systemd = Column(String, default="")
    related_paths = Column(String, default="")

    inserted_at = Column(DateTime, default=datetime.utcnow)

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)

    type = Column(String, nullable=False)
    message = Column(String, nullable=False)
    rule = Column(String)
    source_file = Column(String)
    tags = Column(String)

    meta = Column(JSON)  # stored as JSON

    namespace = Column(String)
    artifact = Column(String)
    indicator = Column(String)

    inserted_at = Column(DateTime, default=datetime.utcnow)


class DB:
    def __init__(self, db_file):
        self.engine = create_engine(f"sqlite:///{db_file}", echo=False, future=True)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
    #############
    # init data #
    #############

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

    def upsert_flow(self, flow):
        session = self.Session()
        try:
            existing = session.query(NetworkFlow).filter_by(
                protocol=flow["protocol"],
                src=flow["src"],
                src_port=flow["src_port"],
                dst=flow["dst"],
                dst_port=flow["dst_port"],
            ).first()

            if existing:
                existing.last_seen = flow["timestamp"]
                existing.packet_count += 1
            else:
                session.add(NetworkFlow(
                    protocol=flow["protocol"],
                    src=flow["src"],
                    src_port=flow["src_port"],
                    dst=flow["dst"],
                    dst_port=flow["dst_port"],
                    first_seen=flow["timestamp"],
                    last_seen=flow["timestamp"],
                    packet_count=1,
                ))

            session.commit()
        finally:
            session.close()

    def add_file_entries(self, entries):
        session = self.Session()
        try:
            for entry in entries:
                session.add(FileEntry(**entry))
            session.commit()
        finally:
            session.close()

    def add_listener_entries(self, entries):
        session = self.Session()
        try:
            for entry in entries:
                session.add(ListenerEntry(**entry))
            session.commit()
        finally:
            session.close()

    ############
    # Analysis #
    ############

    def add_finding_entries(self, findings):
        """
        findings: list[dict]
        """
        session = self.Session()
        try:
            for entry in findings:
                session.add(Finding(
                    type=entry.get("type", ""),
                    message=entry.get("message", ""),
                    rule=entry.get("rule", ""),
                    source_file=entry.get("source_file", ""),
                    tags=entry.get("tags", ""),
                    meta=entry.get("meta", {}) or {},
                    namespace=entry.get("namespace", ""),
                    artifact=entry.get("artifact", ""),
                    indicator=entry.get("indicator", ""),
                ))
            session.commit()
        finally:
            session.close()
