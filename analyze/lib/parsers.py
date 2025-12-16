import os
import logging
from datetime import datetime
from scapy.all import (
    rdpcap, IP, IPv6, TCP, UDP, ARP,
    Ether, ICMP, DNS, DNSQR
)

class CommandsParser:
    def __init__(self, db):
        self.db = db

    def parse_file(self, filepath):
        with open(filepath) as f:
            lines = f.readlines()
        return self._get_command_outputs(lines)

    def parse_dir(self, collection_dir):
        """
        Parse all *.txt files in a directory and store in DB
        """
        cmd_dir = os.path.join(collection_dir, "commands")
        if not os.path.isdir(cmd_dir):
            logging.warning('[-] "checksums" directory not found')
            return
        result = {}
        for fname in os.listdir(cmd_dir):
            if not fname.endswith(".txt"):
                continue
            entry_name = fname.replace('.txt', '')
            filepath = os.path.join(cmd_dir, fname)
            result[entry_name] = self.parse_file(filepath)
        self.db.add_command_outputs(result)

    def _get_command_outputs(self, cmd_lines):
        """
        Extract commands from lines starting with #command: and their outputs
        """
        result = []
        current = {}
        temp_output = []
        in_command = False
        for idx, line in enumerate(cmd_lines):
            line = line.rstrip("\n")
            last_line = idx == len(cmd_lines) - 1

            if line.startswith('#command:') or last_line:
                if in_command:
                    current['output'] = '\n'.join(temp_output)
                    result.append(current)
                    current = {}
                    temp_output = []

                if not last_line:
                    current['commandline'] = line.replace('#command:', '')
                    in_command = True
                    continue

            if in_command:
                temp_output.append(line)
        return result


class ChecksumParser:
    """
    Parse checksum files from a collection directory and store in DB.
    Supports md5.txt, sha1.txt, sha256.txt in "checksums" subdir.
    """

    SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha256"]

    def __init__(self, db):
        self.db = db

    def parse_dir(self, collection_dir):
        checksum_dir = os.path.join(collection_dir, "checksums")
        if not os.path.isdir(checksum_dir):
            logging.warning('[-] "checksums" directory not found')
            return

        all_entries = []

        for algo in self.SUPPORTED_ALGORITHMS:
            file_path = os.path.join(checksum_dir, f"{algo}.txt")
            if not os.path.isfile(file_path):
                logging.warning(f"[-] Checksum file not found: {file_path}")
                continue
            entries = self.parse_file(file_path, algo)
            all_entries.extend(entries)

        if all_entries:
            self.db.add_checksums(all_entries)

    def parse_file(self, filepath, algorithm):
        """
        Parse a single checksum file.
        Returns list of dicts: filepath, checksum, algorithm
        """
        entries = []
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line or " - " not in line:
                    continue
                try:
                    path, checksum = line.rsplit(" - ", 1)
                    entries.append({
                        "filepath": path,
                        "checksum": checksum,
                        "algorithm": algorithm
                    })
                except Exception as e:
                    logging.warning(f"Failed to parse checksum line in {filepath}: {line} ({e})")
        return entries


class PermissionsParser:
    """
    Parse file_permissions.txt and store results in DB
    """

    FILENAME = "file_permissions.txt"

    def __init__(self, db):
        self.db = db

    def parse_dir(self, collection_dir):
        filepath = os.path.join(collection_dir, self.FILENAME)
        if not os.path.isfile(filepath):
            logging.error(f"[-] File not found: {filepath}")
            return

        entries = self.parse_file(filepath)
        if entries:
            self.db.add_file_permissions(entries)

    def parse_file(self, filepath):
        """
        Parse file_permissions.txt file.
        Line format:
        <filepath> <mode> <perm_string> <owner:group> <size> <timestamp>
        """
        entries = []
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    parts = line.split(maxsplit=5)
                    if len(parts) != 6:
                        logging.error(f"Invalid line format: {line}")
                        continue

                    path, mode, perm_string, owner_group, size, ts = parts
                    if ":" in owner_group:
                        owner, group = owner_group.split(":", 1)
                    else:
                        owner = owner_group
                        group = ""

                    entries.append({
                        "filepath": path,
                        "mode": mode,
                        "perm_string": perm_string,
                        "owner": owner,
                        "group": group,
                        "size": int(size),
                        "timestamp": datetime.utcfromtimestamp(float(ts))
                    })
                except Exception as e:
                    logging.error(f"Failed to parse line: {line} ({e})")
        return entries


class PcapParser:
    SUBDIR = "capture"

    def __init__(self, db):
        self.db = db

    def parse_dir(self, collection_dir):
        capture_dir = os.path.join(collection_dir, self.SUBDIR)

        if not os.path.isdir(capture_dir):
            logging.error('[-] "capture" directory not found')
            return

        pcaps = [f for f in os.listdir(capture_dir) if f.endswith(".pcap")]

        if not pcaps:
            logging.error("[-] No pcap files found")
            return

        for pcap in pcaps:
            self.parse_file(
                os.path.join(capture_dir, pcap),
                interface=os.path.splitext(pcap)[0]
            )

    def parse_file(self, pcap_path, interface):
        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            logging.error(f"Failed to read pcap {pcap_path}: {e}")
            return

        rows = []

        for idx, pkt in enumerate(packets, start=1):
            ts = datetime.fromtimestamp(float(pkt.time))

            row = {
                "interface": interface,
                "packet_number": idx,
                "timestamp": ts,
                "protocol": "raw",
                "src": None,
                "src_port": None,
                "dst": None,
                "dst_port": None,
                "icmp_type": None,
                "icmp_code": None,
                "dns_qname": None,
                "dns_qtype": None,
                "raw_content": pkt.summary(),
            }

            # ---- Ethernet ----
            if pkt.haslayer(Ether):
                row["src"] = pkt[Ether].src
                row["dst"] = pkt[Ether].dst

            # ---- IP / IPv6 ----
            if pkt.haslayer(IP):
                row["protocol"] = "ip"
                row["src"] = pkt[IP].src
                row["dst"] = pkt[IP].dst

            elif pkt.haslayer(IPv6):
                row["protocol"] = "ipv6"
                row["src"] = pkt[IPv6].src
                row["dst"] = pkt[IPv6].dst

            # ---- TCP / UDP ----
            if pkt.haslayer(TCP):
                row["protocol"] = "tcp"
                row["src_port"] = pkt[TCP].sport
                row["dst_port"] = pkt[TCP].dport

            elif pkt.haslayer(UDP):
                row["protocol"] = "udp"
                row["src_port"] = pkt[UDP].sport
                row["dst_port"] = pkt[UDP].dport

            # ---- ICMP ----
            if pkt.haslayer(ICMP):
                row["protocol"] = "icmp"
                row["icmp_type"] = pkt[ICMP].type
                row["icmp_code"] = pkt[ICMP].code

            # ---- DNS ----
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                row["protocol"] = "dns"
                row["dns_qname"] = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                row["dns_qtype"] = pkt[DNSQR].qtype

            rows.append(row)

            # ---- Flow update ----
            if row["src"] and row["dst"]:
                self.db.upsert_flow({
                    "protocol": row["protocol"],
                    "src": row["src"],
                    "src_port": row["src_port"],
                    "dst": row["dst"],
                    "dst_port": row["dst_port"],
                    "timestamp": ts,
                })

        self.db.add_pcap_packets(rows)

class FilesAndDirsParser:
    SUBDIR = "files_and_dirs"

    def __init__(self, db):
        self.db = db

    def parse_dir(self, collection_dir):
        base_dir = os.path.join(collection_dir, self.SUBDIR)

        if not os.path.isdir(base_dir):
            logging.error('[-] "files_and_dirs" directory not found')
            return

        collection_realpath = os.path.realpath(collection_dir)
        entries = []

        for root, dirs, files in os.walk(base_dir):
            for name in files + dirs:
                full_path = os.path.join(root, name)

                # Compute relative path starting AFTER files_and_dirs
                rel = os.path.relpath(full_path, base_dir)
                normalized_path = "/" + rel.replace(os.sep, "/")

                entries.append({
                    "collection_path": collection_realpath,
                    "path": normalized_path,
                })

        if entries:
            self.db.add_file_entries(entries)
            logging.info(f"[+] Indexed {len(entries)} files/directories")
