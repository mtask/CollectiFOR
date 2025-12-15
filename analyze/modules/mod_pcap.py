# modules/mod_pcap.py
from pathlib import Path
from scapy.all import PcapReader, TCP, UDP, DNS, IP
import math
import logging
import subprocess
from collections import defaultdict
from contextlib import chdir

# -----------------------------
# Helpers
# -----------------------------

def _entropy(s):
    """Shannon entropy for domain analysis"""
    if not s:
        return 0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((freq[c]/len(s)) * math.log2(freq[c]/len(s)) for c in freq)

def _high_entropy_domain(domain, threshold=3.2, min_label_len=6, whitelist=None):
    """Detect algorithmically generated domain names based on entropy of the first label."""
    labels = domain.split(".")
    first_label = labels[0] if labels else ""
    if whitelist and any(domain.endswith(w) for w in whitelist):
        return False
    if len(first_label) < min_label_len:
        return False
    ent = _entropy(first_label)
    return ent >= threshold

def _normalize_flow(pkt, proto_layer):
    """Determine client → server direction based on ephemeral vs well-known ports"""
    sport = pkt.sport
    dport = pkt.dport
    proto = "TCP" if proto_layer == TCP else "UDP"

    # Client ephemeral port ≥1024, server well-known <1024
    if sport >= 1024 and dport < 1024:
        src_ip, src_port = pkt[IP].src, sport
        dst_ip, dst_port = pkt[IP].dst, dport
    elif dport >= 1024 and sport < 1024:
        src_ip, src_port = pkt[IP].dst, dport
        dst_ip, dst_port = pkt[IP].src, sport
    else:
        # fallback, keep original
        src_ip, src_port = pkt[IP].src, sport
        dst_ip, dst_port = pkt[IP].dst, dport

    return src_ip, src_port, dst_ip, dst_port, proto


# -----------------------------
# Main analysis function
# -----------------------------

def analyze(rootdir, outdir):
    """
    Analyze all PCAPs in capture/ directory for:
      - DNS anomalies (high-entropy domains)
      - Beaconing (periodic connections to same IP)
      - Unusual ports (TCP/UDP outside common set)
      - Normalize flows to client -> server
    """
    results = []
    capture_dir = Path(rootdir) / "capture"
    if not capture_dir.exists():
        return results

    COMMON_TCP_UDP_PORTS = {22, 53, 80, 443, 25, 110, 123, 143, 3389, 445, 139}

    for pcap_file in capture_dir.glob("*.pcap"):
        try:
            conn_times = defaultdict(list)

            with PcapReader(str(pcap_file)) as reader:
                for pkt in reader:
                    if IP not in pkt:
                        continue

                    # -------------------
                    # TCP/UDP connection time tracking (beaconing)
                    # -------------------
                    ts = getattr(pkt, "time", None)
                    if ts is not None:
                        conn_times[pkt[IP].dst].append(ts)

                    # -------------------
                    # DNS analysis
                    # -------------------
                    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qdcount > 0:
                        # Use UDP port 53
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        src_port = getattr(pkt, "sport", "N/A")
                        dst_port = 53
                        proto = "UDP"
                        qname = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
                        if _high_entropy_domain(qname):
                            results.append({
                                "pcap_file": pcap_file.name,
                                "type": "dns",
                                "indicator": "High-entropy domain",
                                "src_ip": src_ip,
                                "src_port": src_port,
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                                "protocol": proto,
                                "query": qname,
                                "description": "DNS query appears algorithmically generated (high entropy)."
                            })

                    # -------------------
                    # TCP/UDP unusual ports
                    # -------------------
                    if TCP in pkt or UDP in pkt:
                        proto_layer = TCP if TCP in pkt else UDP
                        src_ip, src_port, dst_ip, dst_port, proto = _normalize_flow(pkt, proto_layer)
                        if dst_port not in COMMON_TCP_UDP_PORTS:
                            results.append({
                                "pcap_file": pcap_file.name,
                                "type": "unusual_port",
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "src_port": src_port,
                                "dst_port": dst_port,
                                "protocol": proto,
                                "indicator": "Unusual port usage",
                                "description": f"Connection using unusual port {dst_port}."
                            })

        except Exception:
            continue

        # -------------------
        # Beaconing detection heuristic
        # -------------------
        for dst_ip, times in conn_times.items():
            if len(times) < 5:
                continue
            deltas = [t2 - t1 for t1, t2 in zip(times, times[1:])]
            if not deltas:
                continue
            avg_delta = sum(deltas)/len(deltas)
            if all(abs(d - avg_delta)/avg_delta < 0.2 for d in deltas):
                results.append({
                    "pcap_file": pcap_file.name,
                    "type": "beaconing",
                    "dst_ip": dst_ip,
                    "period": round(avg_delta),
                    "count": len(times),
                    "protocol": "TCP/UDP",
                    "indicator": "Beaconing",
                    "description": f"Repeated connection to same host every ~{round(avg_delta)}s."
                })

    return results

