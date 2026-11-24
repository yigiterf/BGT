#!/usr/bin/env python3
"""demo/capture.pcap dosyasini uretir.

Gercek bir ag yakalamasi gibi gorunen, farkli servis ve saldiri
paketlerinden olusan kucuk bir pcap dosyasi yazar. Sunumda
`python3 run.py pcap demo/capture.pcap` ile kullanilir.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from minifirewall.packet import Packet  # noqa: E402
from minifirewall.pcap import write_pcap  # noqa: E402

ATTACKER = "198.51.100.66"
OFFICE = "203.0.113.9"
WEB = "10.0.0.10"
DNS = "10.0.0.53"
SSH = "10.0.0.20"
DB = "10.0.0.30"

RAW = [
    # (src, dst, proto, sport, dport, flags, payload)
    ("10.0.0.42", DNS, "udp", 51515, 53, "", "A example.com"),
    ("10.0.0.42", WEB, "tcp", 51600, 80, "SYN", ""),
    ("10.0.0.42", WEB, "tcp", 51600, 80, "PSH ACK", "GET /index.html HTTP/1.1"),
    (OFFICE, WEB, "tcp", 40022, 443, "SYN", ""),
    (ATTACKER, WEB, "tcp", 44321, 443, "SYN", ""),
    (OFFICE, SSH, "tcp", 40023, 22, "SYN", ""),
    (ATTACKER, SSH, "tcp", 40024, 22, "SYN", ""),
    (ATTACKER, SSH, "tcp", 40024, 22, "PSH ACK", "SSH-2.0 user=admin pass=123456"),
    (ATTACKER, WEB, "tcp", 40025, 21, "SYN", ""),
    (ATTACKER, WEB, "tcp", 40026, 23, "SYN", ""),
    (ATTACKER, WEB, "tcp", 40027, 445, "SYN", ""),
    (ATTACKER, SSH, "tcp", 40028, 3389, "SYN", ""),
    (ATTACKER, WEB, "tcp", 40029, 6379, "SYN", ""),
    (ATTACKER, WEB, "tcp", 40030, 8080, "SYN", ""),
    (ATTACKER, WEB, "icmp", None, None, "", "ICMP echo request"),
    (WEB, DB, "tcp", 41000, 3306, "SYN", "DMZ -> DB"),
    ("10.0.0.25", DB, "tcp", 42000, 3306, "SYN", "app -> DB"),
    ("10.0.0.25", DB, "tcp", 42000, 3306, "PSH ACK", "SELECT * FROM users"),
    (ATTACKER, DNS, "udp", 43000, 53, "", "TXT " + "x" * 120 + ".exfil.example.com"),
    ("10.0.0.42", "93.184.216.34", "tcp", 43001, 443, "SYN", ""),
]


def main() -> int:
    start = time.time() - 60
    packets = [
        Packet(
            src_ip=src, dst_ip=dst, protocol=proto,
            src_port=sport, dst_port=dport, flags=flags,
            size=54 + len(payload), payload=payload,
            ts=start + index * 0.4,
        )
        for index, (src, dst, proto, sport, dport, flags, payload) in enumerate(RAW)
    ]
    out = Path(__file__).resolve().parent.parent / "demo" / "capture.pcap"
    out.parent.mkdir(parents=True, exist_ok=True)
    write_pcap(str(out), packets)
    print(f"{len(packets)} paket yazildi -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
