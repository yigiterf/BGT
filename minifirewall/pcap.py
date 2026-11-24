"""Bagimliliksiz PCAP okuyucu / yazici.

Gercek bir `.pcap` dosyasindaki IPv4 + TCP/UDP/ICMP paketlerini
okur ve `Packet` nesnelerine cevirir. Boylece simulasyon sadece
"uydurma" paketlerle degil, gercek bir yakalama dosyasiyla da
test edilebilir. Harici kutuphane (scapy vb.) gerekmez.

Desteklenen: klasik pcap, Ethernet (VLAN dahil), IPv4, TCP/UDP/ICMP.
Desteklenmeyen: pcapng, IPv6 (uyari ile atlanir).
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from .packet import Packet

TCP_FLAG_BITS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
)

MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}


@dataclass
class PcapResult:
    packets: list[Packet] = field(default_factory=list)
    skipped: int = 0
    warnings: list[str] = field(default_factory=list)


def _flags_to_text(byte: int) -> str:
    return " ".join(name for bit, name in TCP_FLAG_BITS if byte & bit)


def _parse_frame(data: bytes, ts: float) -> Packet | None:
    """Ethernet cercevesini Packet'e cevirir. Desteklenmeyen -> None."""
    if len(data) < 14:
        return None

    ethertype = struct.unpack("!H", data[12:14])[0]
    offset = 14
    # VLAN etiketleri (802.1Q) varsa atla.
    while ethertype in (0x8100, 0x88A8) and len(data) >= offset + 4:
        ethertype = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
        offset += 4

    if ethertype != 0x0800 or len(data) < offset + 20:
        return None  # IPv4 degil

    ip = data[offset:]
    version_ihl = ip[0]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if len(ip) < ihl + 4:
        return None

    proto_num = ip[9]
    src_ip = socket.inet_ntoa(ip[12:16])
    dst_ip = socket.inet_ntoa(ip[16:20])
    total_len = struct.unpack("!H", ip[2:4])[0]
    payload = ip[ihl:]

    if proto_num == 6:  # TCP
        if len(payload) < 20:
            return None
        src_port, dst_port = struct.unpack("!HH", payload[0:4])
        data_offset = (payload[12] >> 4) * 4
        flags = _flags_to_text(payload[13])
        body = payload[data_offset:]
        text = body[:120].decode("utf-8", "replace") if body else ""
        return Packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="tcp",
            src_port=src_port,
            dst_port=dst_port,
            flags=flags,
            size=total_len or len(ip),
            payload=text,
            ts=ts,
        )

    if proto_num == 17:  # UDP
        if len(payload) < 8:
            return None
        src_port, dst_port = struct.unpack("!HH", payload[0:4])
        body = payload[8:]
        text = body[:120].decode("utf-8", "replace") if body else ""
        return Packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="udp",
            src_port=src_port,
            dst_port=dst_port,
            size=total_len or len(ip),
            payload=text,
            ts=ts,
        )

    if proto_num == 1:  # ICMP
        icmp_type = payload[0] if payload else None
        return Packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="icmp",
            size=total_len or len(ip),
            payload=f"icmp type={icmp_type}" if icmp_type is not None else "",
            ts=ts,
        )

    return None


def read_pcap(path: str) -> PcapResult:
    """Bir .pcap dosyasini okur."""
    result = PcapResult()
    with open(path, "rb") as handle:
        header = handle.read(4)
        if header not in MAGIC:
            raise ValueError(
                "Desteklenmeyen dosya bicimi. Klasik .pcap bekleniyordu "
                "(pcapng desteklenmiyor)."
            )
        endian, nano = MAGIC[header]
        rest = handle.read(20)
        if len(rest) < 20:
            raise ValueError("Bozuk pcap basligi")
        _, _, _, _, _, linktype = struct.unpack(endian + "HHiiii", rest)
        if linktype != 1:
            raise ValueError(
                f"Sadece Ethernet (linktype=1) destekleniyor, bulunan: {linktype}"
            )

        while True:
            rec = handle.read(16)
            if len(rec) < 16:
                break
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(
                endian + "IIII", rec
            )
            frame = handle.read(incl_len)
            if len(frame) < incl_len:
                break
            ts = ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6)
            packet = _parse_frame(frame, ts)
            if packet is None:
                result.skipped += 1
                continue
            result.packets.append(packet)

    if result.skipped:
        result.warnings.append(
            f"{result.skipped} cerceve desteklenmeyen protokol oldugu icin atlandi"
        )
    return result


# ---------------------------------------------------------------------- #
# Yazma (demo yakalama dosyasi uretmek icin)
# ---------------------------------------------------------------------- #
def _ip_checksum(header: bytes) -> int:
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + (header[i + 1] if i + 1 < len(header) else 0)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4(src: str, dst: str, proto: int, body: bytes) -> bytes:
    total_len = 20 + len(body)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, total_len, 0x1234, 0x4000, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    checksum = _ip_checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + body


def _tcp(src: str, dst: str, sport: int, dport: int, flags: str, payload: bytes) -> bytes:
    bits = 0
    for bit, name in TCP_FLAG_BITS:
        if name in flags.split():
            bits |= bit
    header = struct.pack(
        "!HHIIBBHHH", sport, dport, 1, 0, (5 << 4), bits, 65535, 0, 0
    )
    return _ipv4(src, dst, 6, header + payload)


def _udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return _ipv4(src, dst, 17, header + payload)


def _icmp(src: str, dst: str, payload: bytes = b"ping") -> bytes:
    body = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + payload
    return _ipv4(src, dst, 1, body)


def _ethernet(frame: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00" + frame


def write_pcap(path: str, packets: list[Packet]) -> None:
    """Packet listesini klasik bir .pcap dosyasina yazar."""
    with open(path, "wb") as handle:
        handle.write(
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        )
        for packet in packets:
            if packet.protocol == "tcp":
                frame = _tcp(
                    packet.src_ip, packet.dst_ip,
                    packet.src_port or 0, packet.dst_port or 0,
                    packet.flags, packet.payload.encode(),
                )
            elif packet.protocol == "udp":
                frame = _udp(
                    packet.src_ip, packet.dst_ip,
                    packet.src_port or 0, packet.dst_port or 0,
                    packet.payload.encode(),
                )
            else:
                frame = _icmp(packet.src_ip, packet.dst_ip)
            frame = _ethernet(frame)
            sec = int(packet.ts)
            usec = int((packet.ts - sec) * 1_000_000)
            handle.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            handle.write(frame)
