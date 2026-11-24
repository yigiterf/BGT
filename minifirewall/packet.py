"""Paket modeli.

Bir ag paketini temsil eden tek bir veri sinifi. Gercek bir paketin
karar vermek icin gereken alanlarini tasir: kaynak/hedef IP, protokol,
portlar, TCP bayraklari ve boyut.

Bu sinif bilerek "aptal" tutuldu: sadece veriyi tasir ve dogrular.
Karar mantigi engine.py icinde.
"""

from __future__ import annotations

import ipaddress
import time
import uuid
from dataclasses import dataclass, field

# Desteklenen protokoller. "any" sadece kural tarafinda kullanilir.
PROTOCOLS = ("tcp", "udp", "icmp")

# TCP bayraklari (gosterim icin normalize ediyoruz).
TCP_FLAGS = ("SYN", "ACK", "FIN", "RST", "PSH", "URG")


def _clean_ip(value: str, field_name: str) -> str:
    """IP adresini dogrular ve normalize eder."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as exc:
        raise ValueError(f"Gecersiz {field_name}: {value!r}") from exc


def _clean_port(value, field_name: str) -> int | None:
    """Portu 0-65535 araligina oturtur. None -> port yok (ICMP)."""
    if value is None or value == "":
        return None
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Gecersiz {field_name}: {value!r}") from exc
    if not 0 <= port <= 65535:
        raise ValueError(f"{field_name} 0-65535 araliginda olmali: {port}")
    return port


@dataclass(slots=True)
class Packet:
    """Filtrelenecek tek bir ag paketi."""

    src_ip: str
    dst_ip: str
    protocol: str = "tcp"
    src_port: int | None = None
    dst_port: int | None = None
    flags: str = ""
    size: int = 64
    payload: str = ""
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])

    def __post_init__(self) -> None:
        self.protocol = str(self.protocol).strip().lower()
        if self.protocol not in PROTOCOLS:
            raise ValueError(
                f"Desteklenmeyen protokol: {self.protocol!r} "
                f"(gecerli: {', '.join(PROTOCOLS)})"
            )
        self.src_ip = _clean_ip(self.src_ip, "kaynak IP")
        self.dst_ip = _clean_ip(self.dst_ip, "hedef IP")

        # ICMP port tasimaz; TCP/UDP port tasir.
        if self.protocol == "icmp":
            self.src_port = None
            self.dst_port = None
            self.flags = ""
        else:
            self.src_port = _clean_port(self.src_port, "kaynak port")
            self.dst_port = _clean_port(self.dst_port, "hedef port")

        self.flags = " ".join(
            part.strip().upper()
            for part in str(self.flags).replace(",", " ").split()
            if part.strip()
        )
        try:
            self.size = max(0, int(self.size))
        except (TypeError, ValueError):
            self.size = 64
        self.payload = str(self.payload)[:500]

    # ------------------------------------------------------------------ #
    # Yardimcilar
    # ------------------------------------------------------------------ #
    def is_reply_to(self, other: "Packet") -> bool:
        """`other` paketinin yaniti mi? (kaynak/hedef yer degistirmis)"""
        return (
            self.protocol == other.protocol
            and self.src_ip == other.dst_ip
            and self.dst_ip == other.src_ip
            and self.src_port == other.dst_port
            and self.dst_port == other.src_port
        )

    def flow_key(self) -> tuple:
        """Oturum takibi icin 5'li anahtar (yonsuz degil)."""
        return (
            self.protocol,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
        )

    def reverse_flow_key(self) -> tuple:
        return (
            self.protocol,
            self.dst_ip,
            self.dst_port,
            self.src_ip,
            self.src_port,
        )

    def port_label(self, port: int | None) -> str:
        if port is None:
            return ""
        return f":{port}"

    def source(self) -> str:
        return f"{self.src_ip}{self.port_label(self.src_port)}"

    def destination(self) -> str:
        return f"{self.dst_ip}{self.port_label(self.dst_port)}"

    def summary(self) -> str:
        """Log satirlarinda kullanilan kisa ozet."""
        proto = self.protocol.upper()
        flags = f" [{self.flags}]" if self.flags else ""
        return f"{proto:<4} {self.source()} -> {self.destination()}{flags}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": self.ts,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "flags": self.flags,
            "size": self.size,
            "payload": self.payload,
            "summary": self.summary(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Packet":
        """API / JSON girdisinden paket uretir."""
        if not isinstance(data, dict):
            raise ValueError("Paket bir JSON nesnesi olmali")
        return cls(
            src_ip=data.get("src_ip", ""),
            dst_ip=data.get("dst_ip", ""),
            protocol=data.get("protocol", "tcp"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            flags=data.get("flags", ""),
            size=data.get("size", 64),
            payload=data.get("payload", ""),
        )
