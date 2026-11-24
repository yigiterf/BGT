"""Kural modeli ve kural ayristirici (ACL).

Kural sozdizimi (iptables'a benzeyen basit bir dil):

    ACTION PROTO KAYNAK KAYNAK_PORT HEDEF HEDEF_PORT [flags=SYN] [# yorum]

Ornekler:
    allow tcp any any 10.0.0.10 443 # Web sunucusu (HTTPS)
    deny  tcp any any 10.0.0.20 22  # SSH'i herkese kapat
    allow tcp 203.0.113.0/24 any 10.0.0.20 22 # Sadece ofis subneti
    allow udp any any 10.0.0.53 53
    allow tcp 10.0.0.0/24 1024-65535 10.0.0.30 3306

Desteklenen alan degerleri:
    IP     : any | 10.0.0.5 | 10.0.0.0/24 | 10.0.0.5,10.0.0.9
    PORT   : any | 443 | 80,443 | 1024-65535 | 1024:65535
    PROTO  : any | tcp | udp | icmp
    ACTION : allow | deny  (accept/drop/block es anlamlilari kabul edilir)
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field

ACTIONS = ("allow", "deny")
ACTION_ALIASES = {
    "allow": "allow",
    "accept": "allow",
    "permit": "allow",
    "pass": "allow",
    "deny": "deny",
    "drop": "deny",
    "block": "deny",
    "reject": "deny",
}

PROTO_ALIASES = {
    "any": "any",
    "all": "any",
    "*": "any",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
}


def _norm_action(value: str) -> str:
    key = str(value).strip().lower()
    if key not in ACTION_ALIASES:
        raise ValueError(f"Gecersiz aksiyon: {value!r} (allow/deny)")
    return ACTION_ALIASES[key]


def _norm_proto(value: str) -> str:
    key = str(value).strip().lower()
    if key not in PROTO_ALIASES:
        raise ValueError(f"Gecersiz protokol: {value!r} (any/tcp/udp/icmp)")
    return PROTO_ALIASES[key]


def parse_ports(spec: str) -> list[tuple[int, int]]:
    """'any' | '443' | '80,443' | '1024-65535' -> [(alt, ust), ...]"""
    text = str(spec).strip().lower()
    if text in ("any", "*", ""):
        return [(0, 65535)]

    ranges: list[tuple[int, int]] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
        elif ":" in part:
            lo_s, hi_s = part.split(":", 1)
        else:
            lo_s = hi_s = part
        try:
            lo, hi = int(lo_s), int(hi_s)
        except ValueError as exc:
            raise ValueError(f"Gecersiz port ifadesi: {part!r}") from exc
        if not (0 <= lo <= 65535 and 0 <= hi <= 65535) or lo > hi:
            raise ValueError(f"Gecersiz port araligi: {part!r}")
        ranges.append((lo, hi))
    if not ranges:
        raise ValueError(f"Gecersiz port ifadesi: {spec!r}")
    return ranges


def parse_networks(spec: str) -> list:
    """'any' | '10.0.0.5' | '10.0.0.0/24' | virgullu liste -> ip_network listesi."""
    text = str(spec).strip().lower()
    if text in ("any", "*", ""):
        return [ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0")]

    networks = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError as exc:
            raise ValueError(f"Gecersiz IP/CIDR: {part!r}") from exc
    if not networks:
        raise ValueError(f"Gecersiz IP ifadesi: {spec!r}")
    return networks


def network_matches(spec: str, ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in parse_networks(spec))


def port_matches(spec: str, port: int | None) -> bool:
    if port is None:
        return False
    return any(lo <= port <= hi for lo, hi in parse_ports(spec))


@dataclass
class Rule:
    """Tek bir erisim kontrol kurali (ACL girdisi)."""

    action: str = "allow"
    protocol: str = "any"
    src: str = "any"
    sport: str = "any"
    dst: str = "any"
    dport: str = "any"
    flags: str = ""
    comment: str = ""
    enabled: bool = True
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    hits: int = 0

    def __post_init__(self) -> None:
        self.action = _norm_action(self.action)
        self.protocol = _norm_proto(self.protocol)
        self.src = str(self.src or "any").strip()
        self.dst = str(self.dst or "any").strip()
        self.sport = str(self.sport or "any").strip()
        self.dport = str(self.dport or "any").strip()
        self.flags = str(self.flags or "").strip().upper()
        self.comment = str(self.comment or "").strip()[:120]
        # Ayristirmayi simdiden dogrula: hatali kural sunucuya hic girmez.
        parse_networks(self.src)
        parse_networks(self.dst)
        parse_ports(self.sport)
        parse_ports(self.dport)

    # ------------------------------------------------------------------ #
    # Eslesme
    # ------------------------------------------------------------------ #
    def mismatches(self, packet) -> list[str]:
        """Paketle uyusmayan alanlarin listesi. Bos liste = tam eslesme.

        Bu fonksiyon hem karar motorunu hem de arayuzdeki "neden
        eslesmedi?" aciklamasini besler.
        """
        reasons: list[str] = []

        if self.protocol != "any" and self.protocol != packet.protocol:
            reasons.append(f"protokol {packet.protocol} ≠ {self.protocol}")

        if not network_matches(self.src, packet.src_ip):
            reasons.append(f"kaynak IP {packet.src_ip} kapsam dışı")

        if not network_matches(self.dst, packet.dst_ip):
            reasons.append(f"hedef IP {packet.dst_ip} kapsam dışı")

        # Port alanları TCP/UDP paketlerinde anlamlıdır (ICMP port taşımaz).
        # Kuralın protokolü "any" olsa bile port şartı geçerlidir.
        if packet.protocol in ("tcp", "udp"):
            if not port_matches(self.sport, packet.src_port):
                reasons.append(f"kaynak port {packet.src_port} kapsam dışı")
            if not port_matches(self.dport, packet.dst_port):
                reasons.append(f"hedef port {packet.dst_port} kapsam dışı")

        if self.flags:
            wanted = set(self.flags.split())
            have = set(packet.flags.split())
            if not wanted.issubset(have):
                reasons.append(
                    f"bayraklar {packet.flags or '-'} ≠ {self.flags}"
                )

        return reasons

    def matches(self, packet) -> bool:
        return not self.mismatches(packet)

    # ------------------------------------------------------------------ #
    # Gosterim
    # ------------------------------------------------------------------ #
    def to_text(self) -> str:
        parts = [self.action, self.protocol, self.src, self.sport, self.dst, self.dport]
        if self.flags:
            parts.append(f"flags={self.flags}")
        line = " ".join(parts)
        if self.comment:
            line += f"  # {self.comment}"
        return line

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "action": self.action,
            "protocol": self.protocol,
            "src": self.src,
            "sport": self.sport,
            "dst": self.dst,
            "dport": self.dport,
            "flags": self.flags,
            "comment": self.comment,
            "enabled": self.enabled,
            "hits": self.hits,
            "text": self.to_text(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        if not isinstance(data, dict):
            raise ValueError("Kural bir JSON nesnesi olmali")
        return cls(
            action=data.get("action", "allow"),
            protocol=data.get("protocol", "any"),
            src=data.get("src", "any"),
            sport=data.get("sport", "any"),
            dst=data.get("dst", "any"),
            dport=data.get("dport", "any"),
            flags=data.get("flags", ""),
            comment=data.get("comment", ""),
            enabled=bool(data.get("enabled", True)),
            id=data.get("id") or uuid.uuid4().hex[:8],
            hits=int(data.get("hits", 0) or 0),
        )

    @classmethod
    def from_text(cls, line: str) -> "Rule":
        """'allow tcp any any 10.0.0.10 443 # web' satirini ayristirir."""
        raw = str(line).strip()
        if not raw or raw.startswith("#"):
            raise ValueError("Bos veya yorum satiri kural degildir")

        comment = ""
        if "#" in raw:
            raw, comment = raw.split("#", 1)
            comment = comment.strip()

        tokens = raw.split()
        flags = ""
        kept: list[str] = []
        for token in tokens:
            if token.lower().startswith("flags="):
                flags = token.split("=", 1)[1]
            else:
                kept.append(token)

        if len(kept) < 6:
            raise ValueError(
                "Kural en az 6 alan ister: ACTION PROTO KAYNAK SPORT HEDEF DPORT"
            )
        action, proto, src, sport, dst, dport = kept[:6]
        return cls(
            action=action,
            protocol=proto,
            src=src,
            sport=sport,
            dst=dst,
            dport=dport,
            flags=flags,
            comment=comment,
        )
