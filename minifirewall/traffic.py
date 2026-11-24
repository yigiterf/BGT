"""Saldiri / trafik ureticileri.

Arayuzdeki "saldiri" butonlari ve terminal demosu bu fonksiyonlari
kullanir. Amac gercek bir saldiri araci yazmak degil; filtreleme
kararlarini gorsellestirmek icin gercekci paket dizileri uretmek.
"""

from __future__ import annotations

import random

from .packet import Packet

WEB = "10.0.0.10"
DNS = "10.0.0.53"
SSH = "10.0.0.20"
DB = "10.0.0.30"

ATTACKER = "198.51.100.66"
OFFICE = "203.0.113.0/24"

# Ornek port taramasi hedefleri: dusuk portlar + yaygin servis portlari.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 631, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389,
    5000, 5432, 5900, 6379, 8000, 8080, 8443, 9000, 9200, 11211, 27017,
]


def _ephemeral(rng: random.Random) -> int:
    return rng.randint(32768, 60999)


def port_scan(rng: random.Random, count: int = 120) -> list[Packet]:
    """Hedef web sunucusuna sirali port taramasi (TCP SYN)."""
    ports = list(range(1, count + 1))
    ports += [port for port in COMMON_PORTS if port > count]
    packets = []
    for i, port in enumerate(ports):
        packets.append(
            Packet(
                src_ip=ATTACKER,
                dst_ip=WEB,
                protocol="tcp",
                src_port=_ephemeral(rng),
                dst_port=port,
                flags="SYN",
                size=54,
                payload="",
                ts=0.0,
            )
        )
    return packets


def syn_flood(rng: random.Random, count: int = 150) -> list[Packet]:
    """Tek kaynaktan HTTPS'e SYN seli."""
    return [
        Packet(
            src_ip=ATTACKER,
            dst_ip=WEB,
            protocol="tcp",
            src_port=rng.randint(1024, 65535),
            dst_port=443,
            flags="SYN",
            size=54,
        )
        for _ in range(count)
    ]


def ddos(rng: random.Random, count: int = 160) -> list[Packet]:
    """Cok sayida farkli kaynaktan dagitik SYN seli (botnet)."""
    return [
        Packet(
            src_ip=f"{rng.choice([45, 91, 103, 185, 193])}.{rng.randint(1, 254)}."
            f"{rng.randint(1, 254)}.{rng.randint(1, 254)}",
            dst_ip=WEB,
            protocol="tcp",
            src_port=rng.randint(1024, 65535),
            dst_port=443,
            flags="SYN",
            size=54,
        )
        for _ in range(count)
    ]


def ssh_brute(rng: random.Random, count: int = 60) -> list[Packet]:
    """SSH'e parola deneme trafigi (TCP PSH/ACK + kisa payload)."""
    return [
        Packet(
            src_ip=ATTACKER,
            dst_ip=SSH,
            protocol="tcp",
            src_port=_ephemeral(rng),
            dst_port=22,
            flags="PSH ACK",
            size=120,
            payload=f"SSH-2.0-libssh user=admin pass=deneme{i}",
        )
        for i in range(count)
    ]


def dns_tunnel(rng: random.Random, count: int = 30) -> list[Packet]:
    """DNS uzerinden veri sizdirma denemesi (buyuk TXT sorgulari)."""
    return [
        Packet(
            src_ip=ATTACKER,
            dst_ip=DNS,
            protocol="udp",
            src_port=_ephemeral(rng),
            dst_port=53,
            size=220,
            payload="TXT " + ("a" * 180) + f".exfil{i}.example.com",
        )
        for i in range(count)
    ]


def ping_sweep(rng: random.Random, count: int = 24) -> list[Packet]:
    """ICMP echo ile ag kesfi."""
    return [
        Packet(
            src_ip=ATTACKER,
            dst_ip=WEB,
            protocol="icmp",
            size=98,
            payload="ICMP echo request",
        )
        for _ in range(count)
    ]


def db_attempt(rng: random.Random) -> list[Packet]:
    """DMZ'deki web sunucusundan ic veritabanina dogrudan erisim denemesi."""
    return [
        Packet(
            src_ip=WEB,
            dst_ip=DB,
            protocol="tcp",
            src_port=_ephemeral(rng),
            dst_port=3306,
            flags="SYN",
            size=60,
            payload="MySQL handshake denemesi",
        )
    ]


BURSTS = {
    "portscan": ("Port taramasi", port_scan),
    "synflood": ("SYN seli", syn_flood),
    "ddos": ("DDoS (botnet)", ddos),
    "sshbrute": ("SSH brute force", ssh_brute),
    "dns": ("DNS tuneli", dns_tunnel),
    "ping": ("Ping sweep", ping_sweep),
    "db": ("DMZ → DB", db_attempt),
}


def make_burst(kind: str, seed: int | None = None) -> list[Packet]:
    if kind not in BURSTS:
        raise ValueError(f"Bilinmeyen saldiri tipi: {kind!r}")
    rng = random.Random(seed)
    _, factory = BURSTS[kind]
    return factory(rng)


def burst_catalog() -> list[dict]:
    return [
        {
            "kind": kind,
            "label": label,
            "count": len(factory(random.Random(1))),
        }
        for kind, (label, factory) in BURSTS.items()
    ]
