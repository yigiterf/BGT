"""Kural listesini gercek iptables komutlarina cevirir.

Amac: "Simulasyondaki kural, Linux'ta gercekte nasil yazilirdi?"
sorusunu cevaplamak. Cikti calistirilmak icin degil, okunmak icindir
(FORWARD zincirini hedefler: firewall iki ag arasinda router gibi durur).
"""

from __future__ import annotations

from .engine import Firewall
from .rules import Rule, parse_networks, parse_ports

TARGET = {"allow": "ACCEPT", "deny": "DROP"}
CHAIN = "FORWARD"


def _ip_arg(spec: str) -> str | None:
    if spec.strip().lower() in ("any", "*", ""):
        return None
    nets = [str(n) for n in parse_networks(spec)]
    return ",".join(nets)


def _port_arg(spec: str) -> str | None:
    if spec.strip().lower() in ("any", "*", ""):
        return None
    parts = []
    for lo, hi in parse_ports(spec):
        parts.append(str(lo) if lo == hi else f"{lo}:{hi}")
    return ",".join(parts)


def _comment(text: str) -> str:
    safe = text.replace('"', "'")
    return f'-m comment --comment "{safe}"' if safe else ""


def rule_to_iptables(rule: Rule) -> list[str]:
    """Tek kuralin iptables karsiligi (bazen 2 satir: protokol 'any' + port)."""
    sport = _port_arg(rule.sport)
    dport = _port_arg(rule.dport)

    if rule.protocol == "any" and (sport or dport):
        protocols = ["tcp", "udp"]  # iptables port icin protokol ister
    elif rule.protocol == "any":
        protocols = [None]
    else:
        protocols = [rule.protocol]

    lines = []
    for proto in protocols:
        parts = [f"iptables -A {CHAIN}"]
        if proto:
            parts.append(f"-p {proto}")
        src, dst = _ip_arg(rule.src), _ip_arg(rule.dst)
        if src:
            parts.append(f"-s {src}")
        if dst:
            parts.append(f"-d {dst}")
        if proto in ("tcp", "udp"):
            for flag, value in (("sport", sport), ("dport", dport)):
                if not value:
                    continue
                if "," in value:
                    parts.append(f"-m multiport --{flag}s {value}")
                else:
                    parts.append(f"--{flag} {value}")
        if proto == "tcp" and rule.flags:
            flags = ",".join(rule.flags.split())
            parts.append(f"--tcp-flags {flags} {flags}")
        comment = _comment(rule.comment)
        if comment:
            parts.append(comment)
        parts.append(f"-j {TARGET[rule.action]}")
        lines.append(" ".join(parts))
    return lines


def to_iptables(fw: Firewall) -> str:
    """Tum guvenlik duvarini (politika + ozellikler + kurallar) betige cevirir."""
    out = [
        "#!/bin/sh",
        "# MiniFirewall Lab → iptables karşılığı (okumak için, çalıştırmak için değil)",
        f"iptables -F {CHAIN}",
        f"iptables -P {CHAIN} {TARGET[fw.default_policy]}"
        + ("   # implicit deny" if fw.default_policy == "deny" else "   # açık firewall"),
        "",
    ]

    if fw.flood_limit:
        out += [
            "# Flood guard: kaynak IP başına hız sınırı",
            f"iptables -A {CHAIN} -m hashlimit --hashlimit-name flood "
            f"--hashlimit-mode srcip --hashlimit-above {fw.flood_limit}/sec -j DROP",
            "",
        ]

    if fw.stateful:
        out += [
            "# Stateful inspection: bilinen oturumların paketleri kurallara bakmadan geçer",
            f"iptables -A {CHAIN} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "",
        ]

    out.append("# Kurallar (ilk eşleşen kazanır — sıra önemli!)")
    if not fw.rules:
        out.append("# (kural yok)")
    for index, rule in enumerate(fw.rules, start=1):
        out.append(f"# kural #{index}")
        if not rule.enabled:
            out += [f"# (devre dışı) {line}" for line in rule_to_iptables(rule)]
            continue
        out += rule_to_iptables(rule)

    return "\n".join(out) + "\n"
