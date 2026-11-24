"""Karar motoru: paket + kural listesi -> ALLOW / DENY.

Temel kural: **ilk eslesen kural kazanir** (first match wins).
Hicbir kural eslesmezse varsayilan politika uygulanir. Varsayilan
politika "deny" oldugunda buna *implicit deny* denir: acikca izin
verilmeyen her sey engellenir.

Karar sirasi:
    1) Flood guard   (opsiyonel) : bir kaynak cok hizli paket yolluyorsa kes
    2) Stateful tablo (opsiyonel) : bilinen oturumun yaniti ise gecir
    3) Kural listesi              : ilk eslesen kural kazanir
    4) Varsayilan politika        : hicbiri eslesmediyse

Opsiyonel `stateful=True` modunda motor, izin verilen ilk paketi
bir oturum olarak hatirlar ve o oturumun geri donus paketlerini
kural listesine bakmadan gecirir (kitaptaki "stateful inspection").

Opsiyonel `flood_limit=N` modunda bir kaynak IP'si `flood_window`
saniye icinde N'den fazla paket gonderirse fazlasi kesilir
(kitaptaki "flood guard").
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

from .packet import Packet
from .rules import Rule

STATE_TTL = 120.0  # saniye: bir oturumun hatirlanma suresi
FLOOD_DEFAULT = 30  # varsayilan: kaynak basina saniyede 30 paket
FLOOD_WINDOW = 1.0  # saniye
LOG_LIMIT = 400
HISTORY_LIMIT = 90


@dataclass
class Decision:
    """Bir paket icin verilen karar ve gerekcesi."""

    allowed: bool
    reason: str
    packet: Packet
    rule: Rule | None = None
    rule_index: int | None = None
    stateful: bool = False
    flood: bool = False
    trace: list[dict] = field(default_factory=list)
    ts: float = field(default_factory=time.time)
    seq: int = 0

    @property
    def action(self) -> str:
        return "allow" if self.allowed else "deny"

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "allowed": self.allowed,
            "action": self.action,
            "reason": self.reason,
            "stateful": self.stateful,
            "flood": self.flood,
            "rule_index": self.rule_index,
            "rule": self.rule.to_dict() if self.rule else None,
            "packet": self.packet.to_dict(),
            "trace": self.trace,
        }


class Firewall:
    """Sirali ACL listesi + varsayilan politika ile calisan filtre."""

    def __init__(
        self,
        rules: list[Rule] | None = None,
        default_policy: str = "deny",
        stateful: bool = False,
        flood_limit: int | None = None,
        flood_window: float = FLOOD_WINDOW,
        clock=time.monotonic,
    ) -> None:
        self.rules: list[Rule] = list(rules or [])
        self.default_policy = self._norm_policy(default_policy)
        self.stateful = bool(stateful)
        self.flood_limit = int(flood_limit) if flood_limit else None
        self.flood_window = float(flood_window)
        self._clock = clock  # testlerde sahte saat verilebilsin diye
        self.lock = threading.RLock()

        self._states: dict[tuple, float] = {}
        self._flood: dict[str, deque] = {}
        self._seq = 0
        self.log: deque[dict] = deque(maxlen=LOG_LIMIT)
        self.history: deque[dict] = deque(maxlen=HISTORY_LIMIT)

        self.total = 0
        self.allowed = 0
        self.denied = 0
        self.stateful_allows = 0
        self.flood_blocks = 0
        self.by_proto: dict[str, dict[str, int]] = {
            "tcp": {"allowed": 0, "denied": 0},
            "udp": {"allowed": 0, "denied": 0},
            "icmp": {"allowed": 0, "denied": 0},
        }
        self.started_at = time.time()

    # ------------------------------------------------------------------ #
    # Kural yonetimi
    # ------------------------------------------------------------------ #
    @staticmethod
    def _norm_policy(value: str) -> str:
        policy = str(value).strip().lower()
        if policy in ("allow", "accept", "permit"):
            return "allow"
        if policy in ("deny", "drop", "block"):
            return "deny"
        raise ValueError(f"Gecersiz varsayilan politika: {value!r}")

    def set_rules(self, rules: list[Rule]) -> None:
        with self.lock:
            self.rules = list(rules)
            self._states.clear()

    def add_rule(self, rule: Rule, index: int | None = None) -> Rule:
        with self.lock:
            if index is None:
                self.rules.append(rule)
            else:
                self.rules.insert(max(0, min(index, len(self.rules))), rule)
            return rule

    def move_rule(self, index: int, delta: int) -> None:
        with self.lock:
            target = index + delta
            if 0 <= index < len(self.rules) and 0 <= target < len(self.rules):
                self.rules[index], self.rules[target] = (
                    self.rules[target],
                    self.rules[index],
                )

    def clear_state(self) -> None:
        with self.lock:
            self._states.clear()

    def set_flood_limit(self, limit: int | None) -> None:
        with self.lock:
            self.flood_limit = int(limit) if limit else None
            self._flood.clear()

    # ------------------------------------------------------------------ #
    # Ana karar fonksiyonu
    # ------------------------------------------------------------------ #
    def evaluate(self, packet: Packet) -> Decision:
        """Paketi kurallardan gecirir ve gerekceli bir karar dondurur."""
        with self.lock:
            self._seq += 1
            trace: list[dict] = []

            # 0) Flood guard: kaynak IP'si cok hizli paket yolluyor mu?
            if self.flood_limit and self._flood_exceeded(packet.src_ip):
                decision = Decision(
                    allowed=False,
                    reason=(
                        f"Flood guard: {packet.src_ip} saniyede "
                        f"{self.flood_limit} paket sınırını aştı → DENY"
                    ),
                    packet=packet,
                    flood=True,
                    trace=[
                        {
                            "stage": "flood",
                            "matched": True,
                            "text": (
                                f"{packet.src_ip}: {self.flood_window:g} sn "
                                f"içinde > {self.flood_limit} paket"
                            ),
                        }
                    ],
                    seq=self._seq,
                )
                self._record(decision)
                return decision

            # 1) Stateful kontrol: bu paket bilinen bir oturumun yaniti mi?
            if self.stateful:
                self._expire_states()
                if packet.flow_key() in self._states:
                    decision = Decision(
                        allowed=True,
                        reason=(
                            "Stateful tablo: bu paket izin verilmiş bir "
                            "oturumun devamı → ALLOW"
                        ),
                        packet=packet,
                        stateful=True,
                        trace=[
                            {
                                "stage": "stateful",
                                "matched": True,
                                "text": "Oturum tablosunda kayıt bulundu",
                            }
                        ],
                        seq=self._seq,
                    )
                    self._record(decision)
                    return decision

            # 2) Kurallari sirayla dene (first match wins).
            winner: Rule | None = None
            winner_index: int | None = None
            for index, rule in enumerate(self.rules):
                if not rule.enabled:
                    trace.append(
                        {
                            "index": index,
                            "text": rule.to_text(),
                            "action": rule.action,
                            "matched": False,
                            "disabled": True,
                            "mismatches": ["kural devre dışı"],
                        }
                    )
                    continue

                mismatches = rule.mismatches(packet)
                trace.append(
                    {
                        "index": index,
                        "text": rule.to_text(),
                        "action": rule.action,
                        "matched": not mismatches,
                        "disabled": False,
                        "mismatches": mismatches,
                    }
                )
                if not mismatches:
                    winner, winner_index = rule, index
                    break

            # 3) Kural yoksa varsayilan politika.
            if winner is not None:
                allowed = winner.action == "allow"
                label = winner.comment or winner.to_text()
                reason = (
                    f"Kural #{winner_index + 1} eşleşti → "
                    f"{winner.action.upper()} ({label})"
                )
            else:
                allowed = self.default_policy == "allow"
                if allowed:
                    reason = (
                        "Hiçbir kural eşleşmedi → varsayılan politika "
                        "ALLOW (açık firewall)"
                    )
                else:
                    reason = (
                        "Hiçbir kural eşleşmedi → varsayılan politika "
                        "DENY (implicit deny)"
                    )

            decision = Decision(
                allowed=allowed,
                reason=reason,
                packet=packet,
                rule=winner,
                rule_index=winner_index,
                trace=trace,
                seq=self._seq,
            )

            # 4) Stateful ise izin verilen akisi hatirla (iki yon).
            if self.stateful and allowed:
                ttl = time.time() + STATE_TTL
                self._states[packet.flow_key()] = ttl
                self._states[packet.reverse_flow_key()] = ttl

            self._record(decision)
            return decision

    # ------------------------------------------------------------------ #
    # Ic kayit islemleri
    # ------------------------------------------------------------------ #
    def _expire_states(self) -> None:
        now = time.time()
        dead = [key for key, exp in self._states.items() if exp < now]
        for key in dead:
            self._states.pop(key, None)

    def _flood_exceeded(self, src_ip: str) -> bool:
        """Kayan pencere: son `flood_window` sn'de bu kaynaktan kac paket geldi?

        Engellenen paketler de sayilir; yani saldirgan saldirmaya devam
        ettikce engel surer, sustugunda pencere bosalir ve trafik akar.
        """
        now = self._clock()
        cutoff = now - self.flood_window
        stamps = self._flood.setdefault(src_ip, deque())
        while stamps and stamps[0] < cutoff:
            stamps.popleft()
        stamps.append(now)

        # DDoS gibi cok sayida farkli kaynakta tablo sisip durmasin.
        if len(self._flood) > 4096:
            for key in [k for k, v in self._flood.items() if not v or v[-1] < cutoff]:
                self._flood.pop(key, None)
        return len(stamps) > self.flood_limit

    def _record(self, decision: Decision) -> None:
        packet = decision.packet
        self.total += 1
        if decision.allowed:
            self.allowed += 1
            if decision.stateful:
                self.stateful_allows += 1
        else:
            self.denied += 1
            if decision.flood:
                self.flood_blocks += 1

        bucket = self.by_proto.setdefault(
            packet.protocol, {"allowed": 0, "denied": 0}
        )
        bucket["allowed" if decision.allowed else "denied"] += 1

        if decision.rule is not None:
            decision.rule.hits += 1

        self.history.append(
            {"ts": decision.ts, "allowed": decision.allowed, "seq": decision.seq}
        )
        self.log.append(
            {
                "seq": decision.seq,
                "ts": decision.ts,
                "allowed": decision.allowed,
                "action": decision.action,
                "reason": decision.reason,
                "stateful": decision.stateful,
                "flood": decision.flood,
                "rule_index": decision.rule_index,
                "rule_text": decision.rule.to_text() if decision.rule else "",
                "protocol": packet.protocol,
                "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip,
                "src_port": packet.src_port,
                "dst_port": packet.dst_port,
                "flags": packet.flags,
                "size": packet.size,
                "summary": packet.summary(),
            }
        )

    # ------------------------------------------------------------------ #
    # API / arayuz
    # ------------------------------------------------------------------ #
    def reset_counters(self) -> None:
        with self.lock:
            self.total = self.allowed = self.denied = 0
            self.stateful_allows = 0
            self.flood_blocks = 0
            self._flood.clear()
            self.by_proto = {
                "tcp": {"allowed": 0, "denied": 0},
                "udp": {"allowed": 0, "denied": 0},
                "icmp": {"allowed": 0, "denied": 0},
            }
            for rule in self.rules:
                rule.hits = 0
            self.log.clear()
            self.history.clear()
            self._states.clear()
            self.started_at = time.time()

    def logs_since(self, since: int) -> list[dict]:
        with self.lock:
            return [entry for entry in self.log if entry["seq"] > since]

    def stats(self) -> dict:
        with self.lock:
            rate = (self.denied / self.total * 100.0) if self.total else 0.0
            return {
                "total": self.total,
                "allowed": self.allowed,
                "denied": self.denied,
                "block_rate": round(rate, 1),
                "stateful_allows": self.stateful_allows,
                "flood_blocks": self.flood_blocks,
                "by_proto": {k: dict(v) for k, v in self.by_proto.items()},
                "history": list(self.history),
                "rule_hits": [rule.hits for rule in self.rules],
                "uptime": round(time.time() - self.started_at, 1),
                "active_states": len(self._states),
            }

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "rules": [rule.to_dict() for rule in self.rules],
                "default_policy": self.default_policy,
                "stateful": self.stateful,
                "flood_limit": self.flood_limit,
                "stats": self.stats(),
                "last_seq": self._seq,
            }
