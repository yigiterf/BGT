"""Kural listesi analizi (lint).

"Ilk eslesen kural kazanir" oldugu icin kural SIRASI guvenligi dogrudan
etkiler. Bu modul kural listesine bakip tipik hatalari bulur:

    shadowed   Bir kural, ondan ONCE gelen bir kural tarafindan tamamen
               kapsandigi icin HICBIR ZAMAN calismaz. Aksiyonlari farkliysa
               bu gercek bir guvenlik acigidir (ornegin ustteki "allow any"
               alttaki "deny ssh" kuralini oldurur).
    redundant  Ayni sey, ama aksiyonlar ayni: gereksiz kural.
    overlap    Iki kural kismen cakisiyor ve aksiyonlari farkli: sira
               onemli, dikkat.
    broad      Cok genis bir ALLOW kurali (any -> any, tum portlar).
    policy     Varsayilan politika ALLOW.

Fonksiyonlar paket gerektirmez; kurallari "kume" olarak karsilastirir.
"""

from __future__ import annotations

from .rules import Rule, parse_networks, parse_ports


# ---------------------------------------------------------------------- #
# Kume islemleri
# ---------------------------------------------------------------------- #
def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(ranges):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def _ports_cover(outer: str, inner: str) -> bool:
    big = _merge_ranges(parse_ports(outer))
    return all(
        any(b_lo <= lo and hi <= b_hi for b_lo, b_hi in big)
        for lo, hi in parse_ports(inner)
    )


def _ports_overlap(a: str, b: str) -> bool:
    return any(
        lo1 <= hi2 and lo2 <= hi1
        for lo1, hi1 in parse_ports(a)
        for lo2, hi2 in parse_ports(b)
    )


def _nets_cover(outer: str, inner: str) -> bool:
    big = parse_networks(outer)
    return all(
        any(n.version == o.version and n.subnet_of(o) for o in big)
        for n in parse_networks(inner)
    )


def _nets_overlap(a: str, b: str) -> bool:
    return any(
        x.version == y.version and x.overlaps(y)
        for x in parse_networks(a)
        for y in parse_networks(b)
    )


def _proto_cover(a: Rule, b: Rule) -> bool:
    return a.protocol == "any" or a.protocol == b.protocol


def _proto_overlap(a: Rule, b: Rule) -> bool:
    return a.protocol == "any" or b.protocol == "any" or a.protocol == b.protocol


def _ports_relevant(a: Rule, b: Rule) -> bool:
    """Port alanlari sadece TCP/UDP icin anlamli (ICMP port tasimaz)."""
    return not (a.protocol == "icmp" or b.protocol == "icmp")


def covers(a: Rule, b: Rule) -> bool:
    """`a` kurali, `b` kuralinin esledigi HER paketi eslestiriyor mu?"""
    if not _proto_cover(a, b):
        return False
    if not _nets_cover(a.src, b.src) or not _nets_cover(a.dst, b.dst):
        return False
    if _ports_relevant(a, b):
        if not _ports_cover(a.sport, b.sport) or not _ports_cover(a.dport, b.dport):
            return False
    # `a` daha az bayrak istiyorsa daha genistir.
    return set(a.flags.split()) <= set(b.flags.split())


def overlaps(a: Rule, b: Rule) -> bool:
    """Iki kuralin ayni anda eslestigi en az bir paket olabilir mi?"""
    if not _proto_overlap(a, b):
        return False
    if not _nets_overlap(a.src, b.src) or not _nets_overlap(a.dst, b.dst):
        return False
    if _ports_relevant(a, b):
        if not _ports_overlap(a.sport, b.sport) or not _ports_overlap(a.dport, b.dport):
            return False
    return True


# ---------------------------------------------------------------------- #
# Lint
# ---------------------------------------------------------------------- #
def lint_rules(rules: list[Rule], default_policy: str = "deny") -> list[dict]:
    """Kural listesini inceler; her bulgu bir sozluk:

    {"index": int | None, "level": "error|warn|info", "kind": str,
     "message": str, "other": int | None}
    """
    findings: list[dict] = []

    if default_policy == "allow":
        findings.append(
            {
                "index": None,
                "level": "warn",
                "kind": "policy",
                "other": None,
                "message": (
                    "Varsayılan politika ALLOW: açıkça yasaklanmayan her şey "
                    "geçer. Güvenli tasarım 'implicit deny' ister."
                ),
            }
        )

    active = [(i, r) for i, r in enumerate(rules) if r.enabled]

    for pos, (j, later) in enumerate(active):
        shadowed_by = None
        for i, earlier in active[:pos]:
            if covers(earlier, later):
                shadowed_by = (i, earlier)
                break

        if shadowed_by:
            i, earlier = shadowed_by
            if earlier.action != later.action:
                findings.append(
                    {
                        "index": j,
                        "level": "error",
                        "kind": "shadowed",
                        "other": i,
                        "message": (
                            f"Kural #{j + 1} ({later.action.upper()}) HİÇBİR ZAMAN "
                            f"çalışmaz: üstündeki #{i + 1} ({earlier.action.upper()}) "
                            f"tüm paketleri önceden yakalıyor. Sırayı değiştir!"
                        ),
                    }
                )
            else:
                findings.append(
                    {
                        "index": j,
                        "level": "warn",
                        "kind": "redundant",
                        "other": i,
                        "message": (
                            f"Kural #{j + 1} gereksiz: #{i + 1} zaten aynı "
                            f"paketleri aynı aksiyonla kapsıyor."
                        ),
                    }
                )
            continue

        # Gölgelenmediyse: karşıt aksiyonlu kısmi çakışma var mı?
        for i, earlier in active[:pos]:
            if earlier.action != later.action and overlaps(earlier, later):
                findings.append(
                    {
                        "index": j,
                        "level": "info",
                        "kind": "overlap",
                        "other": i,
                        "message": (
                            f"Kural #{j + 1} ile #{i + 1} kısmen çakışıyor ve "
                            f"aksiyonları farklı: aralarındaki SIRA sonucu belirler."
                        ),
                    }
                )
                break

        if (
            later.action == "allow"
            and later.src == "any"
            and later.dst == "any"
            and later.dport == "any"
        ):
            findings.append(
                {
                    "index": j,
                    "level": "warn",
                    "kind": "broad",
                    "other": None,
                    "message": (
                        f"Kural #{j + 1} çok geniş: herkesten herkese, tüm "
                        f"portlara ALLOW. En az yetki ilkesine aykırı."
                    ),
                }
            )

    return findings
