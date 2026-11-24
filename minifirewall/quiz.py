"""Terminalde interaktif 'ALLOW mi DENY mi?' yarismasi.

Sunumda izleyicilere sorulur: ekranda bir paket ve kural listesi gorunur,
herkes tahminini soyler; sunucu Enter'a basinca motor kararini ve
kural kural gerekcesini gosterir. Bazi sorular bilerek tuzaklidir
(CIDR siniri, TCP/UDP farki, stateful donus paketi, kural sirasi).

    python3 run.py quiz            # interaktif
    python3 run.py quiz --auto     # tahmin sormadan hepsini gosterir
"""

from __future__ import annotations

import sys

from . import scenarios
from .engine import Firewall
from .packet import Packet

ATTACKER = "198.51.100.66"


def P(src, dst, proto="tcp", sport=None, dport=None, flags="SYN") -> Packet:
    if proto == "udp":
        flags = ""
    return Packet(src_ip=src, dst_ip=dst, protocol=proto,
                  src_port=sport, dst_port=dport, flags=flags)


# setup: soru sorulmadan once sessizce motora verilen paketler (oturum kurmak icin)
QUESTIONS = [
    {
        "scenario": "web",
        "title": "Kolay ısınma",
        "packet": P(ATTACKER, "10.0.0.10", sport=50001, dport=443),
        "lesson": "Saldırgan bile olsa HTTPS herkese açık bir servis: kural #2 izin veriyor.",
    },
    {
        "scenario": "web",
        "title": "Kapalı port",
        "packet": P(ATTACKER, "10.0.0.10", sport=50002, dport=8080),
        "lesson": "Hiçbir kural 8080'i anmıyor → implicit deny. İzin yoksa yasak.",
    },
    {
        "scenario": "web",
        "title": "Aynı port, farklı protokol",
        "packet": P("10.0.0.42", "10.0.0.53", proto="tcp", sport=50003, dport=53),
        "lesson": "DNS kuralı sadece UDP 53 için. TCP 53 (büyük yanıtlar, zone transfer) "
                  "farklı bir protokol → eşleşmez → DENY.",
    },
    {
        "scenario": "bastion",
        "title": "CIDR sınırı (içeride)",
        "packet": P("203.0.113.200", "10.0.0.20", sport=50004, dport=22),
        "lesson": "203.0.113.0/24 aralığı .0 ile .255 arasıdır; .200 içeride → ALLOW.",
    },
    {
        "scenario": "bastion",
        "title": "CIDR sınırı (hemen dışarıda)",
        "packet": P("203.0.114.5", "10.0.0.20", sport=50005, dport=22),
        "lesson": "203.0.114.x, 203.0.113.0/24'ün dışında. Bir sayı fark → DENY.",
    },
    {
        "scenario": "dmz",
        "title": "DMZ'den içeri",
        "packet": P("10.0.0.10", "10.0.0.30", sport=50006, dport=3306),
        "lesson": "Ele geçirilmiş web sunucusu DB'ye uzanamasın: kural #1 DENY. "
                  "Ağ ayırma (network separation) tam olarak bu.",
    },
    {
        "scenario": "dmz",
        "title": "Uygulama sunucusu",
        "packet": P("10.0.0.25", "10.0.0.30", sport=50007, dport=3306),
        "lesson": "Yetkili tek kaynak 10.0.0.25 → kural #2 ALLOW.",
    },
    {
        "scenario": "stateful",
        "title": "Davetsiz dönüş paketi",
        "packet": P("93.184.216.34", "10.0.0.42", sport=443, dport=51515, flags="SYN ACK"),
        "lesson": "Bu bağlantıyı içeriden kimse başlatmadı. Tabloda kayıt yok, kural da yok → DENY.",
    },
    {
        "scenario": "stateful",
        "title": "Beklenen dönüş paketi",
        "setup": [P("10.0.0.42", "93.184.216.34", sport=51515, dport=443)],
        "packet": P("93.184.216.34", "10.0.0.42", sport=443, dport=51515, flags="SYN ACK"),
        "lesson": "İç ağ bağlantıyı başlattı (kural #1 izin verdi, oturum hatırlandı). "
                  "Dönüş paketi kural listesine bakılmadan geçer → ALLOW.",
    },
    {
        "scenario": "messy",
        "title": "Tuzak: kural sırası",
        "packet": P(ATTACKER, "10.0.0.20", sport=50008, dport=22),
        "lesson": "SSH'i yasaklayan kural #2 var ama #1 (allow any) onu gölgeliyor. "
                  "İlk eşleşen kazanır → ALLOW. Güvenlik açığı!",
    },
]


def _answer_of(decision) -> str:
    return "a" if decision.allowed else "d"


def run_quiz(auto: bool = False, c=None, pause=None) -> int:
    """`c` renk sinifi, `pause` bekleme fonksiyonu cli.py'den gelir."""
    interactive = (not auto) and sys.stdin.isatty()

    class _NoColor:
        RESET = BOLD = DIM = RED = GREEN = YELLOW = CYAN = MAGENTA = GREY = ""

    c = c or _NoColor
    pause = pause or (lambda *_: None)

    print(f"\n{c.BOLD}{c.MAGENTA}ALLOW mi DENY mi?{c.RESET}  "
          f"{c.GREY}— tahmin et, sonra motor gösterir{c.RESET}")

    score = asked = 0
    last_scenario = None
    fw: Firewall | None = None

    for number, q in enumerate(QUESTIONS, start=1):
        if q["scenario"] != last_scenario or fw is None or q.get("setup"):
            fw = scenarios.build(q["scenario"])
            last_scenario = q["scenario"]
        for packet in q.get("setup", []):
            fw.evaluate(packet)

        data = scenarios.SCENARIOS[q["scenario"]]
        print(f"\n{c.CYAN}{c.BOLD}── Soru {number}/{len(QUESTIONS)}: {q['title']} "
              f"{'─' * max(0, 44 - len(q['title']))}{c.RESET}")
        print(f"  {c.GREY}Senaryo : {data['label']}{c.RESET}")
        print(f"  {c.GREY}Politika: {fw.default_policy.upper()}"
              f"{'  |  stateful AÇIK' if fw.stateful else ''}{c.RESET}")
        for i, rule in enumerate(fw.rules, start=1):
            print(f"  {c.GREY}#{i}{c.RESET} {rule.to_text()}")
        if q.get("setup"):
            for packet in q["setup"]:
                print(f"  {c.YELLOW}(önceden geçen paket){c.RESET} {packet.summary()}")
        print(f"\n  {c.BOLD}Paket: {q['packet'].summary()}{c.RESET}\n")

        guess = None
        if interactive:
            try:
                raw = input("  Tahminin? [a=ALLOW, d=DENY, Enter=sadece göster, q=çık] ")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            raw = raw.strip().lower()
            if raw == "q":
                break
            if raw in ("a", "allow", "e"):
                guess = "a"
            elif raw in ("d", "deny", "r"):
                guess = "d"
        else:
            pause(0.6)

        decision = fw.evaluate(q["packet"])
        for step in decision.trace:
            if "index" not in step:
                print(f"  {c.YELLOW}◆ {step['text']}{c.RESET}")
                continue
            mark = f"{c.GREEN}EŞLEŞTİ{c.RESET}" if step["matched"] else f"{c.GREY}atlandı{c.RESET}"
            rule_part = step["text"].split("  #")[0]
            print(f"  #{step['index'] + 1} {rule_part:<46} {mark}")
        verdict = f"{c.GREEN}ALLOW{c.RESET}" if decision.allowed else f"{c.RED}DENY{c.RESET}"
        print(f"\n  Cevap: {c.BOLD}{verdict}{c.RESET}  {c.GREY}{decision.reason}{c.RESET}")

        if guess is not None:
            asked += 1
            if guess == _answer_of(decision):
                score += 1
                print(f"  {c.GREEN}✔ Doğru!{c.RESET}")
            else:
                print(f"  {c.RED}✘ Yanlış.{c.RESET}")
        print(f"  {c.YELLOW}Ders:{c.RESET} {q['lesson']}")

        if interactive and number < len(QUESTIONS):
            try:
                input(f"\n  {c.GREY}⏎ sıradaki soru{c.RESET}")
            except (EOFError, KeyboardInterrupt):
                print()
                break

    if asked:
        print(f"\n{c.BOLD}Skor: {score}/{asked}{c.RESET}")
    return 0
