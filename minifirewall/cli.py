"""Komut satiri arayuzu.

    python3 run.py demo                 # terminalde hikayeli demo
    python3 run.py demo --step          # her bolumde Enter bekler (sunum modu)
    python3 run.py quiz                 # izleyicilerle ALLOW/DENY yarismasi
    python3 run.py lint --scenario messy
    python3 run.py iptables --scenario web
    python3 run.py pcap demo/capture.pcap --scenario web
    python3 run.py trace --src 198.51.100.66 --dst 10.0.0.20 --dport 22
    python3 run.py serve                # web arayuzu

Amac: ayni kural motorunu kod okuyarak ve terminalde izleyerek
gostermek. Sunumda "kod burada, karar burada" anini kolaylastirir.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from pathlib import Path

from . import scenarios, traffic
from .analysis import lint_rules
from .engine import Firewall
from .export import to_iptables
from .packet import Packet
from .pcap import read_pcap
from .rules import Rule

# ---------------------------------------------------------------------- #
# Renkler
# ---------------------------------------------------------------------- #
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


class C:
    RESET = "\033[0m" if _USE_COLOR else ""
    BOLD = "\033[1m" if _USE_COLOR else ""
    DIM = "\033[2m" if _USE_COLOR else ""
    RED = "\033[91m" if _USE_COLOR else ""
    GREEN = "\033[92m" if _USE_COLOR else ""
    YELLOW = "\033[93m" if _USE_COLOR else ""
    BLUE = "\033[94m" if _USE_COLOR else ""
    MAGENTA = "\033[95m" if _USE_COLOR else ""
    CYAN = "\033[96m" if _USE_COLOR else ""
    GREY = "\033[90m" if _USE_COLOR else ""


def title(text: str) -> None:
    print(f"\n{C.CYAN}{C.BOLD}== {text} {'=' * max(0, 58 - len(text))}{C.RESET}")


def bullet(text: str) -> None:
    print(f"  {C.GREY}>{C.RESET} {text}")


def verdict_line(decision, packet=None, indent: str = "  ") -> None:
    packet = packet or decision.packet
    if decision.allowed:
        mark = f"{C.GREEN}ALLOW{C.RESET}"
    else:
        mark = f"{C.RED}DENY {C.RESET}"
    print(f"{indent}{mark} {packet.summary():<52} {C.GREY}{decision.reason}{C.RESET}")


def print_trace(decision, width: int = 62) -> None:
    """Paketin kural kural izini yazdirir (flood/stateful asamalari dahil)."""
    for step in decision.trace:
        if "index" not in step:
            print(f"  {C.YELLOW}◆ {step['text']}{C.RESET}")
            continue
        mark = f"{C.GREEN}EŞLEŞTİ{C.RESET}" if step["matched"] else f"{C.GREY}atlandı{C.RESET}"
        print(f"  #{step['index'] + 1} {step['text']:<{width}} {mark}")
        if step["mismatches"]:
            print(f"      {C.GREY}neden: {', '.join(step['mismatches'])}{C.RESET}")


def pause(seconds: float = 0.45) -> None:
    if sys.stdout.isatty():
        time.sleep(seconds)


def print_lint(findings: list[dict]) -> None:
    if not findings:
        print(f"  {C.GREEN}✔ Kural listesinde sorun bulunamadı.{C.RESET}")
        return
    colors = {"error": C.RED, "warn": C.YELLOW, "info": C.CYAN}
    names = {"error": "HATA ", "warn": "UYARI", "info": "BİLGİ"}
    for item in findings:
        color = colors.get(item["level"], C.GREY)
        print(f"  {color}{C.BOLD}{names.get(item['level'], '?')}{C.RESET} {item['message']}")


class Stepper:
    """Sunum modu: `--step` ile her bolum arasinda Enter bekler."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled and sys.stdin.isatty()

    def wait(self, label: str = "devam") -> None:
        if not self.enabled:
            pause(0.6)
            return
        try:
            input(f"\n  {C.GREY}⏎ {label}{C.RESET}")
        except (EOFError, KeyboardInterrupt):
            print()
            raise SystemExit(0)


# ---------------------------------------------------------------------- #
# demo
# ---------------------------------------------------------------------- #
def run_demo(step: bool = False) -> int:
    stepper = Stepper(step)
    print(f"{C.BOLD}{C.MAGENTA}MiniFirewall Lab - terminal demosu{C.RESET}")
    print(f"{C.GREY}Aynı motor, aynı kurallar. Sadece arayüz yok.{C.RESET}")
    stepper.wait("başla")

    # 1) Acik firewall -------------------------------------------------- #
    title("1) Varsayılan politika ALLOW - her şey geçiyor")
    fw = scenarios.build("allowall")
    bullet("Kural yok, varsayılan politika ALLOW. Filtreleme yok gibi.")
    pause()
    scan = traffic.port_scan(random.Random(7), count=24)
    for packet in scan[:6]:
        verdict_line(fw.evaluate(packet))
    print(f"  {C.GREY}... (toplam {len(scan)} paket){C.RESET}")
    allowed = sum(1 for p in scan if fw.evaluate(p).allowed)
    print(f"  Sonuç: {C.RED}{allowed}/{len(scan)} paket geçti{C.RESET}")
    stepper.wait("sıradaki: implicit deny")

    # 2) Implicit deny -------------------------------------------------- #
    title("2) Aynı saldırı, varsayılan politika DENY (implicit deny)")
    fw = scenarios.build("web")
    bullet("Sadece 80/443/53 ve uygulama→DB açık. Geri kalan her şey kapalı.")
    pause()
    decisions = [fw.evaluate(p) for p in scan]
    blocked = sum(1 for d in decisions if not d.allowed)
    print(f"  {C.GREEN}{blocked}/{len(scan)} paket engellendi{C.RESET}")
    for decision in decisions:
        if decision.allowed:
            verdict_line(decision)
    print(f"  {C.GREY}(sadece izin verilenler gösterildi){C.RESET}")
    stepper.wait("sıradaki: tek paketin izi")

    # 3) Tek paket, kural kural ----------------------------------------- #
    title("3) Tek paket: kural kural iz sürme")
    fw = scenarios.build("web")
    packet = Packet(
        src_ip=traffic.ATTACKER, dst_ip=traffic.SSH,
        protocol="tcp", src_port=51234, dst_port=22, flags="SYN",
    )
    print(f"  Paket: {C.BOLD}{packet.summary()}{C.RESET}\n")
    decision = fw.evaluate(packet)
    print_trace(decision)
    print()
    verdict_line(decision)
    stepper.wait("sıradaki: IP tabanlı kural")

    # 4) IP tabanli kural ------------------------------------------------ #
    title("4) Aynı port, farklı kaynak IP")
    fw = scenarios.build("bastion")
    office = Packet(src_ip="203.0.113.9", dst_ip=traffic.SSH, protocol="tcp",
                    src_port=40000, dst_port=22, flags="SYN")
    attacker = Packet(src_ip=traffic.ATTACKER, dst_ip=traffic.SSH, protocol="tcp",
                      src_port=40001, dst_port=22, flags="SYN")
    print(f"  {C.GREY}Kural: allow tcp 203.0.113.0/24 any 10.0.0.20 22{C.RESET}")
    verdict_line(fw.evaluate(office))
    verdict_line(fw.evaluate(attacker))
    stepper.wait("sıradaki: stateful")

    # 5) Stateful -------------------------------------------------------- #
    title("5) Stateful inspection: dönüş paketi kural olmadan geçer")
    fw = scenarios.build("stateful")
    out = Packet(src_ip="10.0.0.42", dst_ip="93.184.216.34", protocol="tcp",
                 src_port=51515, dst_port=443, flags="SYN")
    reply = Packet(src_ip="93.184.216.34", dst_ip="10.0.0.42", protocol="tcp",
                   src_port=443, dst_port=51515, flags="SYN ACK")
    print(f"  {C.GREY}Kural: allow tcp 10.0.0.0/24 any any 443 (sadece çıkış){C.RESET}")
    print(f"  {C.GREY}Önce dönüş paketi, oturum YOKKEN:{C.RESET}")
    verdict_line(fw.evaluate(reply))
    print(f"  {C.GREY}İç ağ bağlantıyı başlatıyor:{C.RESET}")
    verdict_line(fw.evaluate(out))
    print(f"  {C.GREY}Aynı dönüş paketi, şimdi oturum VAR:{C.RESET}")
    verdict_line(fw.evaluate(reply))
    stepper.wait("sıradaki: kural sırası tuzağı")

    # 6) Kural sirasi ---------------------------------------------------- #
    title("6) Kural SIRASI güvenliği belirler (first match wins)")
    fw = scenarios.build("messy")
    ssh = Packet(src_ip=traffic.ATTACKER, dst_ip=traffic.SSH, protocol="tcp",
                 src_port=40100, dst_port=22, flags="SYN")
    bullet("Yöneticinin niyeti: SSH dışarıdan kapalı olsun. Kurallar:")
    for i, rule in enumerate(fw.rules, start=1):
        print(f"    {C.GREY}#{i}{C.RESET} {rule.to_text()}")
    print()
    verdict_line(fw.evaluate(ssh))
    print(f"\n  {C.YELLOW}Lint (statik analiz) ne diyor?{C.RESET}")
    print_lint(lint_rules(fw.rules, fw.default_policy))
    print(f"\n  {C.GREY}Çözüm: geniş kuralı sil / yasağı en üste taşı.{C.RESET}")
    fixed = Firewall(
        rules=[fw.rules[1], fw.rules[2]],
        default_policy="deny",
    )
    verdict_line(fixed.evaluate(ssh))
    stepper.wait("sıradaki: flood guard")

    # 7) Flood guard ----------------------------------------------------- #
    title("7) Flood guard: kaynak başına hız sınırı")
    fw = scenarios.build("flood")
    flood = traffic.syn_flood(random.Random(3), count=150)
    bullet(f"Tek kaynaktan {len(flood)} SYN paketi, limit saniyede {fw.flood_limit}:")
    results = [fw.evaluate(p) for p in flood]
    passed = sum(1 for d in results if d.allowed)
    print(f"  {C.GREEN}{passed} geçti{C.RESET}, {C.RED}{len(results) - passed} kesildi{C.RESET}")
    verdict_line(next(d for d in results if not d.allowed))
    fw = scenarios.build("flood")
    botnet = traffic.ddos(random.Random(3), count=160)
    bullet(f"Şimdi {len(botnet)} paket ama HER BİRİ farklı kaynaktan (botnet):")
    results = [fw.evaluate(p) for p in botnet]
    passed = sum(1 for d in results if d.allowed)
    print(f"  {C.RED}{passed}/{len(results)} paket geçti{C.RESET}  "
          f"{C.GREY}→ kaynak başına limit dağıtık saldırıyı durduramaz.{C.RESET}")
    stepper.wait("özet")

    # 8) Ozet ------------------------------------------------------------ #
    title("Özet")
    print("  İlk eşleşen kural kazanır; eşleşme yoksa varsayılan politika.")
    print("  'deny' varsayılan = implicit deny: açıkça izin verilmeyen kapalı.")
    print("  IP / port / protokol alanları bağımsız eşleşir; CIDR ve aralık destekli.")
    print("  Stateful: oturum hatırlanır. Flood guard: kaynak başına hız sınırı.")
    print(f"\n  {C.CYAN}Şimdi arayüze:{C.RESET} python3 run.py serve")
    return 0


# ---------------------------------------------------------------------- #
# trace
# ---------------------------------------------------------------------- #
def run_trace(args) -> int:
    fw = scenarios.build(args.scenario)
    packet = Packet(
        src_ip=args.src, dst_ip=args.dst, protocol=args.proto,
        src_port=args.sport, dst_port=args.dport, flags=args.flags,
    )
    print(f"\n  Paket: {C.BOLD}{packet.summary()}{C.RESET}")
    print(f"  Politika: {fw.default_policy.upper()}  |  Stateful: {fw.stateful}\n")
    decision = fw.evaluate(packet)
    print_trace(decision, width=64)
    print()
    verdict_line(decision)
    return 0


# ---------------------------------------------------------------------- #
# lint / iptables
# ---------------------------------------------------------------------- #
def _firewall_from_args(args) -> Firewall:
    fw = scenarios.build(args.scenario)
    if getattr(args, "rules", None):
        lines = Path(args.rules).read_text(encoding="utf-8").splitlines()
        fw.set_rules([Rule.from_text(line) for line in lines if line.strip() and not line.strip().startswith("#")])
    return fw


def run_lint(args) -> int:
    fw = _firewall_from_args(args)
    title(f"Kural analizi: {args.scenario}")
    for i, rule in enumerate(fw.rules, start=1):
        print(f"  {C.GREY}#{i}{C.RESET} {rule.to_text()}")
    print()
    findings = lint_rules(fw.rules, fw.default_policy)
    print_lint(findings)
    return 1 if any(f["level"] == "error" for f in findings) else 0


def run_iptables(args) -> int:
    fw = _firewall_from_args(args)
    print(to_iptables(fw), end="")
    return 0


# ---------------------------------------------------------------------- #
# pcap
# ---------------------------------------------------------------------- #
def run_pcap(args) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"{C.RED}Dosya bulunamadı: {path}{C.RESET}")
        return 2

    result = read_pcap(str(path))
    fw = _firewall_from_args(args)

    title(f"PCAP analizi: {path.name}")
    print(
        f"  {len(result.packets)} paket okundu"
        + (f", {result.skipped} atlandı" if result.skipped else "")
        + f"  |  senaryo: {args.scenario}"
    )
    print(
        f"  {C.GREY}{'ZAMAN':<10} {'KARAR':<6} {'PROTO':<5} "
        f"{'KAYNAK':<24} {'HEDEF':<24} GEREKÇE{C.RESET}"
    )

    allowed = denied = 0
    for packet in result.packets:
        decision = fw.evaluate(packet)
        if decision.allowed:
            allowed += 1
            mark = f"{C.GREEN}ALLOW{C.RESET}"
        else:
            denied += 1
            mark = f"{C.RED}DENY {C.RESET}"
        stamp = time.strftime("%H:%M:%S", time.localtime(packet.ts))
        src = packet.source()[:24]
        dst = packet.destination()[:24]
        reason = decision.reason
        if len(reason) > 58:
            reason = reason[:55] + "..."
        print(
            f"  {stamp:<10} {mark} {packet.protocol.upper():<5} "
            f"{src:<24} {dst:<24} {C.GREY}{reason}{C.RESET}"
        )
        if args.slow:
            time.sleep(args.slow)

    total = allowed + denied
    rate = (denied / total * 100) if total else 0
    title("Özet")
    print(f"  Toplam {total}  |  {C.GREEN}izin {allowed}{C.RESET}  |  "
          f"{C.RED}engel {denied}{C.RESET}  |  engel oranı %{rate:.0f}")
    stats = fw.stats()
    for proto, data in stats["by_proto"].items():
        if data["allowed"] or data["denied"]:
            print(f"  {proto.upper():<5} izin {data['allowed']:<4} engel {data['denied']}")
    for warning in result.warnings:
        print(f"  {C.YELLOW}uyarı: {warning}{C.RESET}")
    return 0


# ---------------------------------------------------------------------- #
# argparse
# ---------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    # Kolaylik: "python3 run.py --port 9000" -> "serve --port 9000"
    if raw and raw[0].startswith("-") and raw[0] not in ("-h", "--help"):
        raw.insert(0, "serve")

    parser = argparse.ArgumentParser(
        prog="minifirewall",
        description="MiniFirewall Lab - IP/port/protokol tabanlı paket filtreleme",
    )
    sub = parser.add_subparsers(dest="command")
    scenario_names = sorted(scenarios.SCENARIOS)

    demo = sub.add_parser("demo", help="terminalde hikayeli demo çalıştır")
    demo.add_argument("--step", action="store_true",
                      help="her bölüm arasında Enter bekle (sunum modu)")

    quiz = sub.add_parser("quiz", help="izleyicilerle ALLOW/DENY yarışması")
    quiz.add_argument("--auto", action="store_true",
                      help="tahmin sormadan tüm cevapları göster")

    serve_parser = sub.add_parser("serve", help="web arayüzünü başlat")
    serve_parser.add_argument("--port", type=int, default=8080)
    serve_parser.add_argument("--no-browser", action="store_true")
    serve_parser.add_argument("--scenario", default=None, choices=scenario_names)

    trace = sub.add_parser("trace", help="tek paketin kural izini göster")
    trace.add_argument("--src", default="198.51.100.66")
    trace.add_argument("--dst", default="10.0.0.20")
    trace.add_argument("--proto", default="tcp", choices=["tcp", "udp", "icmp"])
    trace.add_argument("--sport", type=int, default=51234)
    trace.add_argument("--dport", type=int, default=22)
    trace.add_argument("--flags", default="SYN")
    trace.add_argument("--scenario", default=scenarios.DEFAULT_SCENARIO, choices=scenario_names)

    pcap = sub.add_parser("pcap", help="bir .pcap dosyasını kurallardan geçir")
    pcap.add_argument("file")
    pcap.add_argument("--scenario", default=scenarios.DEFAULT_SCENARIO, choices=scenario_names)
    pcap.add_argument("--rules", default=None, help="kural dosyası (satır başına bir kural)")
    pcap.add_argument("--slow", type=float, default=0.0,
                      help="her paket arasında saniye bekle (canlı akış efekti)")

    lint = sub.add_parser("lint", help="kural listesindeki hataları (gölgeleme vb.) bul")
    lint.add_argument("--scenario", default="messy", choices=scenario_names)
    lint.add_argument("--rules", default=None, help="kural dosyası (satır başına bir kural)")

    ipt = sub.add_parser("iptables", help="kuralları gerçek iptables komutlarına çevir")
    ipt.add_argument("--scenario", default=scenarios.DEFAULT_SCENARIO, choices=scenario_names)
    ipt.add_argument("--rules", default=None, help="kural dosyası (satır başına bir kural)")

    args = parser.parse_args(raw)

    if args.command in (None, "serve"):
        from .server import serve
        serve(
            port=getattr(args, "port", 8080),
            open_browser=not getattr(args, "no_browser", False),
            scenario=getattr(args, "scenario", None),
        )
        return 0
    if args.command == "demo":
        return run_demo(step=args.step)
    if args.command == "quiz":
        from .quiz import run_quiz
        return run_quiz(auto=args.auto, c=C, pause=pause)
    if args.command == "trace":
        return run_trace(args)
    if args.command == "pcap":
        return run_pcap(args)
    if args.command == "lint":
        return run_lint(args)
    if args.command == "iptables":
        return run_iptables(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
