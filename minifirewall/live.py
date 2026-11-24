"""Iki terminalli canli client/server demosu.

    python3 run.py live-server                  # sunucu konsolu (bos kurallarla baslar)
    python3 run.py live-server --scenario web    # haziz bir senaryoyla baslar
    python3 run.py live-client                  # istemci konsolu (ayri bir terminalde)

Sunucu terminali bir `Firewall` orneginini barindirir, TCP uzerinden gelen
paketleri degerlendirip ALLOW/DENY kararini canli basar; sunum sirasinda
konsoldan kural ekleyip/degistirip ayni anda etkisini gorebilirsin.
Istemci terminali tekil paket gonderir ya da `traffic.py`'deki hazir
saldiri paternlerini (`burst`) tetikler.

Iletisim, satir-bazli JSON (NDJSON) ile duz bir TCP soketi uzerinden
yapilir -- gercek bir ag protokolu degil, sadece iki surecin ayni
`Firewall` kararini paylasmasini saglayan basit bir tasima katmani.

Onemli: bu modul `cli.py`'yi import ETMEZ (dongusellik olmasin diye,
`quiz.py`'nin zaten kullandigi desenle ayni). Renkli yazdirma icin `c`
parametresi disaridan (cli.py'den ya da `_default_colors()` ile kendi
icinden) enjekte edilir.
"""

from __future__ import annotations

import json
import os
import random
import socket
import sys
import threading
import time

from . import scenarios, traffic
from .engine import Firewall
from .packet import Packet
from .rules import Rule

# ---------------------------------------------------------------------- #
# Tel protokolu: satir-bazli JSON (NDJSON)
# ---------------------------------------------------------------------- #
class LiveProtocolError(Exception):
    """Soketten gelen bir satir gecerli bir JSON nesnesi degil."""


def encode_message(msg: dict) -> bytes:
    return (json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8")


def iter_messages(sock_file):
    """`sock_file` (satir-bazli, metin modunda dosya benzeri nesne) uzerinden
    gelen her satiri JSON olarak coz, dict olarak yield et.

    Bos satirlar atlanir. EOF'ta durur. Gecersiz JSON/obje olmayan satir
    icin `LiveProtocolError` firlatir -- cagiran taraf bunu yakalayip o
    baglantiyi temiz bir mesajla kapatabilir, surec cokmez.
    """
    for line in sock_file:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LiveProtocolError(f"Geçersiz JSON satırı: {exc}") from exc
        if not isinstance(msg, dict):
            raise LiveProtocolError("Mesaj bir JSON nesnesi (obje) olmalı")
        yield msg


# ---------------------------------------------------------------------- #
# Renkler (cli.C ile ayni ad/arayuz, ama bagimsiz -- dongusellik olmasin)
# ---------------------------------------------------------------------- #
class _Colors:
    def __init__(self, use_color: bool) -> None:
        self.RESET = "\033[0m" if use_color else ""
        self.BOLD = "\033[1m" if use_color else ""
        self.DIM = "\033[2m" if use_color else ""
        self.RED = "\033[91m" if use_color else ""
        self.GREEN = "\033[92m" if use_color else ""
        self.YELLOW = "\033[93m" if use_color else ""
        self.BLUE = "\033[94m" if use_color else ""
        self.MAGENTA = "\033[95m" if use_color else ""
        self.CYAN = "\033[96m" if use_color else ""
        self.GREY = "\033[90m" if use_color else ""


def _default_colors() -> _Colors:
    use_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    return _Colors(bool(use_color))


def enable_windows_ansi() -> None:
    """Windows'ta eski `cmd.exe` icin ANSI/VT100 isleme ac (best-effort).

    Modern Windows Terminal / PowerShell 7 zaten destekliyor; bu sadece
    klasik cmd.exe icin gerekli. Her turlu hatada sessizce vazgecer,
    hicbir platformda cokmez."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


def _verdict_text(c, label: str, allowed: bool, reason: str) -> str:
    mark = f"{c.GREEN}ALLOW{c.RESET}" if allowed else f"{c.RED}DENY {c.RESET}"
    return f"{label:<58} {mark} {c.GREY}{reason}{c.RESET}"


# ---------------------------------------------------------------------- #
# Sunucu
# ---------------------------------------------------------------------- #
class LiveServer:
    """TCP uzerinden NDJSON konusan, paylasilan bir `Firewall`'u degerlendiren
    canli sunucu.

    `fw.lock` (Firewall'un kendi RLock'u) motor durumunun (kurallar,
    politika, istatistikler) es zamanli erisimini zaten koruyor -- burada
    AYRICA bir motor kilidi eklenmez. `print_lock` tamamen farkli bir
    sorumluluk tasir: konsol komut dongusu (ana thread) ile baglanti
    thread'lerinin stdout'a ayni anda yazip birbirine karismasini onler.
    Bu ikisini birbirine karistirma.
    """

    def __init__(
        self,
        fw: Firewall,
        host: str,
        port: int,
        c,
        print_lock: threading.Lock | None = None,
    ) -> None:
        self.fw = fw
        self.host = host
        self.port = port
        self.c = c
        self.print_lock = print_lock or threading.Lock()
        self._server_sock: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        self._server_sock = sock
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    @property
    def bound_port(self) -> int:
        if self._server_sock is None:
            return self.port
        return self._server_sock.getsockname()[1]

    def stop(self) -> None:
        self._stop.set()
        if self._server_sock is not None:
            try:
                self._server_sock.close()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._server_sock.accept()  # type: ignore[union-attr]
            except OSError:
                break  # stop() cagrildi, dinleyici soket kapatildi
            threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()

    def _handle_client(self, conn: socket.socket, addr) -> None:
        peer = f"{addr[0]}:{addr[1]}"
        with self.print_lock:
            print(f"{self.c.CYAN}[+] istemci bağlandı: {peer}{self.c.RESET}")
        sock_file = conn.makefile("r", encoding="utf-8", newline="\n")
        try:
            for msg in iter_messages(sock_file):
                mtype = msg.get("type")
                if mtype == "bye":
                    break
                if mtype != "packet":
                    continue
                try:
                    packet = Packet.from_dict(msg.get("packet", {}))
                except ValueError as exc:
                    conn.sendall(encode_message({"type": "error", "message": str(exc)}))
                    continue
                decision = self.fw.evaluate(packet)
                with self.print_lock:
                    label = f"{peer}  {packet.summary()}"
                    print(f"  {_verdict_text(self.c, label, decision.allowed, decision.reason)}")
                conn.sendall(
                    encode_message(
                        {
                            "type": "decision",
                            "packet": packet.to_dict(),
                            "decision": decision.to_dict(),
                        }
                    )
                )
        except (LiveProtocolError, OSError, ConnectionResetError) as exc:
            with self.print_lock:
                print(f"{self.c.YELLOW}[!] {peer} bağlantısı koptu: {exc}{self.c.RESET}")
        finally:
            with self.print_lock:
                print(f"{self.c.GREY}[-] istemci ayrıldı: {peer}{self.c.RESET}")
            try:
                conn.close()
            except OSError:
                pass


HELP_SERVER = """Komutlar:
  list                     kuralları listele
  add <kural metni>        yeni kural ekle (ör: add allow tcp any any 10.0.0.10 443)
  del <no>                 kuralı sil
  enable <no> / disable <no>
  policy allow|deny        varsayılan politika
  stateful on|off
  flood <limit>|off        kaynak başına saniyede paket sınırı
  help
  quit"""


def _print_rules(fw: Firewall, c) -> None:
    with fw.lock:
        if not fw.rules:
            print(f"  {c.GREY}(hiç kural yok — varsayılan politika: {fw.default_policy.upper()}){c.RESET}")
            return
        for i, rule in enumerate(fw.rules, start=1):
            state = "" if rule.enabled else f"  {c.GREY}(devre dışı){c.RESET}"
            print(f"  {c.GREY}#{i}{c.RESET} {rule.to_text()}  {c.CYAN}hits={rule.hits}{c.RESET}{state}")


def run_server_console(fw: Firewall, print_lock: threading.Lock, c) -> None:
    with print_lock:
        print(HELP_SERVER)
    while True:
        try:
            line = input(f"{c.BOLD}server>{c.RESET} ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        line = line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        rest = parts[1].strip() if len(parts) > 1 else ""
        try:
            if cmd == "help":
                print(HELP_SERVER)
            elif cmd == "list":
                _print_rules(fw, c)
            elif cmd == "add":
                if not rest:
                    raise ValueError("kullanım: add <kural metni>")
                rule = Rule.from_text(rest)
                fw.add_rule(rule)
                print(f"  {c.GREEN}eklendi:{c.RESET} #{len(fw.rules)} {rule.to_text()}")
            elif cmd == "del":
                if not rest:
                    raise ValueError("kullanım: del <no>")
                idx = int(rest) - 1
                with fw.lock:
                    removed = fw.rules.pop(idx)
                print(f"  {c.YELLOW}silindi:{c.RESET} {removed.to_text()}")
            elif cmd in ("enable", "disable"):
                if not rest:
                    raise ValueError(f"kullanım: {cmd} <no>")
                idx = int(rest) - 1
                with fw.lock:
                    fw.rules[idx].enabled = cmd == "enable"
                print(f"  #{idx + 1} -> {cmd}")
            elif cmd == "policy":
                with fw.lock:
                    fw.default_policy = Firewall._norm_policy(rest)
                print(f"  varsayılan politika: {fw.default_policy.upper()}")
            elif cmd == "stateful":
                value = rest.lower()
                if value not in ("on", "off"):
                    raise ValueError("kullanım: stateful on|off")
                with fw.lock:
                    fw.stateful = value == "on"
                    if not fw.stateful:
                        fw.clear_state()
                print(f"  stateful: {'açık' if fw.stateful else 'kapalı'}")
            elif cmd == "flood":
                value = rest.lower()
                if value in ("off", ""):
                    fw.set_flood_limit(None)
                    print("  flood guard kapalı")
                else:
                    fw.set_flood_limit(int(value))
                    print(f"  flood guard: saniyede {value} paket")
            elif cmd in ("quit", "exit"):
                print("  kapatılıyor...")
                break
            else:
                print(f"  {c.YELLOW}bilinmeyen komut: {cmd} (help yaz){c.RESET}")
        except (ValueError, IndexError) as exc:
            print(f"  {c.RED}hata: {exc}{c.RESET}")


def run_live_server(args, c=None) -> int:
    enable_windows_ansi()
    c = c or _default_colors()

    if getattr(args, "scenario", None):
        fw = scenarios.build(args.scenario)
        origin = f"senaryo: {args.scenario}"
    else:
        fw = Firewall(default_policy=getattr(args, "policy", "deny"))
        origin = f"boş, varsayılan politika {fw.default_policy.upper()}"

    server = LiveServer(fw, args.host, args.port, c)
    try:
        server.start()
    except OSError as exc:
        print(f"{c.RED}Sunucu başlatılamadı ({args.host}:{args.port}): {exc}{c.RESET}")
        return 2

    print(f"{c.BOLD}{c.MAGENTA}MiniFirewall Lab — canlı sunucu{c.RESET}")
    print(f"{c.GREY}dinleniyor: {args.host}:{server.bound_port}  |  {origin}{c.RESET}")
    try:
        run_server_console(fw, server.print_lock, c)
    finally:
        server.stop()
    return 0


# ---------------------------------------------------------------------- #
# Istemci
# ---------------------------------------------------------------------- #
class LiveClientError(Exception):
    """Istemci tarafinda baglanti/protokol hatasi -- traceback yerine
    dostca bir mesajla yakalanmasi beklenir."""


class LiveClient:
    def __init__(self, host: str, port: int, c, slow: float = 0.0) -> None:
        self.host = host
        self.port = port
        self.c = c
        self.slow = slow
        self.sock: socket.socket | None = None
        self._reader = None

    def connect(self, timeout: float = 3.0) -> None:
        try:
            sock = socket.create_connection((self.host, self.port), timeout=timeout)
        except (ConnectionRefusedError, TimeoutError, OSError) as exc:
            raise LiveClientError(
                f"Sunucuya bağlanılamadı ({self.host}:{self.port}): sunucu çalışıyor mu? ({exc})"
            ) from exc
        sock.settimeout(None)
        self.sock = sock
        self._reader = sock.makefile("r", encoding="utf-8", newline="\n")

    def send_packet(self, packet: Packet) -> dict:
        if self.sock is None:
            raise LiveClientError("bağlı değil")
        try:
            self.sock.sendall(encode_message({"type": "packet", "packet": packet.to_dict()}))
            msg = next(iter_messages(self._reader), None)
        except (OSError, LiveProtocolError) as exc:
            raise LiveClientError(f"sunucu ile iletişim koptu: {exc}") from exc
        if msg is None:
            raise LiveClientError("sunucu bağlantıyı kapattı")
        if msg.get("type") == "error":
            raise LiveClientError(msg.get("message", "sunucu hatası"))
        return msg

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.sendall(encode_message({"type": "bye"}))
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


HELP_CLIENT = """Komutlar:
  send <kaynak_ip> <hedef_ip> <proto> <hedef_port> [bayrak]
                           tek paket gönder (proto: tcp/udp/icmp)
  burst <tür>              hazır saldırı: portscan synflood ddos sshbrute dns ping db
  help
  quit"""


def _build_packet(parts: list[str]) -> Packet:
    if len(parts) < 4:
        raise ValueError("kullanım: send <kaynak_ip> <hedef_ip> <proto> <hedef_port> [bayrak]")
    src_ip, dst_ip, proto, dport = parts[:4]
    flags = parts[4] if len(parts) > 4 else ("SYN" if proto.lower() == "tcp" else "")
    return Packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=proto,
        src_port=random.randint(32768, 60999),
        dst_port=int(dport),
        flags=flags,
    )


def _send_and_print(client: LiveClient, packet: Packet, c) -> dict:
    reply = client.send_packet(packet)
    decision = reply["decision"]
    label = f"SENT  {packet.summary()}"
    print(f"  {_verdict_text(c, label, decision['allowed'], decision['reason'])}")
    return decision


def _run_burst(client: LiveClient, kind: str, c) -> None:
    if kind not in traffic.BURSTS:
        raise ValueError(f"bilinmeyen saldırı türü: {kind} ({', '.join(traffic.BURSTS)})")
    packets = traffic.make_burst(kind)
    allowed = 0
    for packet in packets:
        decision = _send_and_print(client, packet, c)
        if decision["allowed"]:
            allowed += 1
        if client.slow:
            time.sleep(client.slow)
    denied = len(packets) - allowed
    print(
        f"  {c.BOLD}özet:{c.RESET} {len(packets)} paket  "
        f"{c.GREEN}{allowed} geçti{c.RESET}  {c.RED}{denied} engellendi{c.RESET}"
    )


def run_client_console(client: LiveClient, c) -> None:
    print(HELP_CLIENT)
    while True:
        try:
            line = input(f"{c.BOLD}client>{c.RESET} ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        cmd = parts[0].lower()
        rest_args = parts[1:]
        try:
            if cmd == "help":
                print(HELP_CLIENT)
            elif cmd == "send":
                packet = _build_packet(rest_args)
                _send_and_print(client, packet, c)
            elif cmd == "burst":
                if not rest_args:
                    raise ValueError("kullanım: burst <portscan|synflood|ddos|sshbrute|dns|ping|db>")
                _run_burst(client, rest_args[0], c)
            elif cmd in ("quit", "exit"):
                print("  kapatılıyor...")
                break
            else:
                print(f"  {c.YELLOW}bilinmeyen komut: {cmd} (help yaz){c.RESET}")
        except LiveClientError as exc:
            print(f"  {c.RED}{exc}{c.RESET}")
            break  # baglanti koptuysa devam etmenin anlami yok
        except ValueError as exc:
            print(f"  {c.RED}hata: {exc}{c.RESET}")


def run_live_client(args, c=None) -> int:
    enable_windows_ansi()
    c = c or _default_colors()

    client = LiveClient(args.host, args.port, c, slow=getattr(args, "slow", 0.0))
    try:
        client.connect()
    except LiveClientError as exc:
        print(f"{c.RED}{exc}{c.RESET}")
        return 1

    print(f"{c.BOLD}{c.MAGENTA}MiniFirewall Lab — canlı istemci{c.RESET}")
    print(f"{c.GREY}bağlı: {args.host}:{args.port}{c.RESET}")
    try:
        run_client_console(client, c)
    finally:
        client.close()
    return 0
