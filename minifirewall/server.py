"""Mini HTTP sunucusu: arayuzu servis eder ve kural motorunu acar.

Harici bagimlilik yoktur; sadece Python standart kutuphanesi kullanilir.

    python3 run.py            # http://localhost:8080
    python3 run.py --port 9000 --no-browser

API:
    GET  /api/state                 kural listesi + istatistikler
    GET  /api/logs?since=N          N'den sonraki karar kayitlari
    GET  /api/source?file=engine.py kaynak kod (arayuzdeki kod goruntuleyici)
    POST /api/packet                tek paket gonder
    POST /api/burst                 saldiri dizisi gonder
    POST /api/rules                 kural listesini degistir
    POST /api/policy                varsayilan politikayi degistir
    POST /api/stateful              stateful modu ac/kapat
    POST /api/flood                 flood guard (hiz siniri) ac/kapat
    POST /api/scenario              hazir senaryo yukle
    POST /api/reset                 sayaclari sifirla
    GET  /portal | /admin | /db     GERCEK HTTP istegi (ayni motordan gecer)
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import scenarios, traffic
from .analysis import lint_rules
from .engine import FLOOD_DEFAULT, Firewall
from .export import to_iptables
from .packet import Packet
from .rules import Rule

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"
SRC_DIR = Path(__file__).resolve().parent

SOURCE_WHITELIST = {
    "engine.py",
    "rules.py",
    "packet.py",
    "analysis.py",
    "export.py",
    "pcap.py",
    "scenarios.py",
    "traffic.py",
    "quiz.py",
    "server.py",
    "cli.py",
    "run.py",
    "iptables.sh",  # dosya degil: o anki kurallardan canli uretilir
}

SERVICES = [
    {"ip": "10.0.0.10", "name": "Web", "ports": [80, 443], "color": "#22d3ee"},
    {"ip": "10.0.0.53", "name": "DNS", "ports": [53], "color": "#a78bfa"},
    {"ip": "10.0.0.20", "name": "SSH", "ports": [22], "color": "#fbbf24"},
    {"ip": "10.0.0.30", "name": "DB", "ports": [3306], "color": "#34d399"},
]

# Gercek HTTP istegi -> hangi servis paketi olarak degerlendirilecek?
REAL_ENDPOINTS = {
    "/portal": ("10.0.0.10", 80, "Web portali (HTTP)"),
    "/admin": ("10.0.0.20", 22, "Yonetim / SSH"),
    "/db": ("10.0.0.30", 3306, "Veritabani (MySQL)"),
}


class LabState:
    """Sunucunun paylastigi tek durum: firewall + aktif senaryo."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.scenario = scenarios.DEFAULT_SCENARIO
        self.fw: Firewall = scenarios.build(self.scenario)

    def load_scenario(self, name: str) -> None:
        with self.lock:
            self.fw = scenarios.build(name)
            self.scenario = name


LAB = LabState()


class Handler(BaseHTTPRequestHandler):
    server_version = "MiniFirewallLab/1.0"
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------------ #
    # Yardimcilar
    # ------------------------------------------------------------------ #
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        """Varsayilan erisim logunu kapat (terminal temiz kalsin)."""

    def _send(self, body: bytes, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, data, status: int = 200) -> None:
        self._send(
            json.dumps(data, ensure_ascii=False).encode("utf-8"),
            status=status,
            content_type="application/json; charset=utf-8",
        )

    def _error(self, message: str, status: int = 400) -> None:
        self._json({"error": message}, status=status)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Gecersiz JSON govdesi") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON govdesi bir nesne olmali")
        return data

    def _serve_static(self, path: str) -> None:
        rel = path.lstrip("/") or "index.html"
        target = (WEB_DIR / rel).resolve()
        if not str(target).startswith(str(WEB_DIR.resolve())) or not target.is_file():
            self._send(b"404 - Bulunamadi", 404, "text/plain; charset=utf-8")
            return
        ctype, _ = mimetypes.guess_type(str(target))
        if target.suffix in (".js", ".css"):
            ctype = f"{ctype}; charset=utf-8"
        self._send(target.read_bytes(), 200, ctype or "application/octet-stream")

    # ------------------------------------------------------------------ #
    # GET
    # ------------------------------------------------------------------ #
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        try:
            if path == "/api/state":
                self._json(self._state_payload())
            elif path == "/api/stats":
                self._json({"stats": LAB.fw.stats(), "last_seq": LAB.fw._seq})
            elif path == "/api/logs":
                since = int(query.get("since", ["0"])[0] or 0)
                logs = LAB.fw.logs_since(since)
                self._json({"logs": logs, "last_seq": LAB.fw._seq})
            elif path == "/api/source":
                name = query.get("file", ["engine.py"])[0]
                self._json(self._source_payload(name))
            elif path == "/favicon.ico":
                self._send(b"", 204, "image/x-icon")
            elif path in REAL_ENDPOINTS:
                self._real_request(path)
            elif path.startswith("/api/"):
                self._error("Bilinmeyen API ucu", 404)
            else:
                self._serve_static(path)
        except Exception as exc:  # arayuzu asla cokertme
            self._error(f"Sunucu hatasi: {exc}", 500)

    def _state_payload(self) -> dict:
        snapshot = LAB.fw.snapshot()
        snapshot.update(
            {
                "scenario": LAB.scenario,
                "scenarios": scenarios.scenario_catalog(),
                "bursts": traffic.burst_catalog(),
                "services": SERVICES,
                "source_files": sorted(SOURCE_WHITELIST),
                "flood_default": FLOOD_DEFAULT,
                "lint": lint_rules(LAB.fw.rules, LAB.fw.default_policy),
                "real_endpoints": [
                    {"path": p, "label": label}
                    for p, (_, _, label) in REAL_ENDPOINTS.items()
                ],
            }
        )
        return snapshot

    def _source_payload(self, name: str) -> dict:
        if name not in SOURCE_WHITELIST:
            raise ValueError(f"Kaynak dosyasi izinli degil: {name}")
        if name == "iptables.sh":
            return {"file": name, "code": to_iptables(LAB.fw)}
        target = (SRC_DIR / name) if name != "run.py" else (BASE_DIR / "run.py")
        if not target.is_file():
            raise ValueError(f"Dosya bulunamadi: {name}")
        return {"file": name, "code": target.read_text(encoding="utf-8")}

    def _real_request(self, path: str) -> None:
        """Tarayicidan gelen GERCEK istegi ayni kural motorundan gecirir."""
        dst_ip, dst_port, label = REAL_ENDPOINTS[path]
        packet = Packet(
            src_ip="127.0.0.1",
            dst_ip=dst_ip,
            protocol="tcp",
            src_port=50000 + (int(time.time() * 1000) % 10000),
            dst_port=dst_port,
            flags="SYN",
            size=74,
            payload=f"GET {path} HTTP/1.1",
        )
        decision = LAB.fw.evaluate(packet)
        self._send(
            _real_request_page(path, label, decision).encode("utf-8"),
            200,
            "text/html; charset=utf-8",
        )

    # ------------------------------------------------------------------ #
    # POST
    # ------------------------------------------------------------------ #
    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            body = self._read_json()

            if path == "/api/packet":
                packet = Packet.from_dict(body.get("packet", body))
                decision = LAB.fw.evaluate(packet)
                self._json(
                    {"decision": decision.to_dict(), "stats": LAB.fw.stats()}
                )

            elif path == "/api/burst":
                kind = str(body.get("kind", "portscan"))
                packets = traffic.make_burst(kind)
                decisions = [LAB.fw.evaluate(p) for p in packets]
                allowed = sum(1 for d in decisions if d.allowed)
                # Arayuz animasyonu icin ornekleme (log zaten tamamini tutar).
                step = max(1, len(decisions) // 120)
                sample = [d.to_dict() for d in decisions[::step]][:120]
                self._json(
                    {
                        "kind": kind,
                        "total": len(decisions),
                        "allowed": allowed,
                        "denied": len(decisions) - allowed,
                        "sample": sample,
                        "stats": LAB.fw.stats(),
                        "last_seq": LAB.fw._seq,
                    }
                )

            elif path == "/api/rules":
                raw_rules = body.get("rules", [])
                if not isinstance(raw_rules, list):
                    raise ValueError("'rules' bir liste olmali")
                rules = [Rule.from_dict(item) for item in raw_rules]
                LAB.fw.set_rules(rules)
                self._json(self._state_payload())

            elif path == "/api/policy":
                LAB.fw.default_policy = Firewall._norm_policy(
                    str(body.get("policy", "deny"))
                )
                self._json(self._state_payload())

            elif path == "/api/stateful":
                LAB.fw.stateful = bool(body.get("enabled", False))
                LAB.fw.clear_state()
                self._json(self._state_payload())

            elif path == "/api/flood":
                if body.get("enabled", False):
                    limit = int(body.get("limit") or FLOOD_DEFAULT)
                    if not 1 <= limit <= 10000:
                        raise ValueError("limit 1-10000 araliginda olmali")
                    LAB.fw.set_flood_limit(limit)
                else:
                    LAB.fw.set_flood_limit(None)
                self._json(self._state_payload())

            elif path == "/api/scenario":
                name = str(body.get("name", ""))
                LAB.load_scenario(name)
                self._json(self._state_payload())

            elif path == "/api/reset":
                LAB.fw.reset_counters()
                self._json(self._state_payload())

            else:
                self._error("Bilinmeyen API ucu", 404)

        except ValueError as exc:
            self._error(str(exc), 400)
        except Exception as exc:
            self._error(f"Sunucu hatasi: {exc}", 500)


# ---------------------------------------------------------------------- #
# Gercek istek sonuc sayfasi
# ---------------------------------------------------------------------- #
def _real_request_page(path: str, label: str, decision) -> str:
    ok = decision.allowed
    color = "#34d399" if ok else "#f87171"
    icon = "&#10003;" if ok else "&#10007;"
    title = "PAKET GECTI" if ok else "PAKET ENGELLENDI"
    rule = decision.rule.to_text() if decision.rule else "—"
    return f"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} - MiniFirewall Lab</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin:0; min-height:100vh; display:grid; place-items:center;
    background: radial-gradient(1000px 600px at 50% -10%, {color}22, transparent 60%), #070b12;
    color:#e6edf5; font-family: ui-sans-serif, system-ui, "Segoe UI", sans-serif;
  }}
  .card {{
    width:min(680px, 92vw); background:#0d1420cc; border:1px solid #1e2c40;
    border-radius:20px; padding:36px 38px; box-shadow:0 30px 80px #000a;
  }}
  .badge {{
    display:inline-flex; gap:10px; align-items:center; font-weight:700;
    color:{color}; letter-spacing:.12em; font-size:13px;
  }}
  .badge span {{ font-size:26px; line-height:1; }}
  h1 {{ font-size:clamp(26px,4vw,40px); margin:14px 0 6px; letter-spacing:-.02em; }}
  .sub {{ color:#8fa3bd; margin:0 0 26px; }}
  dl {{ display:grid; grid-template-columns:150px 1fr; gap:10px 18px; margin:0 0 26px; font-size:14.5px; }}
  dt {{ color:#7c8da6; }}
  dd {{ margin:0; font-family: ui-monospace, "JetBrains Mono", monospace; color:#dbe7f5; }}
  .reason {{
    background:#0a111c; border:1px solid #1e2c40; border-left:3px solid {color};
    border-radius:10px; padding:14px 16px; font-size:14px; color:#c9d7e8; line-height:1.55;
  }}
  .note {{ margin-top:22px; font-size:12.5px; color:#64748b; line-height:1.6; }}
  a {{ color:#22d3ee; text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  .back {{ display:inline-block; margin-top:22px; font-weight:600; }}
</style></head><body>
  <main class="card">
    <div class="badge"><span>{icon}</span> {title}</div>
    <h1>{label}</h1>
    <p class="sub">Bu istek gercekten sunucuya ulasti ve Python kural motorundan gecti.</p>
    <dl>
      <dt>Paket</dt><dd>{decision.packet.summary()}</dd>
      <dt>Kural</dt><dd>{rule}</dd>
      <dt>Gerekce</dt><dd style="font-family:inherit">{decision.reason}</dd>
      <dt>Karar</dt><dd style="color:{color}">{decision.action.upper()}</dd>
    </dl>
    <div class="reason">
      Bu sayfa bir tarayici istegi (HTTP) ile tetiklendi. Gercek bir isletim
      sistemi paketi yakalanmadi; istek, temsil ettigi paket olarak (kaynak
      127.0.0.1 &rarr; hedef {decision.packet.dst_ip}:{decision.packet.dst_port})
      ayni filtre motoruna verildi. Yani <b>karar motoru gercek</b>, paket
      temsili.
    </div>
    <p class="note">Simulasyona donup canli log'da bu istegi gorebilirsin.</p>
    <a class="back" href="/">&larr; MiniFirewall Lab</a>
  </main>
</body></html>"""


# ---------------------------------------------------------------------- #
# Baslatma
# ---------------------------------------------------------------------- #
BANNER = r"""
  __  __ _       __      _____ _                        _   _       _         _
 |  \/  (_)_ __ (_)    |  ___(_)_ __ _____      ____ _| | | |     | |   __ _| |__
 | |\/| | | '_ \| |    | |_  | | '__/ _ \ \ /\ / / _` | | | |     | |  / _` | '_ \
 | |  | | | | | | |    |  _| | | | |  __/\ V  V / (_| | | | |___  | |_| (_| | |_) |
 |_|  |_|_|_| |_|_|    |_|   |_|_|  \___| \_/\_/ \__,_|_| |_____|  |_|\__,_|_.__/
"""


def serve(port: int = 8080, open_browser: bool = True, scenario: str | None = None) -> None:
    if scenario:
        LAB.load_scenario(scenario)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    url = f"http://localhost:{port}"

    print(BANNER)
    print("  IP / PORT / PROTOKOL TABANLI PAKET FILTRELEME SIMULASYONU")
    print("  " + "-" * 62)
    print(f"  Arayuz      : {url}")
    print(f"  Senaryo     : {scenarios.SCENARIOS[LAB.scenario]['label']}")
    print(f"  Kural sayisi: {len(LAB.fw.rules)}")
    print("  Durdurmak   : Ctrl+C")
    print("  " + "-" * 62)
    print(f"  Gercek istek denemesi: {url}/portal  |  {url}/admin  |  {url}/db")
    print()

    if open_browser:
        def _open() -> None:
            time.sleep(0.6)
            try:
                webbrowser.open(url)
            except Exception:
                pass

        threading.Thread(target=_open, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Sunucu kapatiliyor...")
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MiniFirewall Lab sunucusu")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--scenario", default=None, choices=sorted(scenarios.SCENARIOS))
    args = parser.parse_args(argv)
    serve(args.port, not args.no_browser, args.scenario)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
