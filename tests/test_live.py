"""Canli client/server (live.py) testleri.   Calistirma:  python3 -m unittest discover -s tests -v"""

from __future__ import annotations

import io
import socket
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from minifirewall import scenarios  # noqa: E402
from minifirewall.engine import Firewall  # noqa: E402
from minifirewall.live import (  # noqa: E402
    LiveProtocolError,
    LiveServer,
    encode_message,
    iter_messages,
)
from minifirewall.packet import Packet  # noqa: E402
from minifirewall.rules import Rule  # noqa: E402


class _Silent:
    """Testlerde renk kodu uretmeyen, cli.C ile ayni arayuzu tasiyan sahte sinif."""

    RESET = BOLD = DIM = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = GREY = ""


def _start_server(fw: Firewall) -> LiveServer:
    server = LiveServer(fw, "127.0.0.1", 0, _Silent())
    server.start()
    return server


def _connect(server: LiveServer):
    sock = socket.create_connection(("127.0.0.1", server.bound_port), timeout=2)
    sock.settimeout(2)
    return sock, sock.makefile("r", encoding="utf-8", newline="\n")


class ProtocolRoundTrip(unittest.TestCase):
    def test_encode_decode_roundtrip(self):
        packet = Packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="tcp", dst_port=443, flags="SYN")
        raw = encode_message({"type": "packet", "packet": packet.to_dict()})
        self.assertTrue(raw.endswith(b"\n"))
        decoded = next(iter_messages(io.StringIO(raw.decode("utf-8"))))
        self.assertEqual(decoded["type"], "packet")
        self.assertEqual(decoded["packet"]["dst_port"], 443)

    def test_iter_messages_rejects_malformed_line(self):
        with self.assertRaises(LiveProtocolError):
            next(iter_messages(io.StringIO("bu bir json degil\n")))

    def test_iter_messages_skips_blank_lines(self):
        decoded = next(iter_messages(io.StringIO("\n\n" + '{"type": "bye"}\n')))
        self.assertEqual(decoded, {"type": "bye"})


class LiveServerLoopback(unittest.TestCase):
    def test_allowed_packet_over_socket(self):
        fw = scenarios.build("web")
        server = _start_server(fw)
        try:
            sock, reader = _connect(server)
            try:
                packet = Packet(
                    src_ip="198.51.100.66", dst_ip="10.0.0.10",
                    protocol="tcp", src_port=51234, dst_port=443, flags="SYN",
                )
                sock.sendall(encode_message({"type": "packet", "packet": packet.to_dict()}))
                reply = next(iter_messages(reader))
            finally:
                sock.close()
            self.assertEqual(reply["type"], "decision")
            self.assertTrue(reply["decision"]["allowed"])
        finally:
            server.stop()

    def test_rule_added_live_changes_decision(self):
        fw = Firewall(default_policy="deny")
        server = _start_server(fw)
        try:
            sock, reader = _connect(server)
            try:
                packet = Packet(
                    src_ip="198.51.100.66", dst_ip="10.0.0.20",
                    protocol="tcp", src_port=40000, dst_port=22, flags="SYN",
                )

                sock.sendall(encode_message({"type": "packet", "packet": packet.to_dict()}))
                first = next(iter_messages(reader))
                self.assertFalse(first["decision"]["allowed"])  # implicit deny

                fw.add_rule(Rule.from_text("allow tcp any any 10.0.0.20 22"))

                sock.sendall(encode_message({"type": "packet", "packet": packet.to_dict()}))
                second = next(iter_messages(reader))
                self.assertTrue(second["decision"]["allowed"])
            finally:
                sock.close()
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
