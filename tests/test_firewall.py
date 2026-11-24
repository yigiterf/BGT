"""MiniFirewall Lab testleri.   Calistirma:  python3 -m unittest discover -s tests -v"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from minifirewall import scenarios, traffic  # noqa: E402
from minifirewall.analysis import covers, lint_rules  # noqa: E402
from minifirewall.engine import Firewall  # noqa: E402
from minifirewall.export import to_iptables  # noqa: E402
from minifirewall.packet import Packet  # noqa: E402
from minifirewall.pcap import read_pcap, write_pcap  # noqa: E402
from minifirewall.rules import Rule, parse_ports  # noqa: E402


def tcp(src, dst, dport, sport=40000, flags="SYN"):
    return Packet(src_ip=src, dst_ip=dst, protocol="tcp", src_port=sport, dst_port=dport, flags=flags)


def udp(src, dst, dport, sport=40000):
    return Packet(src_ip=src, dst_ip=dst, protocol="udp", src_port=sport, dst_port=dport)


class RuleParsing(unittest.TestCase):
    def test_from_text_basic(self):
        r = Rule.from_text("allow tcp 10.0.0.0/24 1024-65535 10.0.0.30 3306 # db")
        self.assertEqual((r.action, r.protocol, r.dport, r.comment), ("allow", "tcp", "3306", "db"))

    def test_aliases(self):
        self.assertEqual(Rule.from_text("drop tcp any any any 22").action, "deny")
        self.assertEqual(Rule.from_text("accept udp any any any 53").action, "allow")

    def test_flags(self):
        r = Rule.from_text("allow tcp any any any 80 flags=SYN")
        self.assertEqual(r.flags, "SYN")

    def test_invalid_rules_raise(self):
        for bad in ("allow tcp any", "maybe tcp any any any 80", "allow tcp 999.1.1.1 any any 80",
                    "allow tcp any any any 70000", "allow tcp any any any 90-80"):
            with self.assertRaises(ValueError, msg=bad):
                Rule.from_text(bad)

    def test_port_list_and_range(self):
        self.assertEqual(parse_ports("80,443,1000-1010"), [(80, 80), (443, 443), (1000, 1010)])
        self.assertEqual(parse_ports("any"), [(0, 65535)])


class Matching(unittest.TestCase):
    def test_cidr_boundaries(self):
        r = Rule.from_text("allow tcp 203.0.113.0/24 any any 22")
        self.assertTrue(r.matches(tcp("203.0.113.0", "10.0.0.20", 22)))
        self.assertTrue(r.matches(tcp("203.0.113.255", "10.0.0.20", 22)))
        self.assertFalse(r.matches(tcp("203.0.114.0", "10.0.0.20", 22)))
        self.assertFalse(r.matches(tcp("203.0.112.255", "10.0.0.20", 22)))

    def test_port_range_edges(self):
        r = Rule.from_text("allow tcp any 1024-65535 any any")
        self.assertTrue(r.matches(tcp("1.1.1.1", "2.2.2.2", 80, sport=1024)))
        self.assertFalse(r.matches(tcp("1.1.1.1", "2.2.2.2", 80, sport=1023)))

    def test_protocol_must_match(self):
        r = Rule.from_text("allow udp any any any 53")
        self.assertTrue(r.matches(udp("1.1.1.1", "2.2.2.2", 53)))
        self.assertFalse(r.matches(tcp("1.1.1.1", "2.2.2.2", 53)))

    def test_protocol_any_still_checks_ports(self):
        """Eski surumde 'any' protokollu kuralin portu sessizce yok sayiliyordu."""
        r = Rule.from_text("allow any any any 10.0.0.10 443")
        self.assertTrue(r.matches(tcp("1.1.1.1", "10.0.0.10", 443)))
        self.assertTrue(r.matches(udp("1.1.1.1", "10.0.0.10", 443)))
        self.assertFalse(r.matches(tcp("1.1.1.1", "10.0.0.10", 22)))

    def test_icmp_ignores_ports(self):
        r = Rule.from_text("allow icmp any any any any")
        self.assertTrue(r.matches(Packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="icmp")))

    def test_flags_subset(self):
        r = Rule.from_text("allow tcp any any any 80 flags=SYN")
        self.assertTrue(r.matches(tcp("1.1.1.1", "2.2.2.2", 80, flags="SYN")))
        self.assertTrue(r.matches(tcp("1.1.1.1", "2.2.2.2", 80, flags="SYN ACK")))
        self.assertFalse(r.matches(tcp("1.1.1.1", "2.2.2.2", 80, flags="ACK")))


class EngineDecisions(unittest.TestCase):
    def test_first_match_wins(self):
        fw = Firewall([Rule.from_text("deny tcp any any any 22"),
                       Rule.from_text("allow tcp any any any 22")], default_policy="deny")
        d = fw.evaluate(tcp("1.1.1.1", "2.2.2.2", 22))
        self.assertFalse(d.allowed)
        self.assertEqual(d.rule_index, 0)

    def test_order_changes_outcome(self):
        a = Firewall([Rule.from_text("allow tcp any any any any"),
                      Rule.from_text("deny tcp any any any 22")])
        b = Firewall([Rule.from_text("deny tcp any any any 22"),
                      Rule.from_text("allow tcp any any any any")])
        p = tcp("1.1.1.1", "2.2.2.2", 22)
        self.assertTrue(a.evaluate(p).allowed)
        self.assertFalse(b.evaluate(p).allowed)

    def test_implicit_deny_and_open_policy(self):
        p = tcp("1.1.1.1", "2.2.2.2", 9999)
        self.assertFalse(Firewall([], "deny").evaluate(p).allowed)
        self.assertTrue(Firewall([], "allow").evaluate(p).allowed)

    def test_disabled_rule_is_skipped(self):
        rule = Rule.from_text("allow tcp any any any 80")
        rule.enabled = False
        self.assertFalse(Firewall([rule]).evaluate(tcp("1.1.1.1", "2.2.2.2", 80)).allowed)

    def test_counters_and_rule_hits(self):
        fw = scenarios.build("web")
        fw.evaluate(tcp("9.9.9.9", "10.0.0.10", 443))
        fw.evaluate(tcp("9.9.9.9", "10.0.0.10", 9))
        s = fw.stats()
        self.assertEqual((s["total"], s["allowed"], s["denied"]), (2, 1, 1))
        self.assertEqual(s["rule_hits"][1], 1)

    def test_trace_explains_mismatch(self):
        fw = scenarios.build("web")
        d = fw.evaluate(tcp("9.9.9.9", "10.0.0.20", 22))
        self.assertEqual(d.rule_index, 4)
        self.assertTrue(all(not t["matched"] for t in d.trace[:4]))
        self.assertTrue(d.trace[0]["mismatches"])

    def test_every_scenario_builds(self):
        for name in scenarios.SCENARIOS:
            self.assertIsInstance(scenarios.build(name), Firewall)


class Stateful(unittest.TestCase):
    def setUp(self):
        self.fw = scenarios.build("stateful")
        self.out = tcp("10.0.0.42", "93.184.216.34", 443, sport=51515)
        self.reply = tcp("93.184.216.34", "10.0.0.42", 51515, sport=443, flags="SYN ACK")

    def test_reply_without_session_denied(self):
        self.assertFalse(self.fw.evaluate(self.reply).allowed)

    def test_reply_after_session_allowed(self):
        self.assertTrue(self.fw.evaluate(self.out).allowed)
        d = self.fw.evaluate(self.reply)
        self.assertTrue(d.allowed)
        self.assertTrue(d.stateful)

    def test_stateless_mode_denies_reply(self):
        self.fw.stateful = False
        self.fw.evaluate(self.out)
        self.assertFalse(self.fw.evaluate(self.reply).allowed)

    def test_denied_packet_does_not_open_session(self):
        blocked = tcp("10.0.0.42", "93.184.216.34", 8080, sport=51516)
        self.assertFalse(self.fw.evaluate(blocked).allowed)
        back = tcp("93.184.216.34", "10.0.0.42", 51516, sport=8080)
        self.assertFalse(self.fw.evaluate(back).allowed)


class FloodGuard(unittest.TestCase):
    class Clock:
        def __init__(self):
            self.t = 1000.0

        def __call__(self):
            return self.t

    def make(self, limit=5):
        clock = self.Clock()
        fw = Firewall([Rule.from_text("allow tcp any any any 443")], flood_limit=limit, clock=clock)
        return fw, clock

    def test_limit_enforced_per_source(self):
        fw, _ = self.make(5)
        results = [fw.evaluate(tcp("6.6.6.6", "10.0.0.10", 443)).allowed for _ in range(20)]
        self.assertEqual(sum(results), 5)
        self.assertEqual(fw.flood_blocks, 15)

    def test_other_sources_unaffected(self):
        fw, _ = self.make(5)
        for _ in range(20):
            fw.evaluate(tcp("6.6.6.6", "10.0.0.10", 443))
        self.assertTrue(fw.evaluate(tcp("7.7.7.7", "10.0.0.10", 443)).allowed)

    def test_window_slides(self):
        fw, clock = self.make(5)
        for _ in range(10):
            fw.evaluate(tcp("6.6.6.6", "10.0.0.10", 443))
        clock.t += 1.5
        self.assertTrue(fw.evaluate(tcp("6.6.6.6", "10.0.0.10", 443)).allowed)

    def test_ddos_slips_through_per_source_limit(self):
        fw = scenarios.build("flood")
        import random
        results = [fw.evaluate(p).allowed for p in traffic.ddos(random.Random(1), 160)]
        self.assertGreater(sum(results), 150)

    def test_disabled_by_default(self):
        fw = Firewall([Rule.from_text("allow tcp any any any 443")])
        self.assertTrue(all(fw.evaluate(tcp("6.6.6.6", "10.0.0.10", 443)).allowed for _ in range(200)))


class Lint(unittest.TestCase):
    def kinds(self, lines, policy="deny"):
        return [(f["index"], f["kind"]) for f in lint_rules([Rule.from_text(l) for l in lines], policy)]

    def test_shadowed_deny_is_error(self):
        findings = lint_rules([Rule.from_text("allow tcp any any any any"),
                               Rule.from_text("deny tcp any any 10.0.0.20 22")])
        shadow = [f for f in findings if f["kind"] == "shadowed"]
        self.assertEqual(len(shadow), 1)
        self.assertEqual((shadow[0]["index"], shadow[0]["level"]), (1, "error"))

    def test_redundant_same_action(self):
        self.assertIn((1, "redundant"), self.kinds(["allow tcp any any any 80", "allow tcp any any 10.0.0.10 80"]))

    def test_specific_before_general_is_fine(self):
        kinds = self.kinds(["deny tcp any any 10.0.0.20 22", "allow tcp any any any any"])
        self.assertNotIn((1, "shadowed"), kinds)
        self.assertIn((1, "overlap"), kinds)

    def test_disjoint_rules_clean(self):
        self.assertEqual(self.kinds(["allow tcp any any 10.0.0.10 80", "allow tcp any any 10.0.0.10 443"]), [])

    def test_port_range_coverage(self):
        a, b = Rule.from_text("allow tcp any any any 1-1000"), Rule.from_text("allow tcp any any any 80,443")
        self.assertTrue(covers(a, b))
        self.assertFalse(covers(b, a))

    def test_cidr_coverage(self):
        a, b = Rule.from_text("allow tcp 10.0.0.0/16 any any 22"), Rule.from_text("allow tcp 10.0.5.0/24 any any 22")
        self.assertTrue(covers(a, b))
        self.assertFalse(covers(b, a))

    def test_default_allow_warns(self):
        self.assertIn((None, "policy"), self.kinds([], policy="allow"))

    def test_builtin_scenarios_clean_except_messy(self):
        for name, data in scenarios.SCENARIOS.items():
            fw = scenarios.build(name)
            errors = [f for f in lint_rules(fw.rules, fw.default_policy) if f["level"] == "error"]
            self.assertEqual(bool(errors), name == "messy", name)


class Export(unittest.TestCase):
    def test_iptables_output(self):
        text = to_iptables(scenarios.build("web"))
        self.assertIn("iptables -P FORWARD DROP", text)
        self.assertIn("-p tcp -d 10.0.0.10/32 --dport 443", text)
        self.assertIn("-j DROP", text)
        # yorum eklentisi hedeften once olmali
        for line in text.splitlines():
            if "--comment" in line:
                self.assertLess(line.index("--comment"), line.index("-j "))

    def test_stateful_and_flood_lines(self):
        fw = scenarios.build("stateful")
        self.assertIn("conntrack --ctstate ESTABLISHED,RELATED", to_iptables(fw))
        self.assertIn("hashlimit", to_iptables(scenarios.build("flood")))

    def test_any_protocol_with_port_expands_to_tcp_and_udp(self):
        fw = Firewall([Rule.from_text("allow any any any any 53")])
        text = to_iptables(fw)
        self.assertIn("-p tcp", text)
        self.assertIn("-p udp", text)


class PcapRoundTrip(unittest.TestCase):
    def test_write_then_read(self):
        packets = [tcp("1.1.1.1", "2.2.2.2", 80, flags="SYN"), udp("3.3.3.3", "4.4.4.4", 53),
                   Packet(src_ip="5.5.5.5", dst_ip="6.6.6.6", protocol="icmp")]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.pcap")
            write_pcap(path, packets)
            result = read_pcap(path)
        self.assertEqual(len(result.packets), 3)
        self.assertEqual(result.packets[0].flags, "SYN")
        self.assertEqual(result.packets[1].dst_port, 53)
        self.assertEqual(result.packets[2].protocol, "icmp")

    def test_demo_capture_reads(self):
        demo = Path(__file__).resolve().parent.parent / "demo" / "capture.pcap"
        self.assertGreater(len(read_pcap(str(demo)).packets), 10)

    def test_rejects_garbage(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.pcap")
            Path(path).write_bytes(b"not a pcap at all")
            with self.assertRaises(ValueError):
                read_pcap(path)


class PacketValidation(unittest.TestCase):
    def test_bad_input(self):
        with self.assertRaises(ValueError):
            Packet(src_ip="999.1.1.1", dst_ip="1.1.1.1")
        with self.assertRaises(ValueError):
            Packet(src_ip="1.1.1.1", dst_ip="1.1.1.1", dst_port=70000)
        with self.assertRaises(ValueError):
            Packet(src_ip="1.1.1.1", dst_ip="1.1.1.1", protocol="gre")

    def test_reply_helpers(self):
        a = tcp("1.1.1.1", "2.2.2.2", 80, sport=5000)
        b = tcp("2.2.2.2", "1.1.1.1", 5000, sport=80)
        self.assertTrue(b.is_reply_to(a))
        self.assertEqual(a.reverse_flow_key(), b.flow_key())


if __name__ == "__main__":
    unittest.main()
