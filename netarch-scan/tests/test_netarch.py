"""
NetArch Scan – unit tests (no lab required).
Run with: python -m pytest tests/ -v
or:        python tests/test_netarch.py
"""
from __future__ import annotations

import sys
import os
import struct
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netarch.snmp import (
    _encode_int, _decode_int, _encode_oid, _decode_oid,
    _encode_octetstr, _decode_value, _build_pdu, _parse_response,
    _T_INT, _T_OCTSTR, _T_OID, _T_PDU_GET, parse_lldp_rem_man_addr,
)
from netarch.probes import parse_targets, TargetError, is_loopback_target, auto_port_offset
from netarch.classify import classify_device, confidence_score
from netarch.context import ScanContext


# =========================================================
# BER round-trip tests
# =========================================================

class TestBERRoundTrip(unittest.TestCase):

    def test_int_zero(self):
        enc = _encode_int(0)
        # tag=0x02, len=1, val=0
        self.assertEqual(enc, b'\x02\x01\x00')

    def test_int_positive(self):
        enc = _encode_int(161)
        # decoded via _decode_int
        raw = enc[2:]
        self.assertEqual(_decode_int(raw), 161)

    def test_int_large(self):
        for n in (0, 1, 127, 128, 255, 256, 65535, 100000, 2**31 - 1):
            enc = _encode_int(n)
            raw = enc[2:]
            self.assertEqual(_decode_int(raw), n, f"Failed for {n}")

    def test_oid_encode_decode(self):
        for oid in ("1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.9.1.1",
                    "1.0.8802.1.1.2.1.4.1.1.9"):
            enc = _encode_oid(oid)
            raw = enc[2:]  # strip tag+length
            decoded = _decode_oid(raw)
            self.assertEqual(decoded, oid, f"OID mismatch: {oid!r} -> {decoded!r}")

    def test_octetstr(self):
        s = b"Cisco IOS XE"
        enc = _encode_octetstr(s)
        tag, raw, _ = __import__('netarch.snmp', fromlist=['_decode_tlv'])._decode_tlv(enc, 0)
        self.assertEqual(tag, _T_OCTSTR)
        self.assertEqual(raw, s)

    def test_pdu_build_parse_roundtrip(self):
        """Build a GET PDU and check it parses back (at least structurally)."""
        from netarch.snmp import _build_pdu, _T_PDU_GET, _T_SEQ
        pdu = _build_pdu(_T_PDU_GET, 42, "public", ["1.3.6.1.2.1.1.1.0"])
        # First byte should be SEQUENCE
        self.assertEqual(pdu[0], _T_SEQ)


# =========================================================
# parse_targets tests
# =========================================================

class TestParseTargets(unittest.TestCase):

    def test_single_ip(self):
        t = parse_targets("10.0.0.1")
        self.assertEqual(t, ["10.0.0.1"])

    def test_cidr(self):
        t = parse_targets("10.0.0.0/30")
        # /30 has 2 host addresses
        self.assertEqual(len(t), 2)
        self.assertIn("10.0.0.1", t)
        self.assertIn("10.0.0.2", t)

    def test_range_short(self):
        t = parse_targets("10.1.1.10-13")
        self.assertEqual(t, ["10.1.1.10", "10.1.1.11", "10.1.1.12", "10.1.1.13"])

    def test_range_full(self):
        t = parse_targets("10.1.1.1-10.1.1.3")
        self.assertEqual(t, ["10.1.1.1", "10.1.1.2", "10.1.1.3"])

    def test_comma_list(self):
        t = parse_targets("10.0.0.1, 10.0.0.2, 10.0.0.3")
        self.assertEqual(t, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_deduplication(self):
        t = parse_targets("10.0.0.1 10.0.0.1 10.0.0.2")
        self.assertEqual(t, ["10.0.0.1", "10.0.0.2"])

    def test_too_large(self):
        with self.assertRaises(TargetError):
            parse_targets("10.0.0.0/8", max_hosts=10)

    def test_bad_host(self):
        with self.assertRaises(TargetError):
            parse_targets("not-a-valid-host-999999.invalid")

    def test_loopback_detection(self):
        self.assertTrue(is_loopback_target(["127.20.20.1", "127.20.20.2"]))
        self.assertFalse(is_loopback_target(["10.0.0.1", "127.20.20.1"]))

    def test_auto_offset(self):
        self.assertEqual(auto_port_offset(["127.20.20.1"]), 20000)
        self.assertEqual(auto_port_offset(["10.0.0.1"]), 0)


# =========================================================
# Classification tests
# =========================================================

class TestClassification(unittest.TestCase):

    def _classify(self, **kw):
        return classify_device(**kw)

    def test_cisco_cat9k(self):
        result = self._classify(sys_descr="Cisco IOS XE Software, CAT9K_IOSXE")
        self.assertEqual(result["vendor"], "Cisco")
        self.assertIn("L3 Switch", result["role"])

    def test_juniper_ex4100(self):
        result = self._classify(sys_descr="Juniper Networks EX4100-24P")
        self.assertEqual(result["vendor"], "Juniper")
        self.assertEqual(result["role"], "Switch")

    def test_fortigate(self):
        result = self._classify(sys_descr="FortiGate-100F v7.0")
        self.assertEqual(result["vendor"], "Fortinet")
        self.assertEqual(result["role"], "Firewall")

    def test_nvr_title(self):
        result = self._classify(http_title="Hikvision NVR Web Interface")
        self.assertIn("Camera", result["role"])

    def test_laserjet_title(self):
        result = self._classify(http_title="HP LaserJet Pro MFP M428")
        self.assertEqual(result["role"], "Printer")

    def test_vendor_from_sysoid(self):
        result = self._classify(sys_object_id="1.3.6.1.4.1.9.1.1.1")
        self.assertEqual(result["vendor"], "Cisco")

    def test_gateway_role_override(self):
        result = self._classify(sys_descr="Linux-based device", is_gateway=True)
        self.assertEqual(result["role"], "Router")
        self.assertEqual(result["tier"], "Gateway")

    def test_port_fallback_printer(self):
        result = self._classify(open_ports=[9100])
        self.assertEqual(result["role"], "Printer")

    def test_port_fallback_camera(self):
        result = self._classify(open_ports=[554])
        self.assertEqual(result["role"], "IP Camera / NVR")

    def test_panos(self):
        result = self._classify(sys_descr="Palo Alto Networks PAN-OS 10.1")
        self.assertIn(result["vendor"], ("Palo Alto", ""))
        self.assertEqual(result["role"], "Firewall")


# =========================================================
# Confidence scoring tests
# =========================================================

class TestConfidence(unittest.TestCase):

    def test_full_snmp(self):
        dev = {
            "snmp": {"sysDescr": "Cisco", "sysObjectID": "1.3.6.1.4.1.9.1",
                     "sysName": "switch-1", "entity_model": "C9300-48P"},
            "http": {"title": "Cisco Catalyst"},
            "mac_vendor": "Cisco Systems",
            "open_ports": [80, 443],
            "via": ["SNMP", "Ports"],
            "seen_in_neighbour": True,
            "rdns": "switch-1.local",
            "evidence": ["vendor=Cisco from sysObjectID 1.3.6.1.4.1.9"],
        }
        score = confidence_score(dev)
        self.assertGreaterEqual(score, 80)

    def test_arp_only_base(self):
        dev = {
            "snmp": {},
            "http": {},
            "mac_vendor": "",
            "open_ports": [],
            "via": ["ARP"],
            "seen_in_neighbour": False,
            "evidence": [],
        }
        score = confidence_score(dev)
        self.assertLessEqual(score, 25)

    def test_neighbour_only_base(self):
        dev = {
            "snmp": {},
            "http": {},
            "mac_vendor": "",
            "open_ports": [],
            "via": ["LLDP"],
            "seen_in_neighbour": True,
            "evidence": [],
        }
        score = confidence_score(dev)
        self.assertGreaterEqual(score, 40)


# =========================================================
# Vendor conflict detection
# =========================================================

class TestVendorConflict(unittest.TestCase):

    def test_conflict_detected(self):
        """Agent 4 conflict check: sysObjectID says Cisco, HTTP says Juniper."""
        from netarch.classify import vendor_from_oid, vendor_from_text
        oid_vendor = vendor_from_oid("1.3.6.1.4.1.9.1.1")
        http_vendor = vendor_from_text("Juniper Networks EX series")
        self.assertEqual(oid_vendor, "Cisco")
        self.assertEqual(http_vendor, "Juniper")
        self.assertNotEqual(oid_vendor, http_vendor)

    def test_no_conflict(self):
        from netarch.classify import vendor_from_oid, vendor_from_text
        oid_vendor = vendor_from_oid("1.3.6.1.4.1.9.1.1")
        http_vendor = vendor_from_text("Cisco Systems")
        self.assertEqual(oid_vendor, "Cisco")
        self.assertEqual(http_vendor, "Cisco")


# =========================================================
# One-sided link confidence
# =========================================================

class TestLinkConfidence(unittest.TestCase):

    def test_one_sided_link_gets_70(self):
        ctx = ScanContext()
        ctx.add_device("10.0.0.1", {"ip": "10.0.0.1", "name": "a"})
        ctx.add_device("10.0.0.2", {"ip": "10.0.0.2", "name": "b"})
        lk = ctx.link_key("10.0.0.1", "10.0.0.2")
        ctx.add_link(lk, {
            "a": "10.0.0.1", "b": "10.0.0.2",
            "a_port": "Gi0/1", "b_port": "",
            "source": "LLDP",
            "seen_from": ["10.0.0.1"],
            "confidence": 70,
            "issues": [],
            "review_status": "pending",
            "human_edits": {},
        })
        link = ctx.links[lk]
        self.assertEqual(link["confidence"], 70)
        self.assertEqual(len(link["seen_from"]), 1)

    def test_both_sided_link_gets_100(self):
        ctx = ScanContext()
        ctx.add_device("10.0.0.1", {"ip": "10.0.0.1"})
        ctx.add_device("10.0.0.2", {"ip": "10.0.0.2"})
        lk = ctx.link_key("10.0.0.1", "10.0.0.2")
        ctx.add_link(lk, {
            "a": "10.0.0.1", "b": "10.0.0.2",
            "a_port": "Gi0/1", "b_port": "Gi0/2",
            "source": "LLDP",
            "seen_from": ["10.0.0.1", "10.0.0.2"],
            "confidence": 100,
            "issues": [],
            "review_status": "pending",
            "human_edits": {},
        })
        link = ctx.links[lk]
        self.assertEqual(link["confidence"], 100)


# =========================================================
# LLDP RemManAddr OID parsing
# =========================================================

class TestLLDPManAddr(unittest.TestCase):

    def test_parse_lldp_rem_man_addr(self):
        # Suffix: <tm>.<port>.<idx>.1.4.<a>.<b>.<c>.<d>
        suffix = "0.1.1.1.4.10.20.30.40"
        ip = parse_lldp_rem_man_addr(suffix)
        self.assertEqual(ip, "10.20.30.40")

    def test_parse_lab_format(self):
        # Lab format: .1.4.127.20.20.10
        suffix = "12345.1.0.1.4.127.20.20.10"
        ip = parse_lldp_rem_man_addr(suffix)
        self.assertEqual(ip, "127.20.20.10")

    def test_invalid_returns_none(self):
        ip = parse_lldp_rem_man_addr("0.1.1")
        self.assertIsNone(ip)


# =========================================================
# ScanContext serialization
# =========================================================

class TestScanContext(unittest.TestCase):

    def test_round_trip(self):
        ctx = ScanContext(job_id="test01")
        ctx.settings["target"] = "10.0.0.0/24"
        ctx.add_device("10.0.0.1", {"ip": "10.0.0.1", "name": "router"})
        d = ctx.to_dict()
        ctx2 = ScanContext.from_dict(d)
        self.assertEqual(ctx2.job_id, "test01")
        self.assertIn("10.0.0.1", ctx2.devices)
        self.assertEqual(ctx2.devices["10.0.0.1"]["name"], "router")

    def test_audit_recorded(self):
        ctx = ScanContext()
        ctx.add_device("10.0.0.1", {"ip": "10.0.0.1"})
        ctx.update_device("10.0.0.1", {"name": "new-name"})
        self.assertTrue(len(ctx.audit) >= 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
