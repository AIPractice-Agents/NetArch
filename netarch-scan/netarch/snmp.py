"""
SNMPv2c BER client – GET, GETNEXT, and OID-walk.
Pure Python, standard library only (socket + struct).
"""
from __future__ import annotations

import socket
import struct
import time
from typing import Dict, Iterator, List, Optional, Tuple

# ---------------------------------------------------------------------------
# ASN.1 / BER constants
# ---------------------------------------------------------------------------
_T_INT       = 0x02
_T_OCTSTR    = 0x04
_T_NULL      = 0x05
_T_OID       = 0x06
_T_SEQ       = 0x30
_T_IPADDR    = 0x40
_T_COUNTER32 = 0x41
_T_GAUGE32   = 0x42
_T_TIMETICKS = 0x43
_T_OPAQUE    = 0x44
_T_COUNTER64 = 0x46
_T_PDU_GET        = 0xA0
_T_PDU_GETNEXT    = 0xA1
_T_PDU_RESPONSE   = 0xA2

_SNMP_VERSION_2C = 1   # value "1" means v2c on the wire

# Well-known OIDs
OID_sysDescr     = "1.3.6.1.2.1.1.1.0"
OID_sysObjectID  = "1.3.6.1.2.1.1.2.0"
OID_sysName      = "1.3.6.1.2.1.1.5.0"
OID_sysServices  = "1.3.6.1.2.1.1.7.0"
OID_sysLocation  = "1.3.6.1.2.1.1.6.0"

# ENTITY-MIB entPhysicalModelName (entPhysicalTable .1.3.6.1.2.1.47.1.1.1.1.13)
OID_entPhysical_model_prefix = "1.3.6.1.2.1.47.1.1.1.1.13"

# LLDP-MIB
OID_lldpRemSysName    = "1.0.8802.1.1.2.1.4.1.1.9"
OID_lldpRemSysDesc    = "1.0.8802.1.1.2.1.4.1.1.10"
OID_lldpRemPortId     = "1.0.8802.1.1.2.1.4.1.1.7"
OID_lldpRemPortDesc   = "1.0.8802.1.1.2.1.4.1.1.8"
OID_lldpRemManAddr    = "1.0.8802.1.1.2.1.4.2.1.3"  # lldpRemManAddrIfId
OID_lldpLocPortId     = "1.0.8802.1.1.2.1.3.7.1.3"
OID_lldpLocPortDesc   = "1.0.8802.1.1.2.1.3.7.1.4"

# CDP (CISCO-CDP-MIB) – cdpCacheTable
OID_cdpCacheDeviceId  = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
OID_cdpCacheAddress   = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
OID_cdpCachePort      = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
OID_cdpCachePlatform  = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"
OID_ifName            = "1.3.6.1.2.1.31.1.1.1.1"


# ---------------------------------------------------------------------------
# BER encoding helpers
# ---------------------------------------------------------------------------

def _encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    enc = []
    while n:
        enc.append(n & 0xFF)
        n >>= 8
    enc.reverse()
    return bytes([0x80 | len(enc)] + enc)


def _encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_int(n: int) -> bytes:
    if n == 0:
        return _encode_tlv(_T_INT, b"\x00")
    neg = n < 0
    b: List[int] = []
    v = n if n > 0 else (-n - 1)
    while v:
        b.append(v & 0xFF)
        v >>= 8
    b.reverse()
    # sign extension
    if neg:
        b = [x ^ 0xFF for x in b]
        # two's complement
        carry = 1
        for i in range(len(b) - 1, -1, -1):
            s = b[i] + carry
            b[i] = s & 0xFF
            carry = s >> 8
    if b[0] & 0x80 and not neg:
        b = [0] + b
    elif neg and not (b[0] & 0x80):
        b = [0xFF] + b
    return _encode_tlv(_T_INT, bytes(b))


def _encode_octetstr(s: bytes) -> bytes:
    return _encode_tlv(_T_OCTSTR, s)


def _encode_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.strip(".").split(".")]
    if len(parts) < 2:
        parts += [0] * (2 - len(parts))
    encoded = [parts[0] * 40 + parts[1]]
    for p in parts[2:]:
        if p == 0:
            encoded.append(0)
        else:
            sub: List[int] = []
            while p:
                sub.append(p & 0x7F)
                p >>= 7
            sub.reverse()
            for i, b in enumerate(sub):
                encoded.append(b | (0x80 if i < len(sub) - 1 else 0))
    return _encode_tlv(_T_OID, bytes(encoded))


def _encode_null() -> bytes:
    return _encode_tlv(_T_NULL, b"")


def _encode_varbind(oid: str) -> bytes:
    return _encode_tlv(_T_SEQ, _encode_oid(oid) + _encode_null())


def _build_pdu(pdu_type: int, request_id: int, community: str, oids: List[str]) -> bytes:
    varbinds = b"".join(_encode_varbind(o) for o in oids)
    varbind_list = _encode_tlv(_T_SEQ, varbinds)
    pdu_body = (
        _encode_int(request_id)
        + _encode_int(0)   # error-status
        + _encode_int(0)   # error-index
        + varbind_list
    )
    pdu = _encode_tlv(pdu_type, pdu_body)
    msg = (
        _encode_int(_SNMP_VERSION_2C)
        + _encode_octetstr(community.encode())
        + pdu
    )
    return _encode_tlv(_T_SEQ, msg)


# ---------------------------------------------------------------------------
# BER decoding helpers
# ---------------------------------------------------------------------------

def _decode_length(data: bytes, offset: int) -> Tuple[int, int]:
    b = data[offset]
    if b < 0x80:
        return b, offset + 1
    n_bytes = b & 0x7F
    length = int.from_bytes(data[offset + 1: offset + 1 + n_bytes], "big")
    return length, offset + 1 + n_bytes


def _decode_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    tag = data[offset]
    length, offset = _decode_length(data, offset + 1)
    value = data[offset: offset + length]
    return tag, value, offset + length


def _decode_oid(raw: bytes) -> str:
    if not raw:
        return "0.0"
    first = raw[0]
    parts = [first // 40, first % 40]
    i = 1
    while i < len(raw):
        val = 0
        while True:
            b = raw[i]; i += 1
            val = (val << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        parts.append(val)
    return ".".join(str(p) for p in parts)


def _decode_int(raw: bytes) -> int:
    if not raw:
        return 0
    n = int.from_bytes(raw, "big", signed=(raw[0] & 0x80) != 0)
    return n


def _decode_value(tag: int, raw: bytes):
    """Return a Python value from a BER-encoded SNMP varbind value."""
    if tag == _T_NULL:
        return None
    if tag == _T_INT:
        return _decode_int(raw)
    if tag in (_T_COUNTER32, _T_GAUGE32, _T_TIMETICKS, _T_COUNTER64):
        return int.from_bytes(raw, "big")
    if tag == _T_OID:
        return _decode_oid(raw)
    if tag == _T_IPADDR:
        if len(raw) == 4:
            return ".".join(str(b) for b in raw)
        return raw.hex()
    if tag == _T_OCTSTR:
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return raw.hex()
    # Unknown – return hex
    return raw.hex()


def _parse_response(data: bytes) -> List[Tuple[str, int, object]]:
    """Parse an SNMP response and return list of (oid, tag, value)."""
    offset = 0
    tag, msg_val, _ = _decode_tlv(data, offset)
    if tag != _T_SEQ:
        raise ValueError(f"Expected SEQUENCE, got 0x{tag:02X}")
    offset = 0
    # version
    tag, raw, offset = _decode_tlv(msg_val, offset)
    # community
    tag, raw, offset = _decode_tlv(msg_val, offset)
    # PDU
    tag, pdu_val, _ = _decode_tlv(msg_val, offset)
    if tag != _T_PDU_RESPONSE:
        raise ValueError(f"Expected Response PDU 0x{_T_PDU_RESPONSE:02X}, got 0x{tag:02X}")
    offset = 0
    tag, raw, offset = _decode_tlv(pdu_val, offset)  # request-id
    tag, raw, offset = _decode_tlv(pdu_val, offset)  # error-status
    err_status = _decode_int(raw)
    tag, raw, offset = _decode_tlv(pdu_val, offset)  # error-index
    tag, vbl_val, _ = _decode_tlv(pdu_val, offset)   # VarBindList
    results: List[Tuple[str, int, object]] = []
    vb_offset = 0
    while vb_offset < len(vbl_val):
        tag, vb_val, vb_offset = _decode_tlv(vbl_val, vb_offset)
        vb_inner = 0
        t2, oid_raw, vb_inner = _decode_tlv(vb_val, vb_inner)
        oid_str = _decode_oid(oid_raw)
        t3, val_raw, _ = _decode_tlv(vb_val, vb_inner)
        value = _decode_value(t3, val_raw)
        results.append((oid_str, t3, value))
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class SNMPError(Exception):
    pass


def snmp_get(host: str, oids: List[str], community: str = "public",
             port: int = 161, timeout: float = 2.0, retries: int = 1
             ) -> Dict[str, object]:
    """
    Perform an SNMPv2c GET for the given OIDs.
    Returns dict of {oid: value} for all non-null, non-error responses.
    Raises SNMPError on timeout / network error.
    """
    pkt = _build_pdu(_T_PDU_GET, 1, community, oids)
    for attempt in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(pkt, (host, port))
            data, _ = sock.recvfrom(65535)
            results = _parse_response(data)
            return {oid: val for oid, tag, val in results
                    if tag != _T_NULL and val is not None}
        except socket.timeout:
            if attempt >= retries:
                raise SNMPError(f"Timeout: {host}:{port}")
        except OSError as e:
            raise SNMPError(str(e))
        finally:
            sock.close()
    return {}


def snmp_getnext(host: str, oid: str, community: str = "public",
                 port: int = 161, timeout: float = 2.0) -> Optional[Tuple[str, object]]:
    """
    Perform a single SNMP GETNEXT.
    Returns (next_oid, value) or None on error/timeout.
    """
    pkt = _build_pdu(_T_PDU_GETNEXT, 2, community, [oid])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (host, port))
        data, _ = sock.recvfrom(65535)
        results = _parse_response(data)
        if results:
            next_oid, tag, value = results[0]
            if tag == _T_NULL or value is None:
                return None
            # endOfMibView / noSuchObject
            if tag in (0x80, 0x81, 0x82):
                return None
            return next_oid, value
        return None
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


def snmp_walk(host: str, base_oid: str, community: str = "public",
              port: int = 161, timeout: float = 2.0,
              max_entries: int = 2000) -> Iterator[Tuple[str, object]]:
    """
    Walk the subtree rooted at base_oid using GETNEXT.
    Yields (oid, value) while the returned OID starts with base_oid.
    """
    current = base_oid
    count = 0
    while count < max_entries:
        pkt = _build_pdu(_T_PDU_GETNEXT, 3 + count, community, [current])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(pkt, (host, port))
            data, _ = sock.recvfrom(65535)
        except (socket.timeout, OSError):
            return
        finally:
            sock.close()
        try:
            results = _parse_response(data)
        except Exception:
            return
        if not results:
            return
        next_oid, tag, value = results[0]
        if tag in (0x80, 0x81, 0x82):  # noSuchObject, noSuchInstance, endOfMib
            return
        if not next_oid.startswith(base_oid):
            return
        if next_oid == current:
            return  # loop guard
        current = next_oid
        if value is not None and tag != _T_NULL:
            yield next_oid, value
        count += 1


def snmp_walk_dict(host: str, base_oid: str, community: str = "public",
                   port: int = 161, timeout: float = 2.0,
                   max_entries: int = 2000) -> Dict[str, object]:
    """Return the full subtree walk as a dict."""
    return dict(snmp_walk(host, base_oid, community=community, port=port,
                          timeout=timeout, max_entries=max_entries))


def decode_hex_ip(raw) -> Optional[str]:
    """
    Decode a CDP or LLDP address value that might be a hex string like
    '0x0104a0820102' (type 1 = IP, then 4 bytes) or plain dotted-decimal.
    Returns None if unparseable.
    """
    if isinstance(raw, str):
        raw = raw.strip()
        if raw.startswith("0x") or raw.startswith("0X"):
            raw = raw[2:]
            # CDP: type(1)+proto_len(1)+proto(proto_len)+addr_len(1)+addr
            try:
                b = bytes.fromhex(raw)
            except ValueError:
                return None
            if len(b) >= 7 and b[0] == 1:  # NLPID type
                proto_len = b[1]
                proto = b[2:2 + proto_len]
                addr_len_offset = 2 + proto_len
                addr_len = b[addr_len_offset]
                addr = b[addr_len_offset + 1: addr_len_offset + 1 + addr_len]
                if addr_len == 4:
                    return ".".join(str(x) for x in addr)
            return None
        # already dotted decimal?
        parts = raw.split(".")
        if len(parts) == 4:
            try:
                ints = [int(p) for p in parts]
                if all(0 <= x <= 255 for x in ints):
                    return raw
            except ValueError:
                pass
    return None


def parse_lldp_rem_man_addr(oid_suffix: str) -> Optional[str]:
    """
    Parse the IP from an lldpRemManAddr OID suffix.
    Format: <timeMark>.<portNum>.<idx>.1.4.a.b.c.d
    The contract says: ...4.2.1.3.<tm>.<port>.<idx>.1.4.a.b.c.d
    After stripping the base OID we get: <tm>.<port>.<idx>.1.4.a.b.c.d
    """
    parts = oid_suffix.strip(".").split(".")
    # find ".1.4." pattern indicating IPv4 (addrType=1, addrLen=4)
    for i in range(len(parts) - 5):
        if parts[i] == "1" and parts[i + 1] == "4":
            addr_parts = parts[i + 2: i + 6]
            if len(addr_parts) == 4:
                try:
                    ip = ".".join(str(int(x)) for x in addr_parts)
                    return ip
                except ValueError:
                    pass
    return None
