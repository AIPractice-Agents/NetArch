"""
Report generation: SVG diagram, HTML report, CSV exports, Mermaid, JSON, audit CSV.
"""
from __future__ import annotations

import csv
import html
import ipaddress
import json
import os
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple

from netarch.classify import TIER_ORDER
from netarch.context import ScanContext

# ---------------------------------------------------------------------------
# Role icons (emoji)
# ---------------------------------------------------------------------------
_ROLE_ICON = {
    "Router":          "🔀",
    "L3 Switch":       "🔀",
    "Switch":          "🔁",
    "Firewall":        "🔥",
    "Wireless AP":     "📶",
    "IP Camera / NVR": "📷",
    "Printer":         "🖨️",
    "NAS / Storage":   "💾",
    "IP Phone":        "📞",
    "Database Server": "🗄️",
    "Web Server":      "🌐",
    "Workstation":     "💻",
    "Host":            "🖥️",
}

_ROLE_COLOR = {
    "Router":          "#1a73e8",
    "L3 Switch":       "#0d47a1",
    "Switch":          "#1565c0",
    "Firewall":        "#b71c1c",
    "Wireless AP":     "#6a1b9a",
    "IP Camera / NVR": "#1b5e20",
    "Printer":         "#e65100",
    "NAS / Storage":   "#37474f",
    "IP Phone":        "#006064",
    "Database Server": "#4a148c",
    "Web Server":      "#0277bd",
    "Workstation":     "#424242",
    "Host":            "#546e7a",
}


def _esc(s: Any) -> str:
    return html.escape(str(s or ""))


# ---------------------------------------------------------------------------
# Graph layout helpers
# ---------------------------------------------------------------------------

def _build_graph(devices: Dict, links: Dict) -> Dict[str, List[str]]:
    """Return adjacency dict for approved/non-rejected items."""
    adj: Dict[str, List[str]] = {k: [] for k in devices}
    for lk, link in links.items():
        if link.get("review_status") == "rejected":
            continue
        a, b = link["a"], link["b"]
        if a in adj and b in adj:
            adj[a].append(b)
            adj[b].append(a)
    return adj


def _connected_groups(devices: Dict, adj: Dict[str, List[str]]) -> List[List[str]]:
    visited: Set[str] = set()
    groups: List[List[str]] = []
    for k in devices:
        if k in visited:
            continue
        group: List[str] = []
        queue = [k]
        while queue:
            node = queue.pop()
            if node in visited:
                continue
            visited.add(node)
            group.append(node)
            queue.extend(n for n in adj.get(node, []) if n not in visited)
        groups.append(group)
    return groups


def _tier_rank(device: Dict) -> int:
    return TIER_ORDER.get(device.get("tier", "Unknown"), 0)


def _ip_sort_key(ip: str) -> Tuple[int, str]:
    try:
        return (0, str(ipaddress.ip_address(ip or "")))
    except Exception:
        return (1, str(ip or ""))


def _device_sort_key(key: str, device: Dict) -> Tuple[int, int, Tuple[int, str], str, str, str]:
    return (
        0 if device.get("is_gateway") else 1,
        -_tier_rank(device),
        _ip_sort_key(device.get("ip", "")),
        str(device.get("name", "")).lower(),
        str(device.get("role", "")).lower(),
        str(key).lower(),
    )


def _group_sort_key(group: List[str], devices: Dict) -> Tuple[int, int, int, str]:
    has_gateway = any(devices.get(k, {}).get("is_gateway") for k in group)
    max_tier = max((_tier_rank(devices.get(k, {})) for k in group), default=0)
    min_ip = min((_ip_sort_key(devices.get(k, {}).get("ip", "")) for k in group),
                 default=(1, ""))
    return (
        0 if has_gateway else 1,
        -max_tier,
        -len(group),
        f"{min_ip[0]}:{min_ip[1]}",
    )


def _pick_group_root(group: List[str], devices: Dict,
                     adj: Dict[str, List[str]]) -> str:
    """Pick a deterministic root for topology layout."""
    ranked = sorted(
        group,
        key=lambda k: (
            0 if devices.get(k, {}).get("is_gateway") else 1,
            -_tier_rank(devices.get(k, {})),
            -len(adj.get(k, [])),
            _ip_sort_key(devices.get(k, {}).get("ip", "")),
            str(k).lower(),
        ),
    )
    return ranked[0]


def _layout_group_positions(group: List[str], devices: Dict,
                            adj: Dict[str, List[str]],
                            x_base: int, y_base: int) -> Tuple[Dict[str, Tuple[int, int]], int, int]:
    """Lay out a connected group in BFS depth levels (v1 style).

    Returns: (positions, group_width_px, group_height_px)
    """
    positions: Dict[str, Tuple[int, int]] = {}
    if not group:
        return positions, _BOX_W, _BOX_H

    root = _pick_group_root(group, devices, adj)
    group_set = set(group)

    depth: Dict[str, int] = {root: 0}
    parent: Dict[str, Optional[str]] = {root: None}
    children: Dict[str, List[str]] = defaultdict(list)
    visited: Set[str] = {root}
    q = deque([root])

    while q:
        node = q.popleft()
        cur_depth = depth[node]
        neighbors = sorted(
            (n for n in adj.get(node, []) if n in group_set),
            key=lambda k: _device_sort_key(k, devices.get(k, {})),
        )
        for nxt in neighbors:
            if nxt in visited:
                continue
            visited.add(nxt)
            depth[nxt] = cur_depth + 1
            parent[nxt] = node
            children[node].append(nxt)
            q.append(nxt)

    # Safety for any unvisited members (shouldn't happen for connected groups).
    if len(visited) < len(group_set):
        tail_depth = max(depth.values(), default=0)
        for key in sorted(group_set - visited,
                          key=lambda k: _device_sort_key(k, devices.get(k, {}))):
            tail_depth += 1
            depth[key] = tail_depth
            parent[key] = None
            children[root].append(key)

    for node, kids in list(children.items()):
        children[node] = sorted(kids, key=lambda k: _device_sort_key(k, devices.get(k, {})))

    levels: Dict[int, List[str]] = defaultdict(list)
    for key in group:
        levels[depth.get(key, 0)].append(key)

    max_level = max(levels.keys(), default=0)

    # Order each level by parent order from the previous level to reduce crossings.
    ordered_levels: Dict[int, List[str]] = {}
    ordered_levels[0] = [root]

    # Include any additional nodes unexpectedly mapped to depth 0.
    for key in sorted(levels.get(0, []), key=lambda k: _device_sort_key(k, devices.get(k, {}))):
        if key != root:
            ordered_levels[0].append(key)

    for d in range(1, max_level + 1):
        prev_index = {k: i for i, k in enumerate(ordered_levels.get(d - 1, []))}
        ordered_levels[d] = sorted(
            levels.get(d, []),
            key=lambda k: (
                prev_index.get(parent.get(k, ""), 10**9),
                _device_sort_key(k, devices.get(k, {})),
            ),
        )

    max_nodes_in_level = max((len(v) for v in ordered_levels.values()), default=1)

    for d in range(0, max_level + 1):
        row = ordered_levels.get(d, [])
        n = len(row)
        if n == 0:
            continue
        row_offset = (max_nodes_in_level - n) / 2.0
        for i, key in enumerate(row):
            x = x_base + int(round((row_offset + i) * _COL_GAP))
            y = y_base + d * _ROW_GAP
            positions[key] = (x, y)

    group_width = ((max_nodes_in_level - 1) * _COL_GAP) + _BOX_W
    group_height = (max_level * _ROW_GAP) + _BOX_H
    return positions, group_width, group_height


# ---------------------------------------------------------------------------
# SVG diagram
# ---------------------------------------------------------------------------

_BOX_W = 180
_BOX_H = 65
_COL_GAP = 220
_ROW_GAP = 95
_DRAFT_WATERMARK = "DRAFT – pending review"


def _build_svg_internal(devices: Dict, links: Dict, is_draft: bool = False) -> str:
    # Filter out rejected devices
    visible_devices = {k: d for k, d in devices.items()
                       if d.get("review_status") != "rejected"}
    visible_links = {k: lnk for k, lnk in links.items()
                     if lnk.get("review_status") != "rejected"
                     and lnk["a"] in visible_devices
                     and lnk["b"] in visible_devices}

    if not visible_devices:
        return '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="80">' \
               '<text x="10" y="40" font-size="18" fill="#666">No devices to display.</text></svg>'

    adj = _build_graph(visible_devices, visible_links)
    groups = _connected_groups(visible_devices, adj)

    # Deterministic group ordering: gateway-containing group first,
    # then higher-tier groups, then larger groups, then lowest IP.
    groups = sorted(groups, key=lambda g: _group_sort_key(g, visible_devices))

    # Assign positions: each group laid out as top-down hierarchy
    positions: Dict[str, Tuple[int, int]] = {}
    x_base = 30
    y_base = 60
    max_y = y_base
    max_x = x_base
    group_gap = 120

    for group in groups:
        group_positions, group_width, group_height = _layout_group_positions(
            group,
            visible_devices,
            adj,
            x_base,
            y_base,
        )
        positions.update(group_positions)
        max_y = max(max_y, y_base + group_height)
        max_x = max(max_x, x_base + group_width)
        x_base += group_width + group_gap

    total_w = max(400, max_x + 30)
    total_h = max_y + 50

    lines: List[str] = []
    lines.append(f'<svg xmlns="http://www.w3.org/2000/svg" '
                 f'width="{total_w}" height="{total_h}" '
                 f'style="font-family:sans-serif;background:#f8f9fa">')

    if is_draft:
        lines.append(f'<text x="{total_w // 2}" y="{total_h - 10}" '
                     f'text-anchor="middle" font-size="14" fill="#ff000055" '
                     f'font-weight="bold">{_DRAFT_WATERMARK}</text>')

    # Draw links first (behind boxes)
    for lk, link in visible_links.items():
        a, b = link["a"], link["b"]
        if a not in positions or b not in positions:
            continue
        ax, ay = positions[a]
        bx, by = positions[b]
        x1c = ax + _BOX_W // 2
        y1c = ay + _BOX_H // 2
        x2c = bx + _BOX_W // 2
        y2c = by + _BOX_H // 2

        # Prefer orthogonal top-down connectors for readability.
        if y1c <= y2c:
            x_from, y_from = x1c, ay + _BOX_H
            x_to, y_to = x2c, by
        else:
            x_from, y_from = x2c, by + _BOX_H
            x_to, y_to = x1c, ay
        source = link.get("source", "")
        is_inferred = source == "inferred"
        is_manual = source == "manual"
        stroke = "#2196F3" if is_manual else ("#888" if is_inferred else "#1a73e8")
        dash = "6,4" if is_inferred else ("none" if not is_manual else "none")
        sw = "1.5" if is_inferred else "2"
        if abs(y1c - y2c) < 24:
            lines.append(f'<line x1="{x1c}" y1="{y1c}" x2="{x2c}" y2="{y2c}" '
                         f'stroke="{stroke}" stroke-width="{sw}" '
                         f'stroke-dasharray="{dash}"/>')
            label_x = (x1c + x2c) // 2 - 5
            label_y = (y1c + y2c) // 2 - 5
        else:
            mid_y = (y_from + y_to) // 2

            points = f"{x_from},{y_from} {x_from},{mid_y} {x_to},{mid_y} {x_to},{y_to}"
            lines.append(f'<polyline points="{points}" fill="none" '
                         f'stroke="{stroke}" stroke-width="{sw}" '
                         f'stroke-dasharray="{dash}"/>')
            label_x = (x_from + x_to) // 2 - 5
            label_y = mid_y - 5

        # Port labels
        a_port = link.get("a_port", "")
        b_port = link.get("b_port", "")
        if a_port:
            lines.append(f'<text x="{label_x}" y="{label_y}" font-size="9" fill="#555">'
                         f'{_esc(a_port)}</text>')

    # Draw device boxes
    for key, dev in visible_devices.items():
        if key not in positions:
            continue
        x, y = positions[key]
        role = dev.get("role", "Host")
        color = _ROLE_COLOR.get(role, "#546e7a")
        icon = _ROLE_ICON.get(role, "🖥️")
        name = dev.get("name", key)[:22]
        vendor_model = ""
        v = dev.get("vendor", "")
        m = dev.get("model", "")
        if v and v != "-":
            vendor_model = v
        if m and m != "-" and m not in vendor_model:
            vendor_model = (vendor_model + " " + m).strip()
        vendor_model = vendor_model[:25]
        ip_tier = f"{dev.get('ip', '')} · {dev.get('tier', '')}"[:30]
        conf = dev.get("confidence", 0)
        is_pending = dev.get("review_status") == "pending"
        is_edited = dev.get("review_status") == "edited"
        has_crit = any(i.get("severity") == "critical" for i in dev.get("issues", []))

        border_color = "#e53935" if has_crit else color
        border_width = 3 if has_crit else 1.5
        fill_opacity = "0.9"
        stroke_dash = "6,3" if is_pending and is_draft else "none"

        # Build tooltip
        tips = [
            f"IP: {dev.get('ip', '')}",
            f"MAC: {dev.get('mac', '')}",
            f"Vendor: {dev.get('vendor', '')}",
            f"Model: {dev.get('model', '')}",
            f"Title: {dev.get('http', {}).get('title', '')}",
            f"Via: {', '.join(dev.get('via', []))}",
            f"Ports: {dev.get('open_ports', [])}",
            f"Confidence: {conf}",
            f"Issues: {[i['msg'] for i in dev.get('issues', [])]}",
        ]
        tooltip = " | ".join(t for t in tips if t.split(": ", 1)[1])

        lines.append(f'<g>')
        lines.append(f'  <title>{_esc(tooltip)}</title>')
        lines.append(f'  <rect x="{x}" y="{y}" width="{_BOX_W}" height="{_BOX_H}" '
                     f'rx="6" ry="6" fill="{color}" fill-opacity="{fill_opacity}" '
                     f'stroke="{border_color}" stroke-width="{border_width}" '
                     f'stroke-dasharray="{stroke_dash}"/>')

        # Confidence badge
        badge_color = "#4caf50" if conf >= 80 else ("#ff9800" if conf >= 50 else "#f44336")
        lines.append(f'  <rect x="{x + _BOX_W - 32}" y="{y + 2}" width="30" height="14" '
                     f'rx="7" fill="{badge_color}"/>')
        lines.append(f'  <text x="{x + _BOX_W - 17}" y="{y + 12}" text-anchor="middle" '
                     f'font-size="8" fill="white">{conf}%</text>')

        # Edited pencil mark
        if is_edited:
            lines.append(f'  <text x="{x + 2}" y="{y + 11}" font-size="9" fill="white">✏️</text>')

        # Icon + text
        lines.append(f'  <text x="{x + 10}" y="{y + 20}" font-size="13">{icon}</text>')
        lines.append(f'  <text x="{x + 28}" y="{y + 20}" font-size="11" fill="white" '
                     f'font-weight="bold">{_esc(name)}</text>')
        if vendor_model:
            lines.append(f'  <text x="{x + 8}" y="{y + 36}" font-size="9" fill="#ffffffcc">'
                         f'{_esc(vendor_model)}</text>')
        lines.append(f'  <text x="{x + 8}" y="{y + 52}" font-size="9" fill="#ffffffaa">'
                     f'{_esc(ip_tier)}</text>')
        lines.append(f'</g>')

    lines.append('</svg>')
    return "\n".join(lines)


def _build_svg(devices: Dict, links: Dict, is_draft: bool = False) -> str:
    """Generate SVG diagram using netsim_ai layout engine, with fallback."""
    visible_devices = {k: d for k, d in devices.items()
                       if d.get("review_status") != "rejected"}
    visible_links = {k: lnk for k, lnk in links.items()
                     if lnk.get("review_status") != "rejected"
                     and lnk["a"] in visible_devices
                     and lnk["b"] in visible_devices}

    if not visible_devices:
        return ('<svg xmlns="http://www.w3.org/2000/svg" width="400" height="80">'
                '<text x="10" y="40" font-size="18" fill="#666">'
                'No devices to display.</text></svg>')

    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from netsim_ai import render_diagram as _netsim_render
        svg, _mmd = _netsim_render(visible_devices, visible_links, is_draft=is_draft)
        return svg
    except Exception:
        return _build_svg_internal(devices, links, is_draft)


# ---------------------------------------------------------------------------
# Mermaid
# ---------------------------------------------------------------------------

def _build_mermaid_internal(devices: Dict, links: Dict) -> str:
    lines = ["graph TD"]
    visible = {k: d for k, d in devices.items()
               if d.get("review_status") != "rejected"}
    visible_links = {k: lnk for k, lnk in links.items()
                     if lnk.get("review_status") != "rejected"
                     and lnk["a"] in visible and lnk["b"] in visible}

    def node_id(key: str) -> str:
        return re.sub(r'[^a-zA-Z0-9_]', '_', key)

    import re
    for key, dev in visible.items():
        nid = node_id(key)
        label = dev.get("name", key).replace('"', "'")
        lines.append(f'    {nid}["{label}"]')

    for lk, link in visible_links.items():
        a = node_id(link["a"])
        b = node_id(link["b"])
        source = link.get("source", "")
        a_port = link.get("a_port", "")
        b_port = link.get("b_port", "")
        label = f"{a_port}--{b_port}" if (a_port or b_port) else ""
        if source == "inferred":
            connector = f"-.-|{label}|" if label else "-.-"
        elif source == "manual":
            connector = f"==>|{label}|" if label else "==>"
        else:
            connector = f"-->|{label}|" if label else "-->"
        lines.append(f"    {a} {connector} {b}")

    return "\n".join(lines)


def _build_mermaid(devices: Dict, links: Dict) -> str:
    """Generate Mermaid topology using netsim_ai engine, with fallback."""
    visible = {k: d for k, d in devices.items()
               if d.get("review_status") != "rejected"}
    visible_links = {k: lnk for k, lnk in links.items()
                     if lnk.get("review_status") != "rejected"
                     and lnk["a"] in visible and lnk["b"] in visible}

    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from netsim_ai import render_diagram as _netsim_render
        _svg, mmd = _netsim_render(visible, visible_links)
        return mmd
    except Exception:
        return _build_mermaid_internal(devices, links)


# ---------------------------------------------------------------------------
# Insights
# ---------------------------------------------------------------------------

def _build_insights(devices: Dict, links: Dict) -> List[str]:
    visible = {k: d for k, d in devices.items()
               if d.get("review_status") != "rejected"}
    vis_links = {k: lnk for k, lnk in links.items()
                 if lnk.get("review_status") != "rejected"}

    insights: List[str] = []
    n = len(visible)
    if not n:
        return ["No devices in report."]

    # Counts
    role_counts: Dict[str, int] = {}
    vendor_counts: Dict[str, int] = {}
    for d in visible.values():
        r = d.get("role", "-")
        if r and r != "-":
            role_counts[r] = role_counts.get(r, 0) + 1
        v = d.get("vendor", "-")
        if v and v != "-":
            vendor_counts[v] = vendor_counts.get(v, 0) + 1

    insights.append(f"Total devices: {n}. Roles: " +
                    ", ".join(f"{r}: {c}" for r, c in sorted(role_counts.items())))

    if len(vendor_counts) > 1:
        insights.append("Multi-vendor environment: " +
                        ", ".join(f"{v} ({c})" for v, c in sorted(vendor_counts.items(),
                                                                     key=lambda x: -x[1])))

    # ARP-only devices
    arp_only = [d.get("name", k) for k, d in visible.items() if d.get("via") == ["ARP"]]
    if arp_only:
        insights.append(f"ARP-only devices (low confidence): {', '.join(arp_only)}")

    # Neighbour-only
    nbr_only = [d.get("name", k) for k, d in visible.items()
                if k.startswith("nbr:") or (d.get("seen_in_neighbour") and
                                              not d.get("snmp", {}).get("sysDescr"))]
    if nbr_only:
        insights.append(f"Neighbour-only devices (found via LLDP/CDP only): {', '.join(nbr_only)}")

    # Randomized MACs
    rand_macs = [d.get("name", k) for k, d in visible.items()
                 if d.get("mac_vendor") == "Private MAC"]
    if rand_macs:
        insights.append(f"Devices with randomized/private MACs: {', '.join(rand_macs)}")

    # Network devices without SNMP
    net_roles = {"Router", "L3 Switch", "Switch", "Firewall", "Wireless AP"}
    no_snmp = [d.get("name", k) for k, d in visible.items()
               if d.get("role") in net_roles and not d.get("snmp", {}).get("sysDescr")]
    if no_snmp:
        insights.append(f"Network devices without SNMP: {', '.join(no_snmp)}. "
                        "Enable SNMPv2c read-only for better discovery.")

    # Security findings
    sec_issues = []
    for d in visible.values():
        for iss in d.get("issues", []):
            if iss.get("severity") == "critical":
                sec_issues.append(f"{d.get('name')}: {iss['msg']}")
    if sec_issues:
        insights.append("⚠️ Security findings: " + "; ".join(sec_issues))

    # Links
    if vis_links:
        inferred_all = all(lnk.get("source") == "inferred" for lnk in vis_links.values())
        no_meas = not any(lnk.get("source") in ("LLDP", "CDP") for lnk in vis_links.values())
        if inferred_all or no_meas:
            insights.append(
                "No device exposed LLDP/CDP neighbour tables. All links are assumed from "
                "gateway routing. For accurate topology: enable LLDP/CDP on network devices, "
                "scan from a core switch with crawl, or include the gateway in the scan.")
    else:
        insights.append(
            "No links found. Suggestions: enable SNMP + LLDP/CDP on network devices, "
            "scan from a core switch with crawl, or include the gateway.")

    if len(visible) == 1:
        insights.append("Only one device found. Consider scanning the full subnet or "
                         "including the gateway.")

    return insights


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def _html_report(ctx: ScanContext, svg: str, is_draft: bool) -> str:
    devices = {k: d for k, d in ctx.devices.items()
               if d.get("review_status") != "rejected"}
    links = {k: lnk for k, lnk in ctx.links.items()
             if lnk.get("review_status") != "rejected"}
    insights = _build_insights(devices, links)

    n_devices = len(devices)
    meas_links = sum(1 for lnk in links.values() if lnk.get("source") in ("LLDP", "CDP"))
    inf_links  = sum(1 for lnk in links.values() if lnk.get("source") == "inferred")
    man_links  = sum(1 for lnk in links.values() if lnk.get("source") == "manual")
    net_devs   = sum(1 for d in devices.values()
                     if d.get("role") in {"Router","L3 Switch","Switch","Firewall","Wireless AP"})
    vendors    = len(set(d.get("vendor","") for d in devices.values()
                         if d.get("vendor") and d["vendor"] != "-"))
    avg_conf   = 0
    if devices:
        avg_conf = round(sum(d.get("confidence", 0) for d in devices.values()) / len(devices))
    open_issues = sum(len(d.get("issues", [])) for d in devices.values())

    reviewer  = ctx.settings.get("approval", "")
    target    = ctx.settings.get("target", "")
    version   = ctx.report_version
    draft_banner = ('<div style="background:#ff9800;color:white;text-align:center;padding:8px;'
                    'font-weight:bold;font-size:1.1em">DRAFT – pending review</div>'
                    if is_draft else "")

    # Agent pipeline summary
    pipeline_rows = ""
    for aname in ("discovery", "enrichment", "links", "verification", "review"):
        run = ctx.agent_runs.get(aname, {})
        pipeline_rows += (
            f"<tr><td><b>{aname.title()}</b></td>"
            f"<td>{run.get('status','')}</td>"
            f"<td>{run.get('duration_s','')}</td>"
            f"<td>{_esc(run.get('summary',''))}</td></tr>\n"
        )

    # Inventory table
    inv_rows = ""
    for key, d in sorted(devices.items(), key=lambda x: x[0]):
        issues_txt = "; ".join(i["msg"] for i in d.get("issues", []))
        inv_rows += (
            f"<tr>"
            f"<td>{_esc(d.get('name',''))}</td>"
            f"<td>{_esc(d.get('ip',''))}</td>"
            f"<td>{_esc(d.get('mac',''))}</td>"
            f"<td>{_esc(d.get('vendor',''))}</td>"
            f"<td>{_esc(d.get('model',''))}</td>"
            f"<td>{_esc(d.get('role',''))}</td>"
            f"<td>{_esc(d.get('tier',''))}</td>"
            f"<td>{d.get('confidence',0)}</td>"
            f"<td>{_esc(d.get('review_status',''))}</td>"
            f"<td>{_esc(issues_txt)}</td>"
            f"</tr>\n"
        )

    # Links table
    link_rows = ""
    for lk, link in sorted(links.items()):
        a_dev = devices.get(link["a"], {})
        b_dev = devices.get(link["b"], {})
        link_rows += (
            f"<tr>"
            f"<td>{_esc(a_dev.get('name', link['a']))} {_esc(link.get('a_port',''))}</td>"
            f"<td>{_esc(b_dev.get('name', link['b']))} {_esc(link.get('b_port',''))}</td>"
            f"<td>{_esc(link.get('source',''))}</td>"
            f"<td>{'✓' if len(link.get('seen_from',[])) == 2 else '½'}</td>"
            f"<td>{link.get('confidence',0)}</td>"
            f"<td>{_esc('; '.join(i['msg'] for i in link.get('issues',[])))}</td>"
            f"</tr>\n"
        )

    # Audit table
    audit_rows = ""
    for entry in ctx.audit[-200:]:
        audit_rows += (
            f"<tr>"
            f"<td>{_esc(entry.get('time',''))}</td>"
            f"<td>{_esc(entry.get('actor',''))}</td>"
            f"<td>{_esc(entry.get('action',''))}</td>"
            f"<td>{_esc(entry.get('target',''))}</td>"
            f"</tr>\n"
        )

    insights_html = "".join(f"<li>{_esc(i)}</li>" for i in insights)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NetArch — Verified Network Architecture</title>
<style>
body{{font-family:Arial,sans-serif;margin:0;background:#f4f6f9;color:#222}}
header{{background:linear-gradient(135deg,#1a237e,#1976d2);color:white;padding:18px 24px}}
header h1{{margin:0 0 4px 0;font-size:1.6em}}header p{{margin:0;opacity:.85;font-size:.9em}}
.kpi{{display:flex;flex-wrap:wrap;gap:12px;padding:16px 24px}}
.kpi-card{{background:white;border-radius:8px;padding:12px 18px;min-width:120px;
  box-shadow:0 1px 4px rgba(0,0,0,.12);text-align:center}}
.kpi-card .val{{font-size:2em;font-weight:bold;color:#1976d2}}
.kpi-card .lbl{{font-size:.8em;color:#666;margin-top:4px}}
section{{background:white;margin:12px 24px;border-radius:8px;padding:16px 20px;
  box-shadow:0 1px 4px rgba(0,0,0,.08)}}
h2{{font-size:1.1em;margin:0 0 10px 0;color:#1976d2}}
table{{border-collapse:collapse;width:100%;font-size:.85em}}
th{{background:#e3eaf8;padding:6px 8px;text-align:left}}
td{{padding:5px 8px;border-bottom:1px solid #e8ecf2}}
tr:hover td{{background:#f0f4ff}}
ul{{margin:0;padding-left:1.4em;line-height:1.8}}
.svg-wrap{{overflow-x:auto;padding:8px}}
</style>
</head>
<body>
{draft_banner}
<header>
  <h1>NetArch — Verified Network Architecture</h1>
  <p>Target: {_esc(target)} &nbsp;|&nbsp; Reviewer: {_esc(reviewer)} &nbsp;|&nbsp;
     Mode: {'LAB' if ctx.settings.get('live') == False else 'LIVE'} &nbsp;|&nbsp;
     Report v{version} &nbsp;|&nbsp; Generated: {ctx.updated}</p>
</header>

<div class="kpi">
  <div class="kpi-card"><div class="val">{n_devices}</div><div class="lbl">Devices</div></div>
  <div class="kpi-card"><div class="val">{meas_links}</div><div class="lbl">Measured Links</div></div>
  <div class="kpi-card"><div class="val">{inf_links}</div><div class="lbl">Inferred Links</div></div>
  <div class="kpi-card"><div class="val">{man_links}</div><div class="lbl">Manual Links</div></div>
  <div class="kpi-card"><div class="val">{net_devs}</div><div class="lbl">Network Devices</div></div>
  <div class="kpi-card"><div class="val">{vendors}</div><div class="lbl">Vendors</div></div>
  <div class="kpi-card"><div class="val">{avg_conf}%</div><div class="lbl">Avg Confidence</div></div>
  <div class="kpi-card"><div class="val">{open_issues}</div><div class="lbl">Open Issues</div></div>
</div>

<section>
  <h2>Network Diagram</h2>
  <div class="svg-wrap">{svg}</div>
</section>

<section>
  <h2>Insights</h2>
  <ul>{insights_html}</ul>
</section>

<section>
  <h2>Agent Pipeline</h2>
  <table><tr><th>Agent</th><th>Status</th><th>Duration (s)</th><th>Summary</th></tr>
  {pipeline_rows}</table>
</section>

<section>
  <h2>Device Inventory</h2>
  <table>
  <tr><th>Name</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Model</th>
      <th>Role</th><th>Tier</th><th>Conf</th><th>Status</th><th>Issues</th></tr>
  {inv_rows}</table>
</section>

<section>
  <h2>Links</h2>
  <table>
  <tr><th>A (port)</th><th>B (port)</th><th>Source</th><th>Both ends</th><th>Conf</th><th>Issues</th></tr>
  {link_rows}</table>
</section>

<section>
  <h2>Audit Trail (last 200 entries)</h2>
  <table>
  <tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th></tr>
  {audit_rows}</table>
</section>
</body>
</html>"""


# ---------------------------------------------------------------------------
# CSV / JSON / Mermaid exports
# ---------------------------------------------------------------------------

def _write_inventory_csv(devices: Dict, path: str):
    fieldnames = ["Name", "IP", "MAC", "MACVendor", "Vendor", "Model",
                  "Role", "Tier", "IdentifiedVia", "OpenPorts", "WebTitle",
                  "Location", "Confidence", "ReviewStatus", "HumanEdited"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for k, d in sorted(devices.items()):
            w.writerow({
                "Name": d.get("name", ""),
                "IP": d.get("ip", ""),
                "MAC": d.get("mac", ""),
                "MACVendor": d.get("mac_vendor", ""),
                "Vendor": d.get("vendor", ""),
                "Model": d.get("model", ""),
                "Role": d.get("role", ""),
                "Tier": d.get("tier", ""),
                "IdentifiedVia": ",".join(d.get("via", [])),
                "OpenPorts": ",".join(str(p) for p in d.get("open_ports", [])),
                "WebTitle": d.get("http", {}).get("title", ""),
                "Location": d.get("snmp", {}).get("sysLocation", ""),
                "Confidence": d.get("confidence", 0),
                "ReviewStatus": d.get("review_status", ""),
                "HumanEdited": "Yes" if d.get("human_edits") else "No",
            })


def _write_links_csv(links: Dict, devices: Dict, path: str):
    fieldnames = ["A", "A_IP", "A_Port", "B", "B_IP", "B_Port",
                  "Source", "SeenFromBothEnds", "Confidence", "ReviewStatus"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for lk, link in sorted(links.items()):
            a_dev = devices.get(link["a"], {})
            b_dev = devices.get(link["b"], {})
            w.writerow({
                "A": a_dev.get("name", link["a"]),
                "A_IP": a_dev.get("ip", ""),
                "A_Port": link.get("a_port", ""),
                "B": b_dev.get("name", link["b"]),
                "B_IP": b_dev.get("ip", ""),
                "B_Port": link.get("b_port", ""),
                "Source": link.get("source", ""),
                "SeenFromBothEnds": "Yes" if len(link.get("seen_from", [])) == 2 else "No",
                "Confidence": link.get("confidence", 0),
                "ReviewStatus": link.get("review_status", ""),
            })


def _write_audit_csv(ctx: ScanContext, path: str):
    fieldnames = ["Time", "Actor", "Action", "Target", "Before", "After"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for entry in ctx.audit:
            w.writerow({
                "Time": entry.get("time", ""),
                "Actor": entry.get("actor", ""),
                "Action": entry.get("action", ""),
                "Target": entry.get("target", ""),
                "Before": json.dumps(entry.get("before"), default=str)[:200],
                "After": json.dumps(entry.get("after"), default=str)[:200],
            })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def generate_reports(ctx: ScanContext, scans_dir: str = "scans",
                     is_draft: bool = False) -> str:
    """Generate all report files; return path to the HTML report."""
    job_dir = os.path.join(scans_dir, ctx.job_id)
    os.makedirs(job_dir, exist_ok=True)

    version = ctx.report_version
    suffix = f"_v{version}" if version > 1 else ""

    devices_all = ctx.all_devices()
    links_all   = ctx.all_links()

    visible_devs = {k: d for k, d in devices_all.items()
                    if d.get("review_status") != "rejected"}
    visible_links = {k: lnk for k, lnk in links_all.items()
                     if lnk.get("review_status") != "rejected"
                     and lnk["a"] in visible_devs
                     and lnk["b"] in visible_devs}

    # SVG
    svg = _build_svg(devices_all, links_all, is_draft=is_draft)

    # HTML
    html_path = os.path.join(job_dir, f"netarch_report{suffix}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(_html_report(ctx, svg, is_draft))

    # CSV
    _write_inventory_csv(visible_devs,
                         os.path.join(job_dir, f"netarch_inventory{suffix}.csv"))
    _write_links_csv(visible_links, visible_devs,
                     os.path.join(job_dir, f"netarch_links{suffix}.csv"))
    _write_audit_csv(ctx, os.path.join(job_dir, f"netarch_audit{suffix}.csv"))

    # Mermaid
    mmd_path = os.path.join(job_dir, f"netarch_topology{suffix}.mmd")
    with open(mmd_path, "w", encoding="utf-8") as f:
        f.write(_build_mermaid(visible_devs, visible_links))

    # JSON (full context)
    json_path = os.path.join(job_dir, f"netarch_scan{suffix}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(ctx.to_dict(), f, indent=2, default=str)

    return html_path


def get_draft_svg(ctx: ScanContext) -> str:
    """Return a draft SVG for the review UI."""
    return _build_svg(ctx.all_devices(), ctx.all_links(), is_draft=True)
