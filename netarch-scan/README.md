# NetArch Scan

**5-agent network discovery with human-verified architecture diagrams.**

NetArch Scan discovers your network using a pipeline of five agents, identifies every device (vendor, model, role), maps the links between them, verifies confidence scores, then pauses for a human reviewer before generating the final architecture diagram and report.

---

## 5-Agent Pipeline

```
┌────────────────────────────────────────────────────────────────────────┐
│  Agent 1: Discovery      Find live hosts (SNMP, TCP, ICMP, ARP)        │
│  Agent 2: Enrichment     Collect SNMP/HTTP/DNS; classify vendor/role   │
│  Agent 3: Links          Walk LLDP/CDP; crawl; gateway inference       │
│  Agent 4: Verification   Score confidence; flag issues; re-probe weak  │
│  ── PAUSE ──  Human review in web UI or CLI                            │
│  Agent 5: Human Review   Approve / reject / edit; then Finalize        │
└────────────────────────────────────────────────────────────────────────┘
```

Each agent owns a specific set of fields in the shared `ScanContext` blackboard and writes an audit entry for every change it makes.

---

## Quick Start

### Requirements

- Python 3.8+
- Flask 3.x (`pip install flask>=3.0`)

### Install

```bash
cd netarch-scan
pip install -r requirements.txt
```

### Web UI (recommended)

```bash
python app.py
# Open http://127.0.0.1:5002
```

Note: `http://127.0.0.1:5000` (or similar) is your lab web URL, not a scan target.
In NetArch Scan, enter device targets as IP/CIDR (for example `127.20.20.0/24`).

### CLI

```bash
# Single IP (lab)
python scan_cli.py 127.20.20.1 --port-offset 20000

# Subnet (lab) with LLDP crawl
python scan_cli.py 127.20.20.0/24 --community public --crawl 4

# Live network (requires approval)
python scan_cli.py 192.168.1.0/24 --live --gateway auto

# Auto review (CI/CD)
python scan_cli.py 127.20.20.0/24 --review auto --no-browser

# Skip review (lab demos)
python scan_cli.py 127.20.20.0/24 --review skip
```

---

## Lab / Live Detection

| Condition | Offset | Mode tag |
|---|---|---|
| All targets are `127.x.x.x` | 20000 (auto) | LAB |
| Any non-loopback target | 0 (auto) | LIVE |
| `--port-offset N` specified | N (manual) | as above |

---

## Review Workflow

1. After Agent 4 (Verification), the job status becomes **awaiting_review**.
2. The **Pipeline** tab shows a stepper with each agent's status and duration.
3. The **Review** tab shows:
   - Summary chips (pending / approved / edited / rejected / issues)
   - Device table with confidence bars, issue icons, Approve / Edit / Reject buttons
   - Links table with both-ends confirmation indicator
   - Live draft diagram (watermarked "DRAFT – pending review")
   - Finalize panel (reviewer name, approve-remaining checkbox, Finalize button)
4. **Finalize** is blocked if any device has critical issues and is still pending, unless you tick "approve remaining pending items".
5. On Finalize, all reports are written and the job status becomes **done**.
6. A finalized scan can be **reopened** (creates report v2, v3, …).

### Bulk actions

| Button | Effect |
|---|---|
| Approve safe | Approve devices with confidence ≥ 80 and no warning/critical issues |
| Approve all | Approve everything pending |
| Reject ARP-only | Reject devices discovered only from the ARP cache |

---

## Confidence Scoring

| Evidence | Points |
|---|---|
| SNMP identity (sysDescr / sysObjectID / sysName) | +40 |
| ENTITY-MIB model | +10 |
| Vendor from sysObjectID prefix | +15 |
| HTTP title / brand hint | +15 |
| MAC OUI vendor | +5 |
| Open ports | +5 |
| Seen in LLDP/CDP neighbour table | +10 |
| Reverse DNS | +5 |
| **Cap** | **100** |
| Neighbour-only device (base) | 40 |
| ARP-only device (base) | 20 |

---

## overrides.json

When you edit a device during review and tick **"Remember my corrections"**, the
edit is written to `overrides.json` in the project root. On the next scan, Agent 2
(Enrichment) loads this file and applies matching corrections automatically.

Matching order:
1. By MAC address (most reliable)
2. By IP + sysName

To clear all overrides, delete `overrides.json` or edit it manually.

---

## Gateway Inference

If a device does not expose LLDP or CDP, Agent 3 infers a link from the gateway
to the highest-tier device in each connected group that is on the gateway's LAN
but has no measured path to it. Inferred links have:
- `source = "inferred"`
- `confidence = 40`
- An info issue: *"assumed from gateway, not measured"*

To get measured links instead: enable SNMP + LLDP/CDP on network devices, or
run a crawl from a core switch.

---

## Optional: oui.csv (MAC vendor lookup)

Download the IEEE OUI list and place it as `oui.csv` in the project root:

```bash
# Format: prefix,vendor (first two columns)
# Source: https://maclookup.app/downloads/json-database
# or:     https://www.wireshark.org/download/automated/data/manuf
```

If the file is absent, MAC vendor lookup returns empty strings.

---

## Optional: AI Explanations

Enable in the web UI ("AI explanations" toggle) or via the LLM settings.
Set the following environment variables before starting the app:

```bash
# OpenAI-compatible endpoint (e.g. local Ollama)
export NETARCH_LLM_URL=http://localhost:11434/v1
export NETARCH_LLM_MODEL=llama3

# Azure OpenAI
export NETARCH_LLM_URL=https://<resource>.openai.azure.com/openai/deployments/<dep>
export NETARCH_LLM_MODEL=gpt-4o
```

Only the device summary and issue list are sent — no IP credentials or
SNMP community strings.  If the call fails, the scan continues without it.

---

## Shared Contract with NetArch Lab

| Setting | Value |
|---|---|
| Lab subnet | `127.20.20.0/24` |
| Port offset | `+20000` on every service |
| SNMP port | UDP 20161 |
| SSH port | TCP 20022 |
| HTTP port | TCP 20080 |
| Community | `public` (read-only) |
| Lab info endpoint | `GET <lab-url>/api/info` |

The scanner learns about lab devices **only by scanning them** — it never reads
the lab's configuration files.

---

## REST API (selected endpoints)

| Method | Path | Description |
|---|---|---|
| POST | `/api/scan` | Start a scan job |
| GET | `/api/scans` | List all jobs |
| GET | `/api/scans/<id>` | Job status, agent runs, log |
| GET | `/api/scans/<id>/review` | Devices, links, issues, draft SVG |
| PUT | `/api/scans/<id>/devices/<key>` | Approve / reject / edit a device |
| PUT | `/api/scans/<id>/links/<key>` | Approve / reject / edit a link |
| POST | `/api/scans/<id>/links` | Add a manual link |
| POST | `/api/scans/<id>/bulk` | Bulk approve / reject |
| POST | `/api/scans/<id>/rerun/<agent>` | Rerun from an agent |
| POST | `/api/scans/<id>/finalize` | Finalize and generate reports |
| POST | `/api/scans/<id>/discard` | Discard a scan |
| POST | `/api/scans/<id>/reopen` | Reopen a finalized scan |
| GET | `/api/lab-info?url=` | Server-side proxy to NetArch Lab |
| GET | `/scans/<id>/<file>` | Download report files |

---

## Security Notes

- The web app binds to `127.0.0.1` by default.  To expose on the network,
  use `--host 0.0.0.0` and restrict access with a firewall or reverse proxy.
- **There is no login system.** Reviewer names are stored in the audit log
  but are not authenticated.
- **Never scan networks without explicit authorization.**  The CLI shows a
  mandatory approval prompt for live (non-loopback) scans; the web API
  requires the `"I have approval to scan"` string.
- The SNMP community string is transmitted in plaintext (SNMPv2c).
  Use SNMPv3 on production networks where possible.

---

## Running the Tests

```bash
# Unit tests (no lab required)
python -m pytest tests/ -v

# Or directly:
python tests/test_netarch.py
```

Test coverage includes:
- BER encode/decode round-trips
- Target parsing (CIDR, range, list, too-large, bad host)
- Classification (CAT9K_IOSXE, ex4100, FortiGate, NVR title, LaserJet)
- Confidence scoring
- Vendor-conflict detection
- One-sided link confidence (70), two-sided (100)
- LLDP management address OID parsing
- ScanContext serialization round-trip

---

## Project Structure

```
netarch-scan/
  netarch/
    __init__.py
    snmp.py             # SNMPv2c BER client (GET, GETNEXT, walk)
    probes.py           # TCP, HTTP, ping, ARP, gateway, OUI, target parsing
    classify.py         # Vendor / model / role / tier rules + confidence
    context.py          # ScanContext: thread-safe blackboard + audit
    agents/
      base.py           # BaseAgent
      discovery.py      # Agent 1 – find live hosts
      enrichment.py     # Agent 2 – collect data, classify, overrides
      links.py          # Agent 3 – LLDP/CDP, crawl, gateway inference
      verification.py   # Agent 4 – confidence, issues, re-probe, LLM
      review.py         # Agent 5 – transition to awaiting_review
    orchestrator.py     # Pipeline runner, job lifecycle, finalize
    report.py           # SVG, HTML report, CSV, Mermaid, JSON
  scan_cli.py           # CLI (interactive / auto / skip review)
  app.py                # Flask web app on port 5002
  templates/index.html  # Single-page UI (plain HTML/CSS/JS, no CDN)
  overrides.json        # Human corrections (created on first approval)
  requirements.txt      # flask>=3.0
  oui.csv               # Optional IEEE MAC vendor list
  tests/
    test_netarch.py     # Unit tests
```
