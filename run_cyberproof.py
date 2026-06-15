import sys
import os
import argparse
import json
import re
import hashlib
import shutil
from datetime import datetime, timedelta, timezone
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import logging
logging.getLogger('yprov4wfs').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('httpcore').setLevel(logging.WARNING)
logging.getLogger('huggingface_hub').setLevel(logging.WARNING)
logging.getLogger('requests').setLevel(logging.WARNING)
logging.disable(logging.DEBUG)

script_dir    = os.path.dirname(os.path.abspath(__file__))
yprov4wfs_dir = os.path.join(script_dir, 'yprov4wfs')
sys.path.insert(0, yprov4wfs_dir)
sys.path.insert(0, script_dir)

from yprov4wfs.yProv4WFs_SOAR import SOARAdapter
from mcp_enrichment import enrich_container
from generate_evidence import (
    generate_evidence,
    extract_case_metadata,
    extract_incident_time,
    compute_response_time,
    compute_financial_impact,
)

SOAR_URL      = os.environ.get("SOAR_URL", "")
SOAR_USERNAME = os.environ.get("SOAR_USERNAME", "")
SOAR_PASSWORD = os.environ.get("SOAR_PASSWORD", "")
SPLUNK_URL    = os.environ.get("SPLUNK_URL", "")
HEC_URL       = os.environ.get("HEC_URL", "")

_missing = [k for k in ("SOAR_URL", "SOAR_USERNAME", "SOAR_PASSWORD") if not os.environ.get(k)]
if _missing:
    print(f"[FAIL] Missing required environment variables: {', '.join(_missing)}")
    print("       Copy .env.example → .env and fill in your values.")
    sys.exit(1)

PROV_DIR   = os.path.join(script_dir, 'prov_output')
OUTPUT_DIR = os.path.join(script_dir, 'output')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── CLI args ───────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="CyberProof pipeline: SOAR → MCP enrichment → evidence package")
parser.add_argument("--container_id", type=int, required=True,
                    help="SOAR container ID to process (e.g. --container_id 8)")
args = parser.parse_args()
container_id = args.container_id

# ── Step 1: SOAR provenance ────────────────────────────────────────────────
print(f"\n{'='*55}")
print(f"STEP 1 — Extracting provenance for container {container_id}")
print(f"{'='*55}")
print(f"Connecting to SOAR at {SOAR_URL} ...")

adapter = SOARAdapter(
    base_url=SOAR_URL,
    username=SOAR_USERNAME,
    password=SOAR_PASSWORD,
    verify_ssl=False,
)

if not adapter.authenticate():
    print("[FAIL] Authentication failed")
    sys.exit(1)
print("[OK] Authenticated")

containers = adapter.fetch_containers()
if not containers:
    print("[FAIL] No containers returned by SOAR")
    sys.exit(1)

available = {c.get("id"): c for c in containers}
print(f"[INFO] Available containers: {list(available.keys())}")

if container_id not in available:
    print(f"[FAIL] Container {container_id} not found in SOAR")
    print(f"       Available IDs: {list(available.keys())}")
    sys.exit(1)

container = available[container_id]
print(f"[INFO] Processing: {container.get('name', '(no name)')} (ID {container_id})")

playbook_runs = adapter.fetch_playbook_runs(container_id)
print(f"[INFO] Playbook runs found: {len(playbook_runs)}")
if not playbook_runs:
    print("[FAIL] No playbook runs — nothing to map for this container")
    sys.exit(1)

for pr in playbook_runs:
    action_runs = adapter.fetch_action_runs(pr.get("id"))
    print(f"  Playbook run {pr.get('id')}: {len(action_runs)} action run(s)")

os.makedirs(PROV_DIR, exist_ok=True)
prov_file = adapter.build_provenance_workflow(
    output_dir=PROV_DIR,
    container_id=container_id,
)

if not prov_file:
    print("[FAIL] build_provenance_workflow returned nothing")
    sys.exit(1)
print(f"[OK] Provenance saved to: {prov_file}")

with open(prov_file, "rb") as f:
    prov_hash = hashlib.sha256(f.read()).hexdigest()
sha256_path = prov_file.replace(".json", ".sha256")
with open(sha256_path, "w") as f:
    f.write(prov_hash + "\n")
shutil.copy2(prov_file,   os.path.join(OUTPUT_DIR, os.path.basename(prov_file)))
shutil.copy2(sha256_path, os.path.join(OUTPUT_DIR, os.path.basename(sha256_path)))
print(f"[OK] Provenance hash: {prov_hash}")

# ── Provenance graph → SVG ─────────────────────────────────────────────────
# ── Provenance graph → SVG ─────────────────────────────────────────────────
prov_svg_path = None
try:
    import subprocess
    import prov.model
    import prov.dot as _provdot

    _svg_name = f"yProv4WFs_SOAR_{container_id}.svg"
    _dot_name = f"yProv4WFs_SOAR_{container_id}.dot"
    _dot_path = os.path.join(PROV_DIR, _dot_name)
    prov_svg_path = os.path.join(OUTPUT_DIR, _svg_name)

    with open(prov_file, "r", encoding="utf-8") as _f:
        _doc = prov.model.ProvDocument.deserialize(_f)

    with open(_dot_path, "w", encoding="utf-8") as _f:
        _f.write(_provdot.prov_to_dot(_doc).to_string())

    subprocess.run(
        ["dot", "-Tsvg", _dot_path, "-o", prov_svg_path],
        check=True,
        capture_output=True,
        text=True,
    )

    print(f"[OK] Provenance SVG:  {prov_svg_path}")

except ImportError as e:
    prov_svg_path = None
    print(f"[WARN] SVG import failed: {e}")
    print("[HINT] Run: python -m pip install prov pydot")

except FileNotFoundError:
    prov_svg_path = None
    print("[WARN] Graphviz 'dot' not on PATH — SVG skipped")
    print("[HINT] Install Graphviz and make sure 'dot' works from terminal")

except subprocess.CalledProcessError as e:
    prov_svg_path = None
    print(f"[WARN] Graphviz failed: {e.stderr or e}")

except Exception as _e:
    prov_svg_path = None
    print(f"[WARN] SVG generation failed: {_e}")

# ── Step 2: MCP enrichment ─────────────────────────────────────────────────
print(f"\n{'='*55}")
print(f"STEP 2 — Enriching with Splunk MCP forensic data")
print(f"{'='*55}")

enrichment = None
try:
    enrichment = enrich_container(container_id)
    print("[OK] MCP enrichment complete")
except EnvironmentError as e:
    print(f"[WARN] Skipping MCP enrichment: {e}")
except Exception as e:
    print(f"[WARN] MCP enrichment failed, continuing without it: {e}")

# ── Step 3: Generate evidence package ──────────────────────────────────────
print(f"\n{'='*55}")
print(f"STEP 3 — Generating insurance evidence package")
print(f"{'='*55}")

evidence = generate_evidence(container_id, enrichment)
print("[OK] Evidence package generated")

# ── Step 4: Build and publish outputs ──────────────────────────────────────
print(f"\n{'='*55}")
print(f"STEP 4 — Building outputs")
print(f"{'='*55}")

# ── Output 4: enrichment JSON + raw_evidence_summary ──────────────────────
enrich_path = os.path.join(OUTPUT_DIR, f"mcp_enrichment_results_{container_id}.json")
if enrichment:
    summary_lines = []
    for key, rows in enrichment.items():
        if key in ("container_id", "raw_evidence_summary"):
            continue
        if not isinstance(rows, list) or not rows:
            continue
        summary_lines.append(f"Action: {key}")
        for i, row in enumerate(rows[:3]):
            fields = ", ".join(
                f"{k}={str(v)[:80]}"
                for k, v in row.items()
                if not str(v).startswith("/9j/")
            )
            summary_lines.append(f"  Row {i+1}: {fields}")
    enrichment["raw_evidence_summary"] = "\n".join(summary_lines)
    with open(enrich_path, "w", encoding="utf-8") as f:
        json.dump(enrichment, f, indent=2)
    print(f"[OUTPUT] Enrichment:   {enrich_path}")

# ── Output 3: evidence PDF ─────────────────────────────────────────────────
pdf_path = None
try:
    from fpdf import FPDF
    pdf = FPDF()
    pdf.set_margins(15, 15, 15)
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", size=9)
    page_w = pdf.w - pdf.l_margin - pdf.r_margin
    for line in evidence.split("\n"):
        safe = line.encode("latin-1", errors="replace").decode("latin-1")
        if not safe.strip():
            pdf.ln(3)
        else:
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(page_w, 4, safe[:300])
    pdf_path = os.path.join(OUTPUT_DIR, f"evidence_package_{container_id}.pdf")
    pdf.output(pdf_path)
    print(f"[OUTPUT] Evidence PDF: {pdf_path}")
except ImportError:
    print("[WARN] fpdf2 not installed — PDF skipped (pip install fpdf2)")
except Exception as e:
    print(f"[WARN] PDF generation failed: {e}")

# ── Output 2: Splunk dashboard JSON ───────────────────────────────────────
prov_path = os.path.join(PROV_DIR, f"yProv4WFs_SOAR_{container_id}.json")
with open(prov_path, "r", encoding="utf-8") as f:
    prov_graph = json.load(f)

with open(os.path.join(script_dir, "evidence_config.json"), "r") as f:
    _cfg = json.load(f)
_inc = _cfg["incident"]
_hrs = _cfg["deadlines_hours"]

case     = extract_case_metadata(prov_graph)
det_ts   = extract_incident_time(prov_graph)
resp_sec = compute_response_time(prov_graph)
fi       = compute_financial_impact(resp_sec)

activities = prov_graph.get("activity", {})
actions = [
    {
        "name":    act.get("prov:label", key),
        "started": act.get("prov:startTime"),
        "ended":   act.get("prov:endTime"),
        "status":  act.get("yprov4wfs:status"),
    }
    for key, act in activities.items()
    if act.get("yprov4wfs:level") == "2"
]

_PRIVATE_IP_RE = re.compile(
    r'^(10\.\d+\.\d+\.\d+'
    r'|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+'
    r'|192\.168\.\d+\.\d+)$'
)
_ANY_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')

attacker_commands, affected_hosts_set, external_ips = [], set(), set()
if enrichment:
    for key, rows in enrichment.items():
        if key in ("container_id", "raw_evidence_summary") or not isinstance(rows, list):
            continue
        for row in rows:
            cmd = str(row.get("CommandLine", ""))
            if cmd:
                attacker_commands.append(cmd)
            for m in _ANY_IP_RE.finditer(cmd):
                ip = m.group(1)
                if _PRIVATE_IP_RE.match(ip):
                    affected_hosts_set.add(ip)
                else:
                    external_ips.add(ip)
            if row.get("Computer"):
                affected_hosts_set.add(str(row["Computer"]))
            if row.get("host"):
                affected_hosts_set.add(str(row["host"]))
            if row.get("dest_ip") and not _PRIVATE_IP_RE.match(str(row["dest_ip"])):
                external_ips.add(str(row["dest_ip"]))

dashboard = {
    "container_id":    container_id,
    "pipeline_run_at": datetime.now(timezone.utc).isoformat(),
    "incident": {
        "detection_timestamp": det_ts.isoformat(),
        "incident_date":       det_ts.strftime("%Y-%m-%d"),
        "incident_type":       _inc["incident_type"],
        "attacker_ip":         _inc["attacker_ip"],
        "compromised_system":  _inc["compromised_system"],
        "company":             _inc["company_name"],
    },
    "response": {
        "playbook_run_ids":       case["playbook_run_ids"],
        "actions":                actions,
        "total_response_seconds": resp_sec,
        "prepared_by":            case["prepared_by"],
        "engine":                 case["engine"],
    },
    "forensic_summary": {
        "total_events":         len(attacker_commands),
        "attack_commands_count": len(set(attacker_commands)),
        "affected_hosts":        sorted(affected_hosts_set),
        "external_ips_seen":     sorted(external_ips),
    },
    "financial_impact_usd": {
        "downtime": round(fi["downtime"], 2),
        "forensic": fi["forensic"],
        "breach":   round(fi["breach"], 2),
        "total":    round(fi["total_usd"], 2),
    },
    "regulatory_deadlines": {
        "nis2_early_warning":          (det_ts + timedelta(hours=_hrs["nis2_notification"])).isoformat(),
        "gdpr_article_33":             (det_ts + timedelta(hours=_hrs["gdpr_notification"])).isoformat(),
        "insurance_notification":      (det_ts + timedelta(hours=_hrs["insurance_notification"])).isoformat(),
        "nis2_hours_remaining":        round(((det_ts + timedelta(hours=_hrs["nis2_notification"])) - datetime.now()).total_seconds() / 3600, 2),
        "gdpr_hours_remaining":        round(((det_ts + timedelta(hours=_hrs["gdpr_notification"])) - datetime.now()).total_seconds() / 3600, 2),
        "insurance_hours_remaining":   round(((det_ts + timedelta(hours=_hrs["insurance_notification"])) - datetime.now()).total_seconds() / 3600, 2),
    },
    "artifacts": {
        "prov_graph":                f"prov_output/yProv4WFs_SOAR_{container_id}.json",
        "enrichment":                f"output/mcp_enrichment_results_{container_id}.json",
        "evidence_txt":              f"output/evidence_package_{container_id}.txt",
        "evidence_pdf":              f"output/evidence_package_{container_id}.pdf" if pdf_path else None,
        "provenance_standard":        "W3C PROV",
        "provenance_hash":            prov_hash,
        "provenance_svg":             f"output/yProv4WFs_SOAR_{container_id}.svg" if prov_svg_path else None,
        "evidence_sections_complete": len(re.findall(r'^\d+\.', evidence, re.MULTILINE)),
    },
}

dashboard_path = os.path.join(OUTPUT_DIR, f"cyberproof_dashboard_{container_id}.json")
with open(dashboard_path, "w", encoding="utf-8") as f:
    json.dump(dashboard, f, indent=2)
print(f"[OUTPUT] Dashboard:    {dashboard_path}")

# ── Post dashboard to Splunk HEC ───────────────────────────────────────────
HEC_TOKEN = os.environ.get("HEC_TOKEN")
if not HEC_TOKEN:
    print("[WARN] HEC_TOKEN not set — skipping Splunk HEC post")
else:
    hec_url = HEC_URL + "/services/collector/event"
    payload = {
        "sourcetype": "cyberproof:dashboard",
        "index":      "cyberproof",
        "event":      dashboard,
    }
    headers = {
        "Authorization": f"Splunk {HEC_TOKEN}",
        "Content-Type":  "application/json",
    }
    try:
        resp = requests.post(hec_url, json=payload, headers=headers, verify=False, timeout=10)
        if resp.status_code == 200:
            print("[OK] Dashboard posted to Splunk index=cyberproof")
        else:
            print(f"[WARN] HEC post failed: {resp.status_code} {resp.text}")
    except requests.exceptions.ConnectTimeout:
        print(f"[WARN] HEC post timed out — {hec_url} unreachable (check VPN / HEC enabled)")
    except Exception as e:
        print(f"[WARN] HEC post failed: {e}")

print(f"\n[OUTPUT] 4 artifacts saved to output/")
