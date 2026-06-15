import argparse
import json
import os
import re
import time
import requests as _requests
from datetime import datetime, timedelta, timezone

# ── Config ──────────────────────────────────────────────────────────────────
_script_dir = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_script_dir, "evidence_config.json"), "r") as _f:
    _cfg = json.load(_f)

_fin  = _cfg["financial"]
_hrs  = _cfg["deadlines_hours"]
_inc  = _cfg["incident"]
_path = _cfg["paths"]

_TS_FORMATS = (
    '%Y-%m-%d %H:%M:%S.%f',
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%dT%H:%M:%S.%f',
    '%Y-%m-%dT%H:%M:%S',
)


def _parse_ts(ts: str) -> datetime | None:
    if not ts or ts == "None":
        return None
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(ts.rstrip('Z'), fmt)
        except ValueError:
            continue
    return None


def extract_incident_time(prov: dict) -> datetime:
    times = [
        t for act in prov.get("activity", {}).values()
        if (t := _parse_ts(act.get("prov:startTime", ""))) is not None
    ]
    return min(times) if times else datetime.now(timezone.utc).replace(tzinfo=None)


def compute_response_time(prov: dict) -> float:
    starts, ends = [], []
    for act in prov.get("activity", {}).values():
        if act.get("yprov4wfs:level") != "2":
            continue
        if t := _parse_ts(act.get("prov:startTime", "")):
            starts.append(t)
        if t := _parse_ts(act.get("prov:endTime", "")):
            ends.append(t)
    return (max(ends) - min(starts)).total_seconds() if starts and ends else 0.0


def extract_case_metadata(prov: dict) -> dict:
    activities = prov.get("activity", {})
    agents     = prov.get("agent", {})

    container_id = next(
        (act.get("yprov4wfs:container_id")
         for act in activities.values() if act.get("yprov4wfs:container_id")),
        "unknown"
    )
    playbook_run_ids = [
        act.get("yprov4wfs:playbook_run_id", key.replace("soar_playbook_run_", ""))
        for key, act in activities.items()
        if act.get("yprov4wfs:level") == "1"
    ]
    prepared_by = next(
        (agent.get("prov:label", key.replace("soar_user_", ""))
         for key, agent in agents.items() if key.startswith("soar_user_")),
        "unknown"
    )
    engine_name = next(
        (agent.get("prov:label", "Splunk SOAR")
         for key, agent in agents.items() if key == "splunk_soar_platform"),
        "Splunk SOAR"
    )
    return {
        "container_id":     container_id,
        "playbook_run_ids": playbook_run_ids,
        "prepared_by":      prepared_by,
        "engine":           f"{engine_name} {_inc['soar_version']}",
    }


def compute_financial_impact(response_seconds: float) -> dict:
    downtime = _fin["downtime_rate_per_hour_usd"] * (response_seconds / 3600)
    breach   = _fin["breach_notification_usd_per_record"] * _fin["estimated_affected_records"]
    total    = downtime + _fin["forensic_cost_usd"] + breach
    return {
        "response_seconds": response_seconds,
        "downtime":         downtime,
        "forensic":         _fin["forensic_cost_usd"],
        "breach":           breach,
        "total_usd":        total,
    }


def extract_event_count(summary: str) -> str:
    match = re.search(r'Total events:\s*(\d+)', summary)
    if match:
        return f"Total events: {match.group(1)}"
    try:
        data = json.loads(summary)
        if isinstance(data, dict):
            return str(data.get("message") or data.get("count") or summary)
    except (json.JSONDecodeError, ValueError):
        pass
    clean = re.sub(r'\{.*?\}', '', summary, flags=re.DOTALL).strip()
    return clean or summary


def build_narrative(prov: dict) -> tuple[str, str]:
    activities  = prov.get("activity", {})
    entities    = prov.get("entity", {})
    agents      = prov.get("agent", {})
    informed_by = prov.get("wasInformedBy", {})

    narrative = ["=== INCIDENT PROVENANCE CHAIN ===\n"]

    narrative.append("ATTACK RESPONSE TIMELINE:")
    for key, act in activities.items():
        if act.get("yprov4wfs:level") == "2":
            narrative.append(f"  - Action: {act.get('prov:label', key)}")
            narrative.append(f"    Started: {act.get('prov:startTime', 'unknown')}")
            narrative.append(f"    Ended:   {act.get('prov:endTime', 'unknown')}")
            narrative.append(f"    Status:  {act.get('yprov4wfs:status', 'unknown')}")

    narrative.append("\nCAUSAL CHAIN (W3C PROV wasInformedBy):")
    for rel in informed_by.values():
        informed  = rel.get("prov:informed", "")
        informant = rel.get("prov:informant", "")
        narrative.append(
            f"  - '{activities.get(informed, {}).get('prov:label', informed)}'"
            f" was triggered by"
            f" '{activities.get(informant, {}).get('prov:label', informant)}'"
        )

    evidence_lines = []
    narrative.append("\nEVIDENCE COLLECTED:")
    for key, entity in entities.items():
        summary = entity.get("yprov4wfs:result_summary", "")
        if summary:
            label = entity.get("prov:label", key)
            clean = extract_event_count(summary)
            line  = f"{label}: {clean}"
            narrative.append(f"  - {line}")
            evidence_lines.append(line)

    narrative.append("\nACTORS INVOLVED:")
    for key, agent in agents.items():
        narrative.append(f"  - {agent.get('prov:label', key)}")

    return "\n".join(narrative), "\n".join(f"- {e}" for e in evidence_lines)


def _all_rows(enrichment: dict) -> list:
    rows = []
    for key, value in enrichment.items():
        if key in ("container_id", "raw_evidence_summary") or not isinstance(value, list):
            continue
        for row in value:
            if not isinstance(row, dict):
                continue
            if any("/9j/4AA" in str(v) for v in row.values()):
                continue
            rows.append(row)
    return rows


def _build_forensic_narrative(enrichment: dict) -> str:
    timeline_rows: list[dict] = []
    host_rows:     list[dict] = []
    network_rows:  list[dict] = []

    for key, value in enrichment.items():
        if key in ("container_id", "raw_evidence_summary") or not isinstance(value, list):
            continue
        for row in value:
            if not isinstance(row, dict):
                continue
            if any("/9j/4AA" in str(v) for v in row.values()):
                continue
            if row.get("src_ip") or row.get("dest_ip"):
                network_rows.append(row)
            elif row.get("Computer") or (row.get("count") and not row.get("_time")):
                host_rows.append(row)
            elif row.get("_time") or row.get("Image") or row.get("CommandLine"):
                timeline_rows.append(row)

    if not timeline_rows and not host_rows and not network_rows:
        return ""

    lines = ["FORENSIC EVIDENCE FROM SPLUNK MCP SERVER (BOTS v3):"]

    if timeline_rows:
        lines.append("\nATTACKER TIMELINE (EventID 1 — Process Creation):")
        seen: set[tuple] = set()
        unique: list[dict] = []
        for row in timeline_rows:
            k = (row.get("_time"), row.get("CommandLine"))
            if k not in seen:
                seen.add(k)
                unique.append(row)
        for row in unique[:10]:
            ts  = row.get("_time", "?")
            img = row.get("Image", "?")
            cmd = row.get("CommandLine") or row.get("uri_path") or "?"
            lines.append(f"  {ts} — {img} — {cmd}")

    if host_rows:
        lines.append(f"\nAFFECTED SYSTEMS ({len(host_rows)} host(s)):")
        for row in host_rows:
            lines.append(f"  {row.get('Computer', '?')}: {row.get('count', '?')} event(s)")

    if network_rows:
        lines.append("\nNETWORK C2 CONNECTIONS TO/FROM ATTACKER IP:")
        seen_net: set[tuple] = set()
        for row in network_rows:
            k = (row.get("_time"), row.get("src_ip"), row.get("dest_ip"), row.get("uri_path"))
            if k in seen_net:
                continue
            seen_net.add(k)
            lines.append(
                f"  {row.get('_time','?')} — {row.get('src_ip','?')} → "
                f"{row.get('dest_ip','?')} — {row.get('uri_path','?')}"
            )
            if len(seen_net) >= 10:
                break

    return "\n".join(lines)


def _build_affected_data_classification(enrichment: dict, compromised_system: str) -> str:
    all_rows = _all_rows(enrichment)

    affected_hosts = enrichment.get("affected_hosts", [])
    host_names = [h.get("Computer", "") for h in affected_hosts if h.get("Computer")]

    if not affected_hosts:
        host_set: set[str] = set()
        for row in all_rows:
            for m in re.finditer(r'https?://([\d]{1,3}(?:\.[\d]{1,3}){3})',
                                  str(row.get("CommandLine", ""))):
                host_set.add(m.group(1))
            if row.get("host"):
                host_set.add(str(row["host"]))
            if row.get("Computer"):
                host_set.add(str(row["Computer"]))
        host_names = sorted(host_set)
    host_count = len(affected_hosts) if affected_hosts else len(host_names)

    app_exploited = next(
        (str(r.get("CommandLine") or r.get("_raw", "")) for r in all_rows
         if "struts" in str(r.get("CommandLine", r.get("_raw", ""))).lower()
         or "showcase" in str(r.get("CommandLine", r.get("_raw", ""))).lower()),
        None
    )
    creds_accessed = next(
        (str(r.get("CommandLine", "")) for r in all_rows
         if "/etc/passwd" in str(r.get("CommandLine", ""))),
        None
    )

    lines = [
        f"System compromised: Inventory application server {compromised_system}",
        "Data types potentially exposed: Customer records, inventory data, system credentials",
        "Personal data involved: Yes — GDPR Article 33 notification required",
        "Data subjects potentially affected: Under investigation",
        f"Number of affected hosts: {host_count}",
        f"Affected host names: {', '.join(host_names) if host_names else 'Under investigation'}",
    ]
    if app_exploited:
        lines.append(f"Application exploited: {app_exploited[:150]}")
    if creds_accessed:
        lines.append(f"Credentials accessed: {creds_accessed[:150]}")

    return "\n".join(lines)


# ── Token helpers ────────────────────────────────────────────────────────────
_SAUL_URL      = "https://router.huggingface.co/featherless-ai/v1/chat/completions"
_SAUL_CTX      = 4096
_BACKOFF_CODES = {429, 500, 502, 503, 504}


def estimate_tokens(text: str) -> int:
    """Conservative token count: chars/2.
    Security log content (IPs, URLs, hashes) tokenizes at ~1.7 chars/token;
    dividing by 2 safely over-estimates to prevent context overflow."""
    return max(1, len(text) // 2)


def calculate_safe_max_tokens(
    prompt_messages: list,
    requested_max_tokens: int = 500,
    context_limit: int = _SAUL_CTX,
    safety_margin: int = 128,
) -> tuple[int, int]:
    """Return (safe_max_tokens, estimated_prompt_tokens).

    Caps output so that prompt + output <= context_limit - safety_margin.
    """
    prompt_text = "".join(m.get("content", "") for m in prompt_messages)
    est_prompt  = estimate_tokens(prompt_text)
    safe_max    = context_limit - est_prompt - safety_margin
    return max(50, min(requested_max_tokens, safe_max)), est_prompt


# ── Per-section LLM call ────────────────────────────────────────────────────

def call_saul_section(
    section_name: str,
    section_instruction: str,
    evidence_context: str,
    hf_token: str,
    requested_max_tokens: int = 500,
) -> str:
    """Call SaulLM-7B once to generate a single evidence-package section.

    Retry strategy
    --------------
    400 context overflow  → parse server-suggested max_tokens, retry ONCE immediately (no sleep).
    429 / 5xx             → exponential backoff, up to 2 retries (10 s, 20 s).
    Other 400 / unknown   → no retry; return failure placeholder.
    """
    system_msg = (
        "You are a cyber insurance claim expert. "
        "Be concise and specific. Output only the requested section."
    )

    def _msgs(ctx: str) -> list:
        return [
            {"role": "system", "content": system_msg},
            {
                "role": "user",
                "content": (
                    f"=== INCIDENT DATA ===\n{ctx}\n\n"
                    f"=== TASK ===\n{section_instruction}"
                ),
            },
        ]

    messages = _msgs(evidence_context)
    safe_max, est_prompt = calculate_safe_max_tokens(messages, requested_max_tokens)
    compressed = False

    if safe_max < 100:
        # Context too tight — halve the shared context and recalculate
        trimmed_ctx = evidence_context[: len(evidence_context) // 2] + "\n[...truncated...]"
        messages    = _msgs(trimmed_ctx)
        safe_max, est_prompt = calculate_safe_max_tokens(messages, requested_max_tokens)
        compressed  = True

    tag = " [COMPRESSED]" if compressed else ""
    print(f"  [{section_name}] est_prompt={est_prompt}t  max_tokens={safe_max}{tag}")

    headers = {
        "Authorization": f"Bearer {hf_token}",
        "Content-Type":  "application/json",
    }
    payload = {
        "model":       "Equall/Saul-7B-Instruct-v1",
        "messages":    messages,
        "max_tokens":  safe_max,
        "temperature": 0.1,
    }

    backoff_count = 0
    while True:
        resp = _requests.post(_SAUL_URL, headers=headers, json=payload, timeout=120)

        if resp.ok:
            return resp.json()["choices"][0]["message"]["content"]

        code     = resp.status_code
        err_text = resp.text

        if code == 400:
            m = re.search(r"Reduce max_tokens to at most (\d+)", err_text)
            if m:
                new_max = max(50, int(m.group(1)) - 20)
                print(
                    f"  [{section_name}] Context overflow → "
                    f"max_tokens {payload['max_tokens']} → {new_max}  (immediate retry)"
                )
                payload["max_tokens"] = new_max
                r2 = _requests.post(_SAUL_URL, headers=headers, json=payload, timeout=120)
                if r2.ok:
                    return r2.json()["choices"][0]["message"]["content"]
                print(f"  [{section_name}] Context retry failed: {r2.text[:200]}")
            else:
                print(f"  [{section_name}] 400 error: {err_text[:200]}")
            break  # no further retries for 400

        if code in _BACKOFF_CODES:
            backoff_count += 1
            if backoff_count > 2:
                print(f"  [{section_name}] Giving up after {backoff_count} transient retries")
                break
            wait = 10 * backoff_count
            print(f"  [{section_name}] {code} — retrying in {wait}s …")
            time.sleep(wait)
            continue

        print(f"  [{section_name}] {code} (no retry): {err_text[:200]}")
        break

    return f"[{section_name}: generation failed]"


# ── Section definitions ──────────────────────────────────────────────────────

_SECTIONS: list[tuple[str, str, int]] = [
    (
        "Legal Defensibility",
        """Assess the legal defensibility of this cyber insurance claim in 3-4 sentences.
Cover:
1. Whether the W3C PROV provenance chain constitutes court-admissible evidence.
2. Chain of custody integrity — collection method and verification tool.
3. Whether the automated SOAR execution log proves causal responsibility.

End your response with exactly this line:
LEGAL DEFENSIBILITY SCORE: STRONG / ADEQUATE / WEAK — [one-line rationale]""",
        500,
    ),
    (
        "Completeness Assessment",
        """Assess the completeness of this incident documentation in 3-4 sentences.
Cover:
1. Whether all required insurance claim fields are present.
2. What evidence is missing, unclear, or needs corroboration.
3. Whether the playbook execution timeline is complete.

End your response with exactly this line:
COMPLETENESS SCORE: COMPLETE / PARTIAL / INCOMPLETE — [one-line rationale]""",
        500,
    ),
    (
        "Regulatory Compliance",
        """Assess regulatory obligations. For each, state: deadline, whether it can be met, required action.
- NIS2 Article 23: 24-hour early warning to national authority
- GDPR Article 33: 72-hour notification to supervisory authority
- Insurance policy: 48-hour notification to insurer

End your response with exactly this line:
COMPLIANCE STATUS: NIS2=[ON TRACK|AT RISK|BREACHED]  GDPR=[ON TRACK|AT RISK|BREACHED]  INSURANCE=[ON TRACK|AT RISK|BREACHED]""",
        500,
    ),
    (
        "Financial Accuracy",
        """Validate the financial impact estimates in 3-4 sentences.
Cover:
1. Downtime cost: confirm rate × duration is correct.
2. Forensic investigation: confirm figure is industry-defensible.
3. Data breach notification: confirm per-record rate × records is reasonable.
4. Confirm USD total and EUR regulatory fine are correctly separated.

End your response with exactly this line:
FINANCIAL ACCURACY: VERIFIED / OVERSTATED / UNDERSTATED — [one-line rationale]""",
        500,
    ),
    (
        "Claim Approval Likelihood",
        """Estimate insurance claim approval likelihood in 3-4 sentences.
Cover:
1. Which coverage clauses apply: Business Interruption, Cyber Liability, Data Breach, Network Security.
2. Strength of evidence for each applicable clause.
3. Key risks that could lead to claim denial.

End your response with exactly this line:
CLAIM APPROVAL LIKELIHOOD: HIGH / MEDIUM / LOW — [one-line rationale]""",
        500,
    ),
]


# ── Shared context builder ───────────────────────────────────────────────────

def _build_evidence_context(
    case: dict,
    detection_ts: datetime,
    fi: dict,
    narrative: str,
    forensic_narrative: str,
    affected_data_section: str,
    container_id: int,
) -> str:
    """Compact, token-efficient incident summary passed to every section call."""
    ts_fmt  = "%Y-%m-%d %H:%M:%S UTC"
    nis2_dl = (detection_ts + timedelta(hours=_hrs["nis2_notification"])).strftime(ts_fmt)
    gdpr_dl = (detection_ts + timedelta(hours=_hrs["gdpr_notification"])).strftime(ts_fmt)
    ins_dl  = (detection_ts + timedelta(hours=_hrs["insurance_notification"])).strftime(ts_fmt)

    # Trim bulky free-text sections so the shared context stays compact
    narrative_short    = narrative[:1200]         if len(narrative)         > 1200 else narrative
    forensic_short     = forensic_narrative[:800] if len(forensic_narrative) > 800  else forensic_narrative
    affected_short     = affected_data_section[:400] if len(affected_data_section) > 400 else affected_data_section

    parts = [
        f"Container ID: {container_id}",
        f"INCIDENT: {_inc['incident_type']}",
        f"Company: {_inc['company_name']}  |  Date: {detection_ts.strftime('%Y-%m-%d')}",
        f"Attacker IP: {_inc['attacker_ip']}  |  Target: {_inc['compromised_system']}",
        f"Process: {_inc['malicious_process']}  |  Backdoor: {_inc['backdoor_account']}",
        f"Response time: {fi['response_seconds']:.0f}s  |  Prepared by: {case['prepared_by']}",
        f"Engine: {case['engine']}  |  Playbook run(s): {', '.join(case['playbook_run_ids'])}",
        "Provenance standard: W3C PROV-JSON",
        "",
        "FINANCIAL IMPACT (USD):",
        f"  Downtime:  ${fi['downtime']:,.2f}  "
        f"(${_fin['downtime_rate_per_hour_usd']:,}/h × {fi['response_seconds']:.0f}s ÷ 3600)",
        f"  Forensic:  ${fi['forensic']:,.2f}",
        f"  Breach:    ${fi['breach']:,.2f}  "
        f"(${_fin['breach_notification_usd_per_record']}/record × {_fin['estimated_affected_records']:,})",
        f"  Total USD: ${fi['total_usd']:,.2f}",
        f"  NIS2 fine: up to EUR {_fin['nis2_max_fine_eur']:,}  (reported separately)",
        "",
        "REGULATORY DEADLINES:",
        f"  Detected:         {detection_ts.strftime(ts_fmt)}",
        f"  NIS2 (24h):       {nis2_dl}",
        f"  GDPR Art33 (72h): {gdpr_dl}",
        f"  Insurance (48h):  {ins_dl}",
        "",
        narrative_short,
    ]

    if forensic_short:
        parts += ["", forensic_short]

    if affected_short:
        parts += ["", "AFFECTED DATA:", affected_short]

    return "\n".join(parts)


# ── Chunked generation pipeline ──────────────────────────────────────────────

def generate_insurance_evidence_package_chunked(
    evidence_context: str,
    hf_token: str,
    container_id: int,
    detection_ts: datetime,
) -> str:
    """Generate the full evidence package — one SaulLM call per section, combined locally.

    No additional LLM call is made for the final report; it is assembled from section outputs.
    """
    print(
        f"Generating insurance evidence package via SaulLM-7B (Featherless AI) "
        f"— {len(_SECTIONS)} sections …"
    )

    section_outputs: dict[str, str] = {}
    for section_name, instruction, max_tok in _SECTIONS:
        print(f"\n  Generating section: {section_name}")
        section_outputs[section_name] = call_saul_section(
            section_name, instruction, evidence_context, hf_token, max_tok
        )

    # ── Assemble report locally ───────────────────────────────────────────
    lines = [
        "CYBER INSURANCE REIMBURSEMENT EVIDENCE PACKAGE",
        "=" * 55,
        f"Case ID:      SOAR Container {container_id}",
        f"Generated by: SaulLM-7B (Equall/Saul-7B-Instruct-v1) via Featherless AI",
        f"Strategy:     Per-section generation  |  Model context: {_SAUL_CTX} tokens",
        "",
        "INCIDENT CONTEXT",
        "-" * 40,
        evidence_context,
        "",
    ]

    scores: list[str] = []
    for i, (section_name, _, _) in enumerate(_SECTIONS, 1):
        text = section_outputs.get(section_name, "[not generated]")
        lines.append(f"\n{i}. {section_name.upper()}")
        lines.append("-" * 40)
        lines.append(text)

        # Collect trailing score / status lines for executive summary
        last = text.strip().split("\n")[-1] if text.strip() else ""
        if any(kw in last for kw in ("SCORE:", "STATUS:", "LIKELIHOOD:", "ACCURACY:")):
            scores.append(last)

    # ── Executive summary (assembled locally, no LLM call) ───────────────
    lines.append("\n6. EXECUTIVE SUMMARY")
    lines.append("-" * 40)
    if scores:
        lines.append("Assessment scores:")
        for s in scores:
            lines.append(f"  • {s}")
        lines.append("")
    lines.append(
        f"This evidence package documents the cyber security incident affecting "
        f"{_inc['company_name']} (detected {detection_ts.strftime('%Y-%m-%d')}). "
        "It was automatically generated from W3C PROV-JSON provenance captured by Splunk SOAR. "
        "File all regulatory notifications before the stated deadlines and retain this document "
        "as the primary insurance claim evidence package."
    )

    return "\n".join(lines)


# ── Public entry point ───────────────────────────────────────────────────────

def generate_evidence(container_id: int, enrichment: dict | None = None) -> str:
    """Generate an insurance evidence package for a specific SOAR container."""
    hf_token = os.environ.get("HF_TOKEN")
    if not hf_token:
        raise EnvironmentError("HF_TOKEN environment variable is not set.")

    prov_path = os.path.join(
        _script_dir, _path["prov_graph_dir"],
        f"yProv4WFs_SOAR_{container_id}.json"
    )
    with open(prov_path, "r") as f:
        prov_graph = json.load(f)

    narrative, _ = build_narrative(prov_graph)
    case         = extract_case_metadata(prov_graph)
    detection_ts = extract_incident_time(prov_graph)
    resp_secs    = compute_response_time(prov_graph)
    fi           = compute_financial_impact(resp_secs)

    if enrichment is None:
        enrichment_path = os.path.join(
            _script_dir, _path["output_dir"], f"mcp_enrichment_results_{container_id}.json"
        )
        if os.path.exists(enrichment_path):
            with open(enrichment_path, "r") as f:
                enrichment = json.load(f)

    forensic_narrative    = _build_forensic_narrative(enrichment) if enrichment else ""
    affected_data_section = (
        _build_affected_data_classification(enrichment, _inc["compromised_system"])
        if enrichment else
        f"System compromised: {_inc['compromised_system']}\n"
        "Data types potentially exposed: Customer records, inventory data\n"
        "Personal data involved: Yes — GDPR Article 33 notification required"
    )

    evidence_context = _build_evidence_context(
        case, detection_ts, fi,
        narrative, forensic_narrative, affected_data_section,
        container_id,
    )

    evidence = generate_insurance_evidence_package_chunked(
        evidence_context, hf_token, container_id, detection_ts
    )

    output_file = os.path.join(
        _script_dir, _path["output_dir"], f"evidence_package_{container_id}.txt"
    )
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(evidence)

    print(f"\nEvidence package saved to: {output_file}")
    return evidence


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate insurance evidence package from SOAR provenance"
    )
    parser.add_argument("--container_id", type=int, required=True,
                        help="SOAR container ID to generate evidence for")
    args = parser.parse_args()
    generate_evidence(args.container_id)
