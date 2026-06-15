import argparse
import json
import os
import re
import sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

_script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_script_dir, "yprov4wfs"))
from yprov4wfs.yProv4WFs_SOAR import SOARAdapter

_SOAR_URL = os.environ.get("SOAR_URL", "")
_MCP_URL  = os.environ.get("SPLUNK_URL", "").rstrip("/") + "/services/mcp/sse"


def _extract_query(message: str) -> str | None:
    """Parse SPL query from 'For Parameter: {...} Message:' inside an app_run message."""
    m = re.search(r"For Parameter: (\{.+\}) Message:", message, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(1)).get("query")
    except (json.JSONDecodeError, AttributeError):
        return None


def _action_name_from_message(message: str, fallback: str) -> str:
    """Extract action name from the leading 'name' on asset ... prefix in app_run message."""
    m = re.match(r"'([^']+)'", message.strip())
    return m.group(1) if m else fallback


def _fetch_queries_from_soar(container_id: int) -> dict:
    """Authenticate to SOAR and return {action_name: SPL_query} from app_run message fields."""
    adapter = SOARAdapter(
        base_url=_SOAR_URL,
        username=os.environ.get("SOAR_USERNAME", ""),
        password=os.environ.get("SOAR_PASSWORD", ""),
        verify_ssl=False,
    )
    if not adapter.authenticate():
        raise RuntimeError(f"SOAR authentication failed at {_SOAR_URL}")

    resp = adapter.session.get(
        f"{_SOAR_URL}/rest/app_run",
        params={"_filter_container": container_id},
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    app_runs = resp.json().get("data", [])
    print(f"[SOAR] Found {len(app_runs)} app_run(s) for container {container_id}")

    queries = {}
    for app_run in app_runs:
        message = str(app_run.get("message") or "")
        query = _extract_query(message)
        if not query:
            continue
        action_run_id = str(app_run.get("action_run", "unknown"))
        name = _action_name_from_message(message, fallback=f"action_{action_run_id}")
        queries[name] = query
        print(f"  [SOAR] '{name}': {query[:100]}...")

    if not queries:
        raise RuntimeError(
            f"No SPL queries found in app_run messages for container {container_id}. "
            "Expected 'For Parameter: {{...}} Message:' in message fields."
        )
    return queries


def _call_mcp(label: str, query: str, headers: dict) -> list:
    """POST a single splunk_run_query MCP call and return the result rows."""
    print(f"  Querying: {label} ...")
    payload = {
        "method": "tools/call",
        "params": {
            "name": "splunk_run_query",
            "arguments": {
                "query": query,
                "earliest_time": "2018-08-01T00:00:00",
                "latest_time": "now",
                "row_limit": 20,
            },
        },
    }
    try:
        response = requests.post(
            _MCP_URL,
            headers=headers,
            json=payload,
            verify=False,
            timeout=60,
        )
        response.raise_for_status()
        data = response.json()
        content = data.get("result", {}).get("content", [])
        for block in content:
            if block.get("type") == "text":
                try:
                    rows = json.loads(block["text"])
                    if isinstance(rows, list):
                        print(f"    -> {len(rows)} row(s) returned")
                        return rows
                    if isinstance(rows, dict):
                        for v in rows.values():
                            if isinstance(v, list):
                                print(f"    -> {len(v)} row(s) returned")
                                return v
                except (json.JSONDecodeError, KeyError):
                    pass
        print("    -> No structured rows found in response")
        return []
    except requests.exceptions.HTTPError as e:
        print(f"    [ERROR] HTTP {e.response.status_code}: {e.response.text[:200]}")
        return []
    except Exception as e:
        print(f"    [ERROR] {e}")
        return []


def enrich_container(container_id: int) -> dict:
    """Extract SPL queries from SOAR playbook execution and run them via Splunk MCP Server."""
    token = os.environ.get("SPLUNK_MCP_TOKEN")
    if not token:
        raise EnvironmentError("SPLUNK_MCP_TOKEN environment variable is not set.")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    print(f"[MCP] Enriching container {container_id} via {_MCP_URL}")
    queries = _fetch_queries_from_soar(container_id)
    print(f"[MCP] Running {len(queries)} queries extracted from SOAR playbook...\n")

    results = {"container_id": container_id}
    for action_name, query in queries.items():
        results[action_name] = _call_mcp(action_name, query, headers)

    output_dir  = os.path.join(_script_dir, "output")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"mcp_enrichment_results_{container_id}.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\n[MCP] Results saved to: {output_file}")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Enrich SOAR incident with Splunk MCP forensic data"
    )
    parser.add_argument("--container_id", type=int, required=True,
                        help="SOAR container ID to enrich")
    args = parser.parse_args()
    results = enrich_container(args.container_id)
    print(json.dumps(results, indent=2))
