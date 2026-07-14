#!/usr/bin/env python3
"""
AV Scan Helper — scans a binary against VirusTotal API
Requires: VT_API_KEY env var
Usage: python scripts/av_scan.py path/to/morphed.exe
"""

import os
import sys
import requests
import hashlib
import time

VT_API_URL = "https://www.virustotal.com/api/v3"


def scan_file(filepath: str) -> dict:
    with open(filepath, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()

    headers = {"x-apikey": os.environ.get("VT_API_KEY", "")}

    r = requests.get(f"{VT_API_URL}/files/{sha256}", headers=headers)
    if r.status_code == 200:
        data = r.json()
        attr = data.get("data", {}).get("attributes", {})
        if attr.get("last_analysis_results"):
            return attr

    if r.status_code == 404:
        with open(filepath, "rb") as f:
            r = requests.post(f"{VT_API_URL}/files", headers=headers, files={"file": f})
        if r.status_code != 200:
            return {"error": f"Upload failed: {r.status_code}"}

        analysis_id = r.json().get("data", {}).get("id", "")
        for _ in range(12):
            time.sleep(5)
            r = requests.get(f"{VT_API_URL}/analyses/{analysis_id}", headers=headers)
            if r.status_code == 200:
                attr = r.json().get("data", {}).get("attributes", {})
                if attr.get("status") == "completed":
                    return attr

    return {}


def format_results(results: dict) -> str:
    if not results or "error" in results:
        return f"Error: {results.get('error', 'unknown')}"

    stats = results.get("stats", {})
    malicious = stats.get("malicious", 0)
    total = (
        stats.get("harmless", 0)
        + stats.get("malicious", 0)
        + stats.get("suspicious", 0)
        + stats.get("undetected", 0)
    )
    if total == 0:
        total = malicious

    sha256 = results.get("sha256", "")
    results_list = results.get("results", {})
    detected_by = [
        v["engine_name"]
        for v in results_list.values()
        if v.get("category") == "malicious"
    ]

    last_analysis = results.get("last_analysis_date", "")
    if isinstance(last_analysis, int):
        last_analysis = time.strftime("%Y-%m-%d", time.gmtime(last_analysis))

    return f"""VirusTotal Detection: {malicious}/{total}
SHA256: {sha256}
Detected by: {", ".join(detected_by[:5]) or "none"}
Last analysis: {last_analysis}"""


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/av_scan.py path/to/morphed.exe")
        sys.exit(1)

    vt_api_key = os.environ.get("VT_API_KEY", "")
    if not vt_api_key:
        print("Error: VT_API_KEY env var not set")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.isfile(filepath):
        print(f"Error: file not found: {filepath}")
        sys.exit(1)

    result = scan_file(filepath)

    if not result:
        print("No analysis results returned (rate-limited or API error)")
        sys.exit(1)

    print(format_results(result))

    malicious = result.get("stats", {}).get("malicious", 0)
    if malicious >= 5:
        print(
            f"\n⚠️  Detection rate {malicious} — above 5/72 threshold, consider re-morphing"
        )
        sys.exit(1)
