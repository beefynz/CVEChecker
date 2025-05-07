import requests
import json

API_URLS = {
    "KEV": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "EPSS": "https://api.first.org/data/v1/epss",
    "NVD": "https://services.nvd.nist.gov/rest/json/cves/2.0"
}

def fetch_api_data(api_name, cve_id=None, fields=None):
    url = API_URLS[api_name]
    params = {"cveId": cve_id} if cve_id and api_name == "NVD" else fields
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except (requests.exceptions.RequestException, json.JSONDecodeError):
        return None

def fetch_kev_data():
    data = fetch_api_data("KEV")
    return data.get("vulnerabilities", []) if data else []

def fetch_epss_data(cve_id):
    data = fetch_api_data("EPSS", fields={"cve": cve_id})
    return next((entry for entry in data.get("data", []) if entry.get("cve") == cve_id), None) if data else None

def extract_cpes(nvd_data):
    try:
        configurations = nvd_data["vulnerabilities"][0]["cve"]["configurations"]
        cpes = []
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria")
                    if cpe:
                        cpes.append(cpe)
        return list(set(cpes))
    except:
        return []

def get_cvss_score(cve_id):
    try:
        response = requests.get(f"{API_URLS['NVD']}?cveId={cve_id}")
        response.raise_for_status()
        data = response.json()
        if "vulnerabilities" in data and data["vulnerabilities"]:
            cve_item = data["vulnerabilities"][0]["cve"]
            description = next((d["value"] for d in cve_item.get("descriptions", []) if d["lang"] == "en"), "No description available.")
            cwes = [desc["value"] for weakness in cve_item.get("weaknesses", []) for desc in weakness.get("description", []) if desc["lang"] == "en"]
            published = data["vulnerabilities"][0].get("published")
            last_modified = data["vulnerabilities"][0].get("lastModified")
            source = cve_item.get("sourceIdentifier", "Unknown")
            refs = [ref.get("url") for ref in cve_item.get("references", [])]
            cpes = extract_cpes(data)
            for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metric_type in cve_item.get("metrics", {}) and cve_item["metrics"][metric_type]:
                    cvss_data = cve_item["metrics"][metric_type][0]
                    score = cvss_data.get("cvssData", {}).get("baseScore")
                    vector = cvss_data.get("cvssData", {}).get("vectorString")
                    return score, vector, description, cwes, published, last_modified, source, refs, cpes
        return None, None, description, [], None, None, "Unknown", [], []
    except Exception:
        return None, None, "Error retrieving data.", [], None, None, "Unknown", [], []

def assess_epss_risk(score):
    if score >= 0.9:
        return "⚠️ Very high exploitation probability! Immediate action recommended!"
    elif score >= 0.7:
        return "⚠️ High probability of exploitation. Prioritize mitigation."
    elif score >= 0.4:
        return "⚠️ Moderate probability of exploitation. Assess risk."
    else:
        return "✅ Low probability of exploitation. Monitor accordingly."

def assess_combined_severity(cvss_score, epss_score):
    if cvss_score is None or epss_score is None:
        return "Unknown"
    if cvss_score >= 9.0 and epss_score >= 0.9:
        return "💀💀💀💀"  # CRITI    elif cvss_score >= 7.0 and epss_score >= 0.7:
        return "💀💀💀"  # HIGH
    elif cvss_score >= 4.0 or epss_score >= 0.4:
        return "💀💀"  # MEDIUM
    else:
        return "💀"  # LOW

def check_cve(cve_id):
    result = {
        "": cve_id,
        "kev": None,
        "nvd": None,
        "epss": None
    }

    kev_data = fetch_kev_data()
    cve_kev = next((v for v in kev_data if v.get("cveID") == cve_id), None)
    if cve_kev:
        result["kev"] = {
            "vendor": cve_kev.get("vendorProject"),
            "product": cve_kev.get("product"),
            "description": cve_kev.get("shortDescription"),
            "required_action": cve_kev.get("requiredAction"),
            "date_added": cve_kev.get("dateAdded"),
            "due_date": cve_kev.get("dueDate"),
            "notes": cve_kev.get("notes"),
            "known_ransomware": cve_kev.get("knownRansomwareCampaignUse"),
            "name": cve_kev.get("vulnerabilityName"),
            "exploit_addressed": cve_kev.get("cisaExploitAddressed"),
            "source": cve_kev.get("source"),
            "source_url": cve_kev.get("sourceUrl")
        }

    score, vector, description, cwes, published, last_mod, source, refs, cpes = get_cvss_score(cve_id)
    if score is not None:
        result["nvd"] = {
            "cvss_score": score,
            "vector": vector,
            "description": description,
            "cwes": cwes,
            "published": published,
            "last_modified": last_mod,
            "source": source,
            "references": refs,
            "cpes": cpes
        }

    epss = fetch_epss_data(cve_id)
    if epss:
        epss_score = float(epss.get("epss", 0))
        percentile = float(epss.get("percentile", 0))
        result["epss"] = {
            "score": epss_score,
            "percentile": percentile,
            "model_version": epss.get("model_version"),
            "epss_risk_assessment": assess_epss_risk(epss_score)
        }

    return result

def main():
    ascii_title = '''
██████  ██    ██ ███████    █████ ██   ██ ███████  ██████ ██   ██ ███████ ██████  
██      ██    ██ ██        ██     ██   ██ ██      ██      ██  ██  ██      ██   ██ 
██      ██    ██ █████     ██     ███████ █████   ██      █████   █████   ██████  
██       ██  ██  ██        ██     ██   ██ ██      ██      ██  ██  ██      ██   ██ 
 █████    ████   ███████    █████ ██   ██ ███████  ██████ ██   ██ ███████ ██   ██ 
'''
    print(ascii_title)
    print("CVE Checker CLI - KEV, NVD, EPSS")
    print("Type 'exit' or 'q' to quit.\n")

    while True:
        cve_id = input("Enter a CVE ID (e.g., CVE-2021-44228): ").strip().upper()
        if cve_id in {"EXIT", "Q"}:
            print("Exiting CVE Checker. Goodbye!")
            break
        if not cve_id.startswith("CVE-"):
            print("❌ Please enter a valid CVE ID (e.g., CVE-2021-44228).")
            continue

        data = check_cve(cve_id)
        if not any([data["kev"], data["nvd"], data["epss"]]):
            print("❌ No data found for this CVE in KEV, NVD, or EPSS.\n")
            continue

        print("\n📊 Summary Metrics:")
        cvss_score = data["nvd"]["cvss_score"] if data["nvd"] else None
        epss_score = data["epss"]["score"] if data["epss"] else None
        epss_percent = f"{epss_score * 100:.2f}%" if epss_score is not None else "N/A"
        severity = assess_combined_severity(cvss_score, epss_score)
        print(f"- CVSS Score: {cvss_score}")
        print(f"- EPSS Score (next 30 days): {epss_percent}")
        print(f"- Combined Severity: {severity}")

        print("\n📦 Full Details (JSON):")
        print(json.dumps(data, indent=2))
        print("\n"  "\n")


if __name__ == "__main__":
    main()
