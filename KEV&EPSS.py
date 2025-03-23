import requests
import json

# API URLs
API_URLS = {
    "KEV": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "EPSS": "https://api.first.org/data/v1/epss",
    "NVD": "https://services.nvd.nist.gov/rest/json/cves/2.0"
}

def fetch_api_data(api_name, params=None):
    """Fetch data from the specified API."""
    url = API_URLS.get(api_name)
    if not url:
        print(f"Error: Unknown API name '{api_name}'.")
        return None
    
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json() if response.text.strip() else None
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"Error fetching {api_name} data: {e}")
        return None

def fetch_kev_data():
    """Fetch known exploited vulnerabilities from CISA KEV catalog."""
    data = fetch_api_data("KEV")
    return data.get("vulnerabilities", []) if data else []

def fetch_epss_data(cve_id):
    """Fetch EPSS score and additional data for a given CVE."""
    data = fetch_api_data("EPSS", params={"cve": cve_id})
    return next((entry for entry in data.get("data", []) if entry.get("cve") == cve_id), None) if data else None

def get_cvss_score(cve_id):
    """Retrieve CVSS score, description, and CWEs for a given CVE ID."""
    data = fetch_api_data("NVD", params={"cveId": cve_id})
    
    if not data or "vulnerabilities" not in data or not data["vulnerabilities"]:
        return None, None, None, None
    
    cve_item = data["vulnerabilities"][0]["cve"]
    description = next((d["value"] for d in cve_item.get("descriptions", []) if d["lang"] == "en"), None)
    
    cwes = [desc["value"] for weakness in cve_item.get("weaknesses", []) for desc in weakness.get("description", []) if desc["lang"] == "en" and desc["value"].startswith("CWE-")]
    
    for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if metric_type in cve_item.get("metrics", {}):
            cvss_data = cve_item["metrics"][metric_type][0]
            return cvss_data.get("cvssData", {}).get("baseScore"), cvss_data.get("vectorString"), description, cwes
    
    return None, None, description, cwes

def display_epss_data(epss_entry):
    """Display EPSS data with interpretation."""
    if not epss_entry:
        print("\n📊 EPSS Data: No EPSS data available.")
        return
    
    epss_score, percentile = float(epss_entry.get("epss", 0)), float(epss_entry.get("percentile", 0))
    print(f"\n📊 EPSS Data for {epss_entry['cve']}:\n  - EPSS Score: {epss_score:.6f}\n  - Percentile: {percentile:.6f}")
    
    risk_messages = [
        (0.9, "⚠️ Very high exploitation probability! Immediate action recommended!"),
        (0.7, "⚠️ High probability of exploitation. Prioritize mitigation."),
        (0.4, "⚠️ Moderate probability of exploitation. Assess risk."),
    ]
    
    for threshold, message in risk_messages:
        if epss_score >= threshold:
            print(f"  {message}")
            break
    
    if percentile >= 0.99:
        print("  🔥 Ranks in the **top 1%** of vulnerabilities for exploit likelihood.")
    elif percentile >= 0.95:
        print("  🔥 Ranks in the **top 5%** of vulnerabilities for exploit likelihood.")

def check_cve(cve_id):
    """Check CVE details from KEV, NVD, and EPSS."""
    kev_data = fetch_kev_data()
    cve_in_kev = next((v for v in kev_data if v.get("cveID") == cve_id), None)
    
    score, vector, description, cwes = get_cvss_score(cve_id.upper())
    
    if cve_in_kev:
        display_data("🔍 CVE Found in KEV Catalog", {**cve_in_kev, **{"CVSS Score": score, "CVSS Vector": vector}})
    else:
        display_data(f"📄 NVD Data (CVE {cve_id} not in KEV List)", {"CVE ID": cve_id, "CVSS Score": score, "CVSS Vector": vector, "Description": description, "CWEs": ', '.join(cwes) if cwes else "None"})
    
    epss_data = fetch_epss_data(cve_id)
    display_epss_data(epss_data)
    
    if not any([epss_data, score, cve_in_kev]):
        print(f"⚠️ CVE {cve_id} not found in KEV, NVD, or EPSS.")

def display_data(title, data):
    """Helper function to display formatted data."""
    print(f"\n{title}:")
    if data:
        for key, value in data.items():
            print(f"{key}: {value}")
    else:
        print("No data available.")

def main():
    while True:
        cve_id = input("Enter CVE ID to check (or type 'exit' to quit): ").strip()
        if cve_id.lower() == 'exit':
            print("Exiting...")
            break
        check_cve(cve_id)

if __name__ == "__main__":
    main()
