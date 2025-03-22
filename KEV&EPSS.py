import requests
import json

# API URLs
API_URLS = {
    "KEV": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "EPSS": "https://api.first.org/data/v1/epss",
    "NVD": "https://services.nvd.nist.gov/rest/json/cves/2.0"
}

def fetch_api_data(api_name, cve_id=None, fields=None):
    """Generic function to fetch data from APIs."""
    url = API_URLS[api_name]
    params = {"cveId": cve_id} if cve_id and api_name == "NVD" else fields

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()

        # Check if the response body is empty before trying to decode as JSON
        if response.text.strip() == "":
            print(f"Error: Empty response from {api_name}.")
            return None

        try:
            return response.json()
        except json.JSONDecodeError:
            print(f"Error decoding JSON from {api_name}. Response content: {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Error fetching {api_name} data: {e}")
        return None

def fetch_kev_data():
    """Fetch known exploited vulnerabilities from CISA KEV catalog."""
    data = fetch_api_data("KEV")
    return data.get("vulnerabilities", []) if data else []

def fetch_epss_data(cve_id):
    """Fetch EPSS score and additional data for a given CVE from the FIRST EPSS API."""
    data = fetch_api_data("EPSS", fields={"cve": cve_id})
    return next((entry for entry in data.get("data", []) if entry.get("cve") == cve_id), None) if data and data.get("data") else None

def get_cvss_score(cve_id):
    """
    Retrieves the CVSS score, description, and CWEs for a given CVE ID.
    """
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        if "vulnerabilities" in data and data["vulnerabilities"]:
            cve_item = data["vulnerabilities"][0]["cve"]
            descriptions = cve_item.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d["lang"] == "en"), None)

            cwes = []
            if "weaknesses" in cve_item:
                for weakness in cve_item["weaknesses"]:
                    if "description" in weakness:
                        for desc in weakness["description"]:
                            if desc["lang"] == "en" and desc["value"].startswith("CWE-"):
                                cwes.append(desc["value"])

            if "metrics" in cve_item:
                for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if metric_type in cve_item["metrics"] and cve_item["metrics"][metric_type]:
                        cvss_data = cve_item["metrics"][metric_type][0]
                        return cvss_data.get("cvssData", {}).get("baseScore"), cvss_data.get("vectorString"), description, cwes

            return None, None, description, cwes  # No CVSS data found.
        else:
            return None, None, None, None  # CVE not found.

    except requests.exceptions.RequestException as e:
        print(f"Error retrieving CVE data: {e}")
        return None, None, None, None
    except KeyError as e:
        print(f"Error parsing CVE data: {e}")
        return None, None, None, None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None, None, None, None

def display_epss_data(epss_entry):
    """Display EPSS data with interpretation."""
    if not epss_entry:
        print("\n📊 EPSS Data: No EPSS data available.")
        return

    epss_score = float(epss_entry.get("epss", 0))
    percentile = float(epss_entry.get("percentile", 0))
    print(f"\n📊 EPSS Data for {epss_entry['cve']}:\n  - EPSS Score: {epss_score:.6f}\n  - Percentile: {percentile:.6f}")

    if epss_score >= 0.9:
        print("  ⚠️ Very high exploitation probability! Immediate action recommended!")
    elif epss_score >= 0.7:
        print("  ⚠️ High probability of exploitation. Prioritize mitigation.")
    elif epss_score >= 0.4:
        print("  ⚠️ Moderate probability of exploitation. Assess risk.")
    else:
        print("  ✅ Low probability of exploitation. Monitor accordingly.")

    if percentile >= 0.99:
        print("  🔥 Ranks in the **top 1%** of vulnerabilities for exploit likelihood.")
    elif percentile >= 0.95:
        print("  🔥 Ranks in the **top 5%** of vulnerabilities for exploit likelihood.")

def check_cve(cve_id):
    """Check CVE, prioritizing KEV, then NVD, then EPSS."""
    kev_data = fetch_kev_data()
    cve_in_kev = next((v for v in kev_data if v.get("cveID") == cve_id), None)

    score, vector, description, cwes = get_cvss_score(cve_id.upper())

    if cve_in_kev:
        display_data("🔍 CVE Found in KEV Catalog", {**cve_in_kev, **{"CVSS Score": score, "CVSS Vector": vector}})
    else:
        if score is not None or cwes:
            display_data(f"📄 NVD Data (CVE {cve_id} not in KEV List)", {"CVE ID": cve_id, "CVSS Score": score, "CVSS Vector": vector, "Description": description, "CWEs": ', '.join(cwes) if cwes else "None"})
        else:
            print(f"⚠️ CVE {cve_id} not found in NVD.")

    epss_data = fetch_epss_data(cve_id)
    display_epss_data(epss_data)
    if not epss_data and score is None and not cve_in_kev:
        print(f"⚠️ CVE {cve_id} not found in KEV, NVD, or EPSS.")

def display_data(title, data):
    """Helper function to display data."""
    if data:
        print(f"\n{title}:")
        for key, value in data.items():
            print(f"{key}: {value}")
    else:
        print(f"\n{title}: No data available.")

def main():
    while True:
        cve_id = input("Enter CVE ID to check (or type 'exit' to quit): ").strip()
        if cve_id.lower() == 'exit':
            print("Exiting...")
            break
        check_cve(cve_id)

if __name__ == "__main__":
    main()
