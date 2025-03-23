import streamlit as st
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

        if response.text.strip() == "":
            return None

        return response.json()
    except (requests.exceptions.RequestException, json.JSONDecodeError):
        return None

def fetch_kev_data():
    """Fetch known exploited vulnerabilities from CISA KEV catalog."""
    data = fetch_api_data("KEV")
    return data.get("vulnerabilities", []) if data else []

def fetch_epss_data(cve_id):
    """Fetch EPSS score and additional data fora given CVE from the FIRST EPSS API."""
    data = fetch_api_data("EPSS", fields={"cve": cve_id})
    return next((entry for entry in data.get("data", []) if entry.get("cve") == cve_id), None) if data else None

def get_cvss_score(cve_id):
    """Retrieve the CVSS score, description, and CWEs for a given CVE ID."""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        if "vulnerabilities" in data and data["vulnerabilities"]:
            cve_item = data["vulnerabilities"][0]["cve"]
            description = next((d["value"] for d in cve_item.get("descriptions", []) if d["lang"] == "en"), "No description available.")

            cwes = [desc["value"] for weakness in cve_item.get("weaknesses", []) for desc in weakness.get("description", []) if desc["lang"] == "en" and desc["value"].startswith("CWE-")]

            for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metric_type in cve_item.get("metrics", {}) and cve_item["metrics"][metric_type]:
                    cvss_data = cve_item["metrics"][metric_type][0]
                    return cvss_data.get("cvssData", {}).get("baseScore"), cvss_data.get("vectorString"), description, cwes

        return None, None, description, cwes
    except (requests.exceptions.RequestException, KeyError):
        return None, None, "Error retrieving data.", []

def check_cve(cve_id):
    """Check CVE across KEV, NVD, and EPSS and return formatted results."""
    output = []

    # Check KEV
    kev_data = fetch_kev_data()
    cve_in_kev = next((v for v in kev_data if v.get("cveID") == cve_id), None)
    if cve_in_kev:
        output.append(f"✅ CVE {cve_id} is listed in the KEV catalog!")
        output.append(f"- Vendor: {cve_in_kev.get('vendorProject', 'Unknown')}")
        output.append(f"- Product: {cve_in_kev.get('product', 'Unknown')}")
        output.append(f"- Short Description: {cve_in_kev.get('shortDescription', 'No description available.')}")
        output.append(f"- Required Action: {cve_in_kev.get('requiredAction', 'Unknown')}")
        output.append(f"- Date Added: {cve_in_kev.get('dateAdded', 'Unknown')}")
        output.append(f"- Due Date: {cve_in_kev.get('dueDate', 'Unknown')}")
        output.append(f"- Notes: {cve_in_kev.get('notes', 'None')}")
        output.append(f"- Known Ransomware Campaign Use: {cve_in_kev.get('knownRansomwareCampaignUse', False)}")
        output.append(f"- Vulnerability Name: {cve_in_kev.get('vulnerabilityName', 'Unknown')}")
        output.append(f"- CISA Exploit Addressed: {cve_in_kev.get('cisaExploitAddressed', False)}")
        output.append(f"- Source: {cve_in_kev.get('source', 'Unknown')}")
        output.append(f"- Source URL: {cve_in_kev.get('sourceUrl', 'Unknown')}")

    # Fetch CVSS Score & NVD Data
    score, vector, description, cwes = get_cvss_score(cve_id.upper())
    if score is not None:
        output.append(f"\n🔹 **NVD Data:**")
        output.append(f"- **CVSS Score:** {score}")
        output.append(f"- **Vector:** {vector}")
        output.append(f"- **Description:** {description}")
        output.append(f"- **CWEs:** {', '.join(cwes) if cwes else 'None'}")

    # Fetch EPSS Data
    epss_data = fetch_epss_data(cve_id)
    if epss_data:
        epss_score = float(epss_data.get("epss", 0))
        percentile = float(epss_data.get("percentile", 0))
        output.append(f"\n📊 **EPSS Score:** {epss_score:.6f} (Percentile: {percentile:.6f})")
        if epss_score >= 0.9:
            output.append("⚠️ **Very high exploitation probability! Immediate action recommended!**")
        elif epss_score >= 0.7:
            output.append("⚠️ **High probability of exploitation. Prioritize mitigation.**")
        elif epss_score >= 0.4:
            output.append("⚠️ Moderate probability of exploitation. Assess risk.")
        else:
            output.append("✅ Low probability of exploitation. Monitor accordingly.")

    # If no data found
    if not cve_in_kev and score is None and not epss_data:
        output.append(f"❌ CVE {cve_id} not found in KEV, NVD, or EPSS databases.")

    return "\n".join(output)

# Streamlit App UI
st.title("🔍 CVE Security Vulnerability Checker")

st.markdown(
    """
    Enter a **CVE ID** (e.g., CVE-2024-12345) to check its details across multiple vulnerability databases:
    - **CISA Known Exploited Vulnerabilities (KEV)**
    - **NVD (National Vulnerability Database)**
    - **EPSS (Exploit Prediction Scoring System)**
    """
)

cve_id = st.text_input("Enter CVE ID:")

if st.button("Check CVE"):
    if cve_id:
        st.info(f"🔎 Fetching data for: {cve_id}...")
        result = check_cve(cve_id)
        st.markdown(result.replace("\n", "<br>"), unsafe_allow_html=True)
    else:
        st.error("⚠️ Please enter a valid CVE ID.")
