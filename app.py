import streamlit as st
import requests
import json

# API URLs
API_URLS = {
    "KEV": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "EPSS": "https://api.first.org/data/v1/epss",
    "NVD": "https://services.nvd.nist.gov/rest/json/cves/2.0"
}

def fetch_data_from_api(api_name, params=None):
    """Centralized function to fetch data from any API."""
    url = API_URLS[api_name]
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        st.error(f"Error fetching {api_name} data: {e}")
        return None

def extract_cvss_and_cpes(cve_data):
    """Extract relevant CVSS and CPEs from NVD data."""
    try:
        metrics = cve_data.get("metrics", {})
        cvss_data = next((metrics.get(m) for m in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] if metrics.get(m)), None)
        score = cvss_data[0].get("cvssData", {}).get("baseScore") if cvss_data else None
        vector = cvss_data[0].get("cvssData", {}).get("vectorString") if cvss_data else None
        cpes = []
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria")
                    if cpe:
                        cpes.append(cpe)
        return score, vector, cpes
    except KeyError:
        return None, None, []

def assess_epss_risk(score):
    """Assess the EPSS risk based on the score."""
    if score >= 0.9:
        return "⚠️ Very high exploitation probability! Immediate action recommended!"
    elif score >= 0.7:
        return "⚠️ High probability of exploitation. Prioritize mitigation."
    elif score >= 0.4:
        return "⚠️ Moderate probability of exploitation. Assess risk."
    return "✅ Low probability of exploitation. Monitor accordingly."

def assess_combined_severity(cvss_score, epss_score):
    """Determine combined severity based on CVSS and EPSS scores."""
    if cvss_score is None or epss_score is None:
        return "Unknown"
    if cvss_score >= 9.0 and epss_score >= 0.9:
        return "💀💀💀💀"  # CRITICAL
    elif cvss_score >= 7.0 and epss_score >= 0.7:
        return "💀💀💀"  # HIGH
    elif cvss_score >= 4.0 or epss_score >= 0.4:
        return "💀💀"  # MEDIUM
    return "💀"  # LOW

def check_cve(cve_id):
    """Fetch and process data for the given CVE."""
    result = {
        "cve_id": cve_id,
        "kev": None,
        "nvd": None,
        "epss": None
    }

    # KEV Data
    kev_data = fetch_data_from_api("KEV")
    cve_kev = next((v for v in kev_data.get("vulnerabilities", []) if v.get("cveID") == cve_id), None)
    if cve_kev:
        result["kev"] = cve_kev
        # Limited NVD data if the CVE is in the KEV list
        nvd_data = fetch_data_from_api("NVD", {"cveId": cve_id})
        if nvd_data:
            nvd_item = nvd_data.get("vulnerabilities", [])[0].get("cve", {})
            score, vector, cpes = extract_cvss_and_cpes(nvd_item)
            result["nvd"] = {
                "cvss_score": score,
                "vector": vector,
                "cwes": [desc["value"] for weakness in nvd_item.get("weaknesses", []) for desc in weakness.get("description", []) if desc["lang"] == "en"],
                "source": nvd_item.get("sourceIdentifier", "Unknown"),
                "references": [ref.get("url") for ref in nvd_item.get("references", [])],
                "cpes": cpes
            }
    else:
        # Full NVD data if the CVE is not in the KEV list
        nvd_data = fetch_data_from_api("NVD", {"cveId": cve_id})
        if nvd_data:
            nvd_item = nvd_data.get("vulnerabilities", [])[0].get("cve", {})
            score, vector, cpes = extract_cvss_and_cpes(nvd_item)
            result["nvd"] = {
                "cvss_score": score,
                "vector": vector,
                "description": next((d["value"] for d in nvd_item.get("descriptions", []) if d["lang"] == "en"), "No description available."),
                "cwes": [desc["value"] for weakness in nvd_item.get("weaknesses", []) for desc in weakness.get("description", []) if desc["lang"] == "en"],
                "published": nvd_data.get("vulnerabilities", [])[0].get("published"),
                "last_modified": nvd_data.get("vulnerabilities", [])[0].get("lastModified"),
                "source": nvd_item.get("sourceIdentifier", "Unknown"),
                "references": [ref.get("url") for ref in nvd_item.get("references", [])],
                "cpes": cpes
            }

    # EPSS Data
    epss = fetch_data_from_api("EPSS", {"cve": cve_id})
    if epss:
        epss_score = float(epss.get("data", [{}])[0].get("epss", 0))
        result["epss"] = {
            "score": epss_score,
            "percentile": float(epss.get("data", [{}])[0].get("percentile", 0)),
            "model_version": epss.get("data", [{}])[0].get("model_version"),
            "epss_risk_assessment": assess_epss_risk(epss_score)
        }

    return result

# UI
ascii_title = '''
██████  ██    ██ ███████    █████ ██   ██ ███████  ██████ ██   ██ ███████ ██████  
██      ██    ██ ██        ██     ██   ██ ██      ██      ██  ██  ██      ██   ██ 
██      ██    ██ █████     ██     ███████ █████   ██      █████   █████   ██████  
██       ██  ██  ██        ██     ██   ██ ██      ██      ██  ██  ██      ██   ██ 
 █████    ████   ███████    █████ ██   ██ ███████  ██████ ██   ██ ███████ ██   ██ 
'''

st.markdown(f"```{ascii_title}```")

st.markdown("""
Enter a **CVE ID** (e.g., `CVE-2021-44228`) to view detailed information from these API endpoints:
- 🛡️ KEV List - CISA Known Exploited Vulnerabilities Catalog
- 🗂️ NVD - National Vulnerability Database
- 📊 EPSS - Exploit Prediction Scoring System
""")

cve_id = st.text_input("Enter CVE ID:")

if st.button("Check CVE"):
    if cve_id:
        data = check_cve(cve_id.upper())
        if any([data["kev"], data["nvd"], data["epss"]]):
            # Display Summary Metrics
            cvss_score = data["nvd"]["cvss_score"] if data["nvd"] else None
            epss_score = data["epss"]["score"] if data["epss"] else None
            severity = assess_combined_severity(cvss_score, epss_score)

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("CVSS Score", cvss_score)
            with col2:
                epss_percent = f"{epss_score * 100:.2f}%" if epss_score is not None else "N/A"
                st.metric("EPSS Score (next 30 days)", epss_percent)
            with col3:
                st.metric("Severity", severity)

            # Full JSON (includes CPEs)
            st.json(data)
        else:
            st.warning("❌ No data found for this CVE in KEV, NVD, or EPSS.")
    else:
        st.error("Please enter a valid CVE ID.")
