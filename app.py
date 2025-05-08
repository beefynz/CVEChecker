import streamlit as st
import requests
import json
import pandas as pd
import time

# ──────────────────────────────── Constants ────────────────────────────────

API_URLS = {
    "KEV": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "EPSS": "https://api.first.org/data/v1/epss",
    "NVD": "https://services.nvd.nist.gov/rest/json/cves/2.0"
}

# ──────────────────────────────── Setup ────────────────────────────────

st.set_page_config(layout="wide")

ascii_title = '''
██████  ██    ██ ███████    █████ ██   ██ ███████  ██████ ██   ██ ███████ ██████  
██      ██    ██ ██        ██     ██   ██ ██      ██      ██  ██  ██      ██   ██ 
██      ██    ██ █████     ██     ███████ █████   ██      █████   █████   ██████  
██       ██  ██  ██        ██     ██   ██ ██      ██      ██  ██  ██      ██   ██ 
 █████    ████   ███████    █████ ██   ██ ███████  ██████ ██   ██ ███████ ██   ██ 
'''
st.markdown(f"```{ascii_title}```")

st.markdown("""
Enter a **CVE ID** (e.g., `CVE-2021-44228`) to view detailed information from:
- 🛡️ KEV - Known Exploited Vulnerabilities
- 🗂️ NVD - National Vulnerability Database
- 📊 EPSS - Exploit Prediction Scoring System
""")

# ──────────────────────────────── API Interaction ────────────────────────────────

def fetch_api_data(api_name, cve_id=None, fields=None):
    url = API_URLS.get(api_name)
    if not url:
        st.warning(f"Unknown API: {api_name}")
        return None

    params = {"cveId": cve_id} if cve_id and api_name == "NVD" else fields
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        st.warning(f"Error fetching data for {cve_id}: {e}")
        return None

@st.cache_data

def fetch_kev_data():
    data = fetch_api_data("KEV")
    return data.get("vulnerabilities", []) if data else []

def fetch_epss_data(cve_id):
    data = fetch_api_data("EPSS", fields={"cve": cve_id})
    return next((entry for entry in data.get("data", []) if entry.get("cve") == cve_id), None) if data else None

# ──────────────────────────────── Analysis Utilities ────────────────────────────────

def assess_epss_risk(score):
    if score >= 0.9:
        return "⚠️ Very high exploitation probability! Immediate action recommended!"
    elif score >= 0.7:
        return "⚠️ High probability of exploitation. Prioritize mitigation."
    elif score >= 0.4:
        return "⚠️ Moderate probability of exploitation. Assess risk."
    return "✅ Low probability of exploitation. Monitor accordingly."

def assess_combined_severity(cvss_score, epss_score):
    if cvss_score is None or epss_score is None:
        return "Unknown"
    if cvss_score >= 9.0 and epss_score >= 0.9:
        return "💀💀💀💀"
    elif cvss_score >= 7.0 and epss_score >= 0.5:
        return "💀💀💀"
    elif cvss_score >= 4.0 or epss_score >= 0.4:
        return "💀💀"
    return "💀"

def extract_cpes(nvd_data):
    try:
        configurations = nvd_data["vulnerabilities"][0]["cve"]["configurations"]
        cpes = [match.get("criteria") for config in configurations for node in config.get("nodes", [])
                for match in node.get("cpeMatch", []) if match.get("criteria")]
        return list(set(cpes))
    except KeyError:
        return []

# ──────────────────────────────── CVE Handling ────────────────────────────────

def get_cvss_score(cve_id):
    data = fetch_api_data("NVD", cve_id=cve_id)
    if not data:
        return None, {}

    try:
        cve_item = data["vulnerabilities"][0]["cve"]
        metrics = cve_item.get("metrics", {})
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics:
                cvss_data = metrics[key][0]["cvssData"]
                score = cvss_data.get("baseScore")
                details = {
                    "vector": cvss_data.get("vectorString"),
                    "description": next((d["value"] for d in cve_item.get("descriptions", []) if d["lang"] == "en"), "N/A"),
                    "cwes": [desc["value"] for w in cve_item.get("weaknesses", []) for desc in w.get("description", [])],
                    "published": data["vulnerabilities"][0].get("published"),
                    "last_modified": data["vulnerabilities"][0].get("lastModified"),
                    "source": cve_item.get("sourceIdentifier"),
                    "references": [ref["url"] for ref in cve_item.get("references", [])],
                    "cpes": extract_cpes(data),
                }
                return score, details
        return None, {}
    except Exception as e:
        st.warning(f"CVSS parse error: {e}")
        return None, {}

def check_cve(cve_id, kev_list):
    result = {"cve_id": cve_id, "kev": None, "nvd": None, "epss": None}
    result["kev"] = next((v for v in kev_list if v.get("cveID") == cve_id), None)

    score, details = get_cvss_score(cve_id)
    if score is not None:
        result["nvd"] = {"cvss_score": score, **details}

    epss = fetch_epss_data(cve_id)
    if epss:
        epss_score = float(epss.get("epss", 0))
        result["epss"] = {
            "score": epss_score,
            "percentile": float(epss.get("percentile", 0)),
            "model_version": epss.get("model_version"),
            "epss_risk_assessment": assess_epss_risk(epss_score)
        }

    return result

# ──────────────────────────────── UI Rendering ────────────────────────────────

def render_single_result(data):
    if any([data["kev"], data["nvd"], data["epss"]]):
        cvss_score = data["nvd"].get("cvss_score") if data["nvd"] else None
        epss_score = data["epss"].get("score") if data["epss"] else None
        severity = assess_combined_severity(cvss_score, epss_score)

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("CVSS Score", cvss_score)
        with col2:
            epss_percent = f"{epss_score * 100:.2f}%" if epss_score else "N/A"
            st.metric("EPSS Score", epss_percent)
        with col3:
            st.metric("Severity", severity)

        st.json(data)
    else:
        st.warning("❌ No data found for this CVE in KEV, NVD, or EPSS.")

def calculate_priority_score(cvss, epss, in_kev):
    score = 0
    if cvss is not None:
        score += cvss * 0.6
    if epss is not None:
        score += epss * 10 * 0.3
    if in_kev:
        score += 10
    return round(score, 2)

# ──────────────────────────────── Main App ────────────────────────────────

tab_selection = st.radio("Select Option:", ["Single CVE Check", "Bulk Upload"])

if tab_selection == "Single CVE Check":
    cve_id = st.text_input("Enter CVE ID:")
    if st.button("Check CVE") and cve_id:
        kev_list = fetch_kev_data()
        data = check_cve(cve_id.upper(), kev_list)
        render_single_result(data)

elif tab_selection == "Bulk Upload":
    uploaded_file = st.file_uploader("Upload .txt file", type="txt")

    if uploaded_file:
        content = uploaded_file.read().decode("utf-8")
        cve_ids = [line.strip().upper() for line in content.splitlines() if line.strip()]
        st.info(f"Processing {len(cve_ids)} CVE IDs...")

        kev_data = fetch_kev_data()
        results = []

        for cve in cve_ids:
            data = check_cve(cve, kev_data)
            in_kev = data["kev"] is not None
            cvss = data["nvd"].get("cvss_score") if data["nvd"] else None
            epss = data["epss"].get("score") if data["epss"] else None
            desc = data["nvd"].get("description") if data["nvd"] else "No description"
            severity = assess_combined_severity(cvss, epss)
            priority = calculate_priority_score(cvss, epss, in_kev)

            results.append({
                "CVE ID": cve,
                "CVSS": cvss or "N/A",
                "EPSS": f"{epss:.2f}" if epss else "N/A",
                "In KEV": "Yes" if in_kev else "No",
                "Severity": severity,
                "Description": desc,
                "Priority Score": priority
            })

            time.sleep(5)

        df = pd.DataFrame(results).sort_values(by="Priority Score", ascending=False)

        st.markdown("### 📋 Prioritized Bulk Results")
        st.dataframe(df, use_container_width=True)

        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Download Results as CSV", data=csv, file_name="cve_bulk_results.csv", mime="text/csv")
