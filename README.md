# CVE Security Vulnerability Checker 0.4

===========<br>
Description<br>
===========<br><br>
This Streamlit-based web app allows users to query and visualize security vulnerability data for any given CVE ID (e.g., CVE-2021-44228). It pulls real-time information from three major public cybersecurity data sources:
<br><br>
===============<br>
📡 Data Sources<br>
===============<br><br>
🛡️ KEV (Known Exploited Vulnerabilities) – From CISA's official KEV catalog.<br>

🗂️ NVD (National Vulnerability Database) – Provides CVSS scores, vectors, descriptions, CPEs, CWEs, and references.<br>

📊 EPSS (Exploit Prediction Scoring System) – Indicates the probability of a vulnerability being exploited in the next 30 days.<br>
<br><br>
Two main files:<br>

CVE_checker.py - This is the python code that can be run in any IDE or windows command line that has Python installed. This is CLI version<br>
app.py - This code is the same as CVE_Checker.py but has been modified to be used with streamlit for a web UI.<br><br>

===================================================<br>
Instructions for installing streamlit to use Web UI<br>
===================================================<br><br>
✅ 1. Set up your environment<br>
Create a virtual environment (optional but recommended):<br>
<br><br>
python -m venv venv<br>
source venv/bin/activate  # On Windows: venv\Scripts\activate
<br><br>
✅ 2. Install dependencies<br>
At a minimum, you need:<br>
<br><br>
pip install streamlit requests
<br><br>
✅ 3. Run Application<br>
to run application:<br>
<br>
streamlit run app.py  (be in the directory that app.py file is in)<br><br>


=================<br>
new in Version 0.4<br>
=================<br>
updated CVE_Checker_Streamlit.py code with the following:<br>
bulk upload function added, users can upload txt file with CVEs to get data + download CSV file<br>
CVEs retrieved via bulk upload are prioritize based on a calculation based on CVSS, EPSS, Severty + Kev List<br><br>

