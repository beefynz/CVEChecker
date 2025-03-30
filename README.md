# CVE Security Vulnerability Checker 0.2
Quick and easy tool to query CVE data and pull informtion from the below sources<br>
Enter a CVE ID to check details across mulitple vulnerability databases

* CISA Known Exploited Vulnerabilities (KEV) - KEV list are vulnerabilites that are known to be exploited in the wild<br>
* National Vulnerability Databses (NVD) - NVD is a another list of all vulnerabilities and has additional information including CVSS<br>
* Exploit Prediction Scoring System (EPSS) - is a scoring for likelihood of an vulnability being exploited in the wild

* will work to look at adding more sources to enrich CVE data*

Two files required:

KEV&EPSS.py - this is the pure Python code that can be run in any IDE that has Python. you can use the tool using CLI<br>
app.py - this code is the same as KEV&EPSS.py but has been modified to be used with streamlit for a web UI.<br>

Uses Open Soruce API endpoints to pull informaiton into a Streamlit web UI
