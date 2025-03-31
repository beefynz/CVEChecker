# CVE Security Vulnerability Checker 0.2

============<br>
Description<br>
============<br>
Quick and easy tool to query CVE data and pull informtion from the below sources. Enter a CVE ID to check details across mulitple vulnerability databases. The aim is to only use open source endpoints to pull information that is completely free and not requiring API keys. <br>

Current sources below: (Will work to look at adding more sources to enrich CVE data)

* CISA Known Exploited Vulnerabilities (KEV) - KEV list are vulnerabilites that are known to be exploited in the wild<br>
* National Vulnerability Databses (NVD) - NVD is a another list of all vulnerabilities and has additional information including CVSS<br>
* Exploit Prediction Scoring System (EPSS) - provides a score for likelihood of an vulnerability being exploited in the wild

Two main files:

KEV&EPSS.py - This is the pure Python code that can be run in any IDE that has Python installed. This uses CLI<br>
app.py - This code is the same as KEV&EPSS.py but has been modified to be used with streamlit for a web UI.<br>

===================================================<br>
Instructions for installing streamlit to use Web UI<br>
===================================================<br>
work in progress
