# Domain Analyzer

A CLI tool built for GRC teams to quickly analyze domains for whitelisting purposes.
Provide a domain and get a full report covering VirusTotal reputation, email security 
records, and WHOIS data — output as a clean HTML report with an automatic screenshot 
for easy sharing.

## Features


-  **VirusTotal** reputation scan via API
-  **Email security records** — SPF, DMARC, and DKIM lookup
-  **WHOIS** data retrieval
-  **HTML report** generation
-  **Automatic screenshot** of the report for non-terminal users

## Requirements


- Python 3.8+
- A [VirusTotal API key](https://www.virustotal.com/gui/join-us)
- See `requirements.txt` for dependencies

## Usage 

### Single domain
```bash
python3 domain\_analyzer.py example.com [--vt-key YOUR\_API\_KEY]
```
### Multiple domains
```bash
python3 domain\_analyzer.py example.com example2.com [--vt-key YOUR\_API\_KEY]
```
### From a file
```bash
python3 domain\_analyzer.py --file domains.txt [--vt-key YOUR\_API\_KEY]
```
> Never share your VirusTotal API key publicly or commit it to the repository.\\

> The \--vt-key\ flag is optional. If omitted, VirusTotal reputation results will be skipped and only SPF, DMARC, DKIM, and WHOIS data will be returned.

## Output

File	Description
\report.html\	Full domain analysis report
\report.png\	Screenshot of the HTML report
\## Use Case

Designed to support \\GRC (Governance, Risk & Compliance)\\ workflows, specifically for domain whitelisting reviews.
The HTML/screenshot output allows non-technical stakeholders to review domain reputation data without needing terminal access.
Bulk analysis via \--file\ allows analysts to process entire domain lists at once.

