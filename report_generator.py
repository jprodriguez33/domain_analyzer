"""
HTML report generation
"""

from pathlib import Path
from datetime import datetime

class ReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self._copy_css()
    
    def _copy_css(self):
        """Create CSS file"""
        css_content = """
body {
    font-family: Arial, sans-serif;
    max-width: 1000px;
    margin: 40px auto;
    padding: 20px;
    background: #f5f5f5;
}

.container {
    background: white;
    padding: 30px;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.domain-section {
    margin-bottom: 50px;
    padding-bottom: 30px;
    border-bottom: 3px solid #ddd;
}

.domain-section:last-child {
    border-bottom: none;
}

h1 {
    color: #333;
    border-bottom: 3px solid #4CAF50;
    padding-bottom: 10px;
}

.section {
    margin: 30px 0;
    padding: 20px;
    background: #fafafa;
    border-radius: 5px;
    border-left: 4px solid #2196F3;
}

h2 {
    color: #2196F3;
    margin-top: 0;
}

.good { 
    color: #4CAF50; 
    font-weight: bold; 
}

.bad { 
    color: #f44336; 
    font-weight: bold; 
}

.warning { 
    color: #ff9800; 
    font-weight: bold; 
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
}

td {
    padding: 10px;
    border-bottom: 1px solid #ddd;
}

td:first-child {
    font-weight: bold;
    width: 200px;
    color: #555;
}

.timestamp {
    color: #888;
    font-size: 14px;
}

.status-box {
    display: inline-block;
    padding: 5px 15px;
    border-radius: 4px;
    font-weight: bold;
}

.status-pass {
    background: #e8f5e9;
    color: #2e7d32;
}

.status-fail {
    background: #ffebee;
    color: #c62828;
}
"""
        css_file = self.output_dir / "style.css"
        with open(css_file, 'w') as f:
            f.write(css_content)
    
    def save_report(self, domains_results):
        """Generate and save HTML report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if len(domains_results) == 1:
            domain = list(domains_results.keys())[0]
            filename = f"{domain.replace('.', '_')}_{timestamp}.html"
        else:
            filename = f"multi_domain_{timestamp}.html"
        
        html_file = self.output_dir / filename
        html_content = self._generate_html(domains_results)
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[✓] HTML report saved: {html_file}")
        return html_file
    
    def _generate_html(self, domains_results):
        """Generate complete HTML"""
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Domain Security Analysis Report</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
"""
        
        for domain, results in domains_results.items():
            html += self._generate_domain_section(domain, results)
        
        html += """
    </div>
</body>
</html>
"""
        return html
    
    def _generate_domain_section(self, domain, results):
        """Generate HTML for a single domain"""
        html = f"""
        <div class="domain-section">
            <h1>🔒 Domain Security Analysis: {domain}</h1>
            <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d at %I:%M %p')}</p>
"""
        
        # Email Security
        html += self._generate_email_section(results.get('email', {}))
        
        # VirusTotal
        html += self._generate_virustotal_section(domain, results.get('virustotal', {}))
        
        # WHOIS
        html += self._generate_whois_section(results.get('whois', {}))
        
        html += "        </div>"
        return html
    
    def _generate_email_section(self, email_results):
        """Generate email security section"""
        html = """
            <div class="section">
                <h2>📧 Email Security (DMARC/SPF/DKIM)</h2>
"""
        
        if email_results.get('error'):
            html += f'<p class="bad">Error: {email_results["error"]}</p>'
        else:
            html += "<table>"
            
            # DMARC
            dmarc = email_results.get('dmarc', {})
            has_dmarc = bool(dmarc.get('record'))
            status = '<span class="status-box status-pass">✓ PASS</span>' if has_dmarc else '<span class="status-box status-fail">✗ FAIL</span>'
            html += f"<tr><td>DMARC Record</td><td>{status}</td></tr>"
            if has_dmarc:
                html += f'<tr><td>DMARC Policy</td><td>{dmarc.get("policy", "N/A")}</td></tr>'
                html += f'<tr><td>DMARC Record</td><td style="font-family: monospace; font-size: 12px;">{dmarc.get("record", "N/A")}</td></tr>'
            
            # SPF
            spf = email_results.get('spf', {})
            has_spf = bool(spf.get('record'))
            status = '<span class="status-box status-pass">✓ PASS</span>' if has_spf else '<span class="status-box status-fail">✗ FAIL</span>'
            html += f"<tr><td>SPF Record</td><td>{status}</td></tr>"
            if has_spf:
                html += f'<tr><td>SPF Record</td><td style="font-family: monospace; font-size: 12px;">{spf.get("record", "N/A")}</td></tr>'
            
            html += "</table>"
        
        html += "            </div>"
        return html
    
    def _generate_virustotal_section(self, domain, vt_results):
        """Generate VirusTotal section"""
        html = """
            <div class="section">
                <h2>🛡️ VirusTotal Reputation</h2>
"""
        
        if vt_results.get('error'):
            html += f'<p class="warning">Note: {vt_results["error"]}</p>'
        else:
            stats = vt_results.get('stats', {})
            malicious = stats.get('malicious', 0)
            
            html += "<table>"
            status_class = 'bad' if malicious > 0 else 'good'
            html += f'<tr><td>Malicious Detections</td><td class="{status_class}">{malicious}</td></tr>'
            html += f'<tr><td>Suspicious</td><td>{stats.get("suspicious", 0)}</td></tr>'
            html += f'<tr><td>Harmless</td><td>{stats.get("harmless", 0)}</td></tr>'
            html += f'<tr><td>Undetected</td><td>{stats.get("undetected", 0)}</td></tr>'
            html += f'<tr><td>Reputation Score</td><td>{vt_results.get("reputation", "N/A")}</td></tr>'
            
            if vt_results.get('categories'):
                cats = ', '.join(vt_results['categories'].values())
                html += f'<tr><td>Categories</td><td>{cats}</td></tr>'
            
            html += f'<tr><td>VirusTotal Link</td><td><a href="https://www.virustotal.com/gui/domain/{domain}" target="_blank">View Full Report</a></td></tr>'
            html += "</table>"
        
        html += "            </div>"
        return html
    
    def _generate_whois_section(self, whois_results):
        """Generate WHOIS section"""
        html = """
            <div class="section">
                <h2>📋 WHOIS Information</h2>
"""
        
        if whois_results.get('error'):
            html += f'<p class="bad">Error: {whois_results["error"]}</p>'
        else:
            html += "<table>"
            html += f'<tr><td>Registrar</td><td>{whois_results.get("registrar", "N/A")}</td></tr>'
            html += f'<tr><td>Creation Date</td><td>{whois_results.get("creation_date", "N/A")}</td></tr>'
            html += f'<tr><td>Expiration Date</td><td>{whois_results.get("expiration_date", "N/A")}</td></tr>'
            
            if whois_results.get('name_servers'):
                ns = whois_results['name_servers']
                if isinstance(ns, list):
                    ns = ', '.join(ns)
                else:
                    ns = str(ns)
                html += f'<tr><td>Name Servers</td><td>{ns}</td></tr>'
            
            if whois_results.get('status'):
                status = whois_results['status']
                if isinstance(status, list):
                    status = ', '.join(status)
                else:
                    status = str(status)
                html += f'<tr><td>Status</td><td>{status}</td></tr>'
            
            if whois_results.get('org'):
                html += f'<tr><td>Organization</td><td>{whois_results["org"]}</td></tr>'
            
            html += "</table>"
        
        html += "            </div>"
        return html
