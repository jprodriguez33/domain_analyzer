"""
Domain checking logic
"""

import checkdmarc
import requests
import whois


class DomainChecker:
    def __init__(self, vt_api_key=None):
        self.vt_api_key = vt_api_key
    
    def check_domain(self, domain):
        """Run all checks and return results"""
        results = {}
        
        print(f"\n[*] Analyzing {domain}...")
        
        results['email'] = self._check_email_security(domain)
        results['virustotal'] = self._check_virustotal(domain)
        results['whois'] = self._check_whois(domain)
        
        return results
    
    def _check_email_security(self, domain):
        """Check DMARC/SPF/DKIM"""
        print("  - Checking DMARC/SPF/DKIM...")
        try:
            email_results = checkdmarc.check_domains([domain])
            return {
                'dmarc': email_results.get('dmarc', {}),
                'spf': email_results.get('spf', {}),
                'error': None
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _check_virustotal(self, domain):
        """Check VirusTotal reputation"""
        print("  - Checking VirusTotal...")
        
        if not self.vt_api_key:
            return {'error': 'No API key provided'}
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                attrs = data['data']['attributes']
                return {
                    'stats': attrs['last_analysis_stats'],
                    'reputation': attrs.get('reputation', 'N/A'),
                    'categories': attrs.get('categories', {}),
                    'error': None
                }
            else:
                return {'error': f"API Status {response.status_code}"}
        except Exception as e:
            return {'error': str(e)}
    
    def _check_whois(self, domain):
        """Check WHOIS information"""
        print("  - Checking WHOIS...")
        
        try:
            if hasattr(whois, 'query'):
                w = whois.query(domain)
                return {
                    'registrar': w.registrar if hasattr(w, 'registrar') else 'N/A',
                    'creation_date': str(w.creation_date) if hasattr(w, 'creation_date') and w.creation_date else 'N/A',
                    'expiration_date': str(w.expiration_date) if hasattr(w, 'expiration_date') and w.expiration_date else 'N/A',
                    'name_servers': w.name_servers if hasattr(w, 'name_servers') else 'N/A',
                    'status': 'Active' if w else 'N/A',
                    'org': None,
                    'error': None
                }
            else:
                w = whois.whois(domain)
                return {
                    'registrar': w.registrar if hasattr(w, 'registrar') else 'N/A',
                    'creation_date': str(w.creation_date) if w.creation_date else 'N/A',
                    'expiration_date': str(w.expiration_date) if w.expiration_date else 'N/A',
                    'name_servers': w.name_servers if hasattr(w, 'name_servers') else 'N/A',
                    'status': w.status if hasattr(w, 'status') else 'N/A',
                    'org': w.org if hasattr(w, 'org') else None,
                    'error': None
                }
        except Exception as e:
            return {'error': str(e)}
