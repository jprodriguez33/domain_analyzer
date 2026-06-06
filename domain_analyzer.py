#!/usr/bin/env python3
"""
Domain Security Analyzer - Main Script
"""

import sys
from pathlib import Path
from analyzer import DomainChecker
from report_generator import ReportGenerator
from screenshot import ScreenshotTaker

def read_domains_from_file(filename):
    """Read domains from a text file (one per line)"""
    try:
        with open(filename, 'r') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return domains
    except Exception as e:
        print(f"Error reading file {filename}: {e}")
        return []

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Single domain:    python domain_analyzer.py example.com [--vt-key YOUR_API_KEY]")
        print("  Multiple domains: python domain_analyzer.py domain1.com domain2.com [--vt-key YOUR_API_KEY]")
        print("  From file:        python domain_analyzer.py --file domains.txt [--vt-key YOUR_API_KEY]")
        print("\nExample: python domain_analyzer.py example.com google.com --vt-key abc123")
        sys.exit(1)
    
    vt_key = None
    domains = []
    
    # Parse arguments
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--vt-key" and i + 1 < len(sys.argv):
            vt_key = sys.argv[i + 1]
            i += 2
        elif arg == "--file" and i + 1 < len(sys.argv):
            domains = read_domains_from_file(sys.argv[i + 1])
            i += 2
        elif not arg.startswith('--'):
            domains.append(arg)
            i += 1
        else:
            i += 1
    
    if not domains:
        print("Error: No domains provided!")
        sys.exit(1)
    
    print(f"[*] Analyzing {len(domains)} domain(s)...")
    
    # Check all domains
    checker = DomainChecker(vt_key)
    all_results = {}
    
    for domain in domains:
        results = checker.check_domain(domain)
        all_results[domain] = results
    
    # Generate report
    print("\n[*] Generating report...")
    report_gen = ReportGenerator()
    html_file = report_gen.save_report(all_results)
    
    # Take screenshot
    screenshotter = ScreenshotTaker()
    screenshotter.capture(html_file, all_results)

if __name__ == "__main__":
    main()
