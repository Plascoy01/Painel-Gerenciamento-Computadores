#!/usr/bin/env python3
"""
Report Generation System
Aggregate and export scan results
"""

import json
import csv
import os
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

class Report:
    """Report generation and aggregation"""
    
    def __init__(self, target, output_format='json'):
        self.target = target
        self.output_format = output_format  # 'json', 'csv', 'html', 'txt'
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scans': {},
            'vulnerabilities': [],
            'summary': {
                'total_scans': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
    
    def add_scan_result(self, scan_name, result, severity='info'):
        """Add a scan result"""
        self.results['scans'][scan_name] = {
            'result': result,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        self.results['summary']['total_scans'] += 1
        
        if severity == 'critical':
            self.results['summary']['critical'] += 1
        elif severity == 'high':
            self.results['summary']['high'] += 1
        elif severity == 'medium':
            self.results['summary']['medium'] += 1
        elif severity == 'low':
            self.results['summary']['low'] += 1
        else:
            self.results['summary']['info'] += 1
    
    def add_vulnerability(self, vuln_type, description, severity='medium', remediation=None):
        """Add a vulnerability finding"""
        vuln = {
            'type': vuln_type,
            'description': description,
            'severity': severity,
            'remediation': remediation,
            'timestamp': datetime.now().isoformat()
        }
        self.results['vulnerabilities'].append(vuln)
        
        # Update severity count
        if severity == 'critical':
            self.results['summary']['critical'] += 1
        elif severity == 'high':
            self.results['summary']['high'] += 1
        elif severity == 'medium':
            self.results['summary']['medium'] += 1
        elif severity == 'low':
            self.results['summary']['low'] += 1
    
    def export_json(self, filename=None):
        """Export report to JSON"""
        if not filename:
            filename = f"report_{self.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(Fore.GREEN + f"[REPORT] JSON report saved: {filename}")
            return filename
        except Exception as e:
            print(Fore.RED + f"[ERROR] Could not save JSON report: {e}")
            return None
    
    def export_html(self, filename=None):
        """Export report to HTML"""
        if not filename:
            filename = f"report_{self.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>PLASCOV Security Report - {self.target}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 10px;
            margin-bottom: 20px;
        }}
        .summary-item {{
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            color: white;
            font-weight: bold;
        }}
        .critical {{ background-color: #c0392b; }}
        .high {{ background-color: #e74c3c; }}
        .medium {{ background-color: #f39c12; }}
        .low {{ background-color: #3498db; }}
        .info {{ background-color: #95a5a6; }}
        .total {{ background-color: #34495e; }}
        .scan-result {{
            background-color: white;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid #3498db;
            border-radius: 3px;
        }}
        .vulnerability {{
            background-color: #ffe6e6;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid #c0392b;
            border-radius: 3px;
        }}
        .remediation {{
            background-color: #e8f8f5;
            padding: 10px;
            margin-top: 10px;
            border-radius: 3px;
        }}
        h2 {{ color: #2c3e50; }}
        .severity-badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            margin-left: 10px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>PLASCOV Security Report</h1>
        <p>Target: {self.target}</p>
        <p>Timestamp: {self.results['timestamp']}</p>
    </div>
    
    <h2>Summary</h2>
    <div class="summary">
        <div class="summary-item critical">Critical: {self.results['summary']['critical']}</div>
        <div class="summary-item high">High: {self.results['summary']['high']}</div>
        <div class="summary-item medium">Medium: {self.results['summary']['medium']}</div>
        <div class="summary-item low">Low: {self.results['summary']['low']}</div>
        <div class="summary-item info">Info: {self.results['summary']['info']}</div>
        <div class="summary-item total">Total: {self.results['summary']['total_scans']}</div>
    </div>
    
    <h2>Vulnerabilities</h2>
"""
        
        for vuln in self.results['vulnerabilities']:
            severity_color = vuln['severity']
            html_content += f"""
    <div class="vulnerability">
        <strong>{vuln['type']}</strong>
        <span class="severity-badge {severity_color}">{vuln['severity'].upper()}</span>
        <p>{vuln['description']}</p>
"""
            if vuln.get('remediation'):
                html_content += f"""
        <div class="remediation">
            <strong>Remediation:</strong> {vuln['remediation']}
        </div>
"""
            html_content += "    </div>\n"
        
        html_content += """
    <h2>Scan Results</h2>
"""
        
        for scan_name, scan_data in self.results['scans'].items():
            html_content += f"""
    <div class="scan-result">
        <strong>{scan_name}</strong>
        <p>{scan_data['result']}</p>
    </div>
"""
        
        html_content += """
</body>
</html>
"""
        
        try:
            with open(filename, 'w') as f:
                f.write(html_content)
            print(Fore.GREEN + f"[REPORT] HTML report saved: {filename}")
            return filename
        except Exception as e:
            print(Fore.RED + f"[ERROR] Could not save HTML report: {e}")
            return None
    
    def export_csv(self, filename=None):
        """Export vulnerabilities to CSV"""
        if not filename:
            filename = f"vulnerabilities_{self.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Type', 'Description', 'Severity', 'Remediation', 'Timestamp'])
                
                for vuln in self.results['vulnerabilities']:
                    writer.writerow([
                        vuln['type'],
                        vuln['description'],
                        vuln['severity'],
                        vuln.get('remediation', 'N/A'),
                        vuln['timestamp']
                    ])
            
            print(Fore.GREEN + f"[REPORT] CSV report saved: {filename}")
            return filename
        except Exception as e:
            print(Fore.RED + f"[ERROR] Could not save CSV report: {e}")
            return None
    
    def export_txt(self, filename=None):
        """Export report to TXT"""
        if not filename:
            filename = f"report_{self.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        txt_content = f"""PLASCOV Security Report
Target: {self.target}
Timestamp: {self.results['timestamp']}

=== SUMMARY ===
Total Scans: {self.results['summary']['total_scans']}
Critical: {self.results['summary']['critical']}
High: {self.results['summary']['high']}
Medium: {self.results['summary']['medium']}
Low: {self.results['summary']['low']}
Info: {self.results['summary']['info']}

=== VULNERABILITIES ===
"""
        
        for vuln in self.results['vulnerabilities']:
            txt_content += f"""
[{vuln['severity'].upper()}] {vuln['type']}
Description: {vuln['description']}
"""
            if vuln.get('remediation'):
                txt_content += f"Remediation: {vuln['remediation']}\n"
        
        txt_content += "\n=== SCAN RESULTS ===\n"
        
        for scan_name, scan_data in self.results['scans'].items():
            txt_content += f"\n{scan_name}: {scan_data['result']}\n"
        
        try:
            with open(filename, 'w') as f:
                f.write(txt_content)
            print(Fore.GREEN + f"[REPORT] TXT report saved: {filename}")
            return filename
        except Exception as e:
            print(Fore.RED + f"[ERROR] Could not save TXT report: {e}")
            return None
    
    def export(self, format=None, filename=None):
        """Export report in specified format"""
        fmt = format or self.output_format
        
        if fmt == 'json':
            return self.export_json(filename)
        elif fmt == 'html':
            return self.export_html(filename)
        elif fmt == 'csv':
            return self.export_csv(filename)
        elif fmt == 'txt':
            return self.export_txt(filename)
        else:
            print(Fore.YELLOW + f"[INFO] Unknown format: {fmt}")
            return None
    
    def print_summary(self):
        """Print summary to console"""
        print(Fore.MAGENTA + "\n=== REPORT SUMMARY ===")
        print(Fore.CYAN + f"Target: {self.target}")
        print(Fore.CYAN + f"Timestamp: {self.results['timestamp']}")
        print(Fore.RED + f"Critical: {self.results['summary']['critical']}")
        print(Fore.YELLOW + f"High: {self.results['summary']['high']}")
        print(Fore.YELLOW + f"Medium: {self.results['summary']['medium']}")
        print(Fore.BLUE + f"Low: {self.results['summary']['low']}")
        print(Fore.GREEN + f"Info: {self.results['summary']['info']}")
        print(Fore.CYAN + f"Total: {self.results['summary']['total_scans']}")
