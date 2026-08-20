"""Report Generation Module
Generates comprehensive security scan reports in multiple formats with detailed findings and recommendations
"""

from colorama import Fore, Style, init
import json
import datetime
import logging
import time
from typing import Dict, List, Any
from collections import defaultdict
import csv
import html

init(autoreset=True)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReportGenerator:
    """Professional security report generation engine"""
    
    def __init__(self, target: str, findings: List[Dict] = None):
        self.target = target
        self.findings = findings or []
        self.report_date = datetime.datetime.now()
        
        self.severity_levels = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1,
            'Info': 0
        }
        
        self.report_data = {
            'target': target,
            'scan_date': self.report_date.isoformat(),
            'total_findings': len(findings),
            'severity_breakdown': defaultdict(int),
            'findings': [],
            'executive_summary': '',
            'recommendations': [],
            'remediation_steps': []
        }
    
    def categorize_findings(self) -> Dict:
        """Categorize findings by type and severity"""
        categorized = defaultdict(lambda: defaultdict(list))
        
        for finding in self.findings:
            severity = finding.get('severity', 'Low')
            finding_type = finding.get('type', 'Unknown')
            
            categorized[finding_type][severity].append(finding)
            self.report_data['severity_breakdown'][severity] += 1
        
        return dict(categorized)
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary with key metrics"""
        total = len(self.findings)
        critical = self.report_data['severity_breakdown'].get('Critical', 0)
        high = self.report_data['severity_breakdown'].get('High', 0)
        medium = self.report_data['severity_breakdown'].get('Medium', 0)
        low = self.report_data['severity_breakdown'].get('Low', 0)
        
        risk_rating = 'Critical' if critical > 0 else 'High' if high > 3 else 'Medium' if high > 0 or medium > 5 else 'Low'
        
        summary = f"""
SECURITY ASSESSMENT REPORT
{'='*60}

Target: {self.target}
Scan Date: {self.report_date.strftime('%Y-%m-%d %H:%M:%S')}
Overall Risk Rating: {risk_rating}

FINDINGS SUMMARY:
- Total Vulnerabilities: {total}
- Critical Issues: {critical}
- High Issues: {high}
- Medium Issues: {medium}
- Low Issues: {low}

KEY FINDINGS:
"""
        
        # Add top vulnerabilities
        critical_findings = [f for f in self.findings if f.get('severity') == 'Critical']
        if critical_findings:
            summary += f"\nCRITICAL VULNERABILITIES DETECTED ({len(critical_findings)}):\n"
            for finding in critical_findings[:5]:
                summary += f"  • {finding.get('type', 'Unknown')}: {finding.get('description', 'N/A')[:80]}\n"
        
        return summary
    
    def generate_detailed_findings(self) -> str:
        """Generate detailed findings section"""
        findings_text = "\nDETAILED FINDINGS\n" + "="*60 + "\n"
        
        categorized = self.categorize_findings()
        
        for finding_type in sorted(categorized.keys()):
            findings_text += f"\n{finding_type.upper()}\n{'-'*40}\n"
            
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                findings_list = categorized[finding_type].get(severity, [])
                if findings_list:
                    findings_text += f"\n[{severity.upper()}]\n"
                    for idx, finding in enumerate(findings_list, 1):
                        findings_text += f"\n{idx}. {finding.get('type', 'Unknown')}\n"
                        findings_text += f"   Description: {finding.get('description', 'N/A')}\n"
                        findings_text += f"   Impact: {finding.get('impact', 'N/A')}\n"
                        findings_text += f"   Affected Parameter: {finding.get('parameter', 'N/A')}\n"
                        findings_text += f"   Severity: {severity}\n"
        
        return findings_text
    
    def generate_recommendations(self) -> str:
        """Generate remediation recommendations"""
        recommendations = "\nRECOMMENDATIONS\n" + "="*60 + "\n"
        
        recommendation_map = {
            'SQL Injection': [
                '- Use parameterized queries/prepared statements',
                '- Implement input validation and sanitization',
                '- Apply principle of least privilege to database accounts',
                '- Use Web Application Firewall (WAF)'
            ],
            'XSS': [
                '- Implement Content Security Policy (CSP)',
                '- Encode output based on context (HTML, URL, JavaScript)',
                '- Use security-focused template engines',
                '- Apply input validation and output encoding'
            ],
            'SSRF': [
                '- Implement URL/Host validation whitelisting',
                '- Disable dangerous protocols (file://, gopher://)',
                '- Use network segmentation',
                '- Monitor outbound connections'
            ],
            'Authentication': [
                '- Implement multi-factor authentication (MFA)',
                '- Use strong password policies',
                '- Implement account lockout mechanisms',
                '- Use secure session management'
            ],
            'Security Headers': [
                '- Implement HSTS (HTTP Strict-Transport-Security)',
                '- Set Content-Security-Policy (CSP)',
                '- Configure X-Frame-Options',
                '- Implement X-Content-Type-Options: nosniff'
            ]
        }
        
        for finding in self.findings:
            finding_type = finding.get('type', '')
            severity = finding.get('severity', 'Low')
            
            if severity in ['Critical', 'High']:
                recommendations += f"\n[{severity.upper()}] {finding_type}\n"
                
                # Get recommendations for this type
                for finding_key in recommendation_map:
                    if finding_key.lower() in finding_type.lower():
                        for rec in recommendation_map[finding_key]:
                            recommendations += f"  {rec}\n"
                        break
        
        return recommendations
    
    def to_json(self, filename: str = None) -> str:
        """Export report as JSON"""
        self.report_data['findings'] = self.findings
        self.report_data['summary'] = self.generate_executive_summary()
        self.report_data['detailed_findings'] = self.generate_detailed_findings()
        self.report_data['recommendations'] = self.generate_recommendations()
        
        if not filename:
            filename = f"report_{self.target.replace('.', '_')}_{int(time.time())}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.report_data, f, indent=2, default=str)
        
        logger.info(f"JSON report saved to {filename}")
        return filename
    
    def to_text(self, filename: str = None) -> str:
        """Export report as plain text"""
        content = self.generate_executive_summary()
        content += self.generate_detailed_findings()
        content += self.generate_recommendations()
        
        if not filename:
            filename = f"report_{self.target.replace('.', '_')}_{int(time.time())}.txt"
        
        with open(filename, 'w') as f:
            f.write(content)
        
        logger.info(f"Text report saved to {filename}")
        return filename
    
    def to_html(self, filename: str = None) -> str:
        """Export report as HTML"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Scan Report - {html.escape(self.target)}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ background-color: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .critical {{ border-left: 5px solid #c0392b; background-color: #fadbd8; }}
        .high {{ border-left: 5px solid #e74c3c; background-color: #f5b7b1; }}
        .medium {{ border-left: 5px solid #f39c12; background-color: #fdebd0; }}
        .low {{ border-left: 5px solid #f1c40f; background-color: #fef5e7; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #34495e; color: white; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .metric {{ display: inline-block; width: 20%; margin: 10px 2%; padding: 10px; background-color: #ecf0f1; text-align: center; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p><strong>Target:</strong> {html.escape(self.target)}</p>
        <p><strong>Date:</strong> {self.report_date.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
"""
        
        # Add summary metrics
        html_content += "<div class='section'>"
        html_content += "<h2>Summary</h2>"
        html_content += f"<div class='metric'>Total Issues: {len(self.findings)}</div>"
        html_content += f"<div class='metric critical'>Critical: {self.report_data['severity_breakdown'].get('Critical', 0)}</div>"
        html_content += f"<div class='metric high'>High: {self.report_data['severity_breakdown'].get('High', 0)}</div>"
        html_content += f"<div class='metric medium'>Medium: {self.report_data['severity_breakdown'].get('Medium', 0)}</div>"
        html_content += f"<div class='metric low'>Low: {self.report_data['severity_breakdown'].get('Low', 0)}</div>"
        html_content += "</div>"
        
        # Add findings table
        html_content += "<div class='section'><h2>Detailed Findings</h2><table>"
        html_content += "<tr><th>Type</th><th>Severity</th><th>Description</th><th>Parameter</th></tr>"
        
        for finding in self.findings:
            severity = finding.get('severity', 'Low')
            html_content += f"<tr class='{severity.lower()}'>"
            html_content += f"<td>{html.escape(finding.get('type', 'N/A'))}</td>"
            html_content += f"<td>{severity}</td>"
            html_content += f"<td>{html.escape(finding.get('description', 'N/A')[:100])}</td>"
            html_content += f"<td>{html.escape(finding.get('parameter', 'N/A'))}</td>"
            html_content += "</tr>"
        
        html_content += "</table></div>"
        html_content += "<div class='section'><h2>Recommendations</h2><pre>" + html.escape(self.generate_recommendations()) + "</pre></div>"
        html_content += "</body></html>"
        
        if not filename:
            filename = f"report_{self.target.replace('.', '_')}_{int(time.time())}.html"
        
        with open(filename, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved to {filename}")
        return filename


def report_gen(target: str, findings: List[Dict] = None, output_format: str = 'json') -> str:
    """Main report generation function"""
    try:
        findings = findings or []
        generator = ReportGenerator(target, findings)
        
        if output_format.lower() == 'json':
            return generator.to_json()
        elif output_format.lower() == 'text' or output_format.lower() == 'txt':
            return generator.to_text()
        elif output_format.lower() == 'html':
            return generator.to_html()
        else:
            # Default to JSON
            return generator.to_json()
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return f"Error generating report: {e}"