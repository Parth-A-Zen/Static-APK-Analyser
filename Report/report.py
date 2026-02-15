"""
Report Generator Module

Generates JSON and HTML reports from findings.

Author: Generated for APK Security Analysis
License: MIT
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict

from Analyser.Report.manager import FindingManager
from Analyser.Loader.scope_filter import AnalysisReadyAPK

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates security analysis reports in JSON and HTML formats.
    
    Reports include:
    - Scan metadata and timestamp
    - APK information
    - Findings summary
    - Detailed findings with evidence and remediation
    - OWASP category mapping
    """
    
    def __init__(self, manager: FindingManager, data: AnalysisReadyAPK):
        """
        Initialize the report generator.
        
        Args:
            manager: FindingManager instance with collected findings
            data: AnalysisReadyAPK instance with APK information
        """
        self.manager = manager
        self.data = data
        self.logger = logger
        self.scan_timestamp = datetime.utcnow().isoformat() + "Z"
    
    def generate_json_report(self, output_path: str) -> None:
        """
        Generate a JSON format report.
        
        Args:
            output_path: Path where the JSON report will be saved
        """
        self.logger.info(f"Generating JSON report: {output_path}")
        
        report = self._build_report_structure()
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"JSON report saved: {output_path}")
        
        except Exception as e:
            self.logger.error(f"Failed to save JSON report: {str(e)}")
            raise
    
    def generate_html_report(self, output_path: str) -> None:
        """
        Generate an HTML format report.
        
        Args:
            output_path: Path where the HTML report will be saved
        """
        self.logger.info(f"Generating HTML report: {output_path}")
        
        html_content = self._build_html_report()
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report saved: {output_path}")
        
        except Exception as e:
            self.logger.error(f"Failed to save HTML report: {str(e)}")
            raise
    
    def _build_report_structure(self) -> Dict[str, Any]:
        """Build the complete report data structure."""
        findings_by_severity = self.manager.group_by_severity()
        findings_by_owasp = self.manager.group_by_owasp()
        summary = self.manager.get_summary()
        
        return {
            "report_metadata": {
                "scan_timestamp": self.scan_timestamp,
                "report_version": "1.0",
                "owasp_version": "OWASP Mobile Top 10 2024"
            },
            "apk_metadata": {
                "package_name": self.data.package_name,
                "version_name": self.data.version_name,
                "version_code": self.data.version_code,
                "min_sdk_version": self.data.min_sdk_version,
                "target_sdk_version": self.data.target_sdk_version
            },
            "analysis_summary": {
                "total_findings": summary['Total'],
                "critical_findings": summary['Critical'],
                "high_findings": summary['High'],
                "medium_findings": summary['Medium'],
                "low_findings": summary['Low'],
                "has_critical": self.manager.has_critical(),
                "has_high": self.manager.has_high()
            },
            "findings_by_severity": {
                severity: [f.to_dict() for f in findings]
                for severity, findings in findings_by_severity.items()
            },
            "findings_by_owasp_category": {
                category: [f.to_dict() for f in findings]
                for category, findings in findings_by_owasp.items()
            },
            "all_findings": [f.to_dict() for f in self.manager.get_all()]
        }
    
    def _build_html_report(self) -> str:
        """Build an HTML report with styling and interactivity."""
        summary = self.manager.get_summary()
        findings_by_severity = self.manager.group_by_severity()
        findings_by_owasp = self.manager.group_by_owasp()
        
        # Build severity badge color mapping
        severity_colors = {
            'Critical': '#d32f2f',  # Red
            'High': '#f57c00',      # Orange
            'Medium': '#fbc02d',    # Yellow
            'Low': '#388e3c'        # Green
        }
        
        severity_text_colors = {
            'Critical': '#ffffff',
            'High': '#ffffff',
            'Medium': '#000000',
            'Low': '#ffffff'
        }
        
        html_parts = [
            self._html_head(),
            self._html_header(summary, severity_colors),
            self._html_summary_cards(summary, severity_colors, severity_text_colors),
            self._html_findings_section(findings_by_severity, severity_colors, severity_text_colors),
            self._html_owasp_section(findings_by_owasp),
            self._html_footer()
        ]
        
        return '\n'.join(html_parts)
    
    def _html_head(self) -> str:
        """Generate HTML head section."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Security Analysis Report - {self.data.package_name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            line-height: 1.6;
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .metadata {{
            background: #f5f5f5;
            padding: 20px;
            border-bottom: 1px solid #ddd;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }}
        
        .metadata-item {{
            font-size: 0.9em;
        }}
        
        .metadata-label {{
            font-weight: 600;
            color: #666;
            text-transform: uppercase;
            font-size: 0.75em;
            letter-spacing: 1px;
        }}
        
        .metadata-value {{
            color: #333;
            font-size: 1.1em;
            margin-top: 5px;
            word-break: break-all;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .card {{
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            color: white;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        
        .card-number {{
            font-size: 2.5em;
            font-weight: bold;
            display: block;
        }}
        
        .card-label {{
            font-size: 0.9em;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section-title {{
            font-size: 1.5em;
            font-weight: 600;
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        
        .finding {{
            border: 1px solid #ddd;
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 15px;
            background: #fafafa;
        }}
        
        .finding-header {{
            display: flex;
            align-items: flex-start;
            gap: 15px;
            margin-bottom: 15px;
        }}
        
        .severity-badge {{
            padding: 6px 12px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.85em;
            white-space: nowrap;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .finding-title {{
            font-size: 1.1em;
            font-weight: 600;
            color: #333;
            flex: 1;
        }}
        
        .finding-details {{
            margin-left: 0;
        }}
        
        .detail-row {{
            display: grid;
            grid-template-columns: 150px 1fr;
            gap: 15px;
            margin-bottom: 12px;
            font-size: 0.95em;
        }}
        
        .detail-label {{
            font-weight: 600;
            color: #666;
            text-transform: uppercase;
            font-size: 0.8em;
            letter-spacing: 0.5px;
        }}
        
        .detail-value {{
            color: #333;
        }}
        
        .owasp-badge {{
            display: inline-block;
            background: #e3f2fd;
            color: #1565c0;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 500;
        }}
        
        .evidence {{
            background: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 12px;
            margin: 10px 0;
            font-family: "Courier New", monospace;
            font-size: 0.85em;
            color: #d32f2f;
            word-break: break-all;
            max-height: 150px;
            overflow-y: auto;
        }}
        
        .remediation {{
            background: #f0f4c3;
            border-left: 4px solid #9ccc65;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
            font-size: 0.95em;
        }}
        
        .footer {{
            background: #f5f5f5;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.85em;
            border-top: 1px solid #ddd;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            
            .container {{
                box-shadow: none;
                border-radius: 0;
            }}
        }}
    </style>
</head>"""
    
    def _html_header(self, summary: Dict[str, int], severity_colors: Dict[str, str]) -> str:
        """Generate HTML header section."""
        return f"""<body>
<div class="container">
    <div class="header">
        <h1>APK Security Analysis Report</h1>
        <p>{self.data.package_name}</p>
    </div>
    
    <div class="metadata">
        <div class="metadata-item">
            <div class="metadata-label">Package Name</div>
            <div class="metadata-value">{self.data.package_name}</div>
        </div>
        <div class="metadata-item">
            <div class="metadata-label">Version</div>
            <div class="metadata-value">{self.data.version_name} ({self.data.version_code})</div>
        </div>
        <div class="metadata-item">
            <div class="metadata-label">Target SDK</div>
            <div class="metadata-value">{self.data.target_sdk_version or 'Unknown'}</div>
        </div>
        <div class="metadata-item">
            <div class="metadata-label">Scan Date</div>
            <div class="metadata-value">{self.scan_timestamp}</div>
        </div>
    </div>
    
    <div class="content">"""
    
    def _html_summary_cards(
        self,
        summary: Dict[str, int],
        severity_colors: Dict[str, str],
        text_colors: Dict[str, str]
    ) -> str:
        """Generate summary cards section."""
        html = '<div class="summary-cards">\n'
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            count = summary.get(severity, 0)
            color = severity_colors.get(severity, '#999')
            text_color = text_colors.get(severity, '#fff')
            
            html += f"""    <div class="card" style="background-color: {color}; color: {text_color};">
        <span class="card-number">{count}</span>
        <span class="card-label">{severity} Findings</span>
    </div>\n"""
        
        html += '</div>\n'
        return html
    
    def _html_findings_section(
        self,
        findings_by_severity: Dict[str, list],
        severity_colors: Dict[str, str],
        text_colors: Dict[str, str]
    ) -> str:
        """Generate findings section grouped by severity."""
        html = '<div class="section">\n'
        html += '    <h2 class="section-title">Findings by Severity</h2>\n'
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            findings = findings_by_severity.get(severity, [])
            if not findings:
                continue
            
            html += f'    <h3 style="margin-top: 30px; margin-bottom: 15px; color: {severity_colors[severity]};"> {severity} ({len(findings)})</h3>\n'
            
            for finding in findings:
                color = severity_colors[severity]
                
                html += f"""    <div class="finding">
        <div class="finding-header">
            <span class="severity-badge" style="background-color: {color}; color: {text_colors[severity]};">
                {finding.severity}
            </span>
            <span class="owasp-badge">{finding.owasp_category}</span>
        </div>
        <div class="finding-title">{self._escape_html(finding.title)}</div>
        <div class="finding-details">
            <div class="detail-row">
                <div class="detail-label">Description</div>
                <div class="detail-value">{self._escape_html(finding.description)}</div>
            </div>
"""
                
                if finding.affected_component:
                    html += f"""            <div class="detail-row">
                <div class="detail-label">Component</div>
                <div class="detail-value">{self._escape_html(finding.affected_component)}</div>
            </div>
"""
                
                if finding.evidence:
                    html += """            <div class="detail-row">
                <div class="detail-label">Evidence</div>
                <div class="detail-value">"""
                    
                    for key, value in finding.evidence.items():
                        if isinstance(value, (list, dict)):
                            html += f"<div><strong>{key}:</strong> {self._escape_html(str(value)[:100])}</div>"
                        else:
                            html += f"<div><strong>{key}:</strong> {self._escape_html(str(value))}</div>"
                    
                    html += """</div>
            </div>
"""
                
                html += f"""            <div class="remediation">
                <strong>Remediation:</strong><br>
                {self._escape_html(finding.remediation)}
            </div>
        </div>
    </div>
"""
        
        html += '</div>\n'
        return html
    
    def _html_owasp_section(self, findings_by_owasp: Dict[str, list]) -> str:
        """Generate OWASP category section."""
        html = '<div class="section">\n'
        html += '    <h2 class="section-title">Findings by OWASP Category</h2>\n'
        
        for category in sorted(findings_by_owasp.keys()):
            findings = findings_by_owasp[category]
            html += f'    <h3 style="margin-top: 20px; margin-bottom: 10px;">{category} ({len(findings)})</h3>\n'
            html += '    <ul style="margin-left: 20px;">\n'
            
            for finding in findings:
                html += f'        <li>{self._escape_html(finding.title)} - <span style="color: #f57c00;">{finding.severity}</span></li>\n'
            
            html += '    </ul>\n'
        
        html += '</div>\n'
        return html
    
    def _html_footer(self) -> str:
        """Generate HTML footer."""
        return """        </div>
    </div>
    <div class="footer">
        <p>Generated by APK Security Analysis Tool</p>
        <p>OWASP Mobile Top 10 2024</p>
    </div>
</body>
</html>"""
    
    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters."""
        if not isinstance(text, str):
            text = str(text)
        
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))