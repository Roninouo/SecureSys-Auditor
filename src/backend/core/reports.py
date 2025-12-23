"""
PDF Report Generation Service for SecureSys Auditor.

This module provides enterprise-grade PDF report generation using WeasyPrint.
Supports multiple report types:
- Executive Summary: High-level overview for management
- Technical Report: Detailed findings for security teams
- Compliance Report: NIST/ISO 27001 control mapping
"""
import io
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from django.conf import settings
from django.template.loader import render_to_string

logger = logging.getLogger('core')

# Try to import WeasyPrint, gracefully handle if not available
try:
    from weasyprint import HTML, CSS
    from weasyprint.text.fonts import FontConfiguration
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False
    logger.warning("WeasyPrint not available. PDF generation will be disabled.")


class ReportType:
    """Report type constants."""
    EXECUTIVE = 'executive'
    TECHNICAL = 'technical'
    COMPLIANCE = 'compliance'


# NIST CSF Control Mapping
NIST_CONTROL_MAPPING = {
    'access_control': {
        'nist_id': 'PR.AC',
        'nist_name': 'Identity Management and Access Control',
        'iso_control': 'A.9 Access Control',
        'description': 'Access to assets and associated facilities is limited to authorized users, processes, or devices.',
    },
    'authentication': {
        'nist_id': 'PR.AC-1',
        'nist_name': 'Identities and Credentials',
        'iso_control': 'A.9.2 User Access Management',
        'description': 'Identities and credentials are issued, managed, verified, revoked, and audited.',
    },
    'network': {
        'nist_id': 'PR.AC-5',
        'nist_name': 'Network Integrity',
        'iso_control': 'A.13.1 Network Security Management',
        'description': 'Network integrity is protected, incorporating network segregation.',
    },
    'patch_management': {
        'nist_id': 'PR.IP-12',
        'nist_name': 'Vulnerability Management',
        'iso_control': 'A.12.6 Technical Vulnerability Management',
        'description': 'A vulnerability management plan is developed and implemented.',
    },
    'configuration': {
        'nist_id': 'PR.IP-1',
        'nist_name': 'Configuration Management',
        'iso_control': 'A.12.5 Control of Operational Software',
        'description': 'Configuration baseline is established and maintained.',
    },
    'encryption': {
        'nist_id': 'PR.DS-1',
        'nist_name': 'Data-at-rest Protection',
        'iso_control': 'A.10 Cryptography',
        'description': 'Data-at-rest is protected.',
    },
    'logging': {
        'nist_id': 'DE.CM-3',
        'nist_name': 'Personnel Activity Monitoring',
        'iso_control': 'A.12.4 Logging and Monitoring',
        'description': 'Personnel activity is monitored to detect potential cybersecurity events.',
    },
}


class PDFReportGenerator:
    """
    PDF Report Generator using WeasyPrint.
    
    Generates professional security assessment reports with
    customizable templates and branding.
    """
    
    # Base CSS for all reports
    BASE_CSS = """
        @page {
            size: A4;
            margin: 2cm 1.5cm;
            @top-center {
                content: "SecureSys Security Assessment Report";
                font-size: 10px;
                color: #666;
            }
            @bottom-center {
                content: "Page " counter(page) " of " counter(pages);
                font-size: 10px;
                color: #666;
            }
            @bottom-right {
                content: "CONFIDENTIAL";
                font-size: 9px;
                color: #cc0000;
            }
        }
        
        body {
            font-family: 'Helvetica Neue', Arial, sans-serif;
            font-size: 11pt;
            line-height: 1.6;
            color: #333;
        }
        
        h1 {
            color: #1a365d;
            font-size: 24pt;
            border-bottom: 3px solid #3182ce;
            padding-bottom: 10px;
            margin-top: 0;
        }
        
        h2 {
            color: #2c5282;
            font-size: 16pt;
            margin-top: 30px;
            border-left: 4px solid #3182ce;
            padding-left: 10px;
        }
        
        h3 {
            color: #2d3748;
            font-size: 13pt;
            margin-top: 20px;
        }
        
        .cover-page {
            text-align: center;
            padding-top: 150px;
        }
        
        .cover-title {
            font-size: 36pt;
            color: #1a365d;
            margin-bottom: 20px;
        }
        
        .cover-subtitle {
            font-size: 18pt;
            color: #4a5568;
            margin-bottom: 40px;
        }
        
        .cover-info {
            font-size: 12pt;
            color: #718096;
            margin-top: 100px;
        }
        
        .executive-summary {
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .risk-score-box {
            display: inline-block;
            padding: 15px 30px;
            border-radius: 8px;
            font-size: 24pt;
            font-weight: bold;
            text-align: center;
            margin: 10px;
        }
        
        .risk-critical { background: #fed7d7; color: #c53030; }
        .risk-high { background: #feebc8; color: #c05621; }
        .risk-medium { background: #fefcbf; color: #975a16; }
        .risk-low { background: #c6f6d5; color: #276749; }
        
        .maturity-level {
            font-size: 14pt;
            padding: 10px 20px;
            border-radius: 4px;
            display: inline-block;
        }
        
        .maturity-reactive { background: #fed7d7; color: #c53030; }
        .maturity-basic { background: #feebc8; color: #c05621; }
        .maturity-managed { background: #fefcbf; color: #975a16; }
        .maturity-optimized { background: #c6f6d5; color: #276749; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            font-size: 10pt;
        }
        
        th {
            background: #2c5282;
            color: white;
            padding: 10px;
            text-align: left;
        }
        
        td {
            padding: 8px 10px;
            border-bottom: 1px solid #e2e8f0;
        }
        
        tr:nth-child(even) {
            background: #f7fafc;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 9pt;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .severity-critical { background: #c53030; color: white; }
        .severity-high { background: #dd6b20; color: white; }
        .severity-medium { background: #d69e2e; color: white; }
        .severity-low { background: #38a169; color: white; }
        
        .finding-card {
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
            page-break-inside: avoid;
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .recommendation-box {
            background: #ebf8ff;
            border-left: 4px solid #3182ce;
            padding: 10px 15px;
            margin: 10px 0;
        }
        
        .compliance-table {
            margin: 20px 0;
        }
        
        .control-mapping {
            background: #f7fafc;
            padding: 10px;
            border-radius: 4px;
            margin: 5px 0;
        }
        
        .page-break {
            page-break-after: always;
        }
        
        .chart-placeholder {
            background: #f0f0f0;
            border: 2px dashed #ccc;
            padding: 40px;
            text-align: center;
            color: #666;
            margin: 20px 0;
        }
        
        .metric-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 20px 0;
        }
        
        .metric-box {
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
        }
        
        .metric-value {
            font-size: 24pt;
            font-weight: bold;
            color: #2c5282;
        }
        
        .metric-label {
            font-size: 10pt;
            color: #718096;
        }
        
        .footer-note {
            font-size: 9pt;
            color: #718096;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
        }
    """
    
    def __init__(self):
        if not WEASYPRINT_AVAILABLE:
            raise RuntimeError("WeasyPrint is not installed. Install with: pip install weasyprint")
        self.font_config = FontConfiguration()
    
    def generate_report(
        self,
        scan_data: Dict[str, Any],
        report_type: str = ReportType.EXECUTIVE,
        include_recommendations: bool = True,
        company_name: str = "Organization"
    ) -> bytes:
        """
        Generate a PDF report from scan data.
        
        Args:
            scan_data: Dictionary containing scan results
            report_type: Type of report (executive, technical, compliance)
            include_recommendations: Whether to include remediation recommendations
            company_name: Name of the organization for the report
        
        Returns:
            PDF file as bytes
        """
        # Prepare context for template
        context = self._prepare_context(scan_data, report_type, include_recommendations, company_name)
        
        # Generate HTML content
        if report_type == ReportType.EXECUTIVE:
            html_content = self._render_executive_report(context)
        elif report_type == ReportType.TECHNICAL:
            html_content = self._render_technical_report(context)
        elif report_type == ReportType.COMPLIANCE:
            html_content = self._render_compliance_report(context)
        else:
            raise ValueError(f"Unknown report type: {report_type}")
        
        # Convert to PDF
        pdf_bytes = self._html_to_pdf(html_content)
        
        logger.info(f"Generated {report_type} report", extra={
            'report_type': report_type,
            'scan_id': scan_data.get('id'),
            'pdf_size': len(pdf_bytes)
        })
        
        return pdf_bytes
    
    def _prepare_context(
        self,
        scan_data: Dict[str, Any],
        report_type: str,
        include_recommendations: bool,
        company_name: str
    ) -> Dict[str, Any]:
        """Prepare template context from scan data."""
        findings = scan_data.get('findings', [])
        
        # Count findings by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in findings:
            severity = finding.get('severity', 'low').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Group findings by category
        findings_by_category = {}
        for finding in findings:
            category = finding.get('category', 'other')
            if category not in findings_by_category:
                findings_by_category[category] = []
            findings_by_category[category].append(finding)
        
        # Add compliance mappings
        compliance_findings = []
        for finding in findings:
            category = finding.get('category', 'other')
            mapping = NIST_CONTROL_MAPPING.get(category, {})
            compliance_findings.append({
                **finding,
                'nist_id': mapping.get('nist_id', 'N/A'),
                'nist_name': mapping.get('nist_name', 'Not Mapped'),
                'iso_control': mapping.get('iso_control', 'Not Mapped'),
            })
        
        return {
            'company_name': company_name,
            'report_type': report_type,
            'generated_at': datetime.now(),
            'scan_id': scan_data.get('id'),
            'scan_date': scan_data.get('scan_date'),
            'system': scan_data.get('system', {}),
            'risk_score': scan_data.get('risk_score', 0),
            'maturity_level': scan_data.get('maturity_level', 'reactive'),
            'total_findings': len(findings),
            'severity_counts': severity_counts,
            'findings': findings,
            'findings_by_category': findings_by_category,
            'compliance_findings': compliance_findings,
            'include_recommendations': include_recommendations,
            'nist_mapping': NIST_CONTROL_MAPPING,
        }
    
    def _render_executive_report(self, context: Dict[str, Any]) -> str:
        """Render executive summary report HTML."""
        risk_score = context['risk_score']
        risk_class = self._get_risk_class(risk_score)
        maturity_level = context['maturity_level']
        maturity_class = f"maturity-{maturity_level}"
        severity_counts = context['severity_counts']
        
        # Get top 5 critical/high findings for executive summary
        critical_findings = [f for f in context['findings'] 
                          if f.get('severity') in ['critical', 'high']][:5]
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Security Assessment - Executive Summary</title>
        </head>
        <body>
            <div class="cover-page">
                <div class="cover-title">Security Assessment Report</div>
                <div class="cover-subtitle">Executive Summary</div>
                <div style="font-size: 14pt; color: #2c5282;">
                    {context['company_name']}
                </div>
                <div class="cover-info">
                    <p>System: {context['system'].get('hostname', 'N/A')}</p>
                    <p>Assessment Date: {context['scan_date']}</p>
                    <p>Report Generated: {context['generated_at'].strftime('%B %d, %Y')}</p>
                </div>
            </div>
            
            <div class="page-break"></div>
            
            <h1>Executive Summary</h1>
            
            <div class="executive-summary">
                <h3>Overall Security Posture</h3>
                <div style="text-align: center; margin: 30px 0;">
                    <div class="risk-score-box {risk_class}">
                        Risk Score: {risk_score}/100
                    </div>
                    <div class="maturity-level {maturity_class}">
                        Maturity Level: {maturity_level.upper()}
                    </div>
                </div>
                
                <div class="metric-grid">
                    <div class="metric-box">
                        <div class="metric-value" style="color: #c53030;">{severity_counts['critical']}</div>
                        <div class="metric-label">Critical</div>
                    </div>
                    <div class="metric-box">
                        <div class="metric-value" style="color: #dd6b20;">{severity_counts['high']}</div>
                        <div class="metric-label">High</div>
                    </div>
                    <div class="metric-box">
                        <div class="metric-value" style="color: #d69e2e;">{severity_counts['medium']}</div>
                        <div class="metric-label">Medium</div>
                    </div>
                    <div class="metric-box">
                        <div class="metric-value" style="color: #38a169;">{severity_counts['low']}</div>
                        <div class="metric-label">Low</div>
                    </div>
                </div>
            </div>
            
            <h2>Key Findings Requiring Immediate Attention</h2>
            <p>The following {len(critical_findings)} findings require immediate attention from leadership:</p>
            
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Finding</th>
                        <th>Category</th>
                        <th>Business Impact</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for finding in critical_findings:
            severity = finding.get('severity', 'medium')
            html += f"""
                    <tr>
                        <td><span class="severity-badge severity-{severity}">{severity}</span></td>
                        <td>{finding.get('title', 'N/A')}</td>
                        <td>{finding.get('category', 'N/A').replace('_', ' ').title()}</td>
                        <td>{self._get_business_impact(severity)}</td>
                    </tr>
            """
        
        html += f"""
                </tbody>
            </table>
            
            <h2>Recommendations Summary</h2>
            <div class="recommendation-box">
                <h3>Immediate Actions (0-30 days)</h3>
                <ul>
                    <li>Address all critical severity findings</li>
                    <li>Implement emergency patches for vulnerable systems</li>
                    <li>Review and restrict administrative access</li>
                </ul>
            </div>
            
            <div class="recommendation-box">
                <h3>Short-term Actions (30-90 days)</h3>
                <ul>
                    <li>Remediate high severity findings</li>
                    <li>Strengthen authentication mechanisms</li>
                    <li>Implement network segmentation improvements</li>
                </ul>
            </div>
            
            <div class="recommendation-box">
                <h3>Long-term Initiatives (90+ days)</h3>
                <ul>
                    <li>Develop comprehensive security awareness program</li>
                    <li>Establish continuous monitoring capabilities</li>
                    <li>Implement security automation and orchestration</li>
                </ul>
            </div>
            
            <div class="footer-note">
                <p>This report contains confidential security assessment information. 
                Distribution should be limited to authorized personnel only.</p>
                <p>Report ID: {context['scan_id']}</p>
            </div>
        </body>
        </html>
        """
        return html
    
    def _render_technical_report(self, context: Dict[str, Any]) -> str:
        """Render detailed technical report HTML."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Security Assessment - Technical Report</title>
        </head>
        <body>
            <div class="cover-page">
                <div class="cover-title">Security Assessment Report</div>
                <div class="cover-subtitle">Technical Findings & Remediation</div>
                <div style="font-size: 14pt; color: #2c5282;">
                    {context['company_name']}
                </div>
                <div class="cover-info">
                    <p>System: {context['system'].get('hostname', 'N/A')}</p>
                    <p>OS: {context['system'].get('os', 'N/A')} {context['system'].get('os_version', '')}</p>
                    <p>Assessment Date: {context['scan_date']}</p>
                    <p>Report Generated: {context['generated_at'].strftime('%B %d, %Y %H:%M:%S')}</p>
                </div>
            </div>
            
            <div class="page-break"></div>
            
            <h1>Technical Assessment Report</h1>
            
            <h2>System Information</h2>
            <table>
                <tr><td><strong>Hostname</strong></td><td>{context['system'].get('hostname', 'N/A')}</td></tr>
                <tr><td><strong>Operating System</strong></td><td>{context['system'].get('os', 'N/A')}</td></tr>
                <tr><td><strong>OS Version</strong></td><td>{context['system'].get('os_version', 'N/A')}</td></tr>
                <tr><td><strong>Environment</strong></td><td>{context['system'].get('environment', 'N/A')}</td></tr>
                <tr><td><strong>IP Address</strong></td><td>{context['system'].get('ip_address', 'N/A')}</td></tr>
            </table>
            
            <h2>Risk Assessment Summary</h2>
            <table>
                <tr><td><strong>Overall Risk Score</strong></td><td>{context['risk_score']}/100</td></tr>
                <tr><td><strong>Maturity Level</strong></td><td>{context['maturity_level'].upper()}</td></tr>
                <tr><td><strong>Total Findings</strong></td><td>{context['total_findings']}</td></tr>
                <tr><td><strong>Critical</strong></td><td>{context['severity_counts']['critical']}</td></tr>
                <tr><td><strong>High</strong></td><td>{context['severity_counts']['high']}</td></tr>
                <tr><td><strong>Medium</strong></td><td>{context['severity_counts']['medium']}</td></tr>
                <tr><td><strong>Low</strong></td><td>{context['severity_counts']['low']}</td></tr>
            </table>
            
            <div class="page-break"></div>
            
            <h2>Detailed Findings</h2>
        """
        
        # Sort findings by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_findings = sorted(
            context['findings'],
            key=lambda x: severity_order.get(x.get('severity', 'low'), 4)
        )
        
        for i, finding in enumerate(sorted_findings, 1):
            severity = finding.get('severity', 'medium')
            html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <h3>Finding #{i}: {finding.get('title', 'Untitled')}</h3>
                    <span class="severity-badge severity-{severity}">{severity.upper()}</span>
                </div>
                
                <p><strong>Category:</strong> {finding.get('category', 'N/A').replace('_', ' ').title()}</p>
                <p><strong>Description:</strong> {finding.get('description', 'No description provided.')}</p>
                
                <h4>Evidence</h4>
                <pre style="background: #f7fafc; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 9pt;">
{self._format_evidence(finding.get('evidence', {}))}
                </pre>
            """
            
            if context['include_recommendations']:
                recommendations = finding.get('recommendations', [])
                if recommendations:
                    html += "<h4>Remediation Steps</h4>"
                    for rec in recommendations:
                        html += f"""
                <div class="recommendation-box">
                    <strong>{rec.get('title', 'Recommendation')}</strong>
                    <p>{rec.get('description', '')}</p>
                    <p><strong>Priority:</strong> {rec.get('priority', 'medium').upper()} | 
                       <strong>Effort:</strong> {rec.get('effort', 'medium').upper()}</p>
                    <ol>
                        {''.join(f'<li>{step}</li>' for step in rec.get('steps', []))}
                    </ol>
                </div>
                        """
            
            html += "</div>"
        
        html += f"""
            <div class="footer-note">
                <p>This technical report is intended for IT security professionals and system administrators.</p>
                <p>Scan ID: {context['scan_id']}</p>
            </div>
        </body>
        </html>
        """
        return html
    
    def _render_compliance_report(self, context: Dict[str, Any]) -> str:
        """Render compliance mapping report HTML."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Security Assessment - Compliance Report</title>
        </head>
        <body>
            <div class="cover-page">
                <div class="cover-title">Security Assessment Report</div>
                <div class="cover-subtitle">Compliance & Control Mapping</div>
                <div style="font-size: 12pt; color: #4a5568;">
                    NIST Cybersecurity Framework & ISO 27001
                </div>
                <div style="font-size: 14pt; color: #2c5282; margin-top: 20px;">
                    {context['company_name']}
                </div>
                <div class="cover-info">
                    <p>System: {context['system'].get('hostname', 'N/A')}</p>
                    <p>Assessment Date: {context['scan_date']}</p>
                    <p>Report Generated: {context['generated_at'].strftime('%B %d, %Y')}</p>
                </div>
            </div>
            
            <div class="page-break"></div>
            
            <h1>Compliance Assessment Report</h1>
            
            <h2>Framework Reference</h2>
            <p>This report maps identified security findings to industry-standard frameworks:</p>
            <ul>
                <li><strong>NIST Cybersecurity Framework (CSF)</strong> - National Institute of Standards and Technology</li>
                <li><strong>ISO/IEC 27001:2022</strong> - Information Security Management System</li>
            </ul>
            
            <h2>Control Gap Analysis</h2>
            <table class="compliance-table">
                <thead>
                    <tr>
                        <th>NIST Control</th>
                        <th>ISO 27001</th>
                        <th>Finding</th>
                        <th>Severity</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for finding in context['compliance_findings']:
            severity = finding.get('severity', 'medium')
            html += f"""
                    <tr>
                        <td>
                            <strong>{finding.get('nist_id', 'N/A')}</strong><br>
                            <small>{finding.get('nist_name', 'Not Mapped')}</small>
                        </td>
                        <td>{finding.get('iso_control', 'N/A')}</td>
                        <td>{finding.get('title', 'N/A')}</td>
                        <td><span class="severity-badge severity-{severity}">{severity}</span></td>
                        <td>Gap Identified</td>
                    </tr>
            """
        
        html += """
                </tbody>
            </table>
            
            <div class="page-break"></div>
            
            <h2>NIST CSF Control Categories Summary</h2>
        """
        
        # Summary by NIST control category
        for category, mapping in NIST_CONTROL_MAPPING.items():
            category_findings = [f for f in context['compliance_findings'] 
                               if f.get('category') == category]
            finding_count = len(category_findings)
            status = "Compliant" if finding_count == 0 else f"{finding_count} Gap(s) Found"
            status_color = "#38a169" if finding_count == 0 else "#c53030"
            
            html += f"""
            <div class="control-mapping">
                <h4>{mapping['nist_id']} - {mapping['nist_name']}</h4>
                <p><strong>ISO 27001:</strong> {mapping['iso_control']}</p>
                <p><strong>Description:</strong> {mapping['description']}</p>
                <p><strong>Status:</strong> <span style="color: {status_color};">{status}</span></p>
            </div>
            """
        
        html += f"""
            <h2>Compliance Recommendations</h2>
            <div class="recommendation-box">
                <h3>Priority Actions for Compliance</h3>
                <ol>
                    <li>Address critical and high severity gaps immediately</li>
                    <li>Document compensating controls where direct remediation is not feasible</li>
                    <li>Establish regular compliance assessment schedule</li>
                    <li>Implement continuous monitoring for key controls</li>
                    <li>Maintain evidence of control effectiveness</li>
                </ol>
            </div>
            
            <div class="footer-note">
                <p>This compliance report should be reviewed by compliance officers and security leadership.</p>
                <p>Framework mappings are provided for guidance and may require additional context for specific regulatory requirements.</p>
                <p>Scan ID: {context['scan_id']}</p>
            </div>
        </body>
        </html>
        """
        return html
    
    def _html_to_pdf(self, html_content: str) -> bytes:
        """Convert HTML content to PDF bytes."""
        html_doc = HTML(string=html_content)
        css = CSS(string=self.BASE_CSS, font_config=self.font_config)
        
        pdf_buffer = io.BytesIO()
        html_doc.write_pdf(pdf_buffer, stylesheets=[css], font_config=self.font_config)
        pdf_buffer.seek(0)
        
        return pdf_buffer.read()
    
    def _get_risk_class(self, score: int) -> str:
        """Get CSS class for risk score."""
        if score >= 75:
            return 'risk-critical'
        elif score >= 50:
            return 'risk-high'
        elif score >= 25:
            return 'risk-medium'
        else:
            return 'risk-low'
    
    def _get_business_impact(self, severity: str) -> str:
        """Get business impact description for severity level."""
        impacts = {
            'critical': 'Immediate threat to business operations',
            'high': 'Significant risk to data and systems',
            'medium': 'Moderate risk requiring attention',
            'low': 'Minor risk with limited impact'
        }
        return impacts.get(severity, 'Unknown impact')
    
    def _format_evidence(self, evidence: Dict) -> str:
        """Format evidence dictionary for display."""
        if not evidence:
            return "No evidence data available"
        
        lines = []
        for key, value in evidence.items():
            if isinstance(value, list):
                value = ', '.join(str(v) for v in value[:10])
                if len(evidence.get(key, [])) > 10:
                    value += f" ... (+{len(evidence[key]) - 10} more)"
            elif isinstance(value, dict):
                value = str(value)
            lines.append(f"{key}: {value}")
        
        return '\n'.join(lines)


def generate_scan_report(
    scan_id: str,
    report_type: str = ReportType.EXECUTIVE,
    company_name: str = "Organization"
) -> bytes:
    """
    Convenience function to generate a report from a scan ID.
    
    Args:
        scan_id: UUID of the scan
        report_type: Type of report to generate
        company_name: Organization name for the report
    
    Returns:
        PDF report as bytes
    """
    from .models import Scan
    
    scan = Scan.objects.select_related('system').prefetch_related(
        'findings__recommendations'
    ).get(id=scan_id)
    
    # Build scan data dictionary
    scan_data = {
        'id': str(scan.id),
        'scan_date': scan.scan_date.strftime('%Y-%m-%d %H:%M:%S'),
        'risk_score': scan.risk_score or 0,
        'maturity_level': scan.maturity_level or 'reactive',
        'system': {
            'hostname': scan.system.hostname,
            'os': scan.system.os,
            'os_version': scan.system.os_version,
            'environment': scan.system.environment,
            'ip_address': str(scan.system.ip_address) if scan.system.ip_address else None,
        },
        'findings': []
    }
    
    for finding in scan.findings.all():
        finding_data = {
            'title': finding.title,
            'description': finding.description,
            'category': finding.category,
            'severity': finding.severity,
            'evidence': finding.evidence,
            'recommendations': []
        }
        
        for rec in finding.recommendations.all():
            finding_data['recommendations'].append({
                'title': rec.title,
                'description': rec.description,
                'priority': rec.priority,
                'effort': rec.effort,
                'steps': rec.steps,
            })
        
        scan_data['findings'].append(finding_data)
    
    generator = PDFReportGenerator()
    return generator.generate_report(
        scan_data=scan_data,
        report_type=report_type,
        company_name=company_name
    )
