"""
PDF Report Generator.

Moved from core.reports with improved structure.
"""
import io
import logging
from datetime import datetime
from typing import Any, Dict

from django.template.loader import render_to_string

logger = logging.getLogger(__name__)

# Try to import WeasyPrint (requires GTK libraries on some platforms)
WEASYPRINT_AVAILABLE = False
try:
    from weasyprint import CSS, HTML
    from weasyprint.text.fonts import FontConfiguration

    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError) as e:
    logger.warning(f"WeasyPrint not available. PDF generation will be disabled. Error: {e}")

# Try to import ReportLab (pure-Python wheels on most platforms)
REPORTLAB_AVAILABLE = False
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    REPORTLAB_AVAILABLE = True
except ImportError as e:
    logger.warning(f"ReportLab not available. Fallback PDF generation disabled. Error: {e}")

PDF_GENERATION_AVAILABLE = WEASYPRINT_AVAILABLE or REPORTLAB_AVAILABLE


# NIST CSF Control Mapping
NIST_CONTROL_MAPPING = {
    "access_control": {
        "nist_id": "PR.AC",
        "nist_name": "Identity Management and Access Control",
        "iso_control": "A.9 Access Control",
        "description": "Access to assets is limited to authorized users.",
    },
    "authentication": {
        "nist_id": "PR.AC-1",
        "nist_name": "Identities and Credentials",
        "iso_control": "A.9.2 User Access Management",
        "description": "Identities and credentials are managed properly.",
    },
    "network": {
        "nist_id": "PR.AC-5",
        "nist_name": "Network Integrity",
        "iso_control": "A.13.1 Network Security Management",
        "description": "Network integrity is protected.",
    },
    "patch_management": {
        "nist_id": "PR.IP-12",
        "nist_name": "Vulnerability Management",
        "iso_control": "A.12.6 Technical Vulnerability Management",
        "description": "Vulnerability management plan is implemented.",
    },
    "configuration": {
        "nist_id": "PR.IP-1",
        "nist_name": "Configuration Management",
        "iso_control": "A.12.5 Control of Operational Software",
        "description": "Configuration baseline is maintained.",
    },
    "encryption": {
        "nist_id": "PR.DS-1",
        "nist_name": "Data-at-rest Protection",
        "iso_control": "A.10 Cryptography",
        "description": "Data-at-rest is protected.",
    },
    "logging": {
        "nist_id": "DE.CM-3",
        "nist_name": "Personnel Activity Monitoring",
        "iso_control": "A.12.4 Logging and Monitoring",
        "description": "Personnel activity is monitored.",
    },
}


class PDFReportGenerator:
    """
    PDF Report Generator using WeasyPrint.

    Generates professional security assessment reports.
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
        }

        body {
            font-family: 'Helvetica Neue', Arial, sans-serif;
            font-size: 11pt;
            line-height: 1.6;
            color: #333;
        }

        h1 { color: #1a365d; font-size: 24pt; border-bottom: 3px solid #3182ce; }
        h2 { color: #2c5282; font-size: 16pt; margin-top: 30px; }
        h3 { color: #2d3748; font-size: 13pt; }

        .risk-critical { background: #fed7d7; color: #c53030; }
        .risk-high { background: #feebc8; color: #c05621; }
        .risk-medium { background: #fefcbf; color: #975a16; }
        .risk-low { background: #c6f6d5; color: #276749; }

        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 10px; border: 1px solid #e2e8f0; text-align: left; }
        th { background: #f7fafc; font-weight: 600; }
    """

    def generate(self, scan, report_type: str = "executive", company_name: str = "Organization") -> bytes:
        """
        Generate PDF report for a scan.

        Args:
            scan: Scan model instance
            report_type: Type of report
            company_name: Company name for header

        Returns:
            PDF content as bytes
        """
        # Build context once; shared across engines
        context = self._build_context(scan, report_type, company_name)

        if WEASYPRINT_AVAILABLE:
            # Render HTML
            template_name = f"reports/{report_type}_report.html"
            try:
                html_content = render_to_string(template_name, context)
            except Exception:
                # Fallback to inline template
                html_content = self._render_inline_template(context, report_type)

            # Generate PDF
            font_config = FontConfiguration()
            html = HTML(string=html_content)
            css = CSS(string=self.BASE_CSS, font_config=font_config)

            pdf_buffer = io.BytesIO()
            html.write_pdf(pdf_buffer, stylesheets=[css], font_config=font_config)
            return pdf_buffer.getvalue()

        if REPORTLAB_AVAILABLE:
            return self._generate_with_reportlab(context=context, report_type=report_type)

        raise RuntimeError("No PDF engine available (WeasyPrint/ReportLab)")

    def _generate_with_reportlab(self, context: Dict[str, Any], report_type: str) -> bytes:
        """Generate a PDF using ReportLab (fallback when WeasyPrint isn't available)."""
        styles = getSampleStyleSheet()
        buffer = io.BytesIO()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
            title="SecureSys Security Assessment Report",
        )

        scan = context["scan"]
        system = context["system"]
        generated_at = context.get("generated_at")
        company_name = context.get("company_name")

        story = []
        story.append(Paragraph("SecureSys Security Assessment Report", styles["Title"]))
        story.append(Spacer(1, 8))
        story.append(Paragraph(f"Company: {company_name}", styles["Normal"]))
        story.append(Paragraph(f"System: {getattr(system, 'hostname', 'Unknown')}", styles["Normal"]))
        if generated_at:
            story.append(Paragraph(f"Generated: {generated_at.strftime('%Y-%m-%d %H:%M')}", styles["Normal"]))
        story.append(Paragraph(f"Report type: {report_type.title()}", styles["Normal"]))
        story.append(Spacer(1, 14))

        # Summary
        risk_score = getattr(scan, "risk_score", None)
        maturity_level = getattr(scan, "maturity_level", None)
        summary_rows = [
            ["Risk Score", str(risk_score) if risk_score is not None else "N/A"],
            ["Maturity Level", str(maturity_level) if maturity_level else "N/A"],
            ["Total Findings", str(context.get("total_findings", 0))],
            ["Critical", str(context.get("critical_count", 0))],
            ["High", str(context.get("high_count", 0))],
            ["Medium", str(context.get("medium_count", 0))],
            ["Low", str(context.get("low_count", 0))],
        ]

        story.append(Paragraph("Summary", styles["Heading2"]))
        table = Table(summary_rows, hAlign="LEFT", colWidths=[120, 360])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 14))

        findings = context.get("findings", []) or []

        def _finding_line(f):
            title = getattr(f, "title", "Untitled")
            severity = getattr(f, "severity", "unknown")
            category = getattr(f, "category", "uncategorized")
            return f"[{severity.upper()}] {title} ({category})"

        if report_type == "executive":
            story.append(Paragraph("Top Findings", styles["Heading2"]))
            # Prefer critical/high first
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            sorted_findings = sorted(
                findings, key=lambda f: (severity_order.get(getattr(f, "severity", ""), 99), getattr(f, "title", ""))
            )
            for f in sorted_findings[:10]:
                story.append(Paragraph(_finding_line(f), styles["Normal"]))
            story.append(Spacer(1, 10))

        elif report_type == "compliance":
            story.append(Paragraph("Compliance Mapping", styles["Heading2"]))
            category_groups = context.get("category_groups", {}) or {}
            for category, group in category_groups.items():
                control = (group or {}).get("control") or {}
                nist_id = control.get("nist_id", "")
                nist_name = control.get("nist_name", "")
                iso_control = control.get("iso_control", "")
                story.append(Paragraph(f"Category: {category}", styles["Heading3"]))
                if nist_id or nist_name:
                    story.append(Paragraph(f"NIST: {nist_id} {nist_name}", styles["Normal"]))
                if iso_control:
                    story.append(Paragraph(f"ISO 27001: {iso_control}", styles["Normal"]))
                group_findings = (group or {}).get("findings") or []
                for f in group_findings:
                    story.append(Paragraph(_finding_line(f), styles["Normal"]))
                story.append(Spacer(1, 10))

        else:
            # technical
            story.append(Paragraph("Detailed Findings", styles["Heading2"]))
            for f in findings:
                story.append(Paragraph(_finding_line(f), styles["Heading3"]))
                desc = getattr(f, "description", "")
                if desc:
                    story.append(Paragraph(desc, styles["BodyText"]))
                story.append(Spacer(1, 8))

        doc.build(story)
        return buffer.getvalue()

    def _build_context(self, scan, report_type: str, company_name: str) -> Dict[str, Any]:
        """Build template context from scan data."""
        findings = list(scan.findings.all())

        # Group findings by severity
        severity_groups = {
            "critical": [f for f in findings if f.severity == "critical"],
            "high": [f for f in findings if f.severity == "high"],
            "medium": [f for f in findings if f.severity == "medium"],
            "low": [f for f in findings if f.severity == "low"],
        }

        # Group findings by category for compliance report
        category_groups = {}
        for finding in findings:
            category = finding.category
            if category not in category_groups:
                category_groups[category] = {
                    "findings": [],
                    "control": NIST_CONTROL_MAPPING.get(category, {}),
                }
            category_groups[category]["findings"].append(finding)

        return {
            "scan": scan,
            "system": scan.system,
            "findings": findings,
            "severity_groups": severity_groups,
            "category_groups": category_groups,
            "company_name": company_name,
            "report_type": report_type,
            "generated_at": datetime.now(),
            "total_findings": len(findings),
            "critical_count": len(severity_groups["critical"]),
            "high_count": len(severity_groups["high"]),
            "medium_count": len(severity_groups["medium"]),
            "low_count": len(severity_groups["low"]),
        }

    def _render_inline_template(self, context: Dict, report_type: str) -> str:
        """Render inline HTML template as fallback."""
        scan = context["scan"]
        system = context["system"]

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Assessment Report - {system.hostname}</title>
        </head>
        <body>
            <div class="cover-page">
                <h1>Security Assessment Report</h1>
                <h2>{system.hostname}</h2>
                <p>Generated: {context['generated_at'].strftime('%Y-%m-%d %H:%M')}</p>
                <p>Report Type: {report_type.title()}</p>
            </div>

            <h2>Executive Summary</h2>
            <p>Risk Score: <strong>{scan.risk_score}/100</strong></p>
            <p>Maturity Level: <strong>{scan.maturity_level}</strong></p>
            <p>Total Findings: <strong>{context['total_findings']}</strong></p>

            <h2>Findings Summary</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
                <tr class="risk-critical">
                    <td>Critical</td>
                    <td>{context['critical_count']}</td>
                </tr>
                <tr class="risk-high">
                    <td>High</td>
                    <td>{context['high_count']}</td>
                </tr>
                <tr class="risk-medium">
                    <td>Medium</td>
                    <td>{context['medium_count']}</td>
                </tr>
                <tr class="risk-low">
                    <td>Low</td>
                    <td>{context['low_count']}</td>
                </tr>
            </table>

            <h2>Detailed Findings</h2>
        """

        for finding in context["findings"]:
            html += f"""
            <div class="finding">
                <h3 class="risk-{finding.severity}">[{finding.severity.upper()}] {finding.title}</h3>
                <p>{finding.description}</p>
            </div>
            """

        html += """
        </body>
        </html>
        """

        return html
