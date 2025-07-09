"""
Flask Report Generator
Generates PDF and JSON reports for cybersecurity assessments.
"""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class FlaskReportGenerator:
    """
    Report generator for Flask-based cybersecurity assessments.
    Supports PDF and JSON report formats.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.report_templates = self._load_report_templates()

        if not REPORTLAB_AVAILABLE:
            self.logger.warning(
                "ReportLab not available - PDF generation disabled")

        self.logger.info("FlaskReportGenerator initialized")

    def _load_report_templates(self) -> Dict[str, Any]:
        """Load report templates and configurations."""
        return {
            'executive_summary': {
                'title': 'Executive Summary',
                'sections': ['overview', 'key_findings', 'risk_assessment', 'recommendations']
            },
            'technical_report': {
                'title': 'Technical Security Assessment Report',
                'sections': ['methodology', 'reconnaissance', 'scanning', 'testing', 'vulnerabilities', 'recommendations']
            },
            'compliance_report': {
                'title': 'Security Compliance Report',
                'sections': ['compliance_overview', 'test_results', 'findings', 'remediation']
            }
        }

    def generate_pdf_report(self, assessment_data: Dict[str, Any],
                            report_type: str = 'technical_report',
                            output_path: Optional[str] = None) -> str:
        """
        Generate PDF report for assessment.

        Args:
            assessment_data: Complete assessment data including results
            report_type: Type of report to generate
            output_path: Optional custom output path

        Returns:
            Path to generated PDF file
        """
        if not REPORTLAB_AVAILABLE:
            raise RuntimeError(
                "ReportLab not available - cannot generate PDF reports")

        # Create output path if not provided
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            assessment_id = assessment_data.get(
                'assessment', {}).get('id', 'unknown')
            filename = f"assessment_{assessment_id}_{timestamp}.pdf"
            output_path = os.path.join(tempfile.gettempdir(), filename)

        try:
            # Create PDF document
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []

            # Add custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=TA_CENTER
            )

            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                spaceAfter=12,
                spaceBefore=20
            )

            # Generate report content
            story.extend(self._generate_pdf_cover_page(
                assessment_data, title_style, styles))
            story.append(PageBreak())

            story.extend(self._generate_pdf_executive_summary(
                assessment_data, heading_style, styles))
            story.append(PageBreak())

            story.extend(self._generate_pdf_methodology(
                assessment_data, heading_style, styles))
            story.append(PageBreak())

            story.extend(self._generate_pdf_findings(
                assessment_data, heading_style, styles))
            story.append(PageBreak())

            story.extend(self._generate_pdf_recommendations(
                assessment_data, heading_style, styles))
            story.append(PageBreak())

            story.extend(self._generate_pdf_appendix(
                assessment_data, heading_style, styles))

            # Build PDF
            doc.build(story)

            self.logger.info(f"Generated PDF report: {output_path}")
            return output_path

        except Exception as e:
            self.logger.error(f"Failed to generate PDF report: {e}")
            raise

    def _generate_pdf_cover_page(self, assessment_data: Dict[str, Any], title_style, styles) -> List:
        """Generate PDF cover page."""
        story = []
        assessment = assessment_data.get('assessment', {})

        # Title
        story.append(Paragraph("Cybersecurity Assessment Report", title_style))
        story.append(Spacer(1, 0.5*inch))

        # Target information
        target = assessment.get('target', 'Unknown')
        story.append(Paragraph(f"Target: {target}", styles['Heading2']))
        story.append(Spacer(1, 0.3*inch))

        # Assessment details table
        assessment_details = [
            ['Assessment ID:', assessment.get('id', 'N/A')],
            ['Target Type:', assessment.get('target_type', 'N/A')],
            ['Scan Type:', assessment.get('scan_type', 'N/A')],
            ['Start Date:', assessment.get(
                'created_at', 'N/A')[:10] if assessment.get('created_at') else 'N/A'],
            ['Completion Date:', assessment.get(
                'completed_at', 'N/A')[:10] if assessment.get('completed_at') else 'N/A'],
            ['Status:', assessment.get('status', 'N/A')]
        ]

        details_table = Table(assessment_details, colWidths=[2*inch, 3*inch])
        details_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey)
        ]))

        story.append(details_table)
        story.append(Spacer(1, 0.5*inch))

        # Risk summary
        summary = assessment_data.get('summary', {})
        risk_score = summary.get('risk_score', 0)

        story.append(Paragraph("Risk Assessment Summary", styles['Heading3']))
        story.append(Spacer(1, 0.2*inch))

        risk_data = [
            ['Risk Score:', f"{risk_score:.1f}/100"],
            ['Total Vulnerabilities:', str(
                summary.get('total_vulnerabilities', 0))],
            ['Critical Issues:', str(summary.get(
                'severity_breakdown', {}).get('critical', 0))],
            ['High Issues:', str(summary.get(
                'severity_breakdown', {}).get('high', 0))]
        ]

        risk_table = Table(risk_data, colWidths=[2*inch, 2*inch])
        risk_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightblue)
        ]))

        story.append(risk_table)
        story.append(Spacer(1, 1*inch))

        # Report generation info
        story.append(Paragraph(
            f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))

        return story

    def _generate_pdf_executive_summary(self, assessment_data: Dict[str, Any], heading_style, styles) -> List:
        """Generate executive summary section."""
        story = []

        story.append(Paragraph("Executive Summary", heading_style))

        assessment = assessment_data.get('assessment', {})
        summary = assessment_data.get('summary', {})

        # Overview
        overview_text = f"""
        This report presents the findings of a comprehensive cybersecurity assessment conducted on 
        {assessment.get('target', 'the target system')}. The assessment included reconnaissance, 
        port scanning, and security testing to identify potential vulnerabilities and security risks.
        """
        story.append(Paragraph(overview_text, styles['Normal']))
        story.append(Spacer(1, 0.2*inch))

        # Key findings
        story.append(Paragraph("Key Findings", styles['Heading3']))

        total_vulns = summary.get('total_vulnerabilities', 0)
        risk_score = summary.get('risk_score', 0)
        severity_breakdown = summary.get('severity_breakdown', {})

        findings_text = f"""
        • Total vulnerabilities identified: {total_vulns}<br/>
        • Overall risk score: {risk_score:.1f}/100<br/>
        • Critical severity issues: {severity_breakdown.get('critical', 0)}<br/>
        • High severity issues: {severity_breakdown.get('high', 0)}<br/>
        • Medium severity issues: {severity_breakdown.get('medium', 0)}<br/>
        • Low severity issues: {severity_breakdown.get('low', 0)}
        """
        story.append(Paragraph(findings_text, styles['Normal']))
        story.append(Spacer(1, 0.2*inch))

        # Risk assessment
        story.append(Paragraph("Risk Assessment", styles['Heading3']))

        if risk_score >= 80:
            risk_level = "Critical"
            risk_desc = "Immediate action required to address security vulnerabilities."
        elif risk_score >= 60:
            risk_level = "High"
            risk_desc = "Significant security issues that should be addressed promptly."
        elif risk_score >= 40:
            risk_level = "Medium"
            risk_desc = "Moderate security concerns that should be addressed in a timely manner."
        elif risk_score >= 20:
            risk_level = "Low"
            risk_desc = "Minor security issues that should be addressed as resources permit."
        else:
            risk_level = "Minimal"
            risk_desc = "No significant security vulnerabilities identified."

        risk_text = f"""
        The overall risk level for this assessment is classified as <b>{risk_level}</b>. 
        {risk_desc}
        """
        story.append(Paragraph(risk_text, styles['Normal']))

        return story

    def _generate_pdf_methodology(self, assessment_data: Dict[str, Any], heading_style, styles) -> List:
        """Generate methodology section."""
        story = []

        story.append(Paragraph("Assessment Methodology", heading_style))

        methodology_text = """
        This cybersecurity assessment was conducted using a multi-phase approach:
        
        <b>1. Reconnaissance Phase:</b><br/>
        • Subdomain enumeration<br/>
        • DNS record analysis<br/>
        • WHOIS information gathering<br/>
        • Technology stack identification<br/>
        • Open source intelligence (OSINT) gathering<br/>
        
        <b>2. Scanning Phase:</b><br/>
        • Port scanning to identify open services<br/>
        • Service version detection<br/>
        • Operating system fingerprinting<br/>
        • SSL/TLS configuration analysis<br/>
        
        <b>3. Testing Phase:</b><br/>
        • Predefined security test execution<br/>
        • AI-generated custom test cases<br/>
        • Vulnerability assessment<br/>
        • Security control validation<br/>
        """

        story.append(Paragraph(methodology_text, styles['Normal']))

        # Tools used
        story.append(Paragraph("Tools and Technologies", styles['Heading3']))

        tools_text = """
        The following tools and technologies were used during this assessment:
        
        • <b>Nmap</b> - Network scanning and service detection<br/>
        • <b>Masscan</b> - High-speed port scanning<br/>
        • <b>theHarvester</b> - OSINT gathering<br/>
        • <b>Amass</b> - Subdomain enumeration<br/>
        • <b>Shodan API</b> - Internet-connected device intelligence<br/>
        • <b>Custom AI Agent</b> - LLaMA-powered test case generation<br/>
        """

        story.append(Paragraph(tools_text, styles['Normal']))

        return story

    def _generate_pdf_findings(self, assessment_data: Dict[str, Any], heading_style, styles) -> List:
        """Generate findings section."""
        story = []

        story.append(Paragraph("Detailed Findings", heading_style))

        # Reconnaissance findings
        recon_results = assessment_data.get('recon_results', [])
        if recon_results:
            story.append(
                Paragraph("Reconnaissance Results", styles['Heading3']))

            for recon in recon_results:
                if recon.get('status') == 'completed':
                    subdomains = recon.get('subdomains', [])
                    technologies = recon.get('technologies', [])
                    emails = recon.get('emails', [])

                    recon_text = f"""
                    • Subdomains discovered: {len(subdomains)}<br/>
                    • Technologies identified: {len(technologies)}<br/>
                    • Email addresses found: {len(emails)}<br/>
                    """
                    story.append(Paragraph(recon_text, styles['Normal']))

            story.append(Spacer(1, 0.2*inch))

        # Scanning findings
        scan_results = assessment_data.get('scan_results', [])
        if scan_results:
            story.append(
                Paragraph("Port Scanning Results", styles['Heading3']))

            for scan in scan_results:
                if scan.get('status') == 'completed':
                    hosts_data = scan.get('hosts_data', [])
                    summary_data = scan.get('summary_data', {})

                    scan_text = f"""
                    • Scan tool: {scan.get('tool_used', 'Unknown')}<br/>
                    • Hosts scanned: {summary_data.get('total_hosts', 0)}<br/>
                    • Open ports found: {summary_data.get('open_ports', 0)}<br/>
                    """
                    story.append(Paragraph(scan_text, styles['Normal']))

            story.append(Spacer(1, 0.2*inch))

        # Test findings
        test_results = assessment_data.get('test_results', [])
        if test_results:
            story.append(
                Paragraph("Security Test Results", styles['Heading3']))

            # Group by severity
            severity_groups = {'critical': [],
                               'high': [], 'medium': [], 'low': []}
            for test in test_results:
                if test.get('vulnerable', False):
                    severity = test.get('test_severity', 'medium').lower()
                    if severity in severity_groups:
                        severity_groups[severity].append(test)

            for severity in ['critical', 'high', 'medium', 'low']:
                tests = severity_groups[severity]
                if tests:
                    story.append(
                        Paragraph(f"{severity.capitalize()} Severity Issues", styles['Heading4']))

                    for test in tests:
                        test_text = f"""
                        <b>{test.get('test_name', 'Unknown Test')}</b><br/>
                        Category: {test.get('test_category', 'Unknown')}<br/>
                        Status: {test.get('status', 'Unknown')}<br/>
                        """
                        story.append(Paragraph(test_text, styles['Normal']))
                        story.append(Spacer(1, 0.1*inch))

        return story

    def _generate_pdf_recommendations(self, assessment_data: Dict[str, Any], heading_style, styles) -> List:
        """Generate recommendations section."""
        story = []

        story.append(Paragraph("Recommendations", heading_style))

        summary = assessment_data.get('summary', {})
        severity_breakdown = summary.get('severity_breakdown', {})

        # General recommendations based on findings
        recommendations = []

        if severity_breakdown.get('critical', 0) > 0:
            recommendations.append(
                "• Address all critical severity vulnerabilities immediately")
            recommendations.append(
                "• Implement emergency security controls and monitoring")

        if severity_breakdown.get('high', 0) > 0:
            recommendations.append(
                "• Prioritize remediation of high severity issues")
            recommendations.append("• Review and update security policies")

        if severity_breakdown.get('medium', 0) > 0:
            recommendations.append(
                "• Schedule remediation of medium severity vulnerabilities")
            recommendations.append(
                "• Enhance security monitoring and detection capabilities")

        # Default recommendations
        recommendations.extend([
            "• Conduct regular security assessments",
            "• Implement a vulnerability management program",
            "• Provide security awareness training to staff",
            "• Keep systems and software up to date",
            "• Implement network segmentation where appropriate",
            "• Regular security policy reviews and updates"
        ])

        for rec in recommendations:
            story.append(Paragraph(rec, styles['Normal']))

        story.append(Spacer(1, 0.3*inch))

        # Priority matrix
        story.append(
            Paragraph("Remediation Priority Matrix", styles['Heading3']))

        priority_text = """
        <b>Immediate (0-30 days):</b> Critical and high severity vulnerabilities<br/>
        <b>Short-term (1-3 months):</b> Medium severity issues and security improvements<br/>
        <b>Long-term (3-12 months):</b> Low severity issues and proactive security measures<br/>
        """
        story.append(Paragraph(priority_text, styles['Normal']))

        return story

    def _generate_pdf_appendix(self, assessment_data: Dict[str, Any], heading_style, styles) -> List:
        """Generate appendix section."""
        story = []

        story.append(Paragraph("Appendix", heading_style))

        # Raw data summary
        story.append(Paragraph("Technical Details", styles['Heading3']))

        assessment = assessment_data.get('assessment', {})

        # Assessment parameters
        params_data = [
            ['Parameter', 'Value'],
            ['Assessment ID', assessment.get('id', 'N/A')],
            ['Target', assessment.get('target', 'N/A')],
            ['Target Type', assessment.get('target_type', 'N/A')],
            ['Scan Type', assessment.get('scan_type', 'N/A')],
            ['Ports Scanned', assessment.get('ports', 'N/A')]
        ]

        params_table = Table(params_data, colWidths=[2*inch, 3*inch])
        params_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(params_table)
        story.append(Spacer(1, 0.3*inch))

        # Test summary
        test_results = assessment_data.get('test_results', [])
        if test_results:
            story.append(
                Paragraph("Test Execution Summary", styles['Heading4']))

            test_summary_data = [
                ['Test Name', 'Category', 'Severity', 'Status', 'Vulnerable']]

            for test in test_results[:20]:  # Limit to first 20 tests
                test_summary_data.append([
                    test.get('test_name', 'Unknown')[:30],
                    test.get('test_category', 'Unknown'),
                    test.get('test_severity', 'Unknown'),
                    test.get('status', 'Unknown'),
                    'Yes' if test.get('vulnerable', False) else 'No'
                ])

            test_table = Table(test_summary_data, colWidths=[
                               2*inch, 1*inch, 1*inch, 1*inch, 0.8*inch])
            test_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(test_table)

        return story

    def generate_json_report(self, assessment_data: Dict[str, Any],
                             output_path: Optional[str] = None) -> str:
        """
        Generate JSON report for assessment.

        Args:
            assessment_data: Complete assessment data
            output_path: Optional custom output path

        Returns:
            Path to generated JSON file
        """
        # Create output path if not provided
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            assessment_id = assessment_data.get(
                'assessment', {}).get('id', 'unknown')
            filename = f"assessment_{assessment_id}_{timestamp}.json"
            output_path = os.path.join(tempfile.gettempdir(), filename)

        try:
            # Add metadata to the report
            report_data = {
                'report_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'report_version': '1.0',
                    'generator': 'Flask Cybersecurity Automation System'
                },
                'assessment_data': assessment_data
            }

            # Write JSON file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Generated JSON report: {output_path}")
            return output_path

        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {e}")
            raise

    def generate_csv_summary(self, assessment_data: Dict[str, Any],
                             output_path: Optional[str] = None) -> str:
        """
        Generate CSV summary of test results.

        Args:
            assessment_data: Complete assessment data
            output_path: Optional custom output path

        Returns:
            Path to generated CSV file
        """
        import csv

        # Create output path if not provided
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            assessment_id = assessment_data.get(
                'assessment', {}).get('id', 'unknown')
            filename = f"assessment_summary_{assessment_id}_{timestamp}.csv"
            output_path = os.path.join(tempfile.gettempdir(), filename)

        try:
            test_results = assessment_data.get('test_results', [])

            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'test_name', 'test_category', 'test_severity', 'test_source',
                    'status', 'vulnerable', 'started_at', 'completed_at'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                # Write header
                writer.writeheader()

                # Write test results
                for test in test_results:
                    writer.writerow({
                        'test_name': test.get('test_name', ''),
                        'test_category': test.get('test_category', ''),
                        'test_severity': test.get('test_severity', ''),
                        'test_source': test.get('test_source', ''),
                        'status': test.get('status', ''),
                        'vulnerable': test.get('vulnerable', False),
                        'started_at': test.get('started_at', ''),
                        'completed_at': test.get('completed_at', '')
                    })

            self.logger.info(f"Generated CSV summary: {output_path}")
            return output_path

        except Exception as e:
            self.logger.error(f"Failed to generate CSV summary: {e}")
            raise

    def get_available_formats(self) -> List[str]:
        """Get list of available report formats."""
        formats = ['json', 'csv']
        if REPORTLAB_AVAILABLE:
            formats.append('pdf')
        return formats
