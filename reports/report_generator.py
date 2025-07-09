import json
import os
from datetime import datetime
from typing import Dict, Any, List
import logging
from jinja2 import Template
from weasyprint import HTML, CSS
import pandas as pd
from utils.helpers import ensure_directory, safe_json_dumps


class ReportGenerator:
    """Generate comprehensive security assessment reports in multiple formats."""

    def __init__(self, output_dir: str = "./reports/output"):
        self.output_dir = output_dir
        ensure_directory(output_dir)

        # HTML template for reports
        self.html_template = self._get_html_template()

    def generate_comprehensive_report(self, session_data: Dict[str, Any],
                                      formats: List[str] = ['json', 'html', 'pdf']) -> Dict[str, str]:
        """
        Generate comprehensive report in multiple formats.

        Args:
            session_data: Complete session data including all agent results
            formats: List of formats to generate ('json', 'html', 'pdf')

        Returns:
            Dictionary mapping format to file path
        """
        logging.info("Generating comprehensive security assessment report")

        session_id = session_data.get(
            'session', {}).get('session_id', 'unknown')
        target = session_data.get('session', {}).get('target', 'unknown')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        base_filename = f"security_report_{target}_{session_id}_{timestamp}"
        generated_files = {}

        # Generate JSON report
        if 'json' in formats:
            json_path = self._generate_json_report(session_data, base_filename)
            generated_files['json'] = json_path

        # Generate HTML report
        if 'html' in formats:
            html_path = self._generate_html_report(session_data, base_filename)
            generated_files['html'] = html_path

        # Generate PDF report
        if 'pdf' in formats:
            pdf_path = self._generate_pdf_report(session_data, base_filename)
            generated_files['pdf'] = pdf_path

        logging.info(
            f"Report generation completed. Generated formats: {list(generated_files.keys())}")
        return generated_files

    def _generate_json_report(self, session_data: Dict[str, Any], base_filename: str) -> str:
        """Generate JSON format report."""
        # Process and structure the data
        report_data = self._process_session_data(session_data)

        json_filename = f"{base_filename}.json"
        json_path = os.path.join(self.output_dir, json_filename)

        try:
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)

            logging.info(f"JSON report generated: {json_path}")
            return json_path

        except Exception as e:
            logging.error(f"Error generating JSON report: {e}")
            return ""

    def _generate_html_report(self, session_data: Dict[str, Any], base_filename: str) -> str:
        """Generate HTML format report."""
        report_data = self._process_session_data(session_data)

        html_filename = f"{base_filename}.html"
        html_path = os.path.join(self.output_dir, html_filename)

        try:
            template = Template(self.html_template)
            html_content = template.render(data=report_data)

            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            logging.info(f"HTML report generated: {html_path}")
            return html_path

        except Exception as e:
            logging.error(f"Error generating HTML report: {e}")
            return ""

    def _generate_pdf_report(self, session_data: Dict[str, Any], base_filename: str) -> str:
        """Generate PDF format report."""
        # First generate HTML, then convert to PDF
        html_path = self._generate_html_report(
            session_data, f"{base_filename}_temp")

        if not html_path:
            return ""

        pdf_filename = f"{base_filename}.pdf"
        pdf_path = os.path.join(self.output_dir, pdf_filename)

        try:
            # Convert HTML to PDF using WeasyPrint
            HTML(filename=html_path).write_pdf(pdf_path)

            # Clean up temporary HTML file
            if os.path.exists(html_path):
                os.remove(html_path)

            logging.info(f"PDF report generated: {pdf_path}")
            return pdf_path

        except Exception as e:
            logging.error(f"Error generating PDF report: {e}")
            return ""

    def _process_session_data(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process and structure session data for reporting."""
        session_info = session_data.get('session', {})
        recon_results = session_data.get('recon_results', [])
        scan_results = session_data.get('scan_results', [])
        test_results = session_data.get('test_results', [])
        llm_test_cases = session_data.get('llm_test_cases', [])

        # Process reconnaissance data
        processed_recon = self._process_recon_data(recon_results)

        # Process scan data
        processed_scan = self._process_scan_data(scan_results)

        # Process test results
        processed_tests = self._process_test_data(test_results)

        # Process LLM test cases
        processed_llm = self._process_llm_data(llm_test_cases)

        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            session_info, processed_recon, processed_scan, processed_tests
        )

        # Calculate risk metrics
        risk_metrics = self._calculate_risk_metrics(processed_tests)

        return {
            'metadata': {
                'report_generated': datetime.now().isoformat(),
                'session_id': session_info.get('session_id', 'N/A'),
                'target': session_info.get('target', 'N/A'),
                'target_type': session_info.get('target_type', 'N/A'),
                'assessment_duration': self._calculate_duration(session_info)
            },
            'executive_summary': executive_summary,
            'risk_metrics': risk_metrics,
            'reconnaissance': processed_recon,
            'scanning': processed_scan,
            'testing': processed_tests,
            'llm_generated_tests': processed_llm,
            'recommendations': self._generate_recommendations(processed_tests),
            'raw_data': session_data
        }

    def _process_recon_data(self, recon_results: List[Dict]) -> Dict[str, Any]:
        """Process reconnaissance results."""
        processed = {
            'summary': {
                'total_subdomains': 0,
                'total_emails': 0,
                'technologies_found': 0,
                'certificates_found': 0
            },
            'subdomains': [],
            'emails': [],
            'dns_records': {},
            'technologies': [],
            'certificates': [],
            'social_media': [],
            'whois_info': {}
        }

        for result in recon_results:
            try:
                data = json.loads(result.get('data', '{}'))
                result_type = result.get('result_type', '')

                if result_type == 'subdomains':
                    processed['subdomains'].extend(data.get('subdomains', []))
                elif result_type == 'emails':
                    processed['emails'].extend(data.get('emails', []))
                elif result_type == 'dns_records':
                    processed['dns_records'].update(
                        data.get('dns_records', {}))
                elif result_type == 'technologies':
                    processed['technologies'].extend(
                        data.get('technologies', []))
                elif result_type == 'certificates':
                    processed['certificates'].extend(
                        data.get('certificates', []))
                elif result_type == 'social_media':
                    processed['social_media'].extend(
                        data.get('social_media', []))
                elif result_type == 'whois':
                    processed['whois_info'].update(data.get('whois_info', {}))

            except Exception as e:
                logging.warning(f"Error processing recon result: {e}")

        # Update summary
        processed['summary']['total_subdomains'] = len(
            set(processed['subdomains']))
        processed['summary']['total_emails'] = len(set(processed['emails']))
        processed['summary']['technologies_found'] = len(
            processed['technologies'])
        processed['summary']['certificates_found'] = len(
            processed['certificates'])

        return processed

    def _process_scan_data(self, scan_results: List[Dict]) -> Dict[str, Any]:
        """Process scanning results."""
        processed = {
            'summary': {
                'total_ports_scanned': 0,
                'open_ports': 0,
                'services_identified': 0,
                'vulnerabilities_found': 0
            },
            'open_ports': [],
            'services': [],
            'vulnerabilities': [],
            'port_distribution': {},
            'service_distribution': {},
            'vulnerability_severity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }

        for result in scan_results:
            port_info = {
                'port': result.get('port'),
                'service': result.get('service'),
                'version': result.get('version'),
                'state': result.get('state'),
                'banner': result.get('banner'),
                'vulnerabilities': json.loads(result.get('vulnerabilities', '[]')) if result.get('vulnerabilities') else []
            }

            if port_info['state'] == 'open':
                processed['open_ports'].append(port_info)

                # Count port distribution
                port = port_info['port']
                processed['port_distribution'][port] = processed['port_distribution'].get(
                    port, 0) + 1

                # Count service distribution
                service = port_info['service']
                if service:
                    processed['service_distribution'][service] = processed['service_distribution'].get(
                        service, 0) + 1

                # Process vulnerabilities
                for vuln in port_info['vulnerabilities']:
                    processed['vulnerabilities'].append({
                        'port': port,
                        'service': service,
                        'vulnerability': vuln,
                        'severity': 'medium'  # Default severity
                    })

        # Update summary
        processed['summary']['open_ports'] = len(processed['open_ports'])
        processed['summary']['services_identified'] = len(
            set(p['service'] for p in processed['open_ports'] if p['service']))
        processed['summary']['vulnerabilities_found'] = len(
            processed['vulnerabilities'])

        return processed

    def _process_test_data(self, test_results: List[Dict]) -> Dict[str, Any]:
        """Process test case results."""
        processed = {
            'summary': {
                'total_tests': len(test_results),
                'passed': 0,
                'failed': 0,
                'skipped': 0,
                'errors': 0
            },
            'by_category': {},
            'by_severity': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': []
            },
            'findings': [],
            'failed_tests': []
        }

        for result in test_results:
            status = result.get('status', 'unknown')
            category = result.get('category', 'Unknown')
            severity = result.get('severity', 'medium').lower()

            # Count by status
            if status in processed['summary']:
                processed['summary'][status] += 1

            # Group by category
            if category not in processed['by_category']:
                processed['by_category'][category] = {
                    'total': 0,
                    'passed': 0,
                    'failed': 0,
                    'tests': []
                }

            processed['by_category'][category]['total'] += 1
            processed['by_category'][category]['tests'].append(result)

            if status == 'passed':
                processed['by_category'][category]['passed'] += 1

                # Add to findings
                finding = {
                    'test_name': result.get('test_name', ''),
                    'category': category,
                    'severity': severity,
                    'description': result.get('result', ''),
                    'evidence': result.get('evidence', []),
                    'recommendations': self._get_test_recommendations(result)
                }
                processed['findings'].append(finding)

                # Group by severity
                if severity in processed['by_severity']:
                    processed['by_severity'][severity].append(finding)
            else:
                processed['by_category'][category]['failed'] += 1

                if status == 'failed':
                    processed['failed_tests'].append(result)

        return processed

    def _process_llm_data(self, llm_test_cases: List[Dict]) -> Dict[str, Any]:
        """Process LLM-generated test cases."""
        processed = {
            'summary': {
                'total_generated': len(llm_test_cases),
                'approved': 0,
                'executed': 0,
                'pending_approval': 0
            },
            'test_cases': [],
            'by_category': {}
        }

        for test_case in llm_test_cases:
            try:
                test_data = json.loads(test_case.get('test_case_data', '{}'))
                approved = test_case.get('approved', False)
                executed = test_case.get('executed', False)

                processed_case = {
                    'id': test_case.get('id'),
                    'name': test_data.get('name', 'Unknown'),
                    'category': test_data.get('category', 'Custom'),
                    'severity': test_data.get('severity', 'medium'),
                    'description': test_data.get('description', ''),
                    'methodology': test_data.get('methodology', ''),
                    'approved': approved,
                    'executed': executed,
                    'result': test_case.get('result', '')
                }

                processed['test_cases'].append(processed_case)

                # Count statuses
                if approved:
                    processed['summary']['approved'] += 1
                else:
                    processed['summary']['pending_approval'] += 1

                if executed:
                    processed['summary']['executed'] += 1

                # Group by category
                category = processed_case['category']
                if category not in processed['by_category']:
                    processed['by_category'][category] = []
                processed['by_category'][category].append(processed_case)

            except Exception as e:
                logging.warning(f"Error processing LLM test case: {e}")

        return processed

    def _calculate_duration(self, session_info: Dict) -> str:
        """Calculate assessment duration."""
        try:
            start_time = session_info.get('start_time')
            end_time = session_info.get('end_time')

            if start_time and end_time:
                start = datetime.fromisoformat(
                    start_time.replace('Z', '+00:00'))
                end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
                duration = end - start

                hours = duration.total_seconds() // 3600
                minutes = (duration.total_seconds() % 3600) // 60

                return f"{int(hours)}h {int(minutes)}m"
            else:
                return "In Progress"

        except Exception as e:
            logging.warning(f"Error calculating duration: {e}")
            return "Unknown"

    def _generate_executive_summary(self, session_info: Dict, recon_data: Dict,
                                    scan_data: Dict, test_data: Dict) -> Dict[str, Any]:
        """Generate executive summary."""
        total_findings = len(test_data.get('findings', []))
        critical_findings = len(test_data.get(
            'by_severity', {}).get('critical', []))
        high_findings = len(test_data.get('by_severity', {}).get('high', []))

        risk_level = 'Low'
        if critical_findings > 0:
            risk_level = 'Critical'
        elif high_findings > 0:
            risk_level = 'High'
        elif total_findings > 0:
            risk_level = 'Medium'

        return {
            'target': session_info.get('target', 'N/A'),
            'assessment_type': 'Automated Security Assessment',
            'overall_risk_level': risk_level,
            'total_findings': total_findings,
            'critical_findings': critical_findings,
            'high_findings': high_findings,
            'key_statistics': {
                'subdomains_discovered': recon_data.get('summary', {}).get('total_subdomains', 0),
                'open_ports': scan_data.get('summary', {}).get('open_ports', 0),
                'services_identified': scan_data.get('summary', {}).get('services_identified', 0),
                'tests_executed': test_data.get('summary', {}).get('total_tests', 0)
            },
            'top_risks': self._get_top_risks(test_data),
            'recommendations_summary': self._get_summary_recommendations(test_data)
        }

    def _calculate_risk_metrics(self, test_data: Dict) -> Dict[str, Any]:
        """Calculate risk metrics and scores."""
        findings = test_data.get('findings', [])

        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1
        }

        total_score = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for finding in findings:
            severity = finding.get('severity', 'medium').lower()
            if severity in severity_weights:
                total_score += severity_weights[severity]
                severity_counts[severity] += 1

        # Calculate risk level
        if total_score >= 50:
            risk_level = 'Critical'
        elif total_score >= 30:
            risk_level = 'High'
        elif total_score >= 10:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'

        return {
            'total_risk_score': total_score,
            'risk_level': risk_level,
            'severity_distribution': severity_counts,
            'risk_categories': self._categorize_risks(test_data)
        }

    def _categorize_risks(self, test_data: Dict) -> Dict[str, int]:
        """Categorize risks by type."""
        categories = {}

        for finding in test_data.get('findings', []):
            category = finding.get('category', 'Unknown')
            categories[category] = categories.get(category, 0) + 1

        return categories

    def _get_top_risks(self, test_data: Dict) -> List[Dict]:
        """Get top 5 risks ordered by severity."""
        findings = test_data.get('findings', [])

        # Sort by severity (critical > high > medium > low)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(
                x.get('severity', 'medium').lower(), 4)
        )

        return sorted_findings[:5]

    def _get_summary_recommendations(self, test_data: Dict) -> List[str]:
        """Get summary of top recommendations."""
        recommendations = []

        critical_findings = test_data.get(
            'by_severity', {}).get('critical', [])
        high_findings = test_data.get('by_severity', {}).get('high', [])

        if critical_findings:
            recommendations.append(
                "Immediately address critical security vulnerabilities")

        if high_findings:
            recommendations.append(
                "Prioritize remediation of high-severity findings")

        # Add category-specific recommendations
        categories = test_data.get('by_category', {})

        if 'Authentication' in categories:
            recommendations.append(
                "Review and strengthen authentication mechanisms")

        if 'Web Security' in categories:
            recommendations.append(
                "Implement web security best practices and headers")

        if 'Information Disclosure' in categories:
            recommendations.append("Restrict unnecessary information exposure")

        return recommendations[:5]

    def _get_test_recommendations(self, test_result: Dict) -> List[str]:
        """Get recommendations for a specific test result."""
        test_name = test_result.get('test_name', '').lower()
        category = test_result.get('category', '').lower()

        recommendations = []

        if 'ssh' in test_name and 'credential' in test_name:
            recommendations.extend([
                "Change default SSH credentials immediately",
                "Implement key-based authentication",
                "Disable password authentication if possible",
                "Configure fail2ban for SSH protection"
            ])
        elif 'ftp' in test_name and 'anonymous' in test_name:
            recommendations.extend([
                "Disable anonymous FTP access",
                "Use SFTP or FTPS instead of plain FTP",
                "Implement proper authentication"
            ])
        elif 'web' in test_name and 'credential' in test_name:
            recommendations.extend([
                "Change default web application credentials",
                "Implement strong password policies",
                "Enable account lockout mechanisms",
                "Use multi-factor authentication"
            ])
        elif 'header' in test_name:
            recommendations.extend([
                "Implement missing security headers",
                "Configure Content Security Policy (CSP)",
                "Enable HTTP Strict Transport Security (HSTS)",
                "Set proper cache control headers"
            ])
        elif 'directory' in test_name:
            recommendations.extend([
                "Disable directory listing",
                "Remove or protect sensitive directories",
                "Implement proper access controls"
            ])
        else:
            recommendations.append(
                "Review and remediate the identified security issue")

        return recommendations

    def _generate_recommendations(self, test_data: Dict) -> Dict[str, Any]:
        """Generate comprehensive recommendations."""
        immediate_actions = []
        short_term_actions = []
        long_term_actions = []

        critical_findings = test_data.get(
            'by_severity', {}).get('critical', [])
        high_findings = test_data.get('by_severity', {}).get('high', [])
        medium_findings = test_data.get('by_severity', {}).get('medium', [])

        # Immediate actions for critical findings
        for finding in critical_findings:
            immediate_actions.extend(finding.get('recommendations', [])[:2])

        # Short-term actions for high findings
        for finding in high_findings:
            short_term_actions.extend(finding.get('recommendations', [])[:2])

        # Long-term actions for medium findings
        for finding in medium_findings:
            long_term_actions.extend(finding.get('recommendations', [])[:1])

        # Remove duplicates while preserving order
        immediate_actions = list(dict.fromkeys(immediate_actions))
        short_term_actions = list(dict.fromkeys(short_term_actions))
        long_term_actions = list(dict.fromkeys(long_term_actions))

        return {
            'immediate_actions': immediate_actions[:10],
            'short_term_actions': short_term_actions[:10],
            'long_term_actions': long_term_actions[:10],
            'general_recommendations': [
                "Implement a regular vulnerability assessment program",
                "Establish security monitoring and logging",
                "Develop an incident response plan",
                "Provide security awareness training",
                "Regularly update and patch systems"
            ]
        }

    def _get_html_template(self) -> str:
        """Return HTML template for report generation."""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2c3e50;
            margin: 0;
            font-size: 2.5em;
        }
        .metadata {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .section {
            margin-bottom: 30px;
        }
        .section h2 {
            color: #34495e;
            border-left: 4px solid #3498db;
            padding-left: 15px;
            margin-bottom: 15px;
        }
        .section h3 {
            color: #2c3e50;
            margin-top: 20px;
        }
        .risk-level {
            padding: 10px 20px;
            border-radius: 5px;
            font-weight: bold;
            display: inline-block;
            margin: 10px 0;
        }
        .risk-critical { background-color: #e74c3c; color: white; }
        .risk-high { background-color: #f39c12; color: white; }
        .risk-medium { background-color: #f1c40f; color: black; }
        .risk-low { background-color: #27ae60; color: white; }
        .finding {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
            background: #fafafa;
        }
        .finding h4 {
            margin-top: 0;
            color: #2c3e50;
        }
        .severity {
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            display: inline-block;
        }
        .severity-critical { background-color: #e74c3c; color: white; }
        .severity-high { background-color: #f39c12; color: white; }
        .severity-medium { background-color: #f1c40f; color: black; }
        .severity-low { background-color: #27ae60; color: white; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-box {
            background: #3498db;
            color: white;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            display: block;
        }
        .table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        .table th, .table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        .table th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        .recommendations {
            background: #e8f5e8;
            border-left: 4px solid #27ae60;
            padding: 15px;
            margin: 15px 0;
        }
        .recommendations h4 {
            color: #27ae60;
            margin-top: 0;
        }
        .recommendations ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        .footer {
            margin-top: 50px;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
            border-top: 1px solid #ecf0f1;
            padding-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>Security Assessment Report</h1>
            <p>Comprehensive Cybersecurity Evaluation</p>
        </div>

        <!-- Metadata -->
        <div class="metadata">
            <h3>Assessment Information</h3>
            <p><strong>Target:</strong> {{ data.metadata.target }}</p>
            <p><strong>Session ID:</strong> {{ data.metadata.session_id }}</p>
            <p><strong>Assessment Type:</strong> {{ data.metadata.target_type|title }}</p>
            <p><strong>Duration:</strong> {{ data.metadata.assessment_duration }}</p>
            <p><strong>Report Generated:</strong> {{ data.metadata.report_generated }}</p>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <h2>Executive Summary</h2>
            <p><strong>Overall Risk Level:</strong> 
                <span class="risk-level risk-{{ data.executive_summary.overall_risk_level.lower() }}">
                    {{ data.executive_summary.overall_risk_level }}
                </span>
            </p>
            
            <div class="stats-grid">
                <div class="stat-box">
                    <span class="stat-number">{{ data.executive_summary.total_findings }}</span>
                    <span>Total Findings</span>
                </div>
                <div class="stat-box">
                    <span class="stat-number">{{ data.executive_summary.critical_findings }}</span>
                    <span>Critical Issues</span>
                </div>
                <div class="stat-box">
                    <span class="stat-number">{{ data.executive_summary.key_statistics.open_ports }}</span>
                    <span>Open Ports</span>
                </div>
                <div class="stat-box">
                    <span class="stat-number">{{ data.executive_summary.key_statistics.services_identified }}</span>
                    <span>Services Found</span>
                </div>
            </div>

            {% if data.executive_summary.top_risks %}
            <h3>Top Security Risks</h3>
            {% for risk in data.executive_summary.top_risks %}
            <div class="finding">
                <h4>{{ risk.test_name }}</h4>
                <span class="severity severity-{{ risk.severity }}">{{ risk.severity|upper }}</span>
                <p>{{ risk.description }}</p>
            </div>
            {% endfor %}
            {% endif %}
        </div>

        <!-- Risk Metrics -->
        <div class="section">
            <h2>Risk Assessment</h2>
            <p><strong>Total Risk Score:</strong> {{ data.risk_metrics.total_risk_score }}</p>
            
            <h3>Findings by Severity</h3>
            <table class="table">
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
                {% for severity, count in data.risk_metrics.severity_distribution.items() %}
                <tr>
                    <td><span class="severity severity-{{ severity }}">{{ severity|upper }}</span></td>
                    <td>{{ count }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>

        <!-- Reconnaissance Results -->
        {% if data.reconnaissance.summary.total_subdomains > 0 %}
        <div class="section">
            <h2>Reconnaissance Results</h2>
            
            <div class="stats-grid">
                <div class="stat-box">
                    <span class="stat-number">{{ data.reconnaissance.summary.total_subdomains }}</span>
                    <span>Subdomains Found</span>
                </div>
                <div class="stat-box">
                    <span class="stat-number">{{ data.reconnaissance.summary.total_emails }}</span>
                    <span>Email Addresses</span>
                </div>
                <div class="stat-box">
                    <span class="stat-number">{{ data.reconnaissance.summary.technologies_found }}</span>
                    <span>Technologies</span>
                </div>
                <div class="stat-box">
                    <span class="stat-number">{{ data.reconnaissance.summary.certificates_found }}</span>
                    <span>Certificates</span>
                </div>
            </div>

            {% if data.reconnaissance.subdomains %}
            <h3>Discovered Subdomains</h3>
            <ul>
                {% for subdomain in data.reconnaissance.subdomains[:20] %}
                <li>{{ subdomain }}</li>
                {% endfor %}
                {% if data.reconnaissance.subdomains|length > 20 %}
                <li><em>... and {{ data.reconnaissance.subdomains|length - 20 }} more</em></li>
                {% endif %}
            </ul>
            {% endif %}
        </div>
        {% endif %}

        <!-- Scanning Results -->
        <div class="section">
            <h2>Port Scanning Results</h2>
            
            {% if data.scanning.open_ports %}
            <h3>Open Ports and Services</h3>
            <table class="table">
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>State</th>
                </tr>
                {% for port in data.scanning.open_ports %}
                <tr>
                    <td>{{ port.port }}</td>
                    <td>{{ port.protocol or 'tcp' }}</td>
                    <td>{{ port.service or 'unknown' }}</td>
                    <td>{{ port.version or 'N/A' }}</td>
                    <td>{{ port.state }}</td>
                </tr>
                {% endfor %}
            </table>
            {% endif %}
        </div>

        <!-- Test Results -->
        <div class="section">
            <h2>Security Test Results</h2>
            
            <h3>Test Summary</h3>
            <table class="table">
                <tr>
                    <th>Status</th>
                    <th>Count</th>
                </tr>
                <tr>
                    <td>Total Tests</td>
                    <td>{{ data.testing.summary.total_tests }}</td>
                </tr>
                <tr>
                    <td>Passed (Vulnerabilities Found)</td>
                    <td>{{ data.testing.summary.passed }}</td>
                </tr>
                <tr>
                    <td>Failed (No Issues)</td>
                    <td>{{ data.testing.summary.failed }}</td>
                </tr>
                <tr>
                    <td>Skipped</td>
                    <td>{{ data.testing.summary.skipped }}</td>
                </tr>
            </table>

            {% if data.testing.findings %}
            <h3>Security Findings</h3>
            {% for finding in data.testing.findings %}
            <div class="finding">
                <h4>{{ finding.test_name }}</h4>
                <span class="severity severity-{{ finding.severity }}">{{ finding.severity|upper }}</span>
                <p><strong>Category:</strong> {{ finding.category }}</p>
                <p>{{ finding.description }}</p>
                
                {% if finding.evidence %}
                <p><strong>Evidence:</strong></p>
                <ul>
                    {% for evidence in finding.evidence %}
                    <li>{{ evidence }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
                
                {% if finding.recommendations %}
                <div class="recommendations">
                    <h4>Recommendations</h4>
                    <ul>
                        {% for rec in finding.recommendations %}
                        <li>{{ rec }}</li>
                        {% endfor %}
                    </ul>
                </div>
                {% endif %}
            </div>
            {% endfor %}
            {% endif %}
        </div>

        <!-- LLM Generated Tests -->
        {% if data.llm_generated_tests.summary.total_generated > 0 %}
        <div class="section">
            <h2>AI-Generated Test Cases</h2>
            
            <p><strong>Total Generated:</strong> {{ data.llm_generated_tests.summary.total_generated }}</p>
            <p><strong>Approved:</strong> {{ data.llm_generated_tests.summary.approved }}</p>
            <p><strong>Pending Approval:</strong> {{ data.llm_generated_tests.summary.pending_approval }}</p>
            
            {% if data.llm_generated_tests.test_cases %}
            <h3>Generated Test Cases</h3>
            {% for test_case in data.llm_generated_tests.test_cases %}
            <div class="finding">
                <h4>{{ test_case.name }}</h4>
                <span class="severity severity-{{ test_case.severity }}">{{ test_case.severity|upper }}</span>
                <p><strong>Category:</strong> {{ test_case.category }}</p>
                <p><strong>Status:</strong> 
                    {% if test_case.approved %}Approved{% else %}Pending Approval{% endif %}
                    {% if test_case.executed %} | Executed{% endif %}
                </p>
                <p>{{ test_case.description }}</p>
                
                {% if test_case.methodology %}
                <p><strong>Methodology:</strong> {{ test_case.methodology }}</p>
                {% endif %}
            </div>
            {% endfor %}
            {% endif %}
        </div>
        {% endif %}

        <!-- Recommendations -->
        <div class="section">
            <h2>Recommendations</h2>
            
            {% if data.recommendations.immediate_actions %}
            <div class="recommendations">
                <h4>🚨 Immediate Actions (Critical Priority)</h4>
                <ul>
                    {% for action in data.recommendations.immediate_actions %}
                    <li>{{ action }}</li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}
            
            {% if data.recommendations.short_term_actions %}
            <div class="recommendations">
                <h4>⚡ Short-term Actions (High Priority)</h4>
                <ul>
                    {% for action in data.recommendations.short_term_actions %}
                    <li>{{ action }}</li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}
            
            {% if data.recommendations.long_term_actions %}
            <div class="recommendations">
                <h4>📋 Long-term Actions (Medium Priority)</h4>
                <ul>
                    {% for action in data.recommendations.long_term_actions %}
                    <li>{{ action }}</li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}
            
            <div class="recommendations">
                <h4>🛡️ General Security Recommendations</h4>
                <ul>
                    {% for rec in data.recommendations.general_recommendations %}
                    <li>{{ rec }}</li>
                    {% endfor %}
                </ul>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>This report was generated by the Multi-Agent Cybersecurity Automation System.</p>
            <p>Report generated on {{ data.metadata.report_generated }}</p>
            <p><strong>CONFIDENTIAL:</strong> This report contains sensitive security information and should be handled accordingly.</p>
        </div>
    </div>
</body>
</html>
        '''
