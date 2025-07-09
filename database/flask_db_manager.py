"""
Flask Database Manager
Handles SQLAlchemy models and database operations for the Flask cybersecurity system.
"""

try:
    from flask_sqlalchemy import SQLAlchemy
except ImportError:
    # Fallback if Flask-SQLAlchemy is not installed
    SQLAlchemy = None

from datetime import datetime, timedelta
import json
import uuid
from typing import Dict, List, Optional, Any
import logging


class FlaskDatabaseManager:
    """
    Database manager for Flask-based cybersecurity automation system.
    Handles assessment storage, results tracking, and data persistence.
    """

    def __init__(self, db):
        self.db = db
        self.logger = logging.getLogger(__name__)

        # Define database models
        self._define_models()

        self.logger.info("FlaskDatabaseManager initialized")

    def _define_models(self):
        """Define SQLAlchemy database models."""

        class Assessment(self.db.Model):
            """Main assessment model."""
            __tablename__ = 'assessments'

            id = self.db.Column(self.db.String(
                36), primary_key=True, default=lambda: str(uuid.uuid4()))
            target = self.db.Column(self.db.String(255), nullable=False)
            target_type = self.db.Column(self.db.String(
                50), nullable=False)  # 'domain' or 'ip'
            status = self.db.Column(self.db.String(
                50), nullable=False, default='created')
            created_at = self.db.Column(
                self.db.DateTime, nullable=False, default=datetime.utcnow)
            updated_at = self.db.Column(
                self.db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
            completed_at = self.db.Column(self.db.DateTime, nullable=True)

            # Configuration
            scan_type = self.db.Column(
                self.db.String(50), default='comprehensive')
            ports = self.db.Column(self.db.String(255), default='top_1000')

            # Results summary
            total_vulnerabilities = self.db.Column(self.db.Integer, default=0)
            risk_score = self.db.Column(self.db.Float, default=0.0)

            # Relationships
            recon_results = self.db.relationship(
                'ReconResult', backref='assessment', lazy=True, cascade='all, delete-orphan')
            scan_results = self.db.relationship(
                'ScanResult', backref='assessment', lazy=True, cascade='all, delete-orphan')
            test_results = self.db.relationship(
                'TestResult', backref='assessment', lazy=True, cascade='all, delete-orphan')

            def to_dict(self):
                return {
                    'id': self.id,
                    'target': self.target,
                    'target_type': self.target_type,
                    'status': self.status,
                    'created_at': self.created_at.isoformat() if self.created_at else None,
                    'updated_at': self.updated_at.isoformat() if self.updated_at else None,
                    'completed_at': self.completed_at.isoformat() if self.completed_at else None,
                    'scan_type': self.scan_type,
                    'ports': self.ports,
                    'total_vulnerabilities': self.total_vulnerabilities,
                    'risk_score': self.risk_score
                }

        class ReconResult(self.db.Model):
            """Reconnaissance results model."""
            __tablename__ = 'recon_results'

            id = self.db.Column(self.db.String(
                36), primary_key=True, default=lambda: str(uuid.uuid4()))
            assessment_id = self.db.Column(self.db.String(
                36), self.db.ForeignKey('assessments.id'), nullable=False)

            # Timing
            started_at = self.db.Column(
                self.db.DateTime, nullable=False, default=datetime.utcnow)
            completed_at = self.db.Column(self.db.DateTime, nullable=True)

            # Status
            status = self.db.Column(self.db.String(
                50), nullable=False, default='running')
            error_message = self.db.Column(self.db.Text, nullable=True)

            # Results (stored as JSON)
            subdomains = self.db.Column(
                self.db.Text, nullable=True)  # JSON array
            dns_records = self.db.Column(
                self.db.Text, nullable=True)  # JSON object
            whois_data = self.db.Column(
                self.db.Text, nullable=True)  # JSON object
            technologies = self.db.Column(
                self.db.Text, nullable=True)  # JSON array
            emails = self.db.Column(self.db.Text, nullable=True)  # JSON array
            social_media = self.db.Column(
                self.db.Text, nullable=True)  # JSON array
            shodan_data = self.db.Column(
                self.db.Text, nullable=True)  # JSON object

            def to_dict(self):
                return {
                    'id': self.id,
                    'assessment_id': self.assessment_id,
                    'started_at': self.started_at.isoformat() if self.started_at else None,
                    'completed_at': self.completed_at.isoformat() if self.completed_at else None,
                    'status': self.status,
                    'error_message': self.error_message,
                    'subdomains': json.loads(self.subdomains) if self.subdomains else [],
                    'dns_records': json.loads(self.dns_records) if self.dns_records else {},
                    'whois_data': json.loads(self.whois_data) if self.whois_data else {},
                    'technologies': json.loads(self.technologies) if self.technologies else [],
                    'emails': json.loads(self.emails) if self.emails else [],
                    'social_media': json.loads(self.social_media) if self.social_media else [],
                    'shodan_data': json.loads(self.shodan_data) if self.shodan_data else {}
                }

        class ScanResult(self.db.Model):
            """Port scanning results model."""
            __tablename__ = 'scan_results'

            id = self.db.Column(self.db.String(
                36), primary_key=True, default=lambda: str(uuid.uuid4()))
            assessment_id = self.db.Column(self.db.String(
                36), self.db.ForeignKey('assessments.id'), nullable=False)

            # Timing
            started_at = self.db.Column(
                self.db.DateTime, nullable=False, default=datetime.utcnow)
            completed_at = self.db.Column(self.db.DateTime, nullable=True)

            # Configuration
            scan_type = self.db.Column(self.db.String(50), nullable=False)
            tool_used = self.db.Column(self.db.String(50), nullable=False)
            ports_scanned = self.db.Column(self.db.String(255), nullable=True)

            # Status
            status = self.db.Column(self.db.String(
                50), nullable=False, default='running')
            error_message = self.db.Column(self.db.Text, nullable=True)

            # Results (stored as JSON)
            hosts_data = self.db.Column(
                self.db.Text, nullable=True)  # JSON object
            summary_data = self.db.Column(
                self.db.Text, nullable=True)  # JSON object

            def to_dict(self):
                return {
                    'id': self.id,
                    'assessment_id': self.assessment_id,
                    'started_at': self.started_at.isoformat() if self.started_at else None,
                    'completed_at': self.completed_at.isoformat() if self.completed_at else None,
                    'scan_type': self.scan_type,
                    'tool_used': self.tool_used,
                    'ports_scanned': self.ports_scanned,
                    'status': self.status,
                    'error_message': self.error_message,
                    'hosts_data': json.loads(self.hosts_data) if self.hosts_data else {},
                    'summary_data': json.loads(self.summary_data) if self.summary_data else {}
                }

        class TestResult(self.db.Model):
            """Test case execution results model."""
            __tablename__ = 'test_results'

            id = self.db.Column(self.db.String(
                36), primary_key=True, default=lambda: str(uuid.uuid4()))
            assessment_id = self.db.Column(self.db.String(
                36), self.db.ForeignKey('assessments.id'), nullable=False)

            # Test information
            test_name = self.db.Column(self.db.String(255), nullable=False)
            test_category = self.db.Column(self.db.String(100), nullable=False)
            test_severity = self.db.Column(self.db.String(50), nullable=False)
            # 'predefined' or 'llm_generated'
            test_source = self.db.Column(self.db.String(50), nullable=False)

            # Timing
            started_at = self.db.Column(
                self.db.DateTime, nullable=False, default=datetime.utcnow)
            completed_at = self.db.Column(self.db.DateTime, nullable=True)

            # Status and results
            # 'passed', 'failed', 'error', 'skipped'
            status = self.db.Column(self.db.String(50), nullable=False)
            vulnerable = self.db.Column(
                self.db.Boolean, nullable=False, default=False)
            error_message = self.db.Column(self.db.Text, nullable=True)

            # Test details (stored as JSON)
            test_data = self.db.Column(
                self.db.Text, nullable=True)  # Original test case
            result_data = self.db.Column(
                self.db.Text, nullable=True)  # Detailed results

            def to_dict(self):
                return {
                    'id': self.id,
                    'assessment_id': self.assessment_id,
                    'test_name': self.test_name,
                    'test_category': self.test_category,
                    'test_severity': self.test_severity,
                    'test_source': self.test_source,
                    'started_at': self.started_at.isoformat() if self.started_at else None,
                    'completed_at': self.completed_at.isoformat() if self.completed_at else None,
                    'status': self.status,
                    'vulnerable': self.vulnerable,
                    'error_message': self.error_message,
                    'test_data': json.loads(self.test_data) if self.test_data else {},
                    'result_data': json.loads(self.result_data) if self.result_data else {}
                }

        # Store model classes for later use
        self.Assessment = Assessment
        self.ReconResult = ReconResult
        self.ScanResult = ScanResult
        self.TestResult = TestResult

    def create_tables(self):
        """Create database tables."""
        try:
            self.db.create_all()
            self.logger.info("Database tables created successfully")
        except Exception as e:
            self.logger.error(f"Failed to create database tables: {e}")
            raise

    def create_assessment(self, target: str, target_type: str, scan_type: str = 'comprehensive',
                          ports: str = 'top_1000') -> str:
        """Create a new assessment."""
        try:
            assessment = self.Assessment(
                target=target,
                target_type=target_type,
                scan_type=scan_type,
                ports=ports,
                status='created'
            )

            self.db.session.add(assessment)
            self.db.session.commit()

            self.logger.info(
                f"Created assessment {assessment.id} for target {target}")
            return assessment.id

        except Exception as e:
            self.db.session.rollback()
            self.logger.error(f"Failed to create assessment: {e}")
            raise

    def get_assessment(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        """Get assessment by ID."""
        try:
            assessment = self.Assessment.query.get(assessment_id)
            return assessment.to_dict() if assessment else None
        except Exception as e:
            self.logger.error(f"Failed to get assessment {assessment_id}: {e}")
            return None

    def update_assessment_status(self, assessment_id: str, status: str) -> bool:
        """Update assessment status."""
        try:
            assessment = self.Assessment.query.get(assessment_id)
            if assessment:
                assessment.status = status
                assessment.updated_at = datetime.utcnow()

                if status == 'completed':
                    assessment.completed_at = datetime.utcnow()

                self.db.session.commit()
                return True
            return False
        except Exception as e:
            self.db.session.rollback()
            self.logger.error(f"Failed to update assessment status: {e}")
            return False

    def save_recon_results(self, assessment_id: str, results: Dict[str, Any]) -> str:
        """Save reconnaissance results."""
        try:
            recon_result = self.ReconResult(
                assessment_id=assessment_id,
                status=results.get('status', 'completed'),
                completed_at=datetime.utcnow() if results.get(
                    'status') == 'completed' else None,
                subdomains=json.dumps(results.get('subdomains', [])),
                dns_records=json.dumps(results.get('dns_records', {})),
                whois_data=json.dumps(results.get('whois_data', {})),
                technologies=json.dumps(results.get('technologies', [])),
                emails=json.dumps(results.get('emails', [])),
                social_media=json.dumps(results.get('social_media', [])),
                shodan_data=json.dumps(results.get('shodan_data', {})),
                error_message=results.get('error')
            )

            self.db.session.add(recon_result)
            self.db.session.commit()

            self.logger.info(
                f"Saved recon results for assessment {assessment_id}")
            return recon_result.id

        except Exception as e:
            self.db.session.rollback()
            self.logger.error(f"Failed to save recon results: {e}")
            raise

    def save_scan_results(self, assessment_id: str, results: Dict[str, Any]) -> str:
        """Save port scanning results."""
        try:
            scan_result = self.ScanResult(
                assessment_id=assessment_id,
                scan_type=results.get('scan_type', 'unknown'),
                tool_used=results.get('tool', 'unknown'),
                ports_scanned=results.get('ports', ''),
                status=results.get('status', 'completed'),
                completed_at=datetime.utcnow() if results.get(
                    'status') == 'completed' else None,
                hosts_data=json.dumps(results.get('hosts', [])),
                summary_data=json.dumps(results.get('summary', {})),
                error_message=results.get('error')
            )

            self.db.session.add(scan_result)
            self.db.session.commit()

            self.logger.info(
                f"Saved scan results for assessment {assessment_id}")
            return scan_result.id

        except Exception as e:
            self.db.session.rollback()
            self.logger.error(f"Failed to save scan results: {e}")
            raise

    def save_test_results(self, assessment_id: str, test_results: List[Dict[str, Any]]) -> List[str]:
        """Save test case execution results."""
        try:
            result_ids = []

            for test_result in test_results:
                test_record = self.TestResult(
                    assessment_id=assessment_id,
                    test_name=test_result.get('test_name', 'Unknown Test'),
                    test_category=test_result.get('test_category', 'unknown'),
                    test_severity=test_result.get('test_severity', 'medium'),
                    test_source=test_result.get('test_source', 'predefined'),
                    status=test_result.get('status', 'unknown'),
                    vulnerable=test_result.get('vulnerable', False),
                    completed_at=datetime.utcnow() if test_result.get(
                        'status') != 'running' else None,
                    error_message=test_result.get('error'),
                    test_data=json.dumps(test_result.get('test_data', {})),
                    result_data=json.dumps(test_result.get('result_data', {}))
                )

                self.db.session.add(test_record)
                result_ids.append(test_record.id)

            self.db.session.commit()

            self.logger.info(
                f"Saved {len(test_results)} test results for assessment {assessment_id}")
            return result_ids

        except Exception as e:
            self.db.session.rollback()
            self.logger.error(f"Failed to save test results: {e}")
            raise

    def get_assessment_results(self, assessment_id: str) -> Dict[str, Any]:
        """Get complete assessment results."""
        try:
            assessment = self.Assessment.query.get(assessment_id)
            if not assessment:
                return {'error': 'Assessment not found'}

            # Get related results
            recon_results = [r.to_dict() for r in assessment.recon_results]
            scan_results = [r.to_dict() for r in assessment.scan_results]
            test_results = [r.to_dict() for r in assessment.test_results]

            # Calculate summary statistics
            total_vulnerabilities = sum(
                1 for t in test_results if t.get('vulnerable', False))

            # Calculate risk score (simplified)
            risk_score = self._calculate_risk_score(test_results)

            # Update assessment with calculated values
            assessment.total_vulnerabilities = total_vulnerabilities
            assessment.risk_score = risk_score
            self.db.session.commit()

            return {
                'assessment': assessment.to_dict(),
                'recon_results': recon_results,
                'scan_results': scan_results,
                'test_results': test_results,
                'summary': {
                    'total_vulnerabilities': total_vulnerabilities,
                    'risk_score': risk_score,
                    'test_categories': self._get_test_categories_summary(test_results),
                    'severity_breakdown': self._get_severity_breakdown(test_results)
                }
            }

        except Exception as e:
            self.logger.error(f"Failed to get assessment results: {e}")
            return {'error': str(e)}

    def _calculate_risk_score(self, test_results: List[Dict[str, Any]]) -> float:
        """Calculate risk score based on test results."""
        if not test_results:
            return 0.0

        severity_weights = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5
        }

        total_score = 0.0
        max_possible_score = 0.0

        for test in test_results:
            severity = test.get('test_severity', 'medium').lower()
            weight = severity_weights.get(severity, 5.0)
            max_possible_score += weight

            if test.get('vulnerable', False):
                total_score += weight

        return (total_score / max_possible_score * 100) if max_possible_score > 0 else 0.0

    def _get_test_categories_summary(self, test_results: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get summary of test results by category."""
        categories = {}
        for test in test_results:
            category = test.get('test_category', 'unknown')
            if category not in categories:
                categories[category] = {'total': 0, 'vulnerable': 0}

            categories[category]['total'] += 1
            if test.get('vulnerable', False):
                categories[category]['vulnerable'] += 1

        return categories

    def _get_severity_breakdown(self, test_results: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get breakdown of vulnerabilities by severity."""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for test in test_results:
            if test.get('vulnerable', False):
                severity = test.get('test_severity', 'medium').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1

        return severity_counts

    def list_assessments(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """List assessments with pagination."""
        try:
            assessments = self.Assessment.query.order_by(
                self.Assessment.created_at.desc()
            ).limit(limit).offset(offset).all()

            return [assessment.to_dict() for assessment in assessments]

        except Exception as e:
            self.logger.error(f"Failed to list assessments: {e}")
            return []

    def delete_assessment(self, assessment_id: str) -> bool:
        """Delete an assessment and all related data."""
        try:
            assessment = self.Assessment.query.get(assessment_id)
            if assessment:
                self.db.session.delete(assessment)
                self.db.session.commit()
                self.logger.info(f"Deleted assessment {assessment_id}")
                return True
            return False
        except Exception as e:
            self.db.session.rollback()
            self.logger.error(f"Failed to delete assessment: {e}")
            return False

    def cleanup_old_assessments(self, days_old: int = 30) -> int:
        """Clean up assessments older than specified days."""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_old)
            old_assessments = self.Assessment.query.filter(
                self.Assessment.created_at < cutoff_date
            ).all()

            count = len(old_assessments)
            for assessment in old_assessments:
                self.db.session.delete(assessment)

            self.db.session.commit()
            self.logger.info(f"Cleaned up {count} old assessments")
            return count

        except Exception as e:
            self.db.session.rollback()
            self.logger.error(f"Failed to cleanup old assessments: {e}")
            return 0
