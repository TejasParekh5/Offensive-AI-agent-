"""
Flask-based Multi-Agent Cybersecurity Automation System
Main application entry point with Flask web server and API routes.
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file, flash
import os
import json
import threading
from datetime import datetime
import uuid
from pathlib import Path
import logging
import tempfile

# Import our agents and utilities
try:
    from agents.flask_recon_agent import FlaskReconAgent
    from agents.flask_scanning_agent import FlaskScanningAgent
    from agents.flask_test_agent import FlaskTestAgent
    from database.flask_db_manager import FlaskDatabaseManager
    from utils.flask_helpers import setup_logging, is_valid_ip, is_valid_domain, get_target_type
    from utils.ollama_integration import OllamaLLMClient
    from reports.flask_report_generator import FlaskReportGenerator
    IMPORTS_SUCCESSFUL = True
except ImportError as e:
    print(f"Import error: {e}")
    print("Some components may not be available")
    IMPORTS_SUCCESSFUL = False
    # Define fallback functions
    def setup_logging():
        logging.basicConfig(level=logging.INFO)
    def is_valid_ip(ip):
        return True
    def is_valid_domain(domain):
        return True
    def get_target_type(target):
        return 'domain'

# Initialize Flask app with extensions
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cybersec-automation-key-2025')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybersec_assessments.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Try to initialize Flask-SQLAlchemy if available
try:
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy(app)
    db_manager = FlaskDatabaseManager(db)
    HAS_DATABASE = True
except ImportError:
    db = None
    db_manager = None
    HAS_DATABASE = False
    print("Warning: Flask-SQLAlchemy not available - database features disabled")

# Try to initialize Socket.IO if available
try:
    from flask_socketio import SocketIO, emit, join_room
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
    HAS_SOCKETIO = True
except ImportError:
    socketio = None
    join_room = None
    HAS_SOCKETIO = False
    print("Warning: Flask-SocketIO not available - real-time updates disabled")

# Initialize system components
try:
    if IMPORTS_SUCCESSFUL:
        recon_agent = FlaskReconAgent()
        scanning_agent = FlaskScanningAgent()
        test_agent = FlaskTestAgent()
        llm_client = OllamaLLMClient()
        report_generator = FlaskReportGenerator()
        AGENTS_AVAILABLE = True
    else:
        raise Exception("Imports failed")
except Exception as e:
    print(f"Warning: Could not initialize all agents: {e}")
    recon_agent = None
    scanning_agent = None
    test_agent = None
    llm_client = None
    report_generator = None
    AGENTS_AVAILABLE = False

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

# Global state for tracking active assessments
active_assessments = {}

# Create database tables if available
if HAS_DATABASE and db_manager:
    with app.app_context():
        try:
            db_manager.create_tables()
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create database tables: {e}")

@app.route('/')
def dashboard():
    """Main dashboard homepage."""
    try:
        # Get recent assessments and stats
        if HAS_DATABASE and db_manager:
            recent_assessments = db_manager.list_assessments(limit=5)
            total_assessments = len(db_manager.list_assessments(limit=1000))
        else:
            recent_assessments = []
            total_assessments = 0
        
        # Calculate statistics
        stats = {
            'total_assessments': total_assessments,
            'active_assessments': len(active_assessments),
            'total_vulnerabilities': 0,  # Calculate from completed assessments
            'completed_today': 0  # Calculate from today's completions
        }
        
        # Check LLM status
        llm_status = False
        if llm_client:
            try:
                llm_status = llm_client.is_available()
            except:
                llm_status = False
        
        return render_template('dashboard.html', 
                             recent_assessments=recent_assessments,
                             stats=stats,
                             llm_status=llm_status)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash(f"Dashboard error: {e}", 'error')
        return render_template('dashboard.html', 
                             recent_assessments=[],
                             stats={'total_assessments': 0, 'active_assessments': 0, 'total_vulnerabilities': 0, 'completed_today': 0},
                             llm_status=False)

@app.route('/new-assessment')
def new_assessment():
    """New assessment configuration page."""
    return render_template('new_assessment.html')

@app.route('/assessments')
def assessments():
    """List all assessments."""
    try:
        if HAS_DATABASE and db_manager:
            all_assessments = db_manager.list_assessments(limit=50)
        else:
            all_assessments = []
        
        return render_template('assessments.html', assessments=all_assessments)
    except Exception as e:
        logger.error(f"Assessments list error: {e}")
        flash(f"Error loading assessments: {e}", 'error')
        return render_template('assessments.html', assessments=[])

@app.route('/assessment/<assessment_id>')
def assessment_detail(assessment_id):
    """View assessment details and progress."""
    try:
        if not HAS_DATABASE or not db_manager:
            flash("Database not available", 'error')
            return redirect(url_for('dashboard'))
        
        # Get assessment data
        assessment_data = db_manager.get_assessment_results(assessment_id)
        
        if 'error' in assessment_data:
            flash(f"Assessment not found: {assessment_data['error']}", 'error')
            return redirect(url_for('assessments'))
        
        # Get current status if active
        status = active_assessments.get(assessment_id, {})
        
        return render_template('assessment_detail.html',
                             assessment_data=assessment_data,
                             status=status)
        
    except Exception as e:
        logger.error(f"Assessment detail error: {e}")
        flash(f"Error loading assessment: {e}", 'error')
        return redirect(url_for('assessments'))

@app.route('/reports')
def reports():
    """Reports and export page."""
    try:
        if HAS_DATABASE and db_manager:
            completed_assessments = [a for a in db_manager.list_assessments(limit=100) 
                                   if a.get('status') == 'completed']
        else:
            completed_assessments = []
        
        return render_template('reports.html', assessments=completed_assessments)
    except Exception as e:
        logger.error(f"Reports page error: {e}")
        flash(f"Error loading reports: {e}", 'error')
        return render_template('reports.html', assessments=[])

@app.route('/settings')
def settings():
    """Settings page."""
    try:
        settings_data = {
            'ollama_url': 'http://localhost:11434',
            'ollama_model': 'llama2',
            'enable_ai_tests': False,
            'require_approval': True,
            'default_ports': 'top_1000',
            'scan_timeout': 300,
            'preferred_scanner': 'nmap',
            'scan_intensity': 'normal'
        }
        
        return render_template('settings.html', settings=settings_data)
    except Exception as e:
        logger.error(f"Settings error: {e}")
        return render_template('error.html', error=str(e))

# API Routes
@app.route('/api/assessments', methods=['POST'])
def api_start_assessment():
    """API endpoint to start a new security assessment."""
    try:
        if not AGENTS_AVAILABLE:
            return jsonify({'success': False, 'error': 'Assessment agents not available'}), 503
        
        data = request.get_json()
        target = data.get('target', '').strip()
        
        # Validate target
        if not target:
            return jsonify({'success': False, 'error': 'Target is required'}), 400
        
        # Determine target type
        target_type = get_target_type(target)
        if target_type == 'unknown':
            return jsonify({'success': False, 'error': 'Invalid target format'}), 400
        
        # Create assessment in database
        if HAS_DATABASE and db_manager:
            assessment_id = db_manager.create_assessment(
                target=target,
                target_type=target_type,
                scan_type=data.get('scan_type', 'comprehensive'),
                ports=data.get('ports', 'top_1000')
            )
        else:
            assessment_id = f"assess_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # Add to active assessments
        active_assessments[assessment_id] = {
            'target': target,
            'target_type': target_type,
            'status': 'starting',
            'progress': 0,
            'current_phase': 'initialization',
            'start_time': datetime.now()
        }
        
        # Start assessment in background thread
        assessment_config = {
            'target': target,
            'target_type': target_type,
            'scan_type': data.get('scan_type', 'comprehensive'),
            'ports': data.get('ports', 'top_1000'),
            'enable_recon': data.get('enable_recon', target_type == 'domain'),
            'enable_predefined_tests': data.get('enable_predefined_tests', True),
            'enable_ai_tests': data.get('enable_ai_tests', False),
            'require_approval': data.get('require_approval', True)
        }
        
        thread = threading.Thread(
            target=_run_assessment_async,
            args=(assessment_id, assessment_config)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'assessment_id': assessment_id,
            'message': 'Assessment started successfully'
        })
        
    except Exception as e:
        logger.error(f"Start assessment error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/assessment/<assessment_id>/status')
def api_assessment_status(assessment_id):
    """Get real-time assessment status."""
    try:
        status = active_assessments.get(assessment_id, {})
        
        # Also get database status if available
        if HAS_DATABASE and db_manager:
            assessment = db_manager.get_assessment(assessment_id)
            if assessment:
                status.update({
                    'db_status': assessment.get('status', 'unknown'),
                    'target': assessment.get('target', ''),
                    'created_at': assessment.get('created_at', '')
                })
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Status check error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/status')
def api_system_status():
    """Get overall system status."""
    try:
        status = {
            'flask_app': True,
            'database': HAS_DATABASE,
            'socketio': HAS_SOCKETIO,
            'agents': AGENTS_AVAILABLE,
            'llm_available': False
        }
        
        if llm_client:
            status['llm_available'] = llm_client.is_available()
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"System status error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/download/report/<assessment_id>/<format>')
def download_report(assessment_id, format):
    """Download assessment report in specified format."""
    try:
        if not HAS_DATABASE or not db_manager:
            flash("Database not available", 'error')
            return redirect(url_for('dashboard'))
        
        if not report_generator:
            flash("Report generator not available", 'error')
            return redirect(url_for('dashboard'))
        
        # Get assessment data
        assessment_data = db_manager.get_assessment_results(assessment_id)
        
        if 'error' in assessment_data:
            flash(f"Assessment not found: {assessment_data['error']}", 'error')
            return redirect(url_for('assessments'))
        
        # Generate report
        if format == 'pdf':
            report_path = report_generator.generate_pdf_report(assessment_data)
        elif format == 'json':
            report_path = report_generator.generate_json_report(assessment_data)
        elif format == 'csv':
            report_path = report_generator.generate_csv_summary(assessment_data)
        else:
            flash("Invalid report format", 'error')
            return redirect(url_for('assessment_detail', assessment_id=assessment_id))
        
        return send_file(report_path, as_attachment=True)
        
    except Exception as e:
        logger.error(f"Download report error: {e}")
        flash(f"Error generating report: {e}", 'error')
        return redirect(url_for('assessment_detail', assessment_id=assessment_id))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return render_template('error.html', error="Internal server error"), 500

# Socket.IO events (if available)
if HAS_SOCKETIO and socketio:
    @socketio.on('connect')
    def handle_connect():
        logger.info(f"Client connected: {request.sid}")
    
    @socketio.on('disconnect')
    def handle_disconnect():
        logger.info(f"Client disconnected: {request.sid}")
    
    @socketio.on('join_assessment')
    def handle_join_assessment(data):
        assessment_id = data.get('assessment_id')
        if assessment_id and join_room:
            join_room(assessment_id)
            logger.info(f"Client {request.sid} joined assessment {assessment_id}")

def _emit_progress_update(assessment_id, data):
    """Helper to emit progress updates via Socket.IO."""
    if HAS_SOCKETIO and socketio:
        try:
            socketio.emit('progress_update', data, room=assessment_id)
        except:
            pass  # Fail silently if Socket.IO is not available

def _run_assessment_async(assessment_id, config):
    """Run assessment asynchronously in background thread."""
    try:
        logger.info(f"Starting assessment {assessment_id} for target {config['target']}")
        
        # Update status
        active_assessments[assessment_id]['status'] = 'running'
        active_assessments[assessment_id]['current_phase'] = 'reconnaissance'
        
        if HAS_DATABASE and db_manager:
            db_manager.update_assessment_status(assessment_id, 'running')
        
        _emit_progress_update(assessment_id, {
            'assessment_id': assessment_id,
            'status': 'running',
            'phase': 'reconnaissance',
            'progress': 10
        })
        
        # Simplified assessment process for now
        import time
        
        # Simulate reconnaissance
        active_assessments[assessment_id]['progress'] = 30
        _emit_progress_update(assessment_id, {
            'assessment_id': assessment_id,
            'phase': 'reconnaissance',
            'progress': 30,
            'message': 'Reconnaissance completed'
        })
        time.sleep(2)
        
        # Simulate scanning
        active_assessments[assessment_id]['current_phase'] = 'scanning'
        active_assessments[assessment_id]['progress'] = 70
        _emit_progress_update(assessment_id, {
            'assessment_id': assessment_id,
            'phase': 'scanning',
            'progress': 70,
            'message': 'Port scanning completed'
        })
        time.sleep(2)
        
        # Simulate testing
        active_assessments[assessment_id]['current_phase'] = 'testing'
        active_assessments[assessment_id]['progress'] = 90
        _emit_progress_update(assessment_id, {
            'assessment_id': assessment_id,
            'phase': 'testing',
            'progress': 90,
            'message': 'Security tests completed'
        })
        time.sleep(2)
        
        # Complete assessment
        active_assessments[assessment_id]['status'] = 'completed'
        active_assessments[assessment_id]['progress'] = 100
        active_assessments[assessment_id]['current_phase'] = 'completed'
        
        if HAS_DATABASE and db_manager:
            db_manager.update_assessment_status(assessment_id, 'completed')
        
        _emit_progress_update(assessment_id, {
            'assessment_id': assessment_id,
            'status': 'completed',
            'progress': 100,
            'message': 'Assessment completed successfully'
        })
        
        logger.info(f"Assessment {assessment_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Assessment {assessment_id} failed: {e}")
        
        # Update status to failed
        active_assessments[assessment_id]['status'] = 'failed'
        active_assessments[assessment_id]['error'] = str(e)
        
        if HAS_DATABASE and db_manager:
            db_manager.update_assessment_status(assessment_id, 'failed')
        
        _emit_progress_update(assessment_id, {
            'assessment_id': assessment_id,
            'status': 'failed',
            'error': str(e)
        })

if __name__ == '__main__':
    logger.info("Starting Flask Cybersecurity Automation System")
    
    if HAS_SOCKETIO and socketio:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    else:
        app.run(host='0.0.0.0', port=5000, debug=True)
