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

@app.route('/api/assessments/bulk', methods=['POST'])
def api_bulk_assessments():
    """API endpoint to start multiple assessments."""
    try:
        data = request.get_json()
        targets = data.get('targets', [])
        scan_type = data.get('scan_type', 'comprehensive')
        
        if not targets:
            return jsonify({'success': False, 'error': 'No targets provided'}), 400
        
        assessment_ids = []
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
                
            target_type = get_target_type(target)
            if target_type == 'unknown':
                continue
            
            # Create assessment
            if HAS_DATABASE and db_manager:
                assessment_id = db_manager.create_assessment(
                    target=target,
                    target_type=target_type,
                    scan_type=scan_type
                )
            else:
                assessment_id = f"assess_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
            
            assessment_ids.append(assessment_id)
            
            # Add to active assessments
            active_assessments[assessment_id] = {
                'target': target,
                'target_type': target_type,
                'status': 'queued',
                'progress': 0,
                'current_phase': 'queued'
            }
        
        # Start assessments (simplified - start all at once)
        for assessment_id in assessment_ids:
            config = active_assessments[assessment_id].copy()
            config['scan_type'] = scan_type
            thread = threading.Thread(
                target=_run_assessment_async,
                args=(assessment_id, config)
            )
            thread.daemon = True
            thread.start()
        
        return jsonify({
            'success': True,
            'count': len(assessment_ids),
            'assessment_ids': assessment_ids
        })
        
    except Exception as e:
        logger.error(f"Bulk assessments error: {e}")
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

@app.route('/api/tools/status')
def api_tools_status():
    """Get scanning tools availability status."""
    try:
        tools_status = {}
        
        if scanning_agent:
            tools_status.update(scanning_agent.get_available_tools())
        else:
            # Default tools check
            tools_status = {
                'nmap': False,
                'masscan': False,
                'rustscan': False
            }
        
        # Add LLM status
        if llm_client:
            tools_status['ollama'] = llm_client.is_available()
        else:
            tools_status['ollama'] = False
        
        return jsonify(tools_status)
        
    except Exception as e:
        logger.error(f"Tools status error: {e}")
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
        
        # Phase 1: Reconnaissance (for domains only)
        if config.get('enable_recon', False) and config['target_type'] == 'domain' and recon_agent:
            try:
                logger.info(f"Starting reconnaissance for {assessment_id}")
                active_assessments[assessment_id]['current_phase'] = 'reconnaissance'
                
                def recon_callback(recon_id, update):
                    active_assessments[assessment_id]['progress'] = min(update.get('progress', 0), 30)
                    _emit_progress_update(assessment_id, {
                        'assessment_id': assessment_id,
                        'phase': 'reconnaissance',
                        'progress': active_assessments[assessment_id]['progress'],
                        'message': update.get('message', 'Running reconnaissance...')
                    })
                
                recon_id = recon_agent.start_reconnaissance(config['target'], callback=recon_callback)
                
                # Wait for completion (simplified)
                import time
                timeout = 300  # 5 minutes
                start_time = time.time()
                while time.time() - start_time < timeout:
                    status = recon_agent.get_recon_status(recon_id)
                    if status.get('status') in ['completed', 'failed']:
                        break
                    time.sleep(5)
                
                # Get results and save
                recon_results = recon_agent.get_recon_results(recon_id)
                if HAS_DATABASE and db_manager and recon_results.get('status') == 'completed':
                    db_manager.save_recon_results(assessment_id, recon_results)
                
            except Exception as e:
                logger.error(f"Reconnaissance failed for {assessment_id}: {e}")
        
        # Phase 2: Port Scanning
        if scanning_agent:
            try:
                logger.info(f"Starting port scan for {assessment_id}")
                active_assessments[assessment_id]['current_phase'] = 'scanning'
                
                def scan_callback(scan_id, update):
                    progress = 30 + min(update.get('progress', 0) * 0.4, 40)  # 30-70%
                    active_assessments[assessment_id]['progress'] = progress
                    _emit_progress_update(assessment_id, {
                        'assessment_id': assessment_id,
                        'phase': 'scanning',
                        'progress': progress,
                        'message': update.get('message', 'Running port scan...')
                    })
                
                scan_id = scanning_agent.start_scan(
                    target=config['target'],
                    scan_type=config.get('scan_type', 'comprehensive'),
                    ports=config.get('ports', 'top_1000'),
                    callback=scan_callback
                )
                
                # Wait for completion
                timeout = 600  # 10 minutes
                start_time = time.time()
                while time.time() - start_time < timeout:
                    status = scanning_agent.get_scan_status(scan_id)
                    if status.get('status') in ['completed', 'failed']:
                        break
                    time.sleep(5)
                
                # Get results and save
                scan_results = scanning_agent.get_scan_results(scan_id)
                if HAS_DATABASE and db_manager and scan_results.get('status') == 'completed':
                    db_manager.save_scan_results(assessment_id, scan_results)
                
            except Exception as e:
                logger.error(f"Port scanning failed for {assessment_id}: {e}")
        
        # Phase 3: Security Testing
        if test_agent:
            try:
                logger.info(f"Starting security tests for {assessment_id}")
                active_assessments[assessment_id]['current_phase'] = 'testing'
                
                def test_callback(test_id, update):
                    progress = 70 + min(update.get('progress', 0) * 0.25, 25)  # 70-95%
                    active_assessments[assessment_id]['progress'] = progress
                    _emit_progress_update(assessment_id, {
                        'assessment_id': assessment_id,
                        'phase': 'testing',
                        'progress': progress,
                        'message': update.get('message', 'Running security tests...')
                    })
                
                # Get predefined tests
                test_suite = []
                if config.get('enable_predefined_tests', True):
                    test_suite.extend(test_agent.get_predefined_tests())
                
                # Execute tests
                if test_suite:
                    execution_id = test_agent.execute_test_suite(
                        test_suite=test_suite,
                        target=config['target'],
                        execution_mode='safe',
                        callback=test_callback
                    )
                    
                    # Wait for completion
                    timeout = 600  # 10 minutes
                    start_time = time.time()
                    while time.time() - start_time < timeout:
                        status = test_agent.get_test_status(execution_id)
                        if status.get('status') in ['completed', 'failed']:
                            break
                        time.sleep(5)
                    
                    # Get results and save
                    test_results = test_agent.get_test_results(execution_id)
                    if HAS_DATABASE and db_manager and 'test_results' in test_results:
                        db_manager.save_test_results(assessment_id, test_results['test_results'])
                
            except Exception as e:
                logger.error(f"Security testing failed for {assessment_id}: {e}")
        
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

# Template filters for Jinja2
@app.template_filter('moment')
def moment_filter(date_string):
    """Simple date formatting filter."""
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M')
    except:
        return date_string

if __name__ == '__main__':
    logger.info("Starting Flask Cybersecurity Automation System")
    
    if HAS_SOCKETIO and socketio:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    else:
        app.run(host='0.0.0.0', port=5000, debug=True)

@app.route('/')
def index():
    """Main dashboard homepage."""
    try:
        # Get recent assessments
        recent_assessments = db_manager.get_recent_assessments(limit=5)
        
        # Get system statistics
        stats = {
            'total_assessments': db_manager.get_total_assessments(),
            'active_assessments': len(active_assessments),
            'ollama_status': llm_client.is_available(),
            'tools_available': _check_tools_status()
        }
        
        return render_template('dashboard.html', 
                             recent_assessments=recent_assessments,
                             stats=stats)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('error.html', error=str(e))

@app.route('/api/start-assessment', methods=['POST'])
def start_assessment():
    """API endpoint to start a new security assessment."""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        scan_type = data.get('scan_type', 'standard')
        include_recon = data.get('include_recon', True)
        include_llm = data.get('include_llm', True)
        
        # Validate target
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Determine target type
        if is_valid_ip(target):
            target_type = 'ip'
            include_recon = False  # Skip recon for IP addresses
        elif is_valid_domain(target):
            target_type = 'domain'
        else:
            return jsonify({'error': 'Invalid target format'}), 400
        
        # Create assessment session
        session_id = str(uuid.uuid4())
        assessment_data = {
            'session_id': session_id,
            'target': target,
            'target_type': target_type,
            'scan_type': scan_type,
            'include_recon': include_recon,
            'include_llm': include_llm,
            'status': 'started',
            'created_at': datetime.now().isoformat()
        }
        
        # Store in database
        db_manager.create_assessment(assessment_data)
        
        # Add to active assessments
        active_assessments[session_id] = {
            'target': target,
            'status': 'starting',
            'progress': 0,
            'current_phase': 'initialization'
        }
        
        # Start assessment in background thread
        thread = threading.Thread(
            target=_run_assessment_async,
            args=(session_id, assessment_data)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'message': 'Assessment started successfully'
        })
        
    except Exception as e:
        logger.error(f"Start assessment error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/assessment/<session_id>')
def view_assessment(session_id):
    """View assessment details and progress."""
    try:
        assessment = db_manager.get_assessment(session_id)
        if not assessment:
            return render_template('error.html', error='Assessment not found')
        
        # Get assessment results
        results = {
            'recon': db_manager.get_recon_results(session_id),
            'scan': db_manager.get_scan_results(session_id),
            'tests': db_manager.get_test_results(session_id),
            'llm_tests': db_manager.get_llm_test_cases(session_id)
        }
        
        # Get current status
        status = active_assessments.get(session_id, {})
        
        return render_template('assessment_view.html',
                             assessment=assessment,
                             results=results,
                             status=status)
        
    except Exception as e:
        logger.error(f"View assessment error: {e}")
        return render_template('error.html', error=str(e))

@app.route('/api/assessment-status/<session_id>')
def assessment_status(session_id):
    """Get real-time assessment status."""
    try:
        status = active_assessments.get(session_id, {})
        assessment = db_manager.get_assessment(session_id)
        
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

@app.route('/api/llm-test-cases/<session_id>')
def get_llm_test_cases(session_id):
    """Get LLM-generated test cases for approval."""
    try:
        test_cases = db_manager.get_llm_test_cases(session_id)
        return jsonify({'test_cases': test_cases})
        
    except Exception as e:
        logger.error(f"LLM test cases error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/approve-llm-test', methods=['POST'])
def approve_llm_test():
    """Approve LLM-generated test case for execution."""
    try:
        data = request.get_json()
        test_id = data.get('test_id')
        approved = data.get('approved', False)
        
        if not test_id:
            return jsonify({'error': 'Test ID required'}), 400
        
        # Update approval status
        success = db_manager.update_llm_test_approval(test_id, approved)
        
        if success:
            return jsonify({'success': True, 'message': 'Test case updated'})
        else:
            return jsonify({'error': 'Failed to update test case'}), 500
            
    except Exception as e:
        logger.error(f"Approve test error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/execute-approved-tests/<session_id>', methods=['POST'])
def execute_approved_tests(session_id):
    """Execute approved LLM test cases."""
    try:
        # Get approved test cases
        approved_tests = db_manager.get_approved_llm_tests(session_id)
        
        if not approved_tests:
            return jsonify({'error': 'No approved test cases found'}), 400
        
        # Execute tests in background
        thread = threading.Thread(
            target=_execute_llm_tests_async,
            args=(session_id, approved_tests)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'message': f'Executing {len(approved_tests)} approved test cases'
        })
        
    except Exception as e:
        logger.error(f"Execute tests error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/reports')
def reports_list():
    """List all available reports."""
    try:
        assessments = db_manager.get_all_assessments()
        return render_template('reports.html', assessments=assessments)
        
    except Exception as e:
        logger.error(f"Reports list error: {e}")
        return render_template('error.html', error=str(e))

@app.route('/api/generate-report/<session_id>')
def generate_report(session_id):
    """Generate and download assessment report."""
    try:
        report_format = request.args.get('format', 'html')
        
        # Get assessment data
        assessment = db_manager.get_assessment(session_id)
        if not assessment:
            return jsonify({'error': 'Assessment not found'}), 404
        
        # Get all results
        report_data = {
            'assessment': assessment,
            'recon': db_manager.get_recon_results(session_id),
            'scan': db_manager.get_scan_results(session_id),
            'tests': db_manager.get_test_results(session_id),
            'llm_tests': db_manager.get_llm_test_cases(session_id)
        }
        
        # Generate report
        report_path = report_generator.generate_report(
            report_data, session_id, report_format
        )
        
        if report_path and os.path.exists(report_path):
            return send_file(
                report_path,
                as_attachment=True,
                download_name=f"cybersec_report_{session_id}.{report_format}"
            )
        else:
            return jsonify({'error': 'Failed to generate report'}), 500
            
    except Exception as e:
        logger.error(f"Generate report error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/settings')
def settings():
    """System settings and configuration page."""
    try:
        settings_data = {
            'ollama_status': llm_client.is_available(),
            'tools_status': _check_tools_status(),
            'database_stats': db_manager.get_database_stats(),
            'system_info': _get_system_info()
        }
        
        return render_template('settings.html', settings=settings_data)
        
    except Exception as e:
        logger.error(f"Settings error: {e}")
        return render_template('error.html', error=str(e))

@app.route('/api/test-ollama')
def test_ollama():
    """Test Ollama LLM connection."""
    try:
        if llm_client.is_available():
            # Test generation
            test_prompt = "Generate a simple security test case for port 80 HTTP service."
            response = llm_client.generate_test_cases(
                {'target': 'test.com', 'target_type': 'domain'},
                [{'port': 80, 'service': 'http', 'state': 'open'}]
            )
            
            return jsonify({
                'status': 'success',
                'message': 'Ollama is working correctly',
                'test_response': response[:200] if response else 'No response'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Ollama is not available or not responding'
            })
            
    except Exception as e:
        logger.error(f"Ollama test error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Ollama test failed: {str(e)}'
        })

# WebSocket events for real-time updates
@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    emit('status', {'message': 'Connected to security assessment system'})

@socketio.on('subscribe_assessment')
def handle_subscribe(data):
    """Subscribe to assessment updates."""
    session_id = data.get('session_id')
    if session_id:
        # Join room for this assessment
        from flask_socketio import join_room
        join_room(session_id)
        emit('subscribed', {'session_id': session_id})

# Helper functions
def _run_assessment_async(session_id, assessment_data):
    """Run assessment in background thread."""
    try:
        target = assessment_data['target']
        target_type = assessment_data['target_type']
        include_recon = assessment_data['include_recon']
        include_llm = assessment_data['include_llm']
        
        # Update status
        _update_assessment_status(session_id, 'running', 10, 'Starting assessment')
        
        recon_results = {}
        scan_results = {}
        
        # Phase 1: Reconnaissance (if domain)
        if include_recon and target_type == 'domain':
            _update_assessment_status(session_id, 'running', 20, 'Running reconnaissance')
            recon_results = recon_agent.perform_reconnaissance(target, session_id)
            db_manager.store_recon_results(session_id, recon_results)
        
        # Phase 2: Scanning
        _update_assessment_status(session_id, 'running', 50, 'Scanning ports and services')
        scan_results = scanning_agent.perform_scan(target, session_id, assessment_data['scan_type'])
        db_manager.store_scan_results(session_id, scan_results)
        
        # Phase 3: Predefined Tests
        _update_assessment_status(session_id, 'running', 70, 'Running security tests')
        test_results = test_agent.execute_predefined_tests(target, session_id, scan_results)
        db_manager.store_test_results(session_id, test_results)
        
        # Phase 4: LLM Test Generation (if enabled)
        if include_llm and llm_client.is_available():
            _update_assessment_status(session_id, 'running', 85, 'Generating LLM test cases')
            llm_tests = test_agent.generate_llm_tests(target, recon_results, scan_results)
            db_manager.store_llm_test_cases(session_id, llm_tests)
        
        # Complete assessment
        _update_assessment_status(session_id, 'completed', 100, 'Assessment completed')
        db_manager.update_assessment_status(session_id, 'completed')
        
        # Notify via WebSocket
        socketio.emit('assessment_complete', {
            'session_id': session_id,
            'message': 'Assessment completed successfully'
        }, room=session_id)
        
    except Exception as e:
        logger.error(f"Assessment error: {e}")
        _update_assessment_status(session_id, 'failed', 0, f'Assessment failed: {str(e)}')
        db_manager.update_assessment_status(session_id, 'failed')

def _execute_llm_tests_async(session_id, approved_tests):
    """Execute approved LLM tests in background."""
    try:
        for test in approved_tests:
            test_id = test['id']
            
            # Execute test
            result = test_agent.execute_llm_test(test)
            
            # Store result
            db_manager.update_llm_test_result(test_id, result)
            
            # Notify via WebSocket
            socketio.emit('llm_test_complete', {
                'session_id': session_id,
                'test_id': test_id,
                'result': result
            }, room=session_id)
            
    except Exception as e:
        logger.error(f"LLM test execution error: {e}")

def _update_assessment_status(session_id, status, progress, message):
    """Update assessment status and notify clients."""
    if session_id in active_assessments:
        active_assessments[session_id].update({
            'status': status,
            'progress': progress,
            'current_phase': message,
            'updated_at': datetime.now().isoformat()
        })
        
        # Emit WebSocket update
        socketio.emit('status_update', {
            'session_id': session_id,
            'status': status,
            'progress': progress,
            'message': message
        }, room=session_id)

def _check_tools_status():
    """Check availability of security tools."""
    tools = ['nmap', 'masscan', 'rustscan', 'amass', 'theharvester']
    status = {}
    
    for tool in tools:
        try:
            import shutil
            status[tool] = shutil.which(tool) is not None
        except:
            status[tool] = False
    
    return status

def _get_system_info():
    """Get system information."""
    import platform
    import psutil
    
    return {
        'platform': platform.system(),
        'python_version': platform.python_version(),
        'memory_total': f"{psutil.virtual_memory().total / (1024**3):.1f} GB",
        'memory_available': f"{psutil.virtual_memory().available / (1024**3):.1f} GB",
        'disk_free': f"{psutil.disk_usage('.').free / (1024**3):.1f} GB"
    }

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error='Internal server error'), 500

# Initialize database
with app.app_context():
    db_manager.init_database()

if __name__ == '__main__':
    # Development server
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
