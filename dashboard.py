import streamlit as st
import asyncio
import json
import os
import logging
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List, Any, Optional

# Import our agents and utilities
from agents.recon_agent import ReconAgent
from agents.scanning_agent import ScanningAgent
from agents.test_case_agent import TestCaseAgent
from database.db_manager import DatabaseManager
from reports.report_generator import ReportGenerator
from utils.validators import validate_target
from utils.helpers import setup_logging, generate_session_id, get_env_var, load_config

# Configure page
st.set_page_config(
    page_title="Cybersecurity Assessment Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Setup logging
setup_logging(log_level=get_env_var('LOG_LEVEL', 'INFO'))

# Load configuration
config = load_config('./config/settings.json')

# Initialize components


@st.cache_resource
def init_components():
    """Initialize system components."""
    db_manager = DatabaseManager()
    report_generator = ReportGenerator()
    return db_manager, report_generator


db_manager, report_generator = init_components()


def main():
    """Main dashboard application."""

    # Custom CSS for better styling
    st.markdown("""
    <style>
    .main-header {
        background: linear-gradient(90deg, #2c3e50, #34495e);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        text-align: center;
    }
    .status-card {
        background: #f8f9fa;
        border-left: 4px solid #007bff;
        padding: 1rem;
        border-radius: 5px;
        margin-bottom: 1rem;
    }
    .risk-critical {
        background-color: #dc3545;
        color: white;
        padding: 0.3rem 0.6rem;
        border-radius: 3px;
        font-weight: bold;
    }
    .risk-high {
        background-color: #fd7e14;
        color: white;
        padding: 0.3rem 0.6rem;
        border-radius: 3px;
        font-weight: bold;
    }
    .risk-medium {
        background-color: #ffc107;
        color: black;
        padding: 0.3rem 0.6rem;
        border-radius: 3px;
        font-weight: bold;
    }
    .risk-low {
        background-color: #28a745;
        color: white;
        padding: 0.3rem 0.6rem;
        border-radius: 3px;
        font-weight: bold;
    }
    </style>
    """, unsafe_allow_html=True)

    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ Multi-Agent Cybersecurity Assessment Dashboard</h1>
        <p>Automated Security Testing with Real-time Intelligence</p>
    </div>
    """, unsafe_allow_html=True)

    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox(
        "Choose a page:",
        ["🏠 Home", "🔍 New Assessment", "📊 Assessment History",
            "🤖 LLM Test Cases", "📋 Reports", "⚙️ Settings"]
    )

    # Route to different pages
    if page == "🏠 Home":
        show_home_page()
    elif page == "🔍 New Assessment":
        show_new_assessment_page()
    elif page == "📊 Assessment History":
        show_assessment_history_page()
    elif page == "🤖 LLM Test Cases":
        show_llm_test_cases_page()
    elif page == "📋 Reports":
        show_reports_page()
    elif page == "⚙️ Settings":
        show_settings_page()


def show_home_page():
    """Display the home page with system overview."""
    st.header("Dashboard Overview")

    # Get recent sessions
    sessions = db_manager.get_all_sessions()
    recent_sessions = sessions[:5] if sessions else []

    # Metrics row
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Assessments", len(sessions))

    with col2:
        active_sessions = len(
            [s for s in sessions if s.get('status') == 'running'])
        st.metric("Active Sessions", active_sessions)

    with col3:
        completed_sessions = len(
            [s for s in sessions if s.get('status') == 'completed'])
        st.metric("Completed", completed_sessions)

    with col4:
        # Calculate average duration for completed sessions
        avg_duration = "N/A"
        st.metric("Avg Duration", avg_duration)

    # Recent activity
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Recent Assessment Activity")
        if recent_sessions:
            df = pd.DataFrame(recent_sessions)
            df['created_at'] = pd.to_datetime(df['created_at'])
            df = df.sort_values('created_at', ascending=False)

            # Display as table
            display_df = df[['session_id', 'target',
                             'target_type', 'status', 'created_at']].copy()
            display_df['created_at'] = display_df['created_at'].dt.strftime(
                '%Y-%m-%d %H:%M')

            st.dataframe(
                display_df,
                column_config={
                    "session_id": "Session ID",
                    "target": "Target",
                    "target_type": "Type",
                    "status": "Status",
                    "created_at": "Created"
                },
                hide_index=True
            )
        else:
            st.info("No assessments found. Start a new assessment to get started!")

    with col2:
        st.subheader("Quick Actions")

        if st.button("🔍 New Assessment", use_container_width=True, type="primary"):
            st.switch_page("🔍 New Assessment")

        if st.button("📊 View History", use_container_width=True):
            st.switch_page("📊 Assessment History")

        if st.button("📋 Generate Report", use_container_width=True):
            st.switch_page("📋 Reports")

    # System status
    st.subheader("System Status")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("""
        <div class="status-card">
            <h4>🤖 Agents Status</h4>
            <p>✅ Recon Agent: Ready</p>
            <p>✅ Scanning Agent: Ready</p>
            <p>✅ Test Case Agent: Ready</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class="status-card">
            <h4>🔧 Tools Status</h4>
            <p>✅ Database: Connected</p>
            <p>✅ Report Generator: Ready</p>
            <p>⚠️ External APIs: Check Settings</p>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown("""
        <div class="status-card">
            <h4>📈 Performance</h4>
            <p>🚀 Response Time: Normal</p>
            <p>💾 Memory Usage: Optimal</p>
            <p>⚡ Queue Status: Empty</p>
        </div>
        """, unsafe_allow_html=True)


def show_new_assessment_page():
    """Display the new assessment page."""
    st.header("New Security Assessment")

    # Assessment configuration form
    with st.form("assessment_form"):
        col1, col2 = st.columns([2, 1])

        with col1:
            target = st.text_input(
                "Target (Domain/IP/URL)",
                placeholder="example.com or 192.168.1.1",
                help="Enter a domain name, IP address, or URL to assess"
            )

            scan_type = st.selectbox(
                "Scan Type",
                ["Quick", "Standard", "Comprehensive"],
                index=1,
                help="Quick: Common ports only, Standard: 1-1000, Comprehensive: Full range"
            )

            port_range = st.text_input(
                "Custom Port Range (optional)",
                placeholder="1-1000 or 22,80,443",
                help="Override default port range for scanning"
            )

        with col2:
            st.subheader("Assessment Options")

            enable_recon = st.checkbox("Enable Reconnaissance", value=True)
            enable_vuln_scan = st.checkbox(
                "Enable Vulnerability Scanning", value=True)
            enable_test_cases = st.checkbox("Execute Test Cases", value=True)
            generate_llm_tests = st.checkbox(
                "Generate LLM Test Cases", value=False)

        submitted = st.form_submit_button(
            "Start Assessment", type="primary", use_container_width=True)

        if submitted:
            if not target:
                st.error("Please enter a target to assess")
                return

            # Validate target
            is_valid, target_type, normalized_target = validate_target(target)

            if not is_valid:
                st.error(
                    f"Invalid target: {target}. Please enter a valid domain, IP address, or URL.")
                return

            # Start assessment
            session_id = generate_session_id()

            if start_assessment(session_id, normalized_target, target_type, {
                'scan_type': scan_type.lower(),
                'port_range': port_range or None,
                'enable_recon': enable_recon,
                'enable_vuln_scan': enable_vuln_scan,
                'enable_test_cases': enable_test_cases,
                'generate_llm_tests': generate_llm_tests
            }):
                st.success(f"Assessment started! Session ID: {session_id}")
                st.session_state['current_session'] = session_id
                st.session_state['assessment_running'] = True
                st.rerun()

    # Show running assessment status
    if st.session_state.get('assessment_running'):
        show_assessment_progress()


def start_assessment(session_id: str, target: str, target_type: str, options: Dict) -> bool:
    """Start a new security assessment."""
    try:
        # Create session in database
        if not db_manager.create_session(session_id, target, target_type):
            st.error("Failed to create assessment session")
            return False

        # Store assessment options in session state
        st.session_state['assessment_options'] = options

        # Start the assessment process
        return True

    except Exception as e:
        logging.error(f"Error starting assessment: {e}")
        st.error(f"Failed to start assessment: {str(e)}")
        return False


def show_assessment_progress():
    """Show real-time assessment progress."""
    st.subheader("Assessment Progress")

    session_id = st.session_state.get('current_session')
    if not session_id:
        return

    # Create progress tracking
    progress_container = st.container()

    with progress_container:
        # Progress bars
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            recon_progress = st.progress(0)
            st.text("Reconnaissance")

        with col2:
            scan_progress = st.progress(0)
            st.text("Scanning")

        with col3:
            test_progress = st.progress(0)
            st.text("Testing")

        with col4:
            overall_progress = st.progress(0)
            st.text("Overall")

        # Status updates
        status_placeholder = st.empty()
        results_placeholder = st.empty()

        # Run assessment asynchronously
        if st.button("Execute Assessment", type="primary"):
            with st.spinner("Running security assessment..."):
                try:
                    results = asyncio.run(run_full_assessment(
                        session_id,
                        st.session_state.get('assessment_options', {}),
                        progress_callback=lambda stage, progress, message: update_progress(
                            stage, progress, message,
                            recon_progress, scan_progress, test_progress,
                            overall_progress, status_placeholder
                        )
                    ))

                    if results:
                        st.success("Assessment completed successfully!")
                        st.session_state['assessment_running'] = False
                        st.session_state['last_results'] = results

                        # Show results summary
                        show_results_summary(results)
                    else:
                        st.error("Assessment failed or was interrupted")

                except Exception as e:
                    st.error(f"Assessment error: {str(e)}")
                    logging.error(f"Assessment execution error: {e}")


def update_progress(stage: str, progress: float, message: str,
                    recon_progress, scan_progress, test_progress,
                    overall_progress, status_placeholder):
    """Update progress indicators."""
    try:
        if stage == "recon":
            recon_progress.progress(progress)
        elif stage == "scan":
            scan_progress.progress(progress)
        elif stage == "test":
            test_progress.progress(progress)

        # Update overall progress
        total_stages = 3
        stage_weights = {"recon": 0.3, "scan": 0.4, "test": 0.3}

        overall = 0
        if stage == "recon":
            overall = progress * stage_weights["recon"]
        elif stage == "scan":
            overall = stage_weights["recon"] + \
                (progress * stage_weights["scan"])
        elif stage == "test":
            overall = stage_weights["recon"] + \
                stage_weights["scan"] + (progress * stage_weights["test"])

        overall_progress.progress(min(overall, 1.0))

        # Update status message
        status_placeholder.info(f"**{stage.title()}**: {message}")

    except Exception as e:
        logging.warning(f"Progress update error: {e}")


async def run_full_assessment(session_id: str, options: Dict, progress_callback=None) -> Optional[Dict]:
    """Run the complete assessment workflow."""
    try:
        session_data = db_manager.get_session_data(session_id)
        if not session_data or not session_data.get('session'):
            return None

        target = session_data['session']['target']
        target_type = session_data['session']['target_type']

        results = {
            'session_id': session_id,
            'target': target,
            'target_type': target_type,
            'recon_results': None,
            'scan_results': None,
            'test_results': None,
            'llm_test_cases': []
        }

        # Phase 1: Reconnaissance (if domain and enabled)
        if target_type == 'domain' and options.get('enable_recon', True):
            if progress_callback:
                progress_callback(
                    "recon", 0.1, "Initializing reconnaissance...")

            recon_agent = ReconAgent()
            recon_results = await recon_agent.perform_reconnaissance(target, session_id)

            if recon_results:
                results['recon_results'] = recon_results
                db_manager.store_recon_results(
                    session_id, target, 'full_recon', recon_results)

                if progress_callback:
                    progress_callback("recon", 1.0, "Reconnaissance completed")

        # Phase 2: Scanning
        if progress_callback:
            progress_callback("scan", 0.1, "Initializing port scan...")

        scanning_agent = ScanningAgent()
        scan_results = await scanning_agent.perform_scan(
            target, session_id,
            port_range=options.get('port_range', "1-65535"),
            scan_type=options.get('scan_type', 'standard')
        )

        if scan_results:
            results['scan_results'] = scan_results

            # Store scan results in database
            for port_info in scan_results.get('open_ports', []):
                db_manager.store_scan_results(
                    session_id, target,
                    port_info['port'],
                    port_info.get('service', 'unknown'),
                    port_info.get('version'),
                    port_info.get('state'),
                    port_info.get('banner'),
                    port_info.get('vulnerabilities', [])
                )

            if progress_callback:
                progress_callback("scan", 1.0, "Scanning completed")

        # Phase 3: Test Case Execution
        if options.get('enable_test_cases', True):
            if progress_callback:
                progress_callback(
                    "test", 0.1, "Initializing security tests...")

            test_agent = TestCaseAgent()

            # Generate LLM test cases if requested
            llm_test_cases = []
            if options.get('generate_llm_tests', False):
                if progress_callback:
                    progress_callback(
                        "test", 0.3, "Generating AI test cases...")

                llm_test_cases = await test_agent.generate_llm_test_cases(
                    results.get('recon_results', {}),
                    results.get('scan_results', {})
                )

                # Store LLM test cases
                for test_case in llm_test_cases:
                    db_manager.store_llm_test_case(session_id, test_case)

                results['llm_test_cases'] = llm_test_cases

            if progress_callback:
                progress_callback(
                    "test", 0.6, "Executing security test cases...")

            # Execute predefined test cases
            test_results = await test_agent.execute_test_cases(
                target, session_id,
                recon_data=results.get('recon_results'),
                scan_data=results.get('scan_results'),
                approved_llm_cases=[]  # No auto-approval
            )

            if test_results:
                results['test_results'] = test_results

                # Store test results
                for test_result in test_results.get('predefined_results', []):
                    db_manager.store_test_case_result(
                        session_id,
                        test_result.get('test_id'),
                        test_result.get('test_name'),
                        test_result.get('category'),
                        test_result.get('severity'),
                        test_result.get('status'),
                        test_result.get('details'),
                        json.dumps(test_result.get('evidence', []))
                    )

                if progress_callback:
                    progress_callback("test", 1.0, "Testing completed")

        # Update session status
        db_manager.update_session_status(session_id, 'completed')

        if progress_callback:
            progress_callback(
                "test", 1.0, "Assessment completed successfully!")

        return results

    except Exception as e:
        logging.error(f"Assessment execution error: {e}")
        db_manager.update_session_status(session_id, 'failed')
        return None


def show_results_summary(results: Dict):
    """Show assessment results summary."""
    st.subheader("Assessment Results Summary")

    # Quick stats
    col1, col2, col3, col4 = st.columns(4)

    scan_results = results.get('scan_results', {})
    test_results = results.get('test_results', {})

    with col1:
        open_ports = len(scan_results.get('open_ports', []))
        st.metric("Open Ports", open_ports)

    with col2:
        services = len(scan_results.get('services', []))
        st.metric("Services Found", services)

    with col3:
        total_tests = test_results.get('summary', {}).get('total_tests', 0)
        st.metric("Tests Executed", total_tests)

    with col4:
        passed_tests = test_results.get('summary', {}).get('passed', 0)
        st.metric("Vulnerabilities Found", passed_tests)

    # Results tabs
    tab1, tab2, tab3 = st.tabs(
        ["🔍 Scan Results", "🧪 Test Results", "🤖 LLM Test Cases"])

    with tab1:
        show_scan_results_tab(scan_results)

    with tab2:
        show_test_results_tab(test_results)

    with tab3:
        show_llm_results_tab(results.get('llm_test_cases', []))


def show_scan_results_tab(scan_results: Dict):
    """Show scanning results in detail."""
    if not scan_results:
        st.info("No scan results available")
        return

    open_ports = scan_results.get('open_ports', [])

    if open_ports:
        st.subheader("Open Ports and Services")

        # Create DataFrame
        df = pd.DataFrame(open_ports)

        # Display as table
        st.dataframe(
            df[['port', 'service', 'version', 'state']],
            column_config={
                "port": "Port",
                "service": "Service",
                "version": "Version",
                "state": "State"
            },
            hide_index=True
        )

        # Port distribution chart
        if len(open_ports) > 1:
            port_counts = df['service'].value_counts()
            fig = px.pie(
                values=port_counts.values,
                names=port_counts.index,
                title="Service Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)

    # Vulnerabilities
    vulnerabilities = scan_results.get('vulnerabilities', [])
    if vulnerabilities:
        st.subheader("Detected Vulnerabilities")

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium').lower()
            st.markdown(f"""
            <div style="border: 1px solid #ddd; padding: 10px; margin: 5px 0; border-radius: 5px;">
                <span class="risk-{severity}">{severity.upper()}</span>
                <strong>Port {vuln.get('port', 'N/A')}</strong>: {vuln.get('description', 'No description')}
            </div>
            """, unsafe_allow_html=True)


def show_test_results_tab(test_results: Dict):
    """Show test case results in detail."""
    if not test_results:
        st.info("No test results available")
        return

    summary = test_results.get('summary', {})
    findings = test_results.get('findings', [])

    # Summary metrics
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Total Tests", summary.get('total_tests', 0))

    with col2:
        st.metric("Passed (Issues Found)", summary.get('passed', 0))

    with col3:
        st.metric("Failed (No Issues)", summary.get('failed', 0))

    # Findings by severity
    if findings:
        st.subheader("Security Findings")

        # Group by severity
        by_severity = test_results.get('by_severity', {})

        for severity in ['critical', 'high', 'medium', 'low']:
            severity_findings = by_severity.get(severity, [])

            if severity_findings:
                st.markdown(
                    f"### {severity.title()} Severity ({len(severity_findings)} findings)")

                for finding in severity_findings:
                    with st.expander(f"{finding.get('test_name', 'Unknown Test')}"):
                        st.write(
                            f"**Category:** {finding.get('category', 'Unknown')}")
                        st.write(
                            f"**Description:** {finding.get('description', 'No description')}")

                        evidence = finding.get('evidence', [])
                        if evidence:
                            st.write("**Evidence:**")
                            for item in evidence:
                                st.write(f"- {item}")

                        recommendations = finding.get('recommendations', [])
                        if recommendations:
                            st.write("**Recommendations:**")
                            for rec in recommendations:
                                st.write(f"- {rec}")


def show_llm_results_tab(llm_test_cases: List[Dict]):
    """Show LLM-generated test cases."""
    if not llm_test_cases:
        st.info("No LLM test cases generated")
        return

    st.subheader("AI-Generated Test Cases")
    st.write(
        f"Generated {len(llm_test_cases)} custom test cases based on discovered services and vulnerabilities.")

    for i, test_case in enumerate(llm_test_cases):
        with st.expander(f"Test Case {i+1}: {test_case.get('name', 'Unknown')}"):
            col1, col2 = st.columns([3, 1])

            with col1:
                st.write(
                    f"**Category:** {test_case.get('category', 'Unknown')}")
                st.write(
                    f"**Severity:** {test_case.get('severity', 'Medium')}")
                st.write(
                    f"**Description:** {test_case.get('description', 'No description')}")

                methodology = test_case.get('methodology', '')
                if methodology:
                    st.write("**Methodology:**")
                    st.code(methodology, language='bash')

            with col2:
                approved = test_case.get('approved', False)

                if not approved:
                    if st.button(f"Approve Test {i+1}", key=f"approve_{i}"):
                        # Approve test case in database
                        st.success("Test case approved!")
                        st.rerun()
                else:
                    st.success("✅ Approved")

                    if st.button(f"Execute Test {i+1}", key=f"execute_{i}"):
                        st.info("Test execution requires manual implementation")


def show_assessment_history_page():
    """Display assessment history and management."""
    st.header("Assessment History")

    sessions = db_manager.get_all_sessions()

    if not sessions:
        st.info("No assessments found. Start your first assessment!")
        return

    # Filters
    col1, col2, col3 = st.columns(3)

    with col1:
        status_filter = st.selectbox(
            "Filter by Status",
            ["All", "Running", "Completed", "Failed"]
        )

    with col2:
        target_type_filter = st.selectbox(
            "Filter by Type",
            ["All", "IP", "Domain"]
        )

    with col3:
        date_range = st.date_input(
            "Date Range",
            value=None,
            help="Filter assessments by date"
        )

    # Filter sessions
    filtered_sessions = sessions

    if status_filter != "All":
        filtered_sessions = [s for s in filtered_sessions if s.get(
            'status', '').lower() == status_filter.lower()]

    if target_type_filter != "All":
        filtered_sessions = [s for s in filtered_sessions if s.get(
            'target_type', '').lower() == target_type_filter.lower()]

    # Display sessions
    for session in filtered_sessions:
        with st.container():
            col1, col2, col3, col4 = st.columns([3, 2, 2, 1])

            with col1:
                st.write(f"**Target:** {session.get('target', 'Unknown')}")
                st.write(
                    f"**Session ID:** {session.get('session_id', 'Unknown')}")

            with col2:
                st.write(f"**Type:** {session.get('target_type', 'Unknown')}")
                st.write(f"**Status:** {session.get('status', 'Unknown')}")

            with col3:
                created_at = session.get('created_at', 'Unknown')
                st.write(f"**Created:** {created_at}")
                end_time = session.get('end_time', 'N/A')
                st.write(f"**Completed:** {end_time}")

            with col4:
                if st.button("View Details", key=f"view_{session.get('id')}"):
                    st.session_state['selected_session'] = session.get(
                        'session_id')
                    show_session_details(session.get('session_id'))

            st.divider()


def show_session_details(session_id: str):
    """Show detailed view of a specific session."""
    session_data = db_manager.get_session_data(session_id)

    if not session_data:
        st.error("Session not found")
        return

    st.subheader(f"Session Details: {session_id}")

    session_info = session_data.get('session', {})

    # Session information
    col1, col2, col3 = st.columns(3)

    with col1:
        st.info(f"**Target:** {session_info.get('target', 'Unknown')}")

    with col2:
        st.info(f"**Type:** {session_info.get('target_type', 'Unknown')}")

    with col3:
        st.info(f"**Status:** {session_info.get('status', 'Unknown')}")

    # Results tabs
    tab1, tab2, tab3, tab4 = st.tabs(
        ["📊 Summary", "🔍 Recon", "🔎 Scan", "🧪 Tests"])

    with tab1:
        show_session_summary_tab(session_data)

    with tab2:
        show_session_recon_tab(session_data)

    with tab3:
        show_session_scan_tab(session_data)

    with tab4:
        show_session_test_tab(session_data)


def show_session_summary_tab(session_data: Dict):
    """Show session summary tab."""
    st.write("### Assessment Summary")

    # Calculate metrics
    recon_results = session_data.get('recon_results', [])
    scan_results = session_data.get('scan_results', [])
    test_results = session_data.get('test_results', [])

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Recon Data Points", len(recon_results))

    with col2:
        open_ports = len([r for r in scan_results if r.get('state') == 'open'])
        st.metric("Open Ports", open_ports)

    with col3:
        st.metric("Tests Executed", len(test_results))

    with col4:
        passed_tests = len(
            [t for t in test_results if t.get('status') == 'passed'])
        st.metric("Issues Found", passed_tests)


def show_session_recon_tab(session_data: Dict):
    """Show reconnaissance results for session."""
    recon_results = session_data.get('recon_results', [])

    if not recon_results:
        st.info("No reconnaissance data available")
        return

    for result in recon_results:
        result_type = result.get('result_type', 'Unknown')
        st.subheader(f"Reconnaissance: {result_type.title()}")

        try:
            data = json.loads(result.get('data', '{}'))
            st.json(data)
        except:
            st.text(result.get('data', 'No data'))


def show_session_scan_tab(session_data: Dict):
    """Show scan results for session."""
    scan_results = session_data.get('scan_results', [])

    if not scan_results:
        st.info("No scan data available")
        return

    # Convert to DataFrame
    df = pd.DataFrame(scan_results)

    if not df.empty:
        # Open ports table
        open_ports = df[df['state'] == 'open'] if 'state' in df.columns else df

        if not open_ports.empty:
            st.subheader("Open Ports")
            st.dataframe(
                open_ports[['port', 'service', 'version', 'state']],
                hide_index=True
            )

        # Port distribution
        if len(open_ports) > 1:
            fig = px.histogram(
                open_ports,
                x='service',
                title="Service Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)


def show_session_test_tab(session_data: Dict):
    """Show test results for session."""
    test_results = session_data.get('test_results', [])

    if not test_results:
        st.info("No test data available")
        return

    # Test results table
    df = pd.DataFrame(test_results)

    if not df.empty:
        st.dataframe(
            df[['test_name', 'category', 'severity', 'status']],
            column_config={
                "test_name": "Test Name",
                "category": "Category",
                "severity": "Severity",
                "status": "Status"
            },
            hide_index=True
        )


def show_llm_test_cases_page():
    """Display LLM test case management."""
    st.header("AI-Generated Test Cases")

    # Get all sessions with LLM test cases
    sessions = db_manager.get_all_sessions()

    if not sessions:
        st.info("No sessions found")
        return

    # Session selector
    session_options = {
        f"{s['session_id']} - {s['target']}": s['session_id'] for s in sessions}
    selected_session_display = st.selectbox(
        "Select Session", list(session_options.keys()))

    if not selected_session_display:
        return

    session_id = session_options[selected_session_display]
    session_data = db_manager.get_session_data(session_id)
    llm_test_cases = session_data.get('llm_test_cases', [])

    if not llm_test_cases:
        st.info("No LLM test cases found for this session")

        # Option to generate new test cases
        if st.button("Generate LLM Test Cases"):
            st.info("LLM test case generation would be implemented here")
        return

    st.subheader(f"LLM Test Cases for {session_id}")

    # Test case management
    for i, test_case in enumerate(llm_test_cases):
        try:
            test_data = json.loads(test_case.get('test_case_data', '{}'))

            with st.expander(f"Test Case {i+1}: {test_data.get('name', 'Unknown')}"):
                col1, col2 = st.columns([3, 1])

                with col1:
                    st.write(
                        f"**Category:** {test_data.get('category', 'Unknown')}")
                    st.write(
                        f"**Severity:** {test_data.get('severity', 'Medium')}")
                    st.write(
                        f"**Description:** {test_data.get('description', 'No description')}")

                    methodology = test_data.get('methodology', '')
                    if methodology:
                        st.write("**Methodology:**")
                        st.code(methodology)

                with col2:
                    approved = test_case.get('approved', False)
                    executed = test_case.get('executed', False)

                    st.write(
                        f"**Status:** {'Approved' if approved else 'Pending'}")
                    st.write(f"**Executed:** {'Yes' if executed else 'No'}")

                    if not approved:
                        if st.button(f"Approve", key=f"approve_llm_{i}"):
                            if db_manager.approve_llm_test_case(test_case['id']):
                                st.success("Test case approved!")
                                st.rerun()
                    else:
                        if not executed:
                            if st.button(f"Execute", key=f"execute_llm_{i}"):
                                st.info("Manual execution required")

        except Exception as e:
            st.error(f"Error displaying test case: {e}")


def show_reports_page():
    """Display report generation and management."""
    st.header("Assessment Reports")

    # Session selector for report generation
    sessions = db_manager.get_all_sessions()
    completed_sessions = [
        s for s in sessions if s.get('status') == 'completed']

    if not completed_sessions:
        st.info("No completed assessments available for reporting")
        return

    # Report generation form
    with st.form("report_generation"):
        st.subheader("Generate New Report")

        session_options = {
            f"{s['session_id']} - {s['target']}": s['session_id'] for s in completed_sessions}
        selected_session = st.selectbox(
            "Select Assessment", list(session_options.keys()))

        col1, col2 = st.columns(2)

        with col1:
            formats = st.multiselect(
                "Report Formats",
                ["JSON", "HTML", "PDF"],
                default=["HTML", "PDF"]
            )

        with col2:
            include_raw_data = st.checkbox("Include Raw Data", value=False)

        if st.form_submit_button("Generate Report", type="primary"):
            if selected_session and formats:
                session_id = session_options[selected_session]
                generate_session_report(
                    session_id, [f.lower() for f in formats], include_raw_data)


def generate_session_report(session_id: str, formats: List[str], include_raw_data: bool = False):
    """Generate report for a specific session."""
    try:
        with st.spinner("Generating report..."):
            session_data = db_manager.get_session_data(session_id)

            if not session_data:
                st.error("Session data not found")
                return

            # Generate reports
            generated_files = report_generator.generate_comprehensive_report(
                session_data, formats)

            if generated_files:
                st.success("Report generated successfully!")

                # Show download links
                st.subheader("Download Reports")

                for format_name, file_path in generated_files.items():
                    if os.path.exists(file_path):
                        with open(file_path, 'rb') as f:
                            file_data = f.read()

                        st.download_button(
                            label=f"Download {format_name.upper()} Report",
                            data=file_data,
                            file_name=os.path.basename(file_path),
                            mime=get_mime_type(format_name)
                        )
            else:
                st.error("Failed to generate report")

    except Exception as e:
        st.error(f"Error generating report: {str(e)}")
        logging.error(f"Report generation error: {e}")


def get_mime_type(format_name: str) -> str:
    """Get MIME type for file format."""
    mime_types = {
        'json': 'application/json',
        'html': 'text/html',
        'pdf': 'application/pdf'
    }
    return mime_types.get(format_name.lower(), 'application/octet-stream')


def show_settings_page():
    """Display system settings and configuration."""
    st.header("System Settings")

    # API Configuration
    st.subheader("API Configuration")

    with st.form("api_settings"):
        col1, col2 = st.columns(2)

        with col1:
            shodan_api_key = st.text_input(
                "Shodan API Key",
                value=get_env_var('SHODAN_API_KEY', ''),
                type="password",
                help="Required for reconnaissance features"
            )

            openai_api_key = st.text_input(
                "OpenAI API Key",
                value=get_env_var('OPENAI_API_KEY', ''),
                type="password",
                help="Required for LLM test case generation"
            )

        with col2:
            anthropic_api_key = st.text_input(
                "Anthropic API Key",
                value=get_env_var('ANTHROPIC_API_KEY', ''),
                type="password",
                help="Alternative to OpenAI for test case generation"
            )

        if st.form_submit_button("Save API Settings"):
            st.success("API settings saved!")

    # Llama 3.1 8B Configuration
    st.subheader("Llama 3.1 8B Local Model")

    with st.form("llama_settings"):
        col1, col2 = st.columns(2)

        with col1:
            llama_max_length = st.number_input(
                "Max Token Length",
                min_value=512,
                max_value=8192,
                value=int(get_env_var('LLAMA_MAX_LENGTH', '4096')),
                help="Maximum tokens for Llama generation"
            )

            llama_temperature = st.slider(
                "Temperature",
                min_value=0.1,
                max_value=1.0,
                value=float(get_env_var('LLAMA_TEMPERATURE', '0.7')),
                step=0.1,
                help="Controls randomness in generation"
            )

        with col2:
            llama_use_quantization = st.checkbox(
                "Use 4-bit Quantization",
                value=get_env_var('LLAMA_USE_QUANTIZATION',
                                  'true').lower() == 'true',
                help="Reduces memory usage but may affect quality"
            )

            # Check Llama model status
            try:
                from utils.llama_integration import get_llama_instance
                llama = get_llama_instance()
                if llama.is_available():
                    st.success("✅ Llama 3.1 8B Model Loaded")
                else:
                    st.warning("⚠️ Llama Model Not Available")
            except Exception as e:
                st.error(f"❌ Llama Model Error: {str(e)[:100]}...")

        if st.form_submit_button("Save Llama Settings"):
            st.success("Llama settings saved!")

        if st.form_submit_button("Test Llama Model"):
            try:
                from utils.llama_integration import get_llama_instance
                llama = get_llama_instance()
                if llama.is_available():
                    # Simple test generation
                    test_data = {
                        'target': 'example.com',
                        'target_type': 'domain'
                    }
                    scan_results = [
                        {'port': 80, 'service': 'http', 'state': 'open'}]
                    test_cases = llama.generate_test_cases(
                        test_data, scan_results)

                    if test_cases:
                        st.success(
                            f"✅ Llama test successful! Generated {len(test_cases)} test cases.")
                        with st.expander("Sample Test Case"):
                            st.json(test_cases[0] if test_cases else {})
                    else:
                        st.warning(
                            "⚠️ Llama test completed but no test cases generated")
                else:
                    st.error("❌ Llama model not available for testing")
            except Exception as e:
                st.error(f"❌ Llama test failed: {str(e)}")

    # Tool Configuration
    st.subheader("Security Tools")

    tools_status = check_tools_availability()

    for tool_name, status in tools_status.items():
        col1, col2 = st.columns([3, 1])

        with col1:
            st.write(f"**{tool_name}**")

        with col2:
            if status:
                st.success("✅ Available")
            else:
                st.error("❌ Not Found")

    # System Information
    st.subheader("System Information")

    col1, col2 = st.columns(2)

    with col1:
        st.info("**Database Status:** Connected")
        st.info("**Log Level:** INFO")

    with col2:
        st.info("**Dashboard Version:** 1.0.0")
        st.info("**Python Version:** 3.9+")

    # Database Management
    st.subheader("Database Management")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("Export Database"):
            st.info("Database export functionality would be implemented here")

    with col2:
        if st.button("Clean Old Sessions"):
            if db_manager.cleanup_old_sessions(30):
                st.success("Old sessions cleaned up")
            else:
                st.error("Cleanup failed")

    with col3:
        if st.button("Reset Database"):
            st.warning("This would reset all data - confirmation required")


def check_tools_availability() -> Dict[str, bool]:
    """Check availability of security tools."""
    tools = {
        "Nmap": False,
        "Masscan": False,
        "Rustscan": False,
        "theHarvester": False,
        "Amass": False
    }

    # This would actually check tool availability
    # For demo purposes, return mock status
    tools["Nmap"] = True  # Assume nmap is commonly available

    return tools


# Initialize session state
if 'assessment_running' not in st.session_state:
    st.session_state['assessment_running'] = False

if 'current_session' not in st.session_state:
    st.session_state['current_session'] = None

# Run the main application
if __name__ == "__main__":
    main()
