# Flask Cybersecurity Automation System

## 🛡️ Overview

A comprehensive, modular Flask-based cybersecurity automation platform featuring multiple specialized agents for reconnaissance, scanning, and vulnerability testing. The system provides a unified web dashboard for managing security assessments with real-time progress tracking and comprehensive reporting.

## 🌟 Key Features

### ✅ **Completed Features**
- **Flask Web Dashboard**: Modern, responsive interface built with Bootstrap 5
- **Multi-Agent Architecture**: Modular design with specialized agents for different security tasks
- **Real-Time Updates**: WebSocket support via Flask-SocketIO for live progress tracking
- **Database Integration**: SQLAlchemy-based data persistence with SQLite backend
- **Report Generation**: PDF, JSON, and CSV export capabilities
- **Local LLM Integration**: Privacy-first Ollama/LLaMA integration for AI-generated test cases
- **RESTful API**: Complete API endpoints for programmatic access
- **Error Handling**: Comprehensive error handling and logging
- **Responsive Design**: Mobile-friendly interface with intuitive navigation

### 🎯 **Core Agents**

#### 1. **Reconnaissance Agent** (`FlaskReconAgent`)
- Domain reconnaissance using multiple OSINT tools
- Shodan API integration for passive intelligence gathering
- DNS enumeration and subdomain discovery
- SSL/TLS certificate analysis
- WHOIS information extraction

#### 2. **Scanning Agent** (`FlaskScanningAgent`)
- Multi-tool port scanning (Nmap, Masscan, RustScan)
- Service detection and version identification
- Customizable port ranges and scan intensities
- Parallel scanning capabilities

#### 3. **Test Agent** (`FlaskTestAgent`)
- Predefined security test suites
- AI-generated test cases via local LLaMA models
- User approval workflow for AI-generated tests
- Safe execution environment with timeout controls

## 🏗️ Architecture

```
flask_app.py                 # Main Flask application
├── agents/                  # Modular agent implementations
│   ├── flask_recon_agent.py     # Reconnaissance operations
│   ├── flask_scanning_agent.py  # Port scanning and service detection
│   └── flask_test_agent.py      # Vulnerability testing
├── database/                # Data persistence layer
│   └── flask_db_manager.py      # SQLAlchemy models and operations
├── reports/                 # Report generation
│   └── flask_report_generator.py # PDF/JSON/CSV report creation
├── utils/                   # Utility functions
│   ├── flask_helpers.py         # Common utilities and validation
│   └── ollama_integration.py    # Local LLM integration
├── templates/               # Jinja2 HTML templates
│   ├── base.html               # Base template with Bootstrap
│   ├── dashboard.html          # Main dashboard
│   ├── new_assessment.html     # Assessment creation form
│   ├── assessment_detail.html  # Detailed assessment view
│   ├── assessments.html        # Assessment listing
│   ├── reports.html            # Reports and exports
│   ├── settings.html           # System configuration
│   └── error.html              # Error page
└── logs/                    # Application logs
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip package manager
- (Optional) Security tools: nmap, masscan, rustscan
- (Optional) Ollama for local LLM capabilities

### Installation
1. **Clone or download the project**
   ```bash
   cd "Offensive AI agent"
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize the system**
   ```bash
   python setup_and_test.py check
   ```

4. **Start the Flask server**
   ```bash
   python flask_app.py
   ```

5. **Access the web interface**
   - Open http://localhost:5000 in your browser
   - Create and manage security assessments through the dashboard

### Testing the System
Run the comprehensive test suite:
```bash
python test_flask_system.py
```

## 🖥️ Web Interface

### Dashboard
- **System Overview**: Real-time statistics and status indicators
- **Recent Assessments**: Quick access to latest security assessments
- **System Health**: Component status and tool availability
- **Quick Actions**: Start new assessments or access reports

### Assessment Workflow
1. **Create Assessment**: Configure target, scan type, and options
2. **Real-time Monitoring**: Track progress through reconnaissance, scanning, and testing phases
3. **Results Analysis**: View detailed findings organized by category
4. **Report Generation**: Export results in PDF, JSON, or CSV formats

### Key Pages
- `/`: Main dashboard with overview and statistics
- `/new-assessment`: Assessment configuration and creation
- `/assessments`: List of all assessments with status tracking
- `/assessment/<id>`: Detailed view of specific assessment
- `/reports`: Report management and bulk export functionality
- `/settings`: System configuration and tool management

## 🔧 API Endpoints

### Assessment Management
- `POST /api/assessments`: Start new security assessment
- `GET /api/assessment/<id>/status`: Get real-time assessment status
- `POST /api/assessments/bulk`: Start multiple assessments

### System Information
- `GET /api/system/status`: Overall system health and component status
- `GET /api/tools/status`: Security tool availability

### Reports and Downloads
- `GET /download/report/<id>/<format>`: Download assessment report
- `POST /api/reports/bulk-download`: Bulk report export

## 📊 Database Schema

The system uses SQLAlchemy with SQLite for data persistence:

- **Assessments**: Main assessment records with metadata
- **Recon Results**: OSINT and reconnaissance findings
- **Scan Results**: Port scanning and service detection data
- **Test Results**: Vulnerability testing outcomes
- **System Logs**: Audit trail and error logging

## 🔒 Security Features

### Privacy-First Design
- **Local Processing**: All analysis performed locally
- **No Cloud Dependencies**: Optional local LLM integration only
- **Data Retention Controls**: Configurable data cleanup policies
- **Audit Logging**: Comprehensive activity tracking

### Safety Measures
- **Read-Only Operations**: Reconnaissance and scanning only
- **Timeout Controls**: Prevent runaway processes
- **Resource Limits**: Configurable execution boundaries
- **User Approval**: Required for AI-generated test execution

## ⚙️ Configuration

### Environment Variables
```bash
# Optional API keys
SHODAN_API_KEY=your_shodan_api_key

# Security settings
SECRET_KEY=your_flask_secret_key

# Database configuration
SQLALCHEMY_DATABASE_URI=sqlite:///cybersec_assessments.db
```

### System Settings
Configure through the web interface at `/settings`:
- **LLM Integration**: Ollama URL and model configuration
- **Scanning Parameters**: Tool preferences and timeout settings
- **API Keys**: External service integration
- **Report Options**: Format preferences and retention policies

## 📝 Logging

Comprehensive logging system with multiple levels:
- **Application Logs**: `logs/flask_app_YYYYMMDD.log`
- **Component Logs**: Individual agent and service logs
- **Audit Trail**: User actions and system events

## 🛠️ Development

### Project Structure
The system follows a modular architecture pattern:
- **Separation of Concerns**: Each agent handles specific functionality
- **Pluggable Components**: Easy to add new agents or tools
- **Configuration-Driven**: Behavior controlled through settings
- **Test Coverage**: Comprehensive test suite included

### Adding New Features
1. **New Agent**: Implement in `agents/` directory following existing patterns
2. **Database Changes**: Update models in `database/flask_db_manager.py`
3. **API Endpoints**: Add routes to `flask_app.py`
4. **UI Components**: Create/update templates in `templates/`

## 📚 Documentation

### Additional Resources
- `USER_GUIDE.md`: Detailed user instructions
- `LLAMA_INTEGRATION.md`: LLM setup and configuration
- `LICENSE`: MIT License for open-source usage

### API Documentation
RESTful API follows standard conventions:
- **GET** requests for data retrieval
- **POST** requests for data creation/modification
- **JSON** format for all request/response bodies
- **HTTP status codes** for operation results

## 🧪 Testing

### Test Coverage
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow verification
- **API Tests**: Complete endpoint validation
- **UI Tests**: Interface functionality verification

### Running Tests
```bash
# Full system test
python test_flask_system.py

# Component tests
python setup_and_test.py test

# LLM integration test
python setup_and_test.py test-llama
```

## 🚧 Future Enhancements

### Planned Features
- **Advanced Reporting**: Enhanced visualizations and dashboards
- **Plugin System**: Third-party agent integration
- **Role-Based Access**: Multi-user support with permissions
- **Distributed Scanning**: Multi-node deployment capability
- **Advanced AI Integration**: Enhanced LLM capabilities

### Known Limitations
- **Windows Tool Support**: Some security tools may require WSL
- **Resource Usage**: Large assessments may require significant memory
- **Network Dependencies**: Requires internet access for external reconnaissance

## 📄 License

MIT License - see `LICENSE` file for details.

## 🤝 Contributing

This project welcomes contributions:
1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request

## 🆘 Support

### Common Issues
1. **Import Errors**: Ensure all dependencies are installed via `pip install -r requirements.txt`
2. **Tool Availability**: Install security tools (nmap, masscan) for full functionality
3. **Port Conflicts**: Change Flask port in `flask_app.py` if 5000 is in use
4. **Database Issues**: Delete `cybersec_assessments.db` to reset database

### Getting Help
- Check the logs in the `logs/` directory
- Run `python setup_and_test.py check` for system diagnostics
- Review the `USER_GUIDE.md` for detailed instructions

---

**Built with Flask, SQLAlchemy, Bootstrap, and modern web technologies for enterprise-grade cybersecurity automation.**
