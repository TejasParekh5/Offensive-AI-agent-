# Multi-Agent Cybersecurity Automation System - User Guide

## Table of Contents

1. [Quick Start](#quick-start)
2. [System Overview](#system-overview)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Using the Dashboard](#using-the-dashboard)
6. [Command Line Interface](#command-line-interface)
7. [Understanding Results](#understanding-results)
8. [API Integration](#api-integration)
9. [Security Considerations](#security-considerations)
10. [Troubleshooting](#troubleshooting)

## Quick Start

### 1. Setup the System

```bash
# Clone or download the system
cd "Offensive AI agent"

# Run setup script
python setup.py

# Configure API keys in .env file
# Edit .env and add your API keys
```

### 2. Launch Dashboard

```bash
python main.py dashboard
# OR
streamlit run dashboard.py
```

### 3. Run Your First Assessment

1. Open the dashboard in your browser (usually http://localhost:8501)
2. Navigate to "🔍 New Assessment"
3. Enter a target (e.g., `example.com` or `192.168.1.1`)
4. Click "Start Assessment"
5. Monitor progress and review results

## System Overview

### Architecture

The system consists of three main intelligent agents:

#### 🕵️ Recon Agent

- **Purpose**: Gather intelligence on domains and infrastructure
- **Tools**: Shodan, theHarvester, Amass, Certificate Transparency
- **Output**: Subdomains, emails, DNS records, technologies, certificates

#### 🔍 Scanning Agent

- **Purpose**: Port and service discovery with vulnerability detection
- **Tools**: Nmap, Masscan, Rustscan
- **Output**: Open ports, service versions, vulnerabilities, banners

#### 🧪 Test Case Agent

- **Purpose**: Execute security test cases and generate AI-powered tests
- **Features**: Predefined tests + LLM-generated custom tests
- **Output**: Security findings, evidence, recommendations

### Workflow Logic

```
Input: Domain/IP
    ↓
Is it a domain? → YES → Recon Agent → Scanning Agent → Test Case Agent
    ↓
    NO (IP Address) → Skip Recon → Scanning Agent → Test Case Agent
    ↓
Dashboard & Reports
```

## Installation

### Prerequisites

- Python 3.8 or higher
- Windows, macOS, or Linux
- At least 2GB RAM
- 1GB free disk space

### Automated Setup

```bash
python setup.py
```

### Manual Installation

1. **Install Python Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

2. **Install Security Tools** (optional but recommended)

   ```bash
   # Windows (using chocolatey)
   choco install nmap

   # macOS (using homebrew)
   brew install nmap masscan

   # Linux (Ubuntu/Debian)
   sudo apt-get install nmap masscan
   ```

3. **Initialize Database**
   ```bash
   python main.py init
   ```

## Configuration

### Environment Variables (.env file)

```env
# API Keys for enhanced functionality
SHODAN_API_KEY=your_shodan_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# Tool Paths (adjust if tools are not in PATH)
NMAP_PATH=nmap
MASSCAN_PATH=masscan
RUSTSCAN_PATH=rustscan

# System Configuration
LOG_LEVEL=INFO
DATABASE_PATH=./database/security_assessment.db
```

### API Keys Setup

#### Shodan API Key

1. Register at https://shodan.io
2. Get your API key from account dashboard
3. Add to `.env` file

#### OpenAI API Key (for LLM test generation)

1. Create account at https://platform.openai.com
2. Generate API key
3. Add to `.env` file

#### Anthropic API Key (alternative to OpenAI)

1. Register at https://console.anthropic.com
2. Get API key
3. Add to `.env` file

### Test Cases Configuration

Edit `config/test_cases.json` to customize predefined security tests:

```json
{
	"test_cases": [
		{
			"id": "TC001",
			"name": "Default SSH Credentials",
			"category": "Authentication",
			"severity": "High",
			"conditions": {
				"ports": [22],
				"services": ["ssh"]
			},
			"credentials": [
				["admin", "admin"],
				["root", "root"]
			]
		}
	]
}
```

## Using the Dashboard

### Home Page

- **Overview**: System status and recent activity
- **Quick Actions**: Start new assessments or view history
- **Metrics**: Active sessions, completed assessments

### New Assessment Page

1. **Target Input**: Enter domain, IP, or URL
2. **Scan Type**: Choose Quick, Standard, or Comprehensive
3. **Options**: Enable/disable recon, vulnerability scanning, test cases
4. **Execution**: Monitor real-time progress

### Assessment Options

- **Quick Scan**: Common ports only (22, 80, 443, etc.)
- **Standard Scan**: Ports 1-1000
- **Comprehensive Scan**: Full port range 1-65535

### Assessment History

- View all previous assessments
- Filter by status, type, or date
- Access detailed results and reports

### LLM Test Cases

The system supports multiple LLM backends for intelligent test case generation:

#### Llama 3.1 8B (Local Model) - Recommended

- **Privacy**: Runs entirely on your local machine
- **Cost**: No API costs after initial setup
- **Performance**: Fast generation once loaded
- **Requirements**: 16GB+ RAM, GPU recommended

**Setup Llama 3.1 8B:**

```bash
# Automated setup
python setup_llama.py

# Manual verification
python test_llama.py
```

**Llama Configuration Options:**

- **Max Length**: Token limit for generation (512-8192)
- **Temperature**: Creativity level (0.1-1.0)
- **Quantization**: Enable 4-bit quantization to reduce memory usage

#### Cloud-based LLMs (OpenAI/Anthropic)

- **OpenAI GPT**: Set `OPENAI_API_KEY` in `.env`
- **Anthropic Claude**: Set `ANTHROPIC_API_KEY` in `.env`

#### LLM Workflow

1. **Generation**: AI analyzes recon and scan data
2. **Review**: Human reviews generated test cases
3. **Approval**: Select which tests to execute
4. **Execution**: Approved tests run automatically

#### Test Case Quality

- Contextual tests based on discovered services
- Risk-prioritized suggestions
- Detailed execution guidance
- Evidence collection instructions

### Reports

- Generate comprehensive reports
- Multiple formats: JSON, HTML, PDF
- Download and share results

## Command Line Interface

### Available Commands

```bash
# Launch dashboard
python main.py dashboard

# Run standalone scan
python main.py scan --target example.com

# Execute security tests
python main.py test --target 192.168.1.1

# Generate reports
python main.py report

# Initialize system
python main.py init
```

### Scan Command Examples

```bash
# Scan a domain
python main.py scan --target example.com

# Scan an IP address
python main.py scan --target 192.168.1.100

# Verbose output
python main.py scan --target example.com --verbose
```

### Test Command Examples

```bash
# Run security tests on target
python main.py test --target example.com

# Test specific IP
python main.py test --target 10.0.0.1
```

## Understanding Results

### Recon Results

- **Subdomains**: Additional attack surfaces
- **Email Addresses**: Social engineering targets
- **DNS Records**: Infrastructure mapping
- **Technologies**: Technology stack identification
- **Certificates**: SSL/TLS configuration analysis

### Scan Results

- **Open Ports**: Accessible network services
- **Service Versions**: Software version information
- **Vulnerabilities**: Known security issues
- **Banners**: Service identification strings

### Test Results

- **Status**: Passed (vulnerability found) or Failed (no issue)
- **Severity**: Critical, High, Medium, Low
- **Evidence**: Proof of vulnerability
- **Recommendations**: Remediation steps

### Risk Levels

- **Critical**: Immediate exploitation possible
- **High**: High likelihood of compromise
- **Medium**: Moderate security risk
- **Low**: Minor security concern

## API Integration

### Using the System Programmatically

```python
import asyncio
from agents.recon_agent import ReconAgent
from agents.scanning_agent import ScanningAgent
from agents.test_case_agent import TestCaseAgent

async def automated_assessment(target):
    # Initialize agents
    recon = ReconAgent()
    scanner = ScanningAgent()
    tester = TestCaseAgent()

    # Run assessment
    session_id = "custom_session"

    # Recon (for domains)
    recon_results = await recon.perform_reconnaissance(target, session_id)

    # Scanning
    scan_results = await scanner.perform_scan(target, session_id)

    # Testing
    test_results = await tester.execute_test_cases(
        target, session_id, scan_data=scan_results
    )

    return {
        'recon': recon_results,
        'scan': scan_results,
        'test': test_results
    }

# Run assessment
results = asyncio.run(automated_assessment("example.com"))
```

## Security Considerations

### Legal and Ethical Usage

⚠️ **IMPORTANT**: This tool is designed for authorized penetration testing only.

#### Requirements:

- Written authorization from target owner
- Compliance with local laws and regulations
- Responsible disclosure of findings
- Professional use only

#### Prohibited Uses:

- Unauthorized scanning of third-party systems
- Malicious activities or actual attacks
- Violation of terms of service
- Any illegal activities

### Safety Features

- Read-only reconnaissance techniques
- No destructive testing by default
- Human-in-the-loop for LLM-generated tests
- Audit logging of all activities

### Data Protection

- Results stored locally by default
- Sensitive data encryption in transit
- Configurable data retention policies
- Secure API key management

## Troubleshooting

### Common Issues

#### "Tool not found" errors

```bash
# Check tool availability
which nmap
which masscan

# Install missing tools or update paths in .env
NMAP_PATH=/usr/local/bin/nmap
```

#### Dashboard won't start

```bash
# Check Streamlit installation
pip install streamlit

# Check port availability
netstat -an | grep 8501

# Try different port
streamlit run dashboard.py --server.port 8502
```

#### Database errors

```bash
# Reinitialize database
python main.py init

# Check permissions
ls -la database/
```

#### API key issues

```bash
# Verify API keys in .env file
cat .env | grep API_KEY

# Test API connectivity
python -c "import shodan; print('Shodan OK')"
```

### Performance Issues

#### Slow scanning

- Use Quick scan mode for initial assessment
- Reduce port range for faster results
- Consider using Masscan or Rustscan for speed

#### Memory usage

- Close unnecessary browser tabs
- Reduce concurrent scans
- Monitor system resources

### Getting Help

#### Log Files

Check logs for detailed error information:

```bash
tail -f logs/system.log
```

#### Debug Mode

Enable verbose logging:

```bash
python main.py scan --target example.com --verbose
```

#### Support Resources

- Check GitHub issues for known problems
- Review documentation for configuration options
- Ensure all dependencies are properly installed

## Advanced Usage

### Custom Test Cases

Add custom test cases to `config/test_cases.json`:

```json
{
	"id": "CUSTOM001",
	"name": "Custom Web Application Test",
	"category": "Web Security",
	"severity": "Medium",
	"conditions": {
		"ports": [80, 443],
		"services": ["http", "https"]
	},
	"description": "Custom security test description"
}
```

### Integration with CI/CD

```bash
# Run in automated pipeline
python main.py scan --target $TARGET_HOST > scan_results.json
python main.py report --output ./reports/
```

### Batch Processing

```python
targets = ["example.com", "test.org", "demo.net"]
for target in targets:
    results = asyncio.run(run_assessment(target))
    generate_report(results, f"report_{target}.html")
```

This comprehensive system provides automated security assessments with intelligent agents, real-time dashboards, and detailed reporting capabilities. Remember to always use this tool responsibly and with proper authorization.
