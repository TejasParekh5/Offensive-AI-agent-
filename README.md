# 🛡️ Multi-Agent Cybersecurity Automation System

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red)](https://streamlit.io)
[![Llama](https://img.shields.io/badge/Llama-3.1%208B-orange)](https://llama.meta.com)

A comprehensive multi-agent cybersecurity automation system with real-time dashboard for streamlined offensive security assessments. Features local Llama 3.1 8B integration for privacy-focused AI-powered test case generation.

![System Architecture](https://via.placeholder.com/800x400/1a1a1a/ffffff?text=Multi-Agent+Cybersecurity+System)

## 🌟 Features

### 🤖 Intelligent Agents
- **🕵️ Recon Agent**: Domain reconnaissance using Shodan, theHarvester, Amass
- **🔍 Scanning Agent**: Port and service discovery with Nmap, Masscan, Rustscan  
- **🧪 Test Case Agent**: Automated testing with AI-generated test cases

### 🦙 Local AI Integration
- **Llama 3.1 8B**: Local LLM for test case generation (no API costs!)
- **Privacy-Focused**: All AI processing happens locally
- **Offline Capable**: Works without internet after initial setup
- **Memory Optimized**: 4-bit quantization support

### 📊 Real-time Dashboard
- **Interactive Interface**: Streamlit-based web dashboard
- **Live Progress Tracking**: Real-time assessment monitoring
- **Human-in-the-Loop**: AI test case approval workflow
- **Multi-format Reports**: JSON, HTML, PDF generation

### 🔧 Tool Integration
- **Shodan**: API integration for infrastructure intelligence
- **Nmap/Masscan/Rustscan**: Comprehensive port scanning
- **theHarvester/Amass**: OSINT and subdomain enumeration
- **Certificate Transparency**: SSL/TLS certificate analysis

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Recon Agent   │───▶│ Scanning Agent  │───▶│ Test Case Agent │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │    Dashboard & DB       │
                    │   🦙 Llama 3.1 8B      │
                    └─────────────────────────┘
```

## 🚀 Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/TejasParekh5/Offensive-AI-agent-.git
cd Offensive-AI-agent-
```

### 2. Install Dependencies
```bash
# Complete setup with Llama 3.1 8B (recommended)
python setup_and_test.py all

# Or setup core system only
python setup_and_test.py setup

# Or just install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your API keys (optional for Llama)
# SHODAN_API_KEY=your_key_here
# OPENAI_API_KEY=your_key_here (fallback)
```

### 4. Launch Dashboard
```bash
python main.py dashboard
# OR
streamlit run dashboard.py
```

### 5. Run Your First Assessment
1. Open browser to `http://localhost:8501`
2. Navigate to "🔍 New Assessment"
3. Enter target (e.g., `example.com` or `192.168.1.1`)
4. Enable "Generate LLM Test Cases"
5. Click "Start Assessment"

## 💻 System Requirements

### Minimum (CPU-only with quantization)
- **OS**: Windows 10+, Ubuntu 18+, macOS 10.15+
- **Python**: 3.8+
- **RAM**: 8GB (12GB recommended)
- **Storage**: 25GB free space
- **Network**: Internet for initial model download

### Recommended (GPU acceleration)
- **RAM**: 16GB+
- **GPU**: NVIDIA GPU with 8GB+ VRAM
- **CUDA**: 11.8+ or 12.x
- **Storage**: SSD with 30GB+ free space

### Supported Tools
- **Required**: Python 3.8+, pip
- **Optional**: Nmap, Masscan, Rustscan, theHarvester, Amass
- **APIs**: Shodan (for enhanced recon)

## 🔧 Configuration

### Environment Variables (.env)
```bash
# API Keys
SHODAN_API_KEY=your_shodan_key
OPENAI_API_KEY=your_openai_key  # Fallback LLM
ANTHROPIC_API_KEY=your_anthropic_key  # Fallback LLM

# Llama Configuration
LLAMA_MAX_LENGTH=4096
LLAMA_TEMPERATURE=0.7
LLAMA_USE_QUANTIZATION=true

# Tool Paths
NMAP_PATH=nmap
MASSCAN_PATH=masscan
RUSTSCAN_PATH=rustscan

# Database & Logging
DATABASE_PATH=./database/security_assessment.db
LOG_LEVEL=INFO
```

### Dashboard Settings
Access `⚙️ Settings` in the dashboard to:
- Configure API keys
- Test Llama model status
- Adjust generation parameters
- Monitor system resources
- Manage database

## 📚 Usage Examples

### CLI Interface
```bash
# Launch interactive dashboard
python main.py dashboard

# Run headless scan
python main.py scan --target example.com --output ./results

# Execute specific tests
python main.py test --target 192.168.1.1 --config custom_tests.json

# Generate reports
python main.py report --session session_id --format pdf
```

### Programmatic Usage
```python
from agents.recon_agent import ReconAgent
from agents.scanning_agent import ScanningAgent
from utils.llama_integration import get_llama_instance

# Initialize agents
recon = ReconAgent()
scanner = ScanningAgent()
llama = get_llama_instance()

# Run assessment
recon_results = await recon.run_reconnaissance("example.com")
scan_results = await scanner.run_scan("example.com")
test_cases = llama.generate_test_cases(target_info, scan_results)
```

## 🔬 AI Model Options

### 1. Llama 3.1 8B (Recommended)
```bash
# Complete setup including Llama
python setup_and_test.py all

# Llama-only setup
python setup_and_test.py setup-llama

# Test Llama integration
python setup_and_test.py test-llama
```

**Pros**: No API costs, privacy-focused, offline capable  
**Cons**: Requires significant hardware resources

### 2. OpenAI GPT (Cloud)
```bash
OPENAI_API_KEY=sk-your_key_here
```

**Pros**: No local hardware requirements, high quality  
**Cons**: API costs, requires internet, data sent to OpenAI

### 3. Anthropic Claude (Cloud)
```bash
ANTHROPIC_API_KEY=your_key_here
```

**Pros**: Alternative to OpenAI, good reasoning  
**Cons**: API costs, requires internet, data sent to Anthropic

## 📊 Project Structure

```
Offensive-AI-agent-/
├── agents/                     # Core agent modules
│   ├── recon_agent.py         # OSINT & reconnaissance
│   ├── scanning_agent.py      # Port & service scanning
│   └── test_case_agent.py     # Test execution & LLM integration
├── config/                     # Configuration files
│   ├── settings.json          # Tool configurations
│   └── test_cases.json        # Predefined test cases
├── database/                   # Data persistence
│   └── db_manager.py          # SQLite database manager
├── reports/                    # Report generation
│   └── report_generator.py    # Multi-format report engine
├── utils/                      # Utility modules
│   ├── helpers.py             # Common utilities
│   ├── validators.py          # Input validation
│   └── llama_integration.py   # Llama 3.1 8B integration
├── dashboard.py               # Streamlit web interface
├── main.py                    # CLI entry point
├── setup_and_test.py         # Unified setup and test utility
├── requirements.txt          # Python dependencies
├── .env.example              # Environment template
└── README.md                 # This file
```

## 🧪 Testing

```bash
# Run comprehensive system test
python setup_and_test.py test

# Test Llama integration only
python setup_and_test.py test-llama

# Check system requirements
python setup_and_test.py check

# Check security tools availability
python setup_and_test.py tools
```

## 📈 Performance Benchmarks

### Llama 3.1 8B Performance
| Hardware | Generation Time | Memory Usage |
|----------|----------------|--------------|
| RTX 4080 | 30-60 seconds | 8-10GB VRAM |
| RTX 3070 | 45-90 seconds | 6-8GB VRAM |
| CPU i7 | 2-5 minutes | 12-16GB RAM |
| CPU (Quantized) | 3-7 minutes | 8-12GB RAM |

### Assessment Speed
- **Small target**: 5-15 minutes (domain + basic scan)
- **Medium target**: 15-45 minutes (full recon + comprehensive scan)
- **Large target**: 45+ minutes (enterprise-grade assessment)

## 🛡️ Security & Legal Notice

### ⚠️ Important Legal Disclaimer
This tool is designed for **authorized penetration testing and security assessments only**. Users are responsible for ensuring compliance with applicable laws and regulations.

### Ethical Use Guidelines
- ✅ Authorized security assessments
- ✅ Bug bounty programs
- ✅ Educational/research purposes
- ✅ Your own systems and networks
- ❌ Unauthorized scanning or testing
- ❌ Malicious activities
- ❌ Illegal purposes

### Privacy & Data Handling
- **Llama 3.1 8B**: All processing happens locally
- **Cloud APIs**: Data sent to respective providers
- **Database**: Local SQLite storage
- **Logs**: Stored locally, configurable levels

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone repository
git clone https://github.com/TejasParekh5/Offensive-AI-agent-.git

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Start development server
streamlit run dashboard.py --server.runOnSave true
```

### Areas for Contribution
- 🔧 Additional tool integrations
- 🧠 LLM model improvements
- 📊 Enhanced visualizations
- 🔍 New test case categories
- 📚 Documentation improvements

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Meta AI** for the Llama 3.1 8B model
- **Streamlit** for the dashboard framework
- **Security community** for open-source tools
- **Contributors** who help improve this project

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/TejasParekh5/Offensive-AI-agent-/issues)
- **Discussions**: [GitHub Discussions](https://github.com/TejasParekh5/Offensive-AI-agent-/discussions)
- **Email**: [Contact](mailto:your-email@example.com)

## 🗺️ Roadmap

### 🔄 Current (v1.0)
- ✅ Multi-agent architecture
- ✅ Llama 3.1 8B integration
- ✅ Real-time dashboard
- ✅ Report generation

### 🎯 Near-term (v1.1)
- 🔄 Enhanced tool integration
- 🔄 Batch processing
- 🔄 API endpoints
- 🔄 Docker containerization

### 🚀 Future (v2.0)
- 📋 Fine-tuned security models
- 📋 Multi-target campaigns
- 📋 Collaborative features
- 📋 Cloud deployment options

---

**Made with ❤️ for the cybersecurity community**

⭐ Star this repository if you find it useful!
