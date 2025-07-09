# Multi-Agent Cybersecurity Automation System

## Overview

A comprehensive multi-agent cybersecurity automation system with real-time dashboard for streamlined offensive security assessments.

## Features

- **Recon Agent**: Domain reconnaissance using Shodan, theHarvester, Amass
- **Scanning Agent**: Port and service discovery with Nmap, Masscan, Rustscan
- **Test Case Agent**: Automated testing with LLM-generated test cases
- **Llama 3.1 8B Integration**: Local LLM for test case generation (no API required)
- **Real-time Dashboard**: Interactive Streamlit interface
- **Report Generation**: Multiple output formats (JSON, PDF, HTML)

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Recon Agent   │───▶│ Scanning Agent  │───▶│ Test Case Agent │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │    Dashboard & DB       │
                    └─────────────────────────┘
```

## Installation

```bash
# Install core dependencies
pip install -r requirements.txt

# Setup Llama 3.1 8B (optional but recommended)
python setup_llama.py
```

## Configuration

1. Copy `.env.example` to `.env`
2. Add your API keys for Shodan, OpenAI, etc.
3. Configure tool paths in `config/settings.json`
4. For Llama 3.1 8B:
   - Ensure 16GB+ RAM for best performance
   - GPU with 8GB+ VRAM recommended
   - Run `python setup_llama.py` for automated setup

## LLM Options

The system supports multiple LLM backends for test case generation:

1. **Llama 3.1 8B (Local)** - Recommended

   - No API costs
   - Privacy-focused (runs locally)
   - Requires significant hardware resources
   - Setup: `python setup_llama.py`

2. **OpenAI GPT** - Cloud-based

   - Set `OPENAI_API_KEY` in `.env`
   - Requires API credits

3. **Anthropic Claude** - Cloud-based
   - Set `ANTHROPIC_API_KEY` in `.env`
   - Requires API credits

## Usage

```bash
streamlit run dashboard.py
```

## Project Structure

```
├── agents/
│   ├── recon_agent.py
│   ├── scanning_agent.py
│   └── test_case_agent.py
├── config/
│   ├── settings.json
│   └── test_cases.json
├── database/
│   └── db_manager.py
├── reports/
│   └── report_generator.py
├── utils/
│   ├── validators.py
│   ├── helpers.py
│   └── llama_integration.py
├── dashboard.py
├── setup_llama.py
├── requirements.txt
└── README.md
```

## System Requirements

- **Minimum**: Python 3.8+, 8GB RAM
- **Recommended for Llama**: Python 3.9+, 16GB+ RAM, GPU with 8GB+ VRAM
- **Operating System**: Windows, Linux, macOS

## Security Notice

This tool is designed for authorized penetration testing and security assessments only. Users are responsible for ensuring compliance with applicable laws and regulations.
