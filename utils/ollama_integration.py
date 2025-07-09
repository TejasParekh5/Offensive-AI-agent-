"""
Ollama LLM Client Integration for Local LLaMA Models
Provides interface to locally hosted LLaMA models via Ollama API.
"""

import requests
import json
import logging
from typing import Dict, List, Optional, Any
import time


class OllamaLLMClient:
    """Client for interacting with Ollama-hosted LLaMA models."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.1:8b"):
        self.base_url = base_url
        self.model = model
        self.timeout = 120  # 2 minutes timeout for generation
        self.logger = logging.getLogger(__name__)

    def is_available(self) -> bool:
        """Check if Ollama service is available."""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                # Check if our model is available
                for model in models:
                    if self.model in model.get('name', ''):
                        return True
                self.logger.warning(
                    f"Model {self.model} not found in available models")
                return False
            return False
        except Exception as e:
            self.logger.error(f"Ollama availability check failed: {e}")
            return False

    def list_models(self) -> List[str]:
        """List available models in Ollama."""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=10)
            if response.status_code == 200:
                models = response.json().get('models', [])
                return [model.get('name', '') for model in models]
            return []
        except Exception as e:
            self.logger.error(f"Failed to list models: {e}")
            return []

    def generate_test_cases(self, target_info: Dict, scan_results: List[Dict]) -> List[Dict]:
        """Generate security test cases using LLaMA model."""
        try:
            # Prepare context for test case generation
            context = self._prepare_context(target_info, scan_results)
            prompt = self._create_test_case_prompt(context)

            # Generate response
            response_text = self._generate_response(prompt)

            if not response_text:
                return []

            # Parse and structure test cases
            test_cases = self._parse_test_cases(response_text)

            self.logger.info(
                f"Generated {len(test_cases)} test cases via Ollama")
            return test_cases

        except Exception as e:
            self.logger.error(f"Test case generation failed: {e}")
            return []

    def analyze_vulnerability(self, vulnerability_data: Dict) -> Dict:
        """Analyze vulnerability and provide insights."""
        try:
            prompt = self._create_vulnerability_prompt(vulnerability_data)
            response_text = self._generate_response(prompt)

            if not response_text:
                return {}

            analysis = self._parse_vulnerability_analysis(response_text)
            return analysis

        except Exception as e:
            self.logger.error(f"Vulnerability analysis failed: {e}")
            return {}

    def generate_remediation(self, findings: List[Dict]) -> List[str]:
        """Generate remediation recommendations."""
        try:
            prompt = self._create_remediation_prompt(findings)
            response_text = self._generate_response(prompt)

            if not response_text:
                return []

            recommendations = self._parse_recommendations(response_text)
            return recommendations

        except Exception as e:
            self.logger.error(f"Remediation generation failed: {e}")
            return []

    def _prepare_context(self, target_info: Dict, scan_results: List[Dict]) -> Dict:
        """Prepare context for test case generation."""
        # Extract relevant information from scan results
        open_ports = []
        services = []
        vulnerabilities = []

        for result in scan_results:
            if result.get('state') == 'open':
                port = result.get('port')
                service = result.get('service', 'unknown')
                version = result.get('version', '')

                if port:
                    open_ports.append(port)
                if service and service != 'unknown':
                    services.append(f"{service}:{port}")

                # Extract vulnerabilities if present
                if result.get('vulnerabilities'):
                    vulnerabilities.extend(result['vulnerabilities'])

        return {
            'target': target_info.get('target', ''),
            'target_type': target_info.get('target_type', ''),
            'open_ports': sorted(list(set(open_ports))),
            'services': list(set(services)),
            'vulnerabilities': vulnerabilities,
            'scan_count': len(scan_results)
        }

    def _create_test_case_prompt(self, context: Dict) -> str:
        """Create structured prompt for test case generation."""
        prompt = f"""You are a cybersecurity expert specializing in penetration testing and vulnerability assessment. Generate specific, actionable security test cases based on the provided scan results.

TARGET INFORMATION:
- Target: {context['target']}
- Type: {context['target_type']}
- Open Ports: {', '.join(map(str, context['open_ports']))}
- Services: {', '.join(context['services'])}

REQUIREMENTS:
Generate 3-5 specific security test cases. Each test case must include:
1. Test Name (concise, descriptive)
2. Category (Network, Web Application, Service, Authentication, etc.)
3. Severity (Critical, High, Medium, Low)
4. Description (what the test checks for)
5. Command or Script (actual command to run)
6. Expected Result (what indicates vulnerability)

Focus on:
- OWASP Top 10 vulnerabilities
- Common misconfigurations
- Default credentials
- Unpatched services
- Information disclosure

Format as JSON array. Example:
[
  {{
    "name": "HTTP Security Headers Check",
    "category": "Web Application",
    "severity": "Medium",
    "description": "Check for missing security headers",
    "command": "curl -I http://{context['target']}",
    "expected_result": "Missing X-Frame-Options, X-XSS-Protection headers",
    "port": 80,
    "service": "http"
  }}
]

Generate practical, executable test cases:"""

        return prompt

    def _create_vulnerability_prompt(self, vuln_data: Dict) -> str:
        """Create prompt for vulnerability analysis."""
        prompt = f"""Analyze the following vulnerability data and provide detailed security assessment:

VULNERABILITY DATA:
{json.dumps(vuln_data, indent=2)}

Provide analysis in JSON format with:
1. risk_level (Critical/High/Medium/Low)
2. impact_description 
3. exploitation_difficulty (Easy/Medium/Hard)
4. remediation_priority (Immediate/High/Medium/Low)
5. recommended_actions (list of specific steps)

Focus on practical, actionable insights:"""

        return prompt

    def _create_remediation_prompt(self, findings: List[Dict]) -> str:
        """Create prompt for remediation recommendations."""
        prompt = f"""Based on the following security findings, generate prioritized remediation recommendations:

SECURITY FINDINGS:
{json.dumps(findings, indent=2)}

Generate 5-10 specific, actionable remediation steps prioritized by risk level. 
Format as JSON array of strings with clear, implementable actions:"""

        return prompt

    def _generate_response(self, prompt: str) -> str:
        """Generate response using Ollama API."""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "top_p": 0.9,
                    "max_tokens": 2048
                }
            }

            self.logger.info(f"Sending request to Ollama model: {self.model}")

            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout
            )

            if response.status_code == 200:
                result = response.json()
                return result.get('response', '').strip()
            else:
                self.logger.error(
                    f"Ollama API error: {response.status_code} - {response.text}")
                return ""

        except requests.exceptions.Timeout:
            self.logger.error("Ollama request timeout")
            return ""
        except Exception as e:
            self.logger.error(f"Ollama generation error: {e}")
            return ""

    def _parse_test_cases(self, response_text: str) -> List[Dict]:
        """Parse test cases from LLM response."""
        try:
            # Try to extract JSON from response
            import re

            # Look for JSON array in response
            json_match = re.search(r'\[.*?\]', response_text, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                test_cases = json.loads(json_str)

                # Validate and clean test cases
                validated_cases = []
                for case in test_cases:
                    if isinstance(case, dict) and 'name' in case:
                        # Ensure required fields
                        validated_case = {
                            'id': f"llm_{int(time.time())}_{len(validated_cases)}",
                            'name': case.get('name', 'Unknown Test'),
                            'category': case.get('category', 'General'),
                            'severity': case.get('severity', 'Medium'),
                            'description': case.get('description', ''),
                            'command': case.get('command', ''),
                            'expected_result': case.get('expected_result', ''),
                            'port': case.get('port'),
                            'service': case.get('service'),
                            'approved': False,
                            'executed': False,
                            'generated_by': 'ollama_llama',
                            'created_at': time.time()
                        }
                        validated_cases.append(validated_case)

                return validated_cases
            else:
                # Fallback: parse structured text
                return self._parse_structured_text(response_text)

        except json.JSONDecodeError as e:
            self.logger.error(f"JSON parsing error: {e}")
            return self._parse_structured_text(response_text)
        except Exception as e:
            self.logger.error(f"Test case parsing error: {e}")
            return []

    def _parse_structured_text(self, text: str) -> List[Dict]:
        """Parse test cases from structured text when JSON parsing fails."""
        test_cases = []
        lines = text.split('\n')

        current_test = {}
        for line in lines:
            line = line.strip()

            if line.startswith('Test Name:') or line.startswith('Name:'):
                if current_test:
                    test_cases.append(current_test)
                current_test = {
                    'id': f"llm_text_{int(time.time())}_{len(test_cases)}",
                    'name': line.split(':', 1)[1].strip(),
                    'approved': False,
                    'executed': False,
                    'generated_by': 'ollama_llama'
                }
            elif line.startswith('Category:') and current_test:
                current_test['category'] = line.split(':', 1)[1].strip()
            elif line.startswith('Severity:') and current_test:
                current_test['severity'] = line.split(':', 1)[1].strip()
            elif line.startswith('Description:') and current_test:
                current_test['description'] = line.split(':', 1)[1].strip()
            elif line.startswith('Command:') and current_test:
                current_test['command'] = line.split(':', 1)[1].strip()

        if current_test:
            test_cases.append(current_test)

        return test_cases

    def _parse_vulnerability_analysis(self, response_text: str) -> Dict:
        """Parse vulnerability analysis from response."""
        try:
            import re

            # Try to extract JSON
            json_match = re.search(r'\{.*?\}', response_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                # Fallback analysis
                return {
                    'risk_level': 'Medium',
                    'impact_description': 'Potential security risk identified',
                    'exploitation_difficulty': 'Medium',
                    'remediation_priority': 'Medium',
                    'recommended_actions': ['Review and assess the vulnerability']
                }

        except Exception as e:
            self.logger.error(f"Vulnerability analysis parsing error: {e}")
            return {}

    def _parse_recommendations(self, response_text: str) -> List[str]:
        """Parse recommendations from response."""
        try:
            import re

            # Try to extract JSON array
            json_match = re.search(r'\[.*?\]', response_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                # Fallback: extract bullet points or numbered items
                lines = response_text.split('\n')
                recommendations = []

                for line in lines:
                    line = line.strip()
                    if (line.startswith('-') or line.startswith('*') or
                            re.match(r'^\d+\.', line)) and len(line) > 10:
                        # Clean up the line
                        clean_line = re.sub(r'^[-*\d.]\s*', '', line)
                        recommendations.append(clean_line)

                return recommendations[:10]  # Limit to 10

        except Exception as e:
            self.logger.error(f"Recommendations parsing error: {e}")
            return []

    def pull_model(self, model_name: str = None) -> bool:
        """Pull/download a model to Ollama."""
        try:
            if not model_name:
                model_name = self.model

            payload = {"name": model_name}

            response = requests.post(
                f"{self.base_url}/api/pull",
                json=payload,
                timeout=300  # 5 minutes for model download
            )

            return response.status_code == 200

        except Exception as e:
            self.logger.error(f"Model pull error: {e}")
            return False

    def get_model_info(self, model_name: str = None) -> Dict:
        """Get information about a model."""
        try:
            if not model_name:
                model_name = self.model

            response = requests.post(
                f"{self.base_url}/api/show",
                json={"name": model_name},
                timeout=10
            )

            if response.status_code == 200:
                return response.json()
            return {}

        except Exception as e:
            self.logger.error(f"Model info error: {e}")
            return {}
