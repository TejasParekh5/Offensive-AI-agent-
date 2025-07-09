"""
Llama 3.1 8B Model Integration for Cybersecurity Automation System
Provides local LLM capabilities for test case generation and analysis.
"""

import logging
import torch
from typing import Dict, List, Optional, Any
import json
import re
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
    pipeline
)
from utils.helpers import get_env_var


class LlamaIntegration:
    """Manages Llama 3.1 8B model for local LLM operations."""

    def __init__(self):
        self.model_name = "meta-llama/Meta-Llama-3.1-8B-Instruct"
        self.tokenizer = None
        self.model = None
        self.pipeline = None
        self.max_length = int(get_env_var('LLAMA_MAX_LENGTH', '4096'))
        self.temperature = float(get_env_var('LLAMA_TEMPERATURE', '0.7'))
        self.use_quantization = get_env_var(
            'LLAMA_USE_QUANTIZATION', 'true').lower() == 'true'

        # Initialize model
        self._initialize_model()

    def _initialize_model(self):
        """Initialize the Llama model with optimizations."""
        try:
            logging.info("Initializing Llama 3.1 8B model...")

            # Configure quantization for memory efficiency
            if self.use_quantization:
                quantization_config = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_compute_dtype=torch.float16,
                    bnb_4bit_use_double_quant=True,
                    bnb_4bit_quant_type="nf4"
                )
            else:
                quantization_config = None

            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                trust_remote_code=True
            )

            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token

            # Load model
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                quantization_config=quantization_config,
                device_map="auto",
                torch_dtype=torch.float16,
                trust_remote_code=True
            )

            # Create pipeline
            self.pipeline = pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer,
                torch_dtype=torch.float16,
                device_map="auto",
            )

            logging.info("Llama 3.1 8B model initialized successfully")

        except Exception as e:
            logging.error(f"Error initializing Llama model: {e}")
            raise

    def is_available(self) -> bool:
        """Check if the model is available and loaded."""
        return self.model is not None and self.tokenizer is not None

    def generate_test_cases(self, target_info: Dict, scan_results: List[Dict]) -> List[Dict]:
        """Generate security test cases based on target information and scan results."""
        if not self.is_available():
            logging.error("Llama model not available")
            return []

        try:
            # Prepare context for test case generation
            context = self._prepare_test_case_context(
                target_info, scan_results)

            prompt = self._create_test_case_prompt(context)

            # Generate response
            response = self._generate_response(prompt)

            # Parse and structure test cases
            test_cases = self._parse_test_cases_response(response)

            return test_cases

        except Exception as e:
            logging.error(f"Error generating test cases with Llama: {e}")
            return []

    def analyze_vulnerability(self, vulnerability_data: Dict) -> Dict:
        """Analyze vulnerability data and provide insights."""
        if not self.is_available():
            logging.error("Llama model not available")
            return {}

        try:
            prompt = self._create_vulnerability_analysis_prompt(
                vulnerability_data)
            response = self._generate_response(prompt)
            analysis = self._parse_vulnerability_analysis(response)

            return analysis

        except Exception as e:
            logging.error(f"Error analyzing vulnerability with Llama: {e}")
            return {}

    def generate_recommendations(self, assessment_results: Dict) -> List[str]:
        """Generate security recommendations based on assessment results."""
        if not self.is_available():
            logging.error("Llama model not available")
            return []

        try:
            prompt = self._create_recommendations_prompt(assessment_results)
            response = self._generate_response(prompt)
            recommendations = self._parse_recommendations(response)

            return recommendations

        except Exception as e:
            logging.error(f"Error generating recommendations with Llama: {e}")
            return []

    def _prepare_test_case_context(self, target_info: Dict, scan_results: List[Dict]) -> Dict:
        """Prepare context for test case generation."""
        # Extract relevant information
        open_ports = []
        services = []

        for result in scan_results:
            if result.get('state') == 'open':
                open_ports.append(result.get('port'))
                if result.get('service'):
                    services.append(result.get('service'))

        return {
            'target': target_info.get('target', ''),
            'target_type': target_info.get('target_type', ''),
            'open_ports': list(set(open_ports)),
            'services': list(set(services)),
            'scan_count': len(scan_results)
        }

    def _create_test_case_prompt(self, context: Dict) -> str:
        """Create prompt for test case generation."""
        prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>

You are a cybersecurity expert specializing in penetration testing and vulnerability assessment. Your task is to generate specific, actionable security test cases based on the provided target information and scan results.

<|eot_id|><|start_header_id|>user<|end_header_id|>

Target Information:
- Target: {context['target']}
- Type: {context['target_type']}
- Open Ports: {context['open_ports']}
- Services: {context['services']}

Please generate 3-5 specific security test cases for this target. Each test case should include:
1. Test Name
2. Category (e.g., "Network", "Web Application", "Service", "Authentication")
3. Severity Level (Critical, High, Medium, Low)
4. Description
5. Expected Outcome
6. Tools/Commands to use

Format your response as a JSON array of test case objects.

<|eot_id|><|start_header_id|>assistant<|end_header_id|>

"""
        return prompt

    def _create_vulnerability_analysis_prompt(self, vuln_data: Dict) -> str:
        """Create prompt for vulnerability analysis."""
        prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>

You are a cybersecurity analyst specializing in vulnerability assessment and risk analysis. Provide detailed analysis of the given vulnerability data.

<|eot_id|><|start_header_id|>user<|end_header_id|>

Vulnerability Data:
{json.dumps(vuln_data, indent=2)}

Please provide:
1. Risk Assessment (Critical/High/Medium/Low)
2. Impact Analysis
3. Exploitation Difficulty
4. Remediation Priority
5. Recommended Actions

Format your response as JSON with these keys: risk_level, impact, exploitation_difficulty, priority, recommendations.

<|eot_id|><|start_header_id|>assistant<|end_header_id|>

"""
        return prompt

    def _create_recommendations_prompt(self, results: Dict) -> str:
        """Create prompt for security recommendations."""
        prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>

You are a cybersecurity consultant providing actionable security recommendations based on assessment results.

<|eot_id|><|start_header_id|>user<|end_header_id|>

Assessment Results Summary:
{json.dumps(results, indent=2)}

Please provide 5-10 prioritized security recommendations based on these results. Each recommendation should be:
- Specific and actionable
- Prioritized by risk level
- Include implementation guidance

Format as a JSON array of recommendation strings.

<|eot_id|><|start_header_id|>assistant<|end_header_id|>

"""
        return prompt

    def _generate_response(self, prompt: str) -> str:
        """Generate response using the Llama model."""
        try:
            # Generate response
            outputs = self.pipeline(
                prompt,
                max_new_tokens=1024,
                temperature=self.temperature,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id,
                eos_token_id=self.tokenizer.eos_token_id,
            )

            # Extract generated text
            generated_text = outputs[0]['generated_text']

            # Remove the prompt from the response
            response = generated_text[len(prompt):].strip()

            return response

        except Exception as e:
            logging.error(f"Error generating response: {e}")
            return ""

    def _parse_test_cases_response(self, response: str) -> List[Dict]:
        """Parse test cases from model response."""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                test_cases = json.loads(json_str)
                return test_cases
            else:
                # Fallback: parse structured text
                return self._parse_structured_test_cases(response)

        except Exception as e:
            logging.error(f"Error parsing test cases response: {e}")
            return []

    def _parse_structured_test_cases(self, response: str) -> List[Dict]:
        """Parse test cases from structured text response."""
        test_cases = []

        # Simple parsing logic for structured text
        lines = response.split('\n')
        current_test = {}

        for line in lines:
            line = line.strip()
            if line.startswith('Test Name:'):
                if current_test:
                    test_cases.append(current_test)
                current_test = {'name': line.replace('Test Name:', '').strip()}
            elif line.startswith('Category:'):
                current_test['category'] = line.replace(
                    'Category:', '').strip()
            elif line.startswith('Severity:'):
                current_test['severity'] = line.replace(
                    'Severity:', '').strip()
            elif line.startswith('Description:'):
                current_test['description'] = line.replace(
                    'Description:', '').strip()

        if current_test:
            test_cases.append(current_test)

        return test_cases

    def _parse_vulnerability_analysis(self, response: str) -> Dict:
        """Parse vulnerability analysis from response."""
        try:
            # Try to extract JSON
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                # Fallback analysis
                return {
                    'risk_level': 'Medium',
                    'impact': 'Potential security risk identified',
                    'exploitation_difficulty': 'Medium',
                    'priority': 'Medium',
                    'recommendations': ['Review and assess the vulnerability', 'Apply security patches if available']
                }
        except Exception as e:
            logging.error(f"Error parsing vulnerability analysis: {e}")
            return {}

    def _parse_recommendations(self, response: str) -> List[str]:
        """Parse recommendations from response."""
        try:
            # Try to extract JSON array
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                # Fallback: split by lines
                lines = response.split('\n')
                recommendations = []
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#') and len(line) > 10:
                        recommendations.append(line)
                return recommendations[:10]  # Limit to 10 recommendations

        except Exception as e:
            logging.error(f"Error parsing recommendations: {e}")
            return []

    def cleanup(self):
        """Clean up model resources."""
        try:
            if self.model:
                del self.model
            if self.tokenizer:
                del self.tokenizer
            if self.pipeline:
                del self.pipeline

            # Clear CUDA cache if available
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

            logging.info("Llama model resources cleaned up")

        except Exception as e:
            logging.error(f"Error cleaning up Llama model: {e}")


# Global instance for model reuse
_llama_instance = None


def get_llama_instance() -> LlamaIntegration:
    """Get or create global Llama instance."""
    global _llama_instance

    if _llama_instance is None:
        _llama_instance = LlamaIntegration()

    return _llama_instance


def cleanup_llama_instance():
    """Clean up global Llama instance."""
    global _llama_instance

    if _llama_instance:
        _llama_instance.cleanup()
        _llama_instance = None
