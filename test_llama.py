#!/usr/bin/env python3
"""
Quick test script for Llama 3.1 8B integration
Tests the Llama model without running the full dashboard.
"""

import sys
import logging
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def test_llama_import():
    """Test if Llama integration can be imported."""
    try:
        from utils.llama_integration import LlamaIntegration, get_llama_instance
        print("✅ Llama integration module imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Failed to import Llama integration: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error importing Llama: {e}")
        return False


def test_dependencies():
    """Test if required dependencies are available."""
    print("\n🔍 Checking dependencies...")

    dependencies = {
        'torch': 'PyTorch',
        'transformers': 'Transformers',
        'accelerate': 'Accelerate',
        'bitsandbytes': 'BitsAndBytes (optional)',
        'sentencepiece': 'SentencePiece'
    }

    all_available = True
    for module, name in dependencies.items():
        try:
            __import__(module)
            print(f"✅ {name} available")
        except ImportError:
            if module == 'bitsandbytes':
                print(
                    f"⚠️ {name} not available (optional, needed for quantization)")
            else:
                print(f"❌ {name} not available")
                all_available = False

    return all_available


def test_model_loading():
    """Test if the Llama model can be loaded."""
    print("\n🦙 Testing Llama model loading...")

    try:
        from utils.llama_integration import LlamaIntegration

        print("Attempting to initialize Llama 3.1 8B...")
        print("Note: This may take several minutes on first run...")

        llama = LlamaIntegration()

        if llama.is_available():
            print("✅ Llama 3.1 8B model loaded successfully!")

            # Test basic generation
            print("\n🧪 Testing generation...")
            test_data = {
                'target': 'test.example.com',
                'target_type': 'domain'
            }
            scan_results = [
                {'port': 80, 'service': 'http', 'state': 'open'},
                {'port': 443, 'service': 'https', 'state': 'open'},
                {'port': 22, 'service': 'ssh', 'state': 'open'}
            ]

            test_cases = llama.generate_test_cases(test_data, scan_results)

            if test_cases:
                print(f"✅ Generated {len(test_cases)} test cases")
                print("\nSample test case:")
                for key, value in test_cases[0].items():
                    print(f"  {key}: {value}")
            else:
                print("⚠️ No test cases generated (this might be normal)")

            # Cleanup
            llama.cleanup()
            return True
        else:
            print("❌ Llama model failed to load")
            return False

    except Exception as e:
        print(f"❌ Error testing model: {e}")

        # Check for common issues
        if "No such file or directory" in str(e):
            print(
                "\n💡 Suggestion: Model may not be downloaded. Run 'python setup_llama.py'")
        elif "CUDA" in str(e):
            print(
                "\n💡 Suggestion: CUDA issue detected. Model will fall back to CPU (slower)")
        elif "memory" in str(e).lower():
            print(
                "\n💡 Suggestion: Insufficient memory. Try enabling quantization in .env")
        elif "access" in str(e).lower() or "gated" in str(e).lower():
            print("\n💡 Suggestion: Model access required. Visit https://huggingface.co/meta-llama/Meta-Llama-3.1-8B-Instruct")

        return False


def test_integration_with_agents():
    """Test integration with the test case agent."""
    print("\n🔗 Testing integration with test case agent...")

    try:
        from agents.test_case_agent import TestCaseAgent

        agent = TestCaseAgent()
        print("✅ Test case agent initialized")

        # Test LLM generation through agent
        recon_data = {
            'subdomains': ['www.test.com', 'api.test.com'],
            'technologies': [{'name': 'nginx'}, {'name': 'php'}]
        }

        scan_data = {
            'target': 'test.com',
            'open_ports': [
                {'port': 80, 'service': 'http', 'state': 'open'},
                {'port': 443, 'service': 'https', 'state': 'open'}
            ]
        }

        # This should try Llama first, then fall back to API models
        print("Testing LLM test case generation through agent...")
        import asyncio

        async def test_generation():
            return await agent.generate_llm_test_cases(recon_data, scan_data)

        test_cases = asyncio.run(test_generation())

        if test_cases:
            print(f"✅ Agent generated {len(test_cases)} test cases via LLM")
        else:
            print("⚠️ No test cases generated (may fall back to API models)")

        return True

    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        return False


def main():
    """Run all tests."""
    print("🦙 Llama 3.1 8B Integration Test Suite")
    print("=" * 50)

    tests = [
        ("Import Test", test_llama_import),
        ("Dependencies Test", test_dependencies),
        ("Model Loading Test", test_model_loading),
        ("Agent Integration Test", test_integration_with_agents)
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        print(f"\n📋 {test_name}")
        print("-" * 30)

        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} PASSED")
            else:
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            print(f"❌ {test_name} FAILED with exception: {e}")

    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! Llama integration is working correctly.")
        print("\nYou can now:")
        print("1. Run the cybersecurity dashboard: python main.py dashboard")
        print("2. Create assessments with LLM test case generation")
        print("3. Check Llama status in dashboard Settings")
    else:
        print("⚠️ Some tests failed. See suggestions above.")
        print("\nTroubleshooting:")
        print("1. Run: python setup_llama.py")
        print("2. Ensure you have sufficient RAM (16GB+ recommended)")
        print("3. Check HuggingFace access if model download failed")

    return passed == total


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⏹️ Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
