#!/usr/bin/env python3
"""
Llama 3.1 8B Setup Script for Cybersecurity Automation System
Downloads and configures the Llama 3.1 8B model for local inference.
"""

import os
import sys
import subprocess
import logging
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def check_system_requirements():
    """Check if system meets minimum requirements for Llama 3.1 8B."""
    print("🔍 Checking system requirements...")

    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ is required")
        return False
    else:
        print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}")

    # Check available memory (rough estimate)
    try:
        import psutil
        memory_gb = psutil.virtual_memory().total / (1024**3)
        if memory_gb < 8:
            print(
                f"⚠️ Warning: Only {memory_gb:.1f}GB RAM available. 16GB+ recommended for Llama 3.1 8B")
        else:
            print(f"✅ Memory: {memory_gb:.1f}GB available")
    except ImportError:
        print("⚠️ Cannot check memory (psutil not installed)")

    # Check CUDA availability
    try:
        import torch
        if torch.cuda.is_available():
            gpu_count = torch.cuda.device_count()
            gpu_memory = torch.cuda.get_device_properties(
                0).total_memory / (1024**3)
            print(
                f"✅ CUDA available: {gpu_count} GPU(s), {gpu_memory:.1f}GB VRAM")
        else:
            print("⚠️ CUDA not available - will use CPU (slower)")
    except ImportError:
        print("⚠️ PyTorch not installed - will install with dependencies")

    return True


def install_dependencies():
    """Install required dependencies for Llama integration."""
    print("\n📦 Installing Llama dependencies...")

    dependencies = [
        "torch>=2.0.0",
        "transformers>=4.40.0",
        "accelerate>=0.20.0",
        "bitsandbytes>=0.41.0",
        "sentencepiece>=0.1.99",
        "huggingface-hub>=0.16.0"
    ]

    for dep in dependencies:
        try:
            print(f"Installing {dep}...")
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", dep, "--quiet"
            ])
            print(f"✅ {dep} installed")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {dep}: {e}")
            return False

    return True


def setup_huggingface_cache():
    """Setup HuggingFace cache directory."""
    print("\n📁 Setting up HuggingFace cache...")

    cache_dir = Path.home() / ".cache" / "huggingface"
    cache_dir.mkdir(parents=True, exist_ok=True)

    print(f"✅ Cache directory: {cache_dir}")
    return str(cache_dir)


def download_model():
    """Download and cache the Llama 3.1 8B model."""
    print("\n⬇️ Downloading Llama 3.1 8B model...")
    print("Note: This may take a while (model is ~16GB)")

    try:
        from transformers import AutoTokenizer, AutoModelForCausalLM

        model_name = "meta-llama/Meta-Llama-3.1-8B-Instruct"

        print("Downloading tokenizer...")
        tokenizer = AutoTokenizer.from_pretrained(
            model_name,
            trust_remote_code=True
        )

        print("Downloading model (this will take time)...")
        model = AutoModelForCausalLM.from_pretrained(
            model_name,
            trust_remote_code=True,
            torch_dtype="auto",
            device_map="auto"
        )

        print("✅ Model downloaded and cached successfully")
        return True

    except Exception as e:
        print(f"❌ Error downloading model: {e}")

        if "gated repo" in str(e).lower() or "access" in str(e).lower():
            print("\n🔐 Model Access Required:")
            print("1. Go to https://huggingface.co/meta-llama/Meta-Llama-3.1-8B-Instruct")
            print("2. Request access to the model")
            print("3. Create a HuggingFace account if you don't have one")
            print("4. Generate an access token at https://huggingface.co/settings/tokens")
            print("5. Run: huggingface-cli login")
            print("6. Enter your access token when prompted")

        return False


def test_model():
    """Test the Llama model integration."""
    print("\n🧪 Testing Llama integration...")

    try:
        from utils.llama_integration import LlamaIntegration

        llama = LlamaIntegration()

        if llama.is_available():
            print("✅ Llama integration successful")

            # Test generation
            test_data = {
                'target': 'test.example.com',
                'target_type': 'domain'
            }
            scan_results = [
                {'port': 80, 'service': 'http', 'state': 'open'},
                {'port': 443, 'service': 'https', 'state': 'open'}
            ]

            print("Testing test case generation...")
            test_cases = llama.generate_test_cases(test_data, scan_results)

            if test_cases:
                print(f"✅ Generated {len(test_cases)} test cases")
                print("Sample test case:")
                print(f"  - {test_cases[0].get('name', 'Unknown')}")
            else:
                print("⚠️ No test cases generated (may be normal)")

            # Cleanup
            llama.cleanup()
            return True
        else:
            print("❌ Llama model not available")
            return False

    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        return False


def setup_environment():
    """Setup environment variables for Llama."""
    print("\n⚙️ Setting up environment...")

    env_file = Path(".env")

    # Read existing .env
    env_vars = {}
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key] = value

    # Set Llama defaults if not present
    llama_defaults = {
        'LLAMA_MAX_LENGTH': '4096',
        'LLAMA_TEMPERATURE': '0.7',
        'LLAMA_USE_QUANTIZATION': 'true'
    }

    updated = False
    for key, default_value in llama_defaults.items():
        if key not in env_vars:
            env_vars[key] = default_value
            updated = True
            print(f"✅ Set {key}={default_value}")

    if updated:
        # Write back to .env
        with open(env_file, 'w') as f:
            for key, value in env_vars.items():
                f.write(f"{key}={value}\n")
        print("✅ Environment variables updated")
    else:
        print("✅ Environment already configured")


def main():
    """Main setup function."""
    print("🦙 Llama 3.1 8B Setup for Cybersecurity Automation")
    print("=" * 60)

    # Check requirements
    if not check_system_requirements():
        print("\n❌ System requirements not met")
        return False

    # Setup environment
    setup_environment()

    # Install dependencies
    if not install_dependencies():
        print("\n❌ Failed to install dependencies")
        return False

    # Setup cache
    setup_huggingface_cache()

    # Download model
    if not download_model():
        print("\n❌ Failed to download model")
        print("\nTroubleshooting:")
        print("1. Ensure you have internet connection")
        print("2. Check HuggingFace access permissions")
        print("3. Try running: huggingface-cli login")
        return False

    # Test integration
    if not test_model():
        print("\n⚠️ Model downloaded but integration test failed")
        print("You may need to restart the application")

    print("\n" + "=" * 60)
    print("🎉 Llama 3.1 8B setup completed!")
    print("\nNext steps:")
    print("1. Restart the cybersecurity dashboard")
    print("2. Go to Settings to verify Llama status")
    print("3. Create a new assessment with LLM test case generation enabled")
    print("\nMemory usage notes:")
    print("- With quantization: ~8-12GB RAM")
    print("- Without quantization: ~16-20GB RAM")
    print("- GPU recommended for better performance")

    return True


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⏹️ Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
