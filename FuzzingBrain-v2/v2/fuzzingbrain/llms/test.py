#!/usr/bin/env python3
"""
LLM Configuration Test Script

Tests if the configuration is correct and API keys are valid.

Usage:
    python -m fuzzingbrain.llms.test
"""

import sys
from pathlib import Path

# Add parent to path for direct execution
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from fuzzingbrain.llms import (
    LLMClient,
    LLMConfig,
    reload_config,
    Provider,
    LLMError,
    LLMAllModelsFailedError,
    # Models for each provider
    CLAUDE_SONNET_4_5,
    GPT_5_2,
    GEMINI_3_FLASH,
    GROK_3,
)


def print_header(text: str) -> None:
    """Print section header"""
    print()
    print("=" * 60)
    print(f"  {text}")
    print("=" * 60)


def print_status(name: str, status: bool, detail: str = "") -> None:
    """Print status line"""
    icon = "✓" if status else "✗"
    color = "\033[92m" if status else "\033[91m"
    reset = "\033[0m"
    print(f"  {color}{icon}{reset} {name}", end="")
    if detail:
        print(f" - {detail}")
    else:
        print()


def test_config() -> LLMConfig:
    """Test configuration loading"""
    print_header("Configuration Check")

    config = reload_config()
    print(f"  Source: {config.config_source}")
    print(f"  Default Model: {config.default_model.name} ({config.default_model.id})")
    print(f"  Fallback: {'Enabled' if config.fallback_enabled else 'Disabled'}")
    print(f"  Temperature: {config.temperature}")
    print(f"  Timeout: {config.timeout}s")

    return config


def test_api_keys(config: LLMConfig) -> dict:
    """Test API key availability"""
    print_header("API Key Check")

    results = {}
    for provider in Provider:
        has_key = config.has_api_key(provider)
        key = config.get_api_key(provider)
        if has_key and key:
            # Mask the key
            masked = key[:8] + "..." + key[-4:] if len(key) > 12 else "***"
            print_status(provider.value, True, masked)
            results[provider] = True
        else:
            print_status(provider.value, False, "Not configured")
            results[provider] = False

    available = [p.value for p, v in results.items() if v]
    if available:
        print(f"\n  Available Providers: {', '.join(available)}")
    else:
        print("\n  ⚠️  No API Keys configured!")
        print("  Edit fuzzingbrain/llm_config.yaml or set environment variables")

    return results


def test_each_provider(config: LLMConfig, api_results: dict) -> dict:
    """Test each provider individually"""
    print_header("Provider Test (Individual)")

    # Map providers to their test models
    provider_models = {
        Provider.ANTHROPIC: ("Claude Sonnet 4.5", CLAUDE_SONNET_4_5),
        Provider.OPENAI: ("GPT-5.2", GPT_5_2),
        Provider.GOOGLE: ("Gemini 3 Flash", GEMINI_3_FLASH),
        Provider.XAI: ("Grok 3", GROK_3),
    }

    results = {}

    for provider, (model_name, model) in provider_models.items():
        if not api_results.get(provider, False):
            print(f"\n  [{provider.value}] {model_name}")
            print_status("Skipped", False, "No API Key")
            results[provider] = None
            continue

        print(f"\n  [{provider.value}] {model_name} ({model.id})")

        # Create client with fallback disabled
        test_config = LLMConfig(
            default_model=model,
            fallback_enabled=False,
            api_keys=config.api_keys,
        )
        client = LLMClient(test_config)

        try:
            response = client.call(
                messages=[{"role": "user", "content": "What is 2+2? Reply with just the number."}],
                model=model,
                max_tokens=10,
            )

            print_status("SUCCESS", True)
            print(f"    Response: {response.content.strip()}")
            print(f"    Latency: {response.latency_ms:.0f}ms")
            print(f"    Tokens: {response.input_tokens} in / {response.output_tokens} out")
            results[provider] = True

        except Exception as e:
            print_status("FAILED", False)
            error_msg = str(e)
            # Truncate long error messages
            if len(error_msg) > 80:
                error_msg = error_msg[:77] + "..."
            print(f"    Error: {error_msg}")
            results[provider] = False

    return results


def test_default_model(config: LLMConfig) -> bool:
    """Test default model call"""
    print_header("Default Model Test")

    available_providers = config.get_available_providers()
    if not available_providers:
        print("  ⚠️  Skipped - No API Key available")
        return False

    print(f"  Model: {config.default_model.name}")
    print(f"  Question: What is the capital of France?")
    print()

    try:
        client = LLMClient(config)
        response = client.call(
            messages=[
                {"role": "user", "content": "What is the capital of France? Reply in one sentence."}
            ],
            max_tokens=100,
        )

        print_status("Call Success", True)
        print(f"\n  Response: {response.content.strip()}")
        print(f"\n  Model: {response.model}")
        print(f"  Tokens: {response.input_tokens} in / {response.output_tokens} out")
        print(f"  Latency: {response.latency_ms:.0f}ms")

        if response.fallback_used:
            print(f"  ⚠️  Fallback used (original: {response.original_model})")

        # Verify answer
        answer = response.content.lower()
        if "paris" in answer:
            print_status("Answer Correct", True, "Paris is the capital of France")
        else:
            print_status("Answer Check", False, "Answer may be incorrect")

        return True

    except LLMAllModelsFailedError as e:
        print_status("Call Failed", False, "All models failed")
        print(f"  Tried models: {', '.join(e.tried_models)}")
        return False

    except LLMError as e:
        print_status("Call Failed", False, str(e))
        return False

    except Exception as e:
        print_status("Call Failed", False, f"{type(e).__name__}: {e}")
        return False


def main():
    """Run all tests"""
    print()
    print("╔════════════════════════════════════════════════════════════╗")
    print("║           FuzzingBrain LLM Configuration Test              ║")
    print("╚════════════════════════════════════════════════════════════╝")

    # Test config
    config = test_config()

    # Test API keys
    api_results = test_api_keys(config)

    # Test each provider individually
    provider_results = test_each_provider(config, api_results)

    # Test default model
    test_default_model(config)

    # Summary
    print_header("Test Summary")

    providers_configured = sum(1 for v in api_results.values() if v)
    providers_working = sum(1 for v in provider_results.values() if v is True)
    providers_failed = sum(1 for v in provider_results.values() if v is False)

    print(f"  API Keys Configured: {providers_configured}/{len(api_results)}")
    print(f"  Providers Working: {providers_working}/{providers_configured}")

    if providers_failed > 0:
        failed_names = [p.value for p, v in provider_results.items() if v is False]
        print(f"  Providers Failed: {', '.join(failed_names)}")

    print()
    if providers_working > 0:
        print_status("LLM Module", True, "Ready to use")
        print("\n  🎉 Configuration complete!")
        return 0
    else:
        if providers_configured == 0:
            print_status("LLM Module", False, "Need API Key")
            print("\n  📝 Setup steps:")
            print("     1. Copy fuzzingbrain/llm_config.yaml")
            print("        -> fuzzingbrain/llm_config.local.yaml")
            print("     2. Fill in your API Key(s)")
            print("     3. Run this test again")
        else:
            print_status("LLM Module", False, "Check errors above")

        return 1


if __name__ == "__main__":
    sys.exit(main())
