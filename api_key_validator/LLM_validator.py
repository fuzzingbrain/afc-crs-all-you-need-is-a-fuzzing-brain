#!/usr/bin/env python3
"""
LLM API Key Validator
Supports validation of API keys for multiple large language models

Supported APIs:
- OpenAI (GPT-3.5, GPT-4, etc.)
- Anthropic (Claude)
- Google Gemini
- xAI (Grok)
"""

import os
import sys
import requests
import json
import argparse
from typing import Dict, Tuple, Optional
from dotenv import load_dotenv
import time

class LLMValidator:
    """LLM API Key Validator Class"""
    
    def __init__(self, advanced_mode=False):
        """Initialize validator"""
        # Load environment variables
        load_dotenv()
        
        self.advanced_mode = advanced_mode
        
        # API endpoints
        self.endpoints = {
            'openai': 'https://api.openai.com/v1/chat/completions',
            'anthropic': 'https://api.anthropic.com/v1/messages',
            'gemini': 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent',
            'xai': 'https://api.x.ai/v1/chat/completions'
        }
        
        # API key environment variable names
        self.api_keys = {
            'openai': os.getenv('OPENAI_API_KEY'),
            'anthropic': os.getenv('ANTHROPIC_API_KEY'),
            'gemini': os.getenv('GEMINI_API_KEY'),
            'xai': os.getenv('XAI_API_KEY')
        }
        
        # Advanced models for testing
        self.advanced_models = {
            'openai': 'gpt-5-2025-08-07',
            'anthropic': 'claude-sonnet-4-20250514',
            'gemini': 'gemini-2.5-flash',
            'xai': 'grok-3'
        }
        
        # Test question
        self.test_question = "What is 2+2? Answer with just the number."
    
    def validate_openai(self) -> Tuple[bool, str]:
        """Validate OpenAI API key"""
        if not self.api_keys['openai']:
            return False, "OPENAI_API_KEY environment variable not found"
        
        try:
            headers = {
                'Authorization': f'Bearer {self.api_keys["openai"]}',
                'Content-Type': 'application/json'
            }
            
            if self.advanced_mode:
                # Use advanced model to test with actual question
                model = self.advanced_models['openai']
                data = {
                    'model': model,
                    'messages': [{'role': 'user', 'content': self.test_question}],
                    'temperature': 1
                }
                
                response = requests.post(self.endpoints['openai'], headers=headers, json=data, timeout=15)
                
                if response.status_code == 200:
                    result = response.json()
                    answer = result['choices'][0]['message']['content'].strip()
                    usage = result.get('usage', {})
                    model_info = result.get('model', model)
                    
                    info_lines = [
                        f"✅ OpenAI API key is valid",
                        f"Model: {model_info}",
                        f"Test answer: {answer}",
                        f"Tokens used: {usage.get('total_tokens', 'N/A')}",
                        f"Prompt tokens: {usage.get('prompt_tokens', 'N/A')}",
                        f"Completion tokens: {usage.get('completion_tokens', 'N/A')}"
                    ]
                    return True, "\n".join(info_lines)
                elif response.status_code == 401:
                    return False, "❌ OpenAI API key is invalid or expired"
                elif response.status_code == 404:
                    return False, f"❌ Model {model} not available (may not be released yet)"
                else:
                    error_detail = response.text[:200] if response.text else "No error details"
                    return False, f"❌ OpenAI API request failed: {response.status_code}\nError: {error_detail}"
            else:
                # Basic validation - just check models endpoint
                models_url = 'https://api.openai.com/v1/models'
                response = requests.get(models_url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    models = response.json().get('data', [])
                    model_names = [model.get('id', '') for model in models[:5]]
                    return True, f"✅ OpenAI API key is valid\nAvailable models: {', '.join(model_names)}"
                else:
                    return False, f"❌ OpenAI API request failed: {response.status_code} - {response.text}"
                
        except requests.exceptions.RequestException as e:
            return False, f"❌ OpenAI API connection error: {str(e)}"
        except Exception as e:
            return False, f"❌ OpenAI validation error: {str(e)}"
    
    def validate_anthropic(self) -> Tuple[bool, str]:
        """Validate Anthropic API key"""
        if not self.api_keys['anthropic']:
            return False, "ANTHROPIC_API_KEY environment variable not found"
        
        try:
            headers = {
                'x-api-key': self.api_keys['anthropic'],
                'Content-Type': 'application/json',
                'anthropic-version': '2023-06-01'
            }
            
            if self.advanced_mode:
                # Use advanced model to test with actual question
                model = self.advanced_models['anthropic']
                data = {
                    'model': model,
                    'max_tokens': 10,
                    'messages': [{'role': 'user', 'content': self.test_question}]
                }
                
                response = requests.post(
                    self.endpoints['anthropic'], 
                    headers=headers, 
                    json=data, 
                    timeout=15
                )
                
                if response.status_code == 200:
                    result = response.json()
                    answer = result['content'][0]['text'].strip()
                    usage = result.get('usage', {})
                    model_info = result.get('model', model)
                    
                    info_lines = [
                        f"✅ Anthropic API key is valid",
                        f"Model: {model_info}",
                        f"Test answer: {answer}",
                        f"Input tokens: {usage.get('input_tokens', 'N/A')}",
                        f"Output tokens: {usage.get('output_tokens', 'N/A')}",
                        f"Stop reason: {result.get('stop_reason', 'N/A')}"
                    ]
                    return True, "\n".join(info_lines)
                elif response.status_code == 404:
                    return False, f"❌ Model {model} not available (may not be released yet)"
                else:
                    error_detail = response.text[:200] if response.text else "No error details"
                    return False, f"❌ Anthropic API request failed: {response.status_code}\nError: {error_detail}"
            else:
                # Basic validation - use simple test message
                data = {
                    'model': 'claude-sonnet-4-20250514',
                    'max_tokens': 10,
                    'messages': [{'role': 'user', 'content': 'Hello'}]
                }
                
                response = requests.post(
                    self.endpoints['anthropic'], 
                    headers=headers, 
                    json=data, 
                    timeout=10
                )
                
                if response.status_code == 200:
                    return True, "✅ Anthropic API key is valid"
                else:
                    return False, f"❌ Anthropic API request failed: {response.status_code} - {response.text}"
                
        except requests.exceptions.RequestException as e:
            return False, f"❌ Anthropic API connection error: {str(e)}"
        except Exception as e:
            return False, f"❌ Anthropic validation error: {str(e)}"
    
    def validate_gemini(self) -> Tuple[bool, str]:
        """Validate Google Gemini API key"""
        if not self.api_keys['gemini']:
            return False, "GEMINI_API_KEY environment variable not found"
        
        try:
            if self.advanced_mode:
                # Use advanced model to test with actual question
                model = self.advanced_models['gemini']
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_keys['gemini']}"
                
                data = {
                    "contents": [{
                        "parts": [{"text": self.test_question}]
                    }],
                    "generationConfig": {
                        "maxOutputTokens": 100,
                        "temperature": 0
                    }
                }
                
                response = requests.post(url, json=data, timeout=15)
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Check if response has the expected structure
                    if 'candidates' not in result or not result['candidates']:
                        return False, f"❌ Google Gemini API response format error: No candidates in response\nResponse: {str(result)[:200]}"
                    
                    candidate = result['candidates'][0]
                    usage = result.get('usageMetadata', {})
                    finish_reason = candidate.get('finishReason', 'N/A')
                    
                    # Check if the response was truncated due to max tokens
                    if finish_reason == 'MAX_TOKENS':
                        return False, f"❌ Google Gemini API response truncated (MAX_TOKENS)\nModel: {model}\nFinish reason: {finish_reason}\nPrompt tokens: {usage.get('promptTokenCount', 'N/A')}\nTotal tokens: {usage.get('totalTokenCount', 'N/A')}\nTry increasing maxOutputTokens in the request"
                    
                    # Check if there's actual content
                    if 'content' not in candidate:
                        return False, f"❌ Google Gemini API response format error: No content in candidate\nResponse: {str(result)[:200]}"
                    
                    content = candidate['content']
                    
                    # Handle different content formats
                    if 'parts' in content and content['parts']:
                        # Traditional format with parts
                        if 'text' in content['parts'][0]:
                            answer = content['parts'][0]['text'].strip()
                        else:
                            return False, f"❌ Google Gemini API response format error: No text in parts\nResponse: {str(result)[:200]}"
                    elif 'text' in content:
                        # Direct text format
                        answer = content['text'].strip()
                    else:
                        # Only role information, no actual content
                        return False, f"❌ Google Gemini API returned no content\nModel: {model}\nFinish reason: {finish_reason}\nContent: {content}\nPrompt tokens: {usage.get('promptTokenCount', 'N/A')}\nTotal tokens: {usage.get('totalTokenCount', 'N/A')}"
                    
                    # Check if answer is empty
                    if not answer:
                        return False, f"❌ Google Gemini API returned empty response\nModel: {model}\nFinish reason: {finish_reason}\nPrompt tokens: {usage.get('promptTokenCount', 'N/A')}\nResponse tokens: {usage.get('candidatesTokenCount', 'N/A')}\nTotal tokens: {usage.get('totalTokenCount', 'N/A')}"
                    
                    info_lines = [
                        f"✅ Google Gemini API key is valid",
                        f"Model: {model}",
                        f"Test answer: {answer}",
                        f"Finish reason: {finish_reason}",
                        f"Prompt tokens: {usage.get('promptTokenCount', 'N/A')}",
                        f"Response tokens: {usage.get('candidatesTokenCount', 'N/A')}",
                        f"Total tokens: {usage.get('totalTokenCount', 'N/A')}"
                    ]
                    return True, "\n".join(info_lines)
                elif response.status_code == 400:
                    error_detail = response.text[:200] if response.text else "No error details"
                    return False, f"❌ Model {model} not available or API key invalid\nError: {error_detail}"
                else:
                    error_detail = response.text[:200] if response.text else "No error details"
                    return False, f"❌ Google Gemini API request failed: {response.status_code}\nError: {error_detail}"
            else:
                # Basic validation - check models endpoint
                models_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={self.api_keys['gemini']}"
                response = requests.get(models_url, timeout=10)
                
                if response.status_code == 200:
                    models = response.json().get('models', [])
                    model_names = [model.get('name', '').split('/')[-1] for model in models[:5]]
                    return True, f"✅ Google Gemini API key is valid\nAvailable models: {', '.join(model_names)}"
                else:
                    return False, f"❌ Google Gemini API request failed: {response.status_code} - {response.text}"
                
        except requests.exceptions.RequestException as e:
            return False, f"❌ Google Gemini API connection error: {str(e)}"
        except Exception as e:
            return False, f"❌ Google Gemini validation error: {str(e)}"
    
    def validate_xai(self) -> Tuple[bool, str]:
        """Validate xAI API key"""
        if not self.api_keys['xai']:
            return False, "XAI_API_KEY environment variable not found"
        
        try:
            headers = {
                'Authorization': f'Bearer {self.api_keys["xai"]}',
                'Content-Type': 'application/json'
            }
            
            if self.advanced_mode:
                # Use advanced model to test with actual question
                model = self.advanced_models['xai']
                data = {
                    'model': model,
                    'messages': [{'role': 'user', 'content': self.test_question}],
                    'max_tokens': 100,
                    'temperature': 0.2
                }
                
                response = requests.post(self.endpoints['xai'], headers=headers, json=data, timeout=15)
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Check if response has the expected structure
                    if 'choices' not in result or not result['choices']:
                        return False, f"❌ xAI API response format error: No choices in response\nResponse: {str(result)[:200]}"
                    
                    choice = result['choices'][0]
                    if 'message' not in choice or 'content' not in choice['message']:
                        return False, f"❌ xAI API response format error: Invalid message structure\nResponse: {str(result)[:200]}"
                    
                    answer = choice['message']['content'].strip()
                    usage = result.get('usage', {})
                    model_info = result.get('model', model)
                    
                    # Check if answer is empty
                    if not answer:
                        return False, f"❌ xAI API returned empty response\nModel: {model_info}\nTokens used: {usage.get('total_tokens', 'N/A')}\nPrompt tokens: {usage.get('prompt_tokens', 'N/A')}\nCompletion tokens: {usage.get('completion_tokens', 'N/A')}"
                    
                    info_lines = [
                        f"✅ xAI API key is valid",
                        f"Model: {model_info}",
                        f"Test answer: {answer}",
                        f"Tokens used: {usage.get('total_tokens', 'N/A')}",
                        f"Prompt tokens: {usage.get('prompt_tokens', 'N/A')}",
                        f"Completion tokens: {usage.get('completion_tokens', 'N/A')}"
                    ]
                    return True, "\n".join(info_lines)
                elif response.status_code == 404:
                    return False, f"❌ Model {model} not available (may not be released yet)"
                else:
                    error_detail = response.text[:200] if response.text else "No error details"
                    return False, f"❌ xAI API request failed: {response.status_code}\nError: {error_detail}"
            else:
                # Basic validation - check models endpoint
                models_url = 'https://api.x.ai/v1/models'
                response = requests.get(models_url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    models = response.json().get('data', [])
                    model_names = [model.get('id', '') for model in models[:5]]
                    return True, f"✅ xAI API key is valid\nAvailable models: {', '.join(model_names)}"
                else:
                    return False, f"❌ xAI API request failed: {response.status_code} - {response.text}"
                
        except requests.exceptions.RequestException as e:
            return False, f"❌ xAI API connection error: {str(e)}"
        except Exception as e:
            return False, f"❌ xAI validation error: {str(e)}"
    
    def validate_all(self) -> Dict[str, Tuple[bool, str]]:
        """Validate all API keys"""
        results = {}
        
        mode_text = "Advanced Mode (Testing with latest models)" if self.advanced_mode else "Basic Mode (Model list validation)"
        print(f"🔍 Starting LLM API key validation... [{mode_text}]")
        print("=" * 50)
        
        # Validate each API
        apis = {
            'OpenAI': self.validate_openai,
            'Anthropic': self.validate_anthropic,
            'Google Gemini': self.validate_gemini,
            'xAI': self.validate_xai
        }
        
        for api_name, validate_func in apis.items():
            print(f"\n🔑 Validating {api_name} API key...")
            try:
                is_valid, message = validate_func()
                results[api_name] = (is_valid, message)
                print(message)
            except Exception as e:
                error_msg = f"❌ Error occurred during {api_name} validation: {str(e)}"
                results[api_name] = (False, error_msg)
                print(error_msg)
            
            # Add delay to avoid too frequent requests
            time.sleep(1)
        
        return results
    
    def print_summary(self, results: Dict[str, Tuple[bool, str]]):
        """Print validation results summary"""
        print("\n" + "=" * 50)
        print("📊 Validation Results Summary:")
        print("=" * 50)
        
        valid_count = 0
        total_count = len(results)
        
        for api_name, (is_valid, message) in results.items():
            status = "✅ Valid" if is_valid else "❌ Invalid"
            print(f"{api_name:15} : {status}")
            if is_valid:
                valid_count += 1
        
        print(f"\nTotal: {valid_count}/{total_count} API keys are valid")
        
        if valid_count == 0:
            print("\n⚠️  Warning: No valid API keys found!")
            print("Please check:")
            print("1. .env file exists and contains correct API keys")
            print("2. API keys are valid and not expired")
            print("3. Network connection is working")
        elif valid_count < total_count:
            print(f"\n⚠️  Note: {total_count - valid_count} API keys are invalid or not configured")
        else:
            print("\n🎉 All API keys are valid!")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='LLM API Key Validator')
    parser.add_argument('--advanced', action='store_true', 
                       help='Use advanced mode to test with latest models (GPT-5, Claude Sonnet 4, Gemini 2.5 Flash, Grok-3)')
    args = parser.parse_args()
    
    print("🤖 LLM API Key Validator")
    print("=" * 50)
    
    if args.advanced:
        print("🚀 Advanced Mode: Testing with latest models")
        print("Models to test:")
        print("  - OpenAI: GPT-5 (gpt-5-2025-08-07)")
        print("  - Anthropic: Claude Sonnet 4 (claude-sonnet-4-20250514)")
        print("  - Google: Gemini 2.5 Flash (gemini-2.5-flash)")
        print("  - xAI: Grok-3 (grok-3)")
        print("  - Test question: 'What is 2+2? Answer with just the number.'")
        print()
    
    # Check if .env file exists
    if not os.path.exists('.env'):
        print("⚠️  .env file not found")
        print("Please create .env file and add your API keys:")
        print("OPENAI_API_KEY=your_openai_key")
        print("ANTHROPIC_API_KEY=your_anthropic_key")
        print("GEMINI_API_KEY=your_gemini_key")
        print("XAI_API_KEY=your_xai_key")
        print("\nOr set the corresponding environment variables")
        
        # Ask if continue
        response = input("\nContinue validating already set environment variables? (y/n): ").lower()
        if response != 'y':
            sys.exit(0)
    
    # Create validator and run validation
    validator = LLMValidator(advanced_mode=args.advanced)
    results = validator.validate_all()
    validator.print_summary(results)

if __name__ == "__main__":
    main()
