# strategy 0
#!/usr/bin/env python3
"""
Strategy 0: LLM-guided test harness generation for vulnerability triggering
"""

import os
import sys
import time
import logging
import datetime
import re
import subprocess
import json
import argparse
import requests
import base64
import random
from pathlib import Path
import tempfile
import shutil
import glob
import tarfile
from litellm import completion
from dotenv import load_dotenv
from typing import Optional, Dict, List, Any, Union, Tuple
import concurrent.futures
import uuid
import pprint

load_dotenv()

import openlit
from opentelemetry import trace
# Initialize openlit
openlit.init(application_name="afc-crs-all-you-need-is-a-fuzzing-brain")
# Acquire a tracer
tracer = trace.get_tracer(__name__)
# for testing only on Nginx
TEST_NGINX = False
GLOBAL_FUNCTION_METADATA = {}

DO_PATCH = False
DO_PATCH_ONLY = False
FULL_SCAN = False
USE_CONTROL_FLOW = True
POV_METADATA_DIR = "successful_povs"
POV_SUCCESS_DIR = f"/tmp/{POV_METADATA_DIR}"
PATCH_METADATA_DIR = "successful_patches"
PATCH_SUCCESS_DIR = f"/tmp/{PATCH_METADATA_DIR}"

PATCH_WORKSPACE_DIR = "patch_workspace"
SUCCESS_PATCH_METADATA_FILE="successful_patch_metadata.json"
DETECT_TIMEOUT_CRASH_SENTINEL = "detect_timeout_crash"

# Constants
MAX_ITERATIONS = 5
FUZZING_TIMEOUT_MINUTES = 45
PATCHING_TIMEOUT_MINUTES = 30
OPENAI_MODEL = "chatgpt-4o-latest"
OPENAI_MODEL_4O_MINI="gpt-4o-mini"
OPENAI_MODEL_O1 = "o1"
OPENAI_MODEL_O1_PRO = "o1-pro"
OPENAI_MODEL_O3 = "o3"
OPENAI_MODEL_O3_MINI = "o3-mini"
OPENAI_MODEL_O4_MINI = "o4-mini"
OPENAI_MODEL_41 = "gpt-4.1"
OPENAI_MODEL_45 = "gpt-4.5-preview"
# OPENAI_MODEL = "chatgpt-4o-latest"
# CLAUDE_MODEL = "gpt-4o-mini"
CLAUDE_MODEL = "claude-3-7-sonnet-latest"
CLAUDE_MODEL_35 = "claude-3-5-sonnet-20241022"
GEMINI_MODEL_PRO_25_0325 = "gemini-2.5-pro-preview-03-25"
GEMINI_MODEL_PRO_25_0506 = "gemini-2.5-pro-preview-05-06"
GEMINI_MODEL_PRO_25 = "gemini-2.5-pro"
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_MODEL_PRO = "gemini-2.0-pro-exp-02-05"
GEMINI_MODEL_FLASH = "gemini-2.5-flash"
GEMINI_MODEL_FLASH_20 = "gemini-2.0-flash"
GEMINI_MODEL_FLASH_LITE = "gemini-2.5-flash-lite-preview-06-17"
GROK_MODEL = "xai/grok-3-beta"
CLAUDE_MODEL_SONNET_4 = "claude-sonnet-4-20250514"
CLAUDE_MODEL_OPUS_4 = "claude-opus-4-20250514"
MODELS = [CLAUDE_MODEL, OPENAI_MODEL, CLAUDE_MODEL_OPUS_4, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25]
CLAUDE_MODEL = CLAUDE_MODEL_SONNET_4
OPENAI_MODEL = CLAUDE_MODEL_SONNET_4
MODELS = [CLAUDE_MODEL_SONNET_4, CLAUDE_MODEL_OPUS_4]

def get_fallback_model(current_model, tried_models):
    """Get a fallback model that hasn't been tried yet"""
    # Define model fallback chains
    fallback_chains = {
        GEMINI_MODEL_PRO_25: [GEMINI_MODEL_FLASH, GEMINI_MODEL_FLASH_20, CLAUDE_MODEL, CLAUDE_MODEL_35, OPENAI_MODEL_41, OPENAI_MODEL_O3],   
        OPENAI_MODEL_41: [OPENAI_MODEL_O4_MINI, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25],   
        OPENAI_MODEL: [GEMINI_MODEL_PRO_25, GEMINI_MODEL_FLASH, GEMINI_MODEL_FLASH_LITE],             
        CLAUDE_MODEL: [CLAUDE_MODEL_SONNET_4,OPENAI_MODEL, CLAUDE_MODEL_35, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25],        
        # Default fallbacks
        "default": [CLAUDE_MODEL, OPENAI_MODEL, OPENAI_MODEL_41,OPENAI_MODEL_O3,GEMINI_MODEL_PRO_25]
    }
    # Get the fallback chain for the current model
    fallback_options = fallback_chains.get(current_model, fallback_chains["default"])
    
    # Find the first model in the fallback chain that hasn't been tried yet
    for model in fallback_options:
        if model not in tried_models:
            return model
    
    # If all models in the chain have been tried, return None
    return None


TEST_QUESTION="""
Hello, are you good at reasoning about code security vulnerabilities such as CWEs?
Limit your response to 100 tokens.
"""

# Logging setup
LOG_DIR = os.environ.get("LOG_DIR", "/tmp/strategy_logs")
os.makedirs(LOG_DIR, exist_ok=True)

def setup_logging(fuzzer_name):
    """Set up logging for the strategy"""
    # Include DO_PATCH_ONLY and FULL_SCAN in the log filename
    patch_status = "patch_only" if DO_PATCH_ONLY else "basic_pov_delta_strategy"
    scan_type = "full_scan" if FULL_SCAN else "delta_scan"
    
    timestamp = int(time.time())
    log_file = os.path.join(LOG_DIR, f"xs0_{fuzzer_name}_{patch_status}_{scan_type}_{timestamp}.log")
    
    # Log initial configuration
    with open(log_file, "w") as f:
        f.write(f"Strategy: XS0\n")
        f.write(f"Fuzzer: {fuzzer_name}\n")
        f.write(f"Timestamp: {timestamp} ({datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')})\n")
        f.write(f"DO_PATCH_ONLY: {DO_PATCH_ONLY}\n")
        f.write(f"FULL_SCAN: {FULL_SCAN}\n")
        f.write(f"FUZZING_TIMEOUT_MINUTES: {FUZZING_TIMEOUT_MINUTES}\n")
        f.write(f"MAX_ITERATIONS: {MAX_ITERATIONS}\n")
        f.write(f"LOG_DIR: {LOG_DIR}\n")
        f.write(f"POV_SUCCESS_DIR: {POV_SUCCESS_DIR}\n")
        f.write(f"MODELS: {', '.join(MODELS)}\n")
        f.write("-" * 80 + "\n")
    
    return log_file

def log_message(log_file, message):
    """Log a message to the log file, print to stdout, and send to telemetry if available"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    
    # Log to file
    with open(log_file, "a") as f:
        f.write(log_entry)
    
    # Print to stdout
    print(message)

def log_cost(log_file, model_name, cost):
    """Log the cost of an LLM call"""
    log_message(log_file, f"Cost for {model_name}: ${cost:.6f}")

def log_time(log_file, start_time, end_time, function_name, description):
    """Log the time taken for a function"""
    duration = end_time - start_time
    log_message(log_file, f"{description}: {duration:.2f} seconds")

def truncate_output(output, max_lines=200):
    """
    Truncate output to show only the first and last parts if it's too long.
    
    Args:
        output: The output string to truncate
        max_lines: Maximum number of lines to show
        
    Returns:
        str: Truncated output
    """
    lines = output.split('\n')
    if len(lines) <= max_lines:
        return output
    
    # Show first 100 and last 100 lines
    first_part = lines[:max_lines//2]
    last_part = lines[-(max_lines//2):]
    
    return '\n'.join(first_part) + '\n\n[...truncated...]\n\n' + '\n'.join(last_part)

def call_gemini_api(log_file, messages, model_name="gemini-1.0-pro") -> (str, bool):
    """Call Gemini API with message history using the chat interface."""

    import google.generativeai as genai
    
    log_message(log_file, f"Calling {model_name} using chat interface...")

    try:
        # Configure Gemini API
        genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
        system_message = None
        # Format messages properly: Replace "content" with "parts", and "assistant" with "model"
        formatted_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_message = msg["content"]
                continue

            role = "model" if msg["role"] == "assistant" else msg["role"]
            formatted_messages.append({
                "role": role,
                "parts": [msg["content"]]  # Ensure content is stored inside "parts"
            })

        # Initialize chat session with formatted history
        model = genai.GenerativeModel(model_name)
        chat = model.start_chat(history=formatted_messages)
        chat.system_instruction = system_message

        # Send the last user message to continue the conversation
        if formatted_messages and formatted_messages[-1]["role"] == "user":
            last_message = formatted_messages[-1]["parts"][0]  # FIXED: Correctly access parts[0]
            # log_message(log_file, f"Sending last user message: {last_message[:50]}...")

            start_time = time.time()
            response = chat.send_message(last_message)
            end_time = time.time()
            
            log_time(log_file, start_time, end_time, "call_gemini_api", f"LLM call to {model_name}")

            if response:
                return response.text, True

        log_message(log_file, "No response received from Gemini")
        return "No response received", False

    except Exception as e:
        log_message(log_file, f"Exception calling Gemini API: {str(e)}")
        return f"Exception: {str(e)}", False



def call_litellm(log_file, messages, model_name) -> (str, bool):
    """Call LiteLLM API with the given messages and model with comprehensive retry logic"""    
    log_message(log_file, f"Calling {model_name}...")
    start_time = time.time()
    
    # Retry parameters
    max_retries = 5
    base_delay = 2  # Start with 2 seconds
    
    # Track models we've tried to implement fallback logic
    current_model = model_name
    log_prefix = "APIError"     
    tried_models_in_this_call = {current_model}

    for attempt in range(max_retries):
        try:
            if attempt > 0:
                log_message(log_file, f"Retry attempt {attempt+1}/{max_retries} using model {current_model}...")
            
            response = completion(
                model=current_model,
                messages=messages,
                temperature=1.0,
                timeout=900
            )
            
            end_time = time.time()
            log_time(log_file, start_time, end_time, "call_litellm", f"LLM call to {current_model}")
            return response['choices'][0]['message']['content'], True
                
        except Exception as e:
            error_str = str(e)
            log_message(log_file, f"Attempt {attempt+1}/{max_retries} failed with model {current_model}: {error_str}")
            
            # Log the messages for debugging
            try:
                # Create a simplified version of messages for logging
                debug_messages = []
                for msg in messages:
                    # Truncate content if it's too long
                    content = msg.get('content', '')
                    if isinstance(content, str) and len(content) > 500:
                        content = content[:500] + "... [truncated]"
                    debug_messages.append({
                        'role': msg.get('role', 'unknown'),
                        'content_length': len(msg.get('content', '')) if isinstance(msg.get('content', ''), str) else 'non-string',
                        'content_preview': content
                    })
                
                log_message(log_file, f"Messages that caused the exception: {json.dumps(debug_messages, indent=2)}")
            except Exception as log_error:
                log_message(log_file, f"Error while logging messages: {str(log_error)}")

            # Determine error type and appropriate action
            # likely OpenAI all API credits are exhausted
            is_auth_error = "AuthenticationError" in error_str or "API_KEY_INVALID" in error_str
            is_overloaded = "Overloaded" in error_str
            is_rate_limited = "rate limit" in error_str.lower() or "too many requests" in error_str.lower()
            is_server_error = "server_error" in error_str or "server had an error" in error_str or "500" in error_str or "API usage limits" in error_str
                        
            # For overloaded/rate limit errors, use exponential backoff
            if (is_auth_error or is_server_error or is_overloaded or is_rate_limited) and attempt < max_retries - 1:
                fallback_model = get_fallback_model(current_model, tried_models_in_this_call)
                log_message(log_file, f"{log_prefix}: Switching from {current_model} to fallback model {fallback_model} due to error.")
                current_model = fallback_model
                tried_models_in_this_call.add(current_model)
                if current_model.startswith("gemini"):
                    try:
                        response_text, response_success = call_gemini_api(log_file, messages, current_model)
                        if response_success:
                            return response_text, response_success
                        else:
                            log_message(log_file, f"Gemini Attempt {attempt+1}/{max_retries} failed with model {current_model}: {error_str}")
                            log_message(log_file, f"Retrying with {GEMINI_MODEL_FLASH}")
                            response = call_gemini_api(log_file, messages, GEMINI_MODEL_FLASH)
                            return response

                    except Exception as e:  
                        error_str = str(e)
                        log_message(log_file, f"Exception in Gemini Attempt {attempt+1}/{max_retries} failed with model {current_model}: {error_str}")
                        continue
                # Use a shorter, fixed delay when switching models before the next attempt
                time.sleep(random.uniform(1, 3)) # Short random delay
                continue # Skip normal backoff, immediately try the fallback model on the next attempt loop iteration
            else:
                log_message(log_file, f"{log_prefix}: Error occurred, but no fallback models left to try. Attempted: {tried_models_in_this_call}")
                # Proceed to normal backoff/failure logic
            
            # For other errors or if we've exhausted model options
            if attempt < max_retries - 1:
                # Still retry other errors with a shorter delay
                delay = base_delay + random.uniform(0, 1)
                log_message(log_file, f"Error occurred. Waiting {delay:.2f} seconds before retry...")
                time.sleep(delay)
            else:
                # This was our last attempt
                log_message(log_file, f"All {max_retries} attempts failed. Giving up.")
                return f"Exception after {max_retries} attempts: {error_str}", False
    
    # Should not be reached if logic is correct
    log_message(log_file, f"Error: call_litellm exited loop unexpectedly after {max_retries} attempts.")
    return f"Unexpected error: all retries failed without exception", False
    

def call_o1_pro_api(log_file, messages, model_name):
    """Call OpenAI's o1-pro model using the responses API"""
    log_message(log_file, f"Calling {model_name} using responses API...")
    start_time = time.time()
    
    user_message = ""
    for msg in messages:
        role = msg["role"]
        content = msg["content"]
        user_message += f"[{role.upper()}]: {content}\n"
    
    if not user_message:
        log_message(log_file, "No user message found in conversation")
        return "No user message found", False
    
    # Get API key from environment
    openai_api_key = os.environ.get("OPENAI_API_KEY")
    if not openai_api_key:
        log_message(log_file, "OPENAI_API_KEY environment variable not set")
        return "API key not set", False
    
    # Prepare the request
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {openai_api_key}"
    }
    
    data = {
        "model": model_name,
        "input": user_message
    }
    # Retry parameters
    max_retries = 5
    base_delay = 2  # Start with 2 seconds
    
    for attempt in range(max_retries):
        try:
            if attempt > 0:
                log_message(log_file, f"Retry attempt {attempt+1}/{max_retries}...")
            
            response = requests.post(
                "https://api.openai.com/v1/responses",
                headers=headers,
                json=data,
                timeout=900
            )
            log_message(log_file, f"Request data: {json.dumps(data, indent=2)}")
            log_message(log_file, f"Response status: {response.status_code}")
            
            # Print full response details
            try:
                response_json = response.json()
                log_message(log_file, f"Response JSON: {json.dumps(response_json, indent=2)}")
            except:
                log_message(log_file, f"Raw response text: {response.text}")
            
            # Log headers for debugging
            log_message(log_file, f"Response headers: {dict(response.headers)}")

            # Check if the request was successful
            if response.status_code != 200:
                error_msg = f"API returned status code {response.status_code}: {response.text}"
                log_message(log_file, error_msg)
                
                # Check if we should retry based on error type
                is_rate_limited = response.status_code == 429
                is_server_error = response.status_code >= 500
                
                if (is_rate_limited or is_server_error) and attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                    log_message(log_file, f"Waiting {delay:.2f} seconds before retry...")
                    time.sleep(delay)
                    continue
                else:
                    return f"API error: {error_msg}", False
            
            # Parse the response
            response_data = response.json()
            content = response_data.get("content", "")
            
            end_time = time.time()
            log_time(log_file, start_time, end_time, "call_o1_pro_api", f"LLM call to {model_name}")
            
            return content, True
            
        except Exception as e:
            error_str = str(e)
            log_message(log_file, f"Attempt {attempt+1}/{max_retries} failed: {error_str}")
            
            # Determine error type and appropriate action
            is_timeout = "timeout" in error_str.lower()
            is_connection_error = "connection" in error_str.lower()
            
            if (is_timeout or is_connection_error) and attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                log_message(log_file, f"Waiting {delay:.2f} seconds before retry...")
                time.sleep(delay)
            elif attempt < max_retries - 1:
                # Still retry other errors with a shorter delay
                delay = base_delay + random.uniform(0, 1)
                log_message(log_file, f"Error occurred. Waiting {delay:.2f} seconds before retry...")
                time.sleep(delay)
            else:
                # This was our last attempt
                log_message(log_file, f"All {max_retries} attempts failed. Giving up.")
                return f"Exception after {max_retries} attempts: {error_str}", False
    
    # This should never be reached due to the return in the last iteration of the loop
    return f"Unexpected error: all retries failed without exception", False

def call_llm(log_file, messages, model_name):
    """Call LLM with telemetry tracking."""   
    with tracer.start_as_current_span("genai") as span:
        span.set_attribute("crs.action.category", "fuzzing")
        span.set_attribute("crs.action.name", "call_llm")
        span.set_attribute("genai.model.name", f"{model_name}")

        try:
            if model_name.startswith("gemini"):
                response = call_gemini_api(log_file, messages, model_name)
            elif model_name == OPENAI_MODEL_O1_PRO:
                response = call_o1_pro_api(log_file, messages, model_name)
            else:
                response = call_litellm(log_file, messages, model_name)
            
            return response

        except Exception as e:
            logging.error(f"Error in LLM call: {str(e)}")
            return "", False

if False:
    log_file = setup_logging('test_telemetry')
    messages = [{"role": "user", "content": TEST_QUESTION}]
    print(call_llm(log_file, messages, OPENAI_MODEL))
    exit(0)

def clean_non_python_code(code):
    """
    Remove non-Python code elements like C/C++ comments and code blocks
    """
    lines = code.split('\n')
    cleaned_lines = []

    for line in lines:
        stripped = line.strip()
        # Skip C/C++ style comments
        if stripped.startswith('//'):
            continue
        # Skip obvious C/C++ code patterns
        if any(pattern in stripped for pattern in ['Before (vulnerable):', 'After (patched):']):
            continue
        cleaned_lines.append(line)

    return '\n'.join(cleaned_lines)

def extract_python_code_from_response(log_file, text, max_retries=2, timeout=30):
    """    
    Args:
        text: The text containing code to extract
        max_retries: Maximum number of retry attempts
        timeout: Timeout in seconds for each API call
        
    Returns:
        str: Extracted Python code or None if extraction failed
    """
    quick_pattern = r"```(?:python)?\s*([\s\S]*?)```"
    m = re.search(quick_pattern, text)
    if m:
        candidate = m.group(1).strip()
        if candidate:                     # non-empty code
            # Clean up non-Python code (C/C++ comments, code blocks)
            candidate = clean_non_python_code(candidate)
            log_message(log_file,
                        f"Quick-path extracted {len(candidate)} chars of code")
            return candidate  
            
    prompt = f"Please extract the Python code from the following text to generate a correct exploit. Return with markdown code blocks ```python ```. No comment. No explanation.\n\nHere is the text:\n{text}"
    messages = [{"role": "user", "content": prompt}]
    use_a_model = OPENAI_MODEL
    for attempt in range(max_retries + 1):
        try:
            print(f"Attempt {attempt+1}/{max_retries+1} to extract code with {use_a_model}")
            start_time = time.time()
                            
            response = completion(
                model=use_a_model,
                messages=messages,
                timeout=timeout
            )
            
            end_time = time.time()
            print(f"API call completed in {end_time - start_time:.2f} seconds")
            
            returned_text = response['choices'][0]['message']['content']
            
            # Extract code from markdown blocks
            pattern = r"```(?:python)?\s*([\s\S]*?)```"
            matches = re.findall(pattern, returned_text)
            if matches:
                extracted_code = matches[0].strip()
                if extracted_code:
                    # Clean up non-Python code
                    extracted_code = clean_non_python_code(extracted_code)
                    # print(f"Successfully extracted {len(extracted_code)} characters of code")
                    return extracted_code
                print("Extracted code block was empty")
            else:
                print("No code blocks found in response")
                
                # If no code blocks but response looks like code, return it directly
                if "def " in returned_text or "class " in returned_text or "import " in returned_text:
                    print("Response looks like code, returning directly")
                    return returned_text.strip()
            
        except Exception as e:
            error_msg = f"Error with {use_a_model} (attempt {attempt+1}): {str(e)}"
            print(error_msg)
            
            # Wait before retrying (exponential backoff)
            if attempt < max_retries:
                wait_time = 2 ** attempt  # 1, 2, 4, 8, ... seconds
                print(f"Waiting {wait_time} seconds before retry")
                time.sleep(wait_time)
    
    use_another_model = GEMINI_MODEL
    try:
        print(f"Falling back to {use_another_model}")

        returned_text, success = call_llm(log_file, messages, use_another_model)
        if success:
            # Extract code from markdown blocks
            pattern = r"```(?:python)?\s*([\s\S]*?)```"
            matches = re.findall(pattern, returned_text)
            if matches:
                extracted_code = matches[0].strip()
                if extracted_code:
                    # Clean up non-Python code
                    extracted_code = clean_non_python_code(extracted_code)
                    # print(f"Successfully extracted {len(extracted_code)} characters of code with fallback model")
                    return extracted_code
        else:
            print(f"Fallback to {use_another_model} also failed")

    except Exception as e:
        print(f"Fallback to {use_another_model} also failed: {str(e)}")
    
    # Last resort: try to extract code directly from the input text
    print("Attempting direct code extraction from input text")
    
    # Look for common Python patterns in the text
    python_patterns = [
        r"def\s+\w+\s*\([^)]*\)\s*:",  # Function definitions
        r"class\s+\w+(?:\([^)]*\))?\s*:",  # Class definitions
        r"import\s+[\w.]+",  # Import statements
        r"from\s+[\w.]+\s+import",  # From import statements
        r"if\s+.*?:",  # If statements
        r"for\s+.*?:",  # For loops
        r"while\s+.*?:",  # While loops
        r"try\s*:",  # Try blocks
    ]
    
    # Find the longest text segment that looks like Python code
    potential_code_segments = []
    
    for pattern in python_patterns:
        matches = re.finditer(pattern, text)
        for match in matches:
            # Get the position of the match
            start_pos = match.start()
            
            # Extract a chunk of text starting from this position
            code_chunk = text[start_pos:start_pos + 5000]  # Limit to 5000 chars
            
            # Add to potential segments
            potential_code_segments.append(code_chunk)
    
    if potential_code_segments:
        # Return the longest segment
        longest_segment = max(potential_code_segments, key=len)
        print(f"Extracted {len(longest_segment)} characters directly from text")
        return longest_segment
    
    print("All extraction methods failed")
    return None

def extract_code(text):
    """Extract Python code from markdown code blocks"""
    pattern = r"```(?:python)?\s*([\s\S]*?)```"
    matches = re.findall(pattern, text)
    if matches:
        return matches[0].strip()
    return None


def is_python_code(text):
    """Check if the response contains Python code"""
    return "```python" in text or "```py" in text or "```" in text

#TODO TEST it
def process_large_diff(diff_content, log_file):
    """Process a large diff to extract the most relevant parts for vulnerability analysis"""
    # Split the diff into individual file changes
    file_diffs = re.split(r'diff --git ', diff_content)
    
    # The first element is usually empty or contains the commit message
    if file_diffs and not file_diffs[0].strip().startswith('a/'):
        header = file_diffs[0]
        file_diffs = file_diffs[1:]
    else:
        header = ""
    
    # Add the 'diff --git' prefix back to each file diff except the header
    file_diffs = ["diff --git " + d if d.strip() else d for d in file_diffs]
    
    # Extract useful information about the diff
    total_files = len(file_diffs)
    log_message(log_file, f"Diff contains changes to {total_files} files")
    
    # Focus only on C and Java files
    c_extensions = ['.c', '.h']
    java_extensions = ['.java']
    binary_indicators = ['Binary files', 'GIT binary patch']
    
    # Categorize files by language
    c_files = []
    java_files = []
    other_files = 0
    binary_files = 0
    
    for file_diff in file_diffs:
        if not file_diff.strip():
            continue
            
        # Skip binary files
        if any(indicator in file_diff for indicator in binary_indicators):
            binary_files += 1
            continue
        
        # Try to extract the filename
        match = re.search(r'a/([^\s]+)', file_diff)
        if not match:
            other_files += 1
            continue
            
        filename = match.group(1)
        ext = os.path.splitext(filename)[1].lower()
        
        # Categorize based on extension
        if ext in c_extensions:
            c_files.append((filename, file_diff))
        elif ext in java_extensions:
            java_files.append((filename, file_diff))
        else:
            other_files += 1
    
    log_message(log_file, f"Categorized files: {len(c_files)} C files, {len(java_files)} Java files, "
                          f"{binary_files} binary files, {other_files} other files")
    
    # Security keywords specific to C and Java
    c_security_keywords = [
        'overflow', 'underflow', 'bounds', 'check', 'validate', 'sanitize', 'input',
        'malloc', 'free', 'alloc', 'realloc', 'memcpy', 'strcpy', 'strncpy', 'strlcpy',
        'buffer', 'size', 'length', 'null', 'nullptr', 'crash', 'assert',
        'error', 'vulnerability', 'exploit', 'security', 'unsafe', 'safe',
        'race', 'deadlock', 'lock', 'mutex', 'semaphore', 'atomic',
        'format', 'printf', 'sprintf', 'fprintf', 'snprintf', 'scanf', 'sscanf',
        'exec', 'system', 'popen', 'shell', 'command', 'injection',
        'crypt', 'encrypt', 'decrypt', 'hash', 'sign', 'verify',
        'random', 'prng', 'secret', 'key', 'token', 'permission',
        'privilege', 'sandbox', 'container', 'isolation',
        'sizeof', 'pointer', 'array', 'index', 'out-of-bounds',
        'integer', 'signed', 'unsigned', 'cast', 'conversion',
        'stack', 'heap', 'use-after-free', 'double-free'
    ]
    
    java_security_keywords = [
        'overflow', 'underflow', 'bounds', 'check', 'validate', 'sanitize', 'input',
        'buffer', 'size', 'length', 'null', 'crash', 'assert', 'exception',
        'error', 'vulnerability', 'exploit', 'security', 'unsafe', 'safe',
        'race', 'deadlock', 'lock', 'mutex', 'semaphore', 'atomic', 'concurrent',
        'format', 'printf', 'String.format', 'injection', 'sql', 'query',
        'auth', 'password', 'crypt', 'encrypt', 'decrypt', 'hash', 'sign', 'verify',
        'certificate', 'random', 'SecureRandom', 'secret', 'key', 'token', 'permission',
        'privilege', 'sandbox', 'isolation', 'escape',
        'ClassLoader', 'Reflection', 'serialization', 'deserialization',
        'XSS', 'CSRF', 'SSRF', 'XXE', 'RCE', 'JNDI', 'LDAP', 'JMX',
        'ArrayIndexOutOfBoundsException', 'NullPointerException'
    ]
    
    # Score C files
    scored_c_files = []
    for filename, file_diff in c_files:
        score = 0
        
        # Check for security keywords in the diff
        for keyword in c_security_keywords:
            score += file_diff.lower().count(keyword) * 2
        
        # Check for added/removed lines that might indicate security changes
        added_lines = len(re.findall(r'^\+(?!\+\+)', file_diff, re.MULTILINE))
        removed_lines = len(re.findall(r'^-(?!--)', file_diff, re.MULTILINE))
        score += (added_lines + removed_lines) // 5  # More changes = higher score
        
        # Bonus for certain high-risk C functions or patterns
        high_risk_c_patterns = [
            'memcpy', 'strcpy', 'strcat', 'sprintf', 'gets', 'malloc', 'free', 
            'sizeof', '[', ']', '->', 'char *', 'void *', 'int *'
        ]
        for pattern in high_risk_c_patterns:
            score += file_diff.count(pattern) * 3
        
        scored_c_files.append((score, filename, file_diff))
    
    # Score Java files
    scored_java_files = []
    for filename, file_diff in java_files:
        score = 0
        
        # Check for security keywords in the diff
        for keyword in java_security_keywords:
            score += file_diff.lower().count(keyword) * 2
        
        # Check for added/removed lines that might indicate security changes
        added_lines = len(re.findall(r'^\+(?!\+\+)', file_diff, re.MULTILINE))
        removed_lines = len(re.findall(r'^-(?!--)', file_diff, re.MULTILINE))
        score += (added_lines + removed_lines) // 5  # More changes = higher score
        
        # Bonus for certain high-risk Java patterns
        high_risk_java_patterns = [
            'Runtime.exec', 'ProcessBuilder', 'System.load', 'URLClassLoader',
            'ObjectInputStream', 'readObject', 'Class.forName', 'reflection',
            'setAccessible', 'doPrivileged', 'native', 'JNI', 'array', 'index',
            'Exception', 'try', 'catch', 'finally', 'throw'
        ]
        for pattern in high_risk_java_patterns:
            score += file_diff.count(pattern) * 3
        
        scored_java_files.append((score, filename, file_diff))
    
    # Sort by score (highest first)
    scored_c_files.sort(reverse=True)
    scored_java_files.sort(reverse=True)
    
    # Build the processed diff
    processed_diff = header + "\n\n"
    processed_diff += f"# Processed diff summary: {total_files} files changed\n"
    
    # Determine which language to prioritize based on file counts and scores
    c_max_score = scored_c_files[0][0] if scored_c_files else 0
    java_max_score = scored_java_files[0][0] if scored_java_files else 0
    
    if len(c_files) > 0 and (len(java_files) == 0 or c_max_score >= java_max_score):
        # Prioritize C files
        processed_diff += f"# Showing most security-relevant changes from C files ({len(c_files)} total C files)\n\n"
        
        # Add the top N most relevant C files
        max_c_files = min(10, len(scored_c_files))
        for i, (score, filename, file_diff) in enumerate(scored_c_files[:max_c_files]):
            processed_diff += f"# C File {i+1}: {filename} (relevance score: {score})\n"
            processed_diff += file_diff + "\n\n"
        
        # Add some Java files if available and space permits
        if java_files and len(processed_diff) < 40000:
            max_java_files = min(3, len(scored_java_files))
            processed_diff += f"\n# Selected Java files ({max_java_files} of {len(java_files)})\n\n"
            for i, (score, filename, file_diff) in enumerate(scored_java_files[:max_java_files]):
                processed_diff += f"# Java File {i+1}: {filename} (relevance score: {score})\n"
                processed_diff += file_diff + "\n\n"
    else:
        # Prioritize Java files
        processed_diff += f"# Showing most security-relevant changes from Java files ({len(java_files)} total Java files)\n\n"
        
        # Add the top N most relevant Java files
        max_java_files = min(10, len(scored_java_files))
        for i, (score, filename, file_diff) in enumerate(scored_java_files[:max_java_files]):
            processed_diff += f"# Java File {i+1}: {filename} (relevance score: {score})\n"
            processed_diff += file_diff + "\n\n"
        
        # Add some C files if available and space permits
        if c_files and len(processed_diff) < 40000:
            max_c_files = min(3, len(scored_c_files))
            processed_diff += f"\n# Selected C files ({max_c_files} of {len(c_files)})\n\n"
            for i, (score, filename, file_diff) in enumerate(scored_c_files[:max_c_files]):
                processed_diff += f"# C File {i+1}: {filename} (relevance score: {score})\n"
                processed_diff += file_diff + "\n\n"
    
    log_message(log_file, f"Processed diff size: {len(processed_diff)} bytes (original: {len(diff_content)} bytes)")
    return processed_diff

# pov_harness
# commit_cpv3.txt
# commit_cpv5.txt
# commit_cpv9.txt
# commit_cpv10.txt
# commit_cpv12.txt
# commit_cpv14.txt
# commit_cpv15.txt
# mail_request_harness
# commit_cpv13.txt
# smtp_harness
# commit_cpv17.txt
def get_commit_info(log_file, project_dir, language):
    """Get information about the commit that introduced the vulnerability"""
    if TEST_NGINX == True:
        commit_file = os.path.join(project_dir, f"commit_{CPV}.txt")        
        with open(commit_file, "r") as f:
            commit_content = f.read()
            return "Commit 45", commit_content

    # Check if diff/ref.diff exists in the project directory
    diff_path = os.path.join(project_dir, "diff", "ref.diff")
    if os.path.exists(diff_path):
        try:
            with open(diff_path, "r") as f:
                diff_content = f.read()
            log_message(log_file, f"Read diff from {diff_path}, len(diff_content): {len(diff_content)}")

            # If the diff is very large, process it to make it more manageable
            if len(diff_content) > 50000:  # More than 50KB
                log_message(log_file, "Diff is large, processing to extract relevant parts...")
                processed_diff = process_large_diff(diff_content, log_file)
                return "Processed commit from diff/ref.diff", processed_diff

            return "Commit from diff/ref.diff", diff_content
        except Exception as e:
            log_message(log_file, f"Error reading diff file: {str(e)}")
    try:
        # Get the latest commit message and diff
        git_log = subprocess.check_output(
            ["git", "log", "-1", "--pretty=format:%h %s"],
            cwd=project_dir,
            text=True
        )
        
        git_diff = subprocess.check_output(
            ["git", "diff", "HEAD~1", "HEAD"],
            cwd=project_dir,
            text=True
        )
        
        log_message(log_file, f"Latest commit: {git_log}")
        return git_log, git_diff
    except subprocess.CalledProcessError as e:
        log_message(log_file, f"Error getting commit info: {str(e)}")
        return "", ""


def is_likely_source_for_fuzzer(file_base, fuzzer_name, base_name):
    # Exact matches
    if file_base == fuzzer_name or file_base == base_name:
        return True
    
    # Common patterns:
    # 1. fuzzer_name = "xyz_fuzzer" and file_base = "xyz"
    if fuzzer_name == f"{file_base}_fuzzer":
        return True
    
    # 2. fuzzer_name = "xyz_fuzzer" and file_base = "xyz_fuzz"
    if base_name == f"{file_base}_fuzz":
        return True
        
    # 3. fuzzer_name = "xyz_fuzzer" and file_base = "fuzz_xyz"
    if base_name == f"fuzz_{file_base}":
        return True
        
    # 4. fuzzer_name = "xyz_fuzzer" and file_base = "xyz_test"
    if base_name == f"{file_base}_test":
        return True
        
    # 5. fuzzer_name = "xyz_fuzzer" and file_base = "test_xyz"
    if base_name == f"test_{file_base}":
        return True
        
    # 6. fuzzer_name = "xyz_abc_fuzzer" and file_base = "xyz_abc"
    if fuzzer_name.startswith(f"{file_base}_"):
        return True
        
    # 7. fuzzer_name = "xyz_fuzzer" and file_base = "libxyz"
    if base_name == file_base.replace("lib", ""):
        return True
        
    # 8. fuzzer_name = "libxyz_fuzzer" and file_base = "xyz"
    if file_base == base_name.replace("lib", ""):
        return True
    
    return False

def strip_license_text(source_code):
    """Strip copyright and license text from source code"""
    # Common patterns that indicate license blocks
    license_start_patterns = [
        "/*", 
        "/**",
        "// Copyright",
        "/* Copyright",
        "# Copyright",
        "// Licensed",
        "/* Licensed",
        "# Licensed",
        "// SPDX-License-Identifier",
        "/* SPDX-License-Identifier"
    ]
    
    license_end_patterns = [
        "*/",
        "**/"
    ]
    
    # Check if the source starts with a license block
    lines = source_code.split('\n')
    in_license_block = False
    license_end_line = -1

    # First, try to find a license block with clear start and end markers
    for i, line in enumerate(lines):
        stripped_line = line.strip()
        
        # Check for license block start
        if not in_license_block:
            for pattern in license_start_patterns:
                if stripped_line.startswith(pattern) and ("copyright" in stripped_line.lower() or 
                                                         "license" in stripped_line.lower() or
                                                         "permission" in stripped_line.lower() or
                                                         "redistribution" in stripped_line.lower()):
                    in_license_block = True
                    break
        
        # Check for license block end if we're in a block
        elif in_license_block:
            for pattern in license_end_patterns:
                if stripped_line.endswith(pattern) and not any(p in stripped_line for p in license_start_patterns):
                    license_end_line = i
                    break
            
            # If we found the end, stop looking
            if license_end_line >= 0:
                break
    
    # If we found a license block with clear markers, remove it
    if in_license_block and license_end_line >= 0:
        return '\n'.join(lines[license_end_line+1:]).strip()

    # If we didn't find a clear license block, try a heuristic approach
    # Look for the first non-comment, non-empty line
    first_code_line = 0
    for i, line in enumerate(lines):
        stripped_line = line.strip()
        # Skip empty lines
        if not stripped_line:
            continue
        
        # If it's not a comment line, this is likely the start of actual code
        if not stripped_line.startswith('//') and not stripped_line.startswith('/*') and not stripped_line.startswith('*') and not stripped_line.startswith('#'):
            first_code_line = i
            break
    
    # If the first several lines contain copyright/license keywords, skip them
    if first_code_line > 0:
        header_text = '\n'.join(lines[:first_code_line]).lower()
        if ("copyright" in header_text or "license" in header_text or 
            "permission" in header_text or "redistribution" in header_text):
            return '\n'.join(lines[first_code_line:]).strip()
    
    # If we couldn't identify a license block, return the original code
    return source_code

# TODO for Java
# count all the *.java files, .py files, and lines of code
# find file with the same name as fuzzer or something similar..
# give build.sh and all the files to AI, and ask it to return the matched files

def find_fuzzer_source(log_file, fuzzer_path, project_name, project_src_dir, focus, language='c'):
    """Find the source code of the fuzzer by using the model to analyze build scripts and source files"""
    if TEST_NGINX == True:
        fuzzer_path = "src/harnesses/pov_harness.cc"

        try:
            with open(fuzzer_path, 'r') as f:
                fuzzer_code = f.read()
            return fuzzer_code
        except Exception as e:
            log_message(log_file, f"Error reading fuzzer code: {str(e)}")
            return ""

    fuzzer_name = os.path.basename(fuzzer_path)
    project_dir = fuzzer_path.split("/fuzz-tooling/build/out")[0] + "/"
    
    log_message(log_file, f"Looking for source of {fuzzer_name} in {project_src_dir}")
    
    # Extract the base name without _fuzzer suffix if present
    base_name = fuzzer_name
    if "_fuzzer" in base_name:
        base_name = base_name.replace("_fuzzer", "")
    
    # First, collect all build scripts
    build_script_paths = []
    build_script_contents = {}
    
    # Search in fuzz-tooling/projects/{project_name}
    project_path = os.path.join(project_dir, f"fuzz-tooling/projects/{project_name}")
    if os.path.exists(project_path):
        for root, dirs, files in os.walk(project_path):
            if "build.sh" in files:
                script_path = os.path.join(root, "build.sh")
                build_script_paths.append(script_path)
                try:
                    with open(script_path, 'r') as f:
                        build_script_contents[script_path] = f.read()
                except Exception as e:
                    log_message(log_file, f"Error reading build script {script_path}: {str(e)}")
    
    if len(build_script_paths) ==0:
        # Also search in {focus} if not found in oss-fuzz
        focus_path = os.path.join(project_dir, focus)
        if os.path.exists(focus_path):
            for root, dirs, files in os.walk(focus_path):
                if "build.sh" in files:
                    script_path = os.path.join(root, "build.sh")
                    build_script_paths.append(script_path)
                    try:
                        with open(script_path, 'r') as f:
                            build_script_contents[script_path] = f.read()
                    except Exception as e:
                        log_message(log_file, f"Error reading build script {script_path}: {str(e)}")
    
    # log_message(log_file, f"Found {len(build_script_paths)} build.sh files")
    
    # Collect potential source files
    source_files = {}        
    extensions = ['.c', '.cc', '.cpp']
    if not language.startswith('c'):
        extensions =['.java']

    # First, look in directories containing build scripts
    for script_path in build_script_paths:
        script_dir = os.path.dirname(script_path)
        for root, dirs, files in os.walk(script_dir):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    # Check if the file name matches common fuzzer naming patterns
                    file_name = os.path.basename(file_path)
                    file_base = os.path.splitext(file_name)[0]
                    
                    # If we find a likely match, return it immediately
                    if is_likely_source_for_fuzzer(file_base, fuzzer_name, base_name):
                        try:
                            with open(file_path, 'r') as f:
                                content = f.read()
                                log_message(log_file, f"Found likely match for fuzzer source: {file_path}")
                                return strip_license_text(content)
                        except Exception as e:
                            log_message(log_file, f"Error reading likely match file {file_path}: {str(e)}")

                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            # Only include files that are not too large
                            if len(content) < 50000:  # Limit to ~50KB
                                source_files[file_path] = content
                    except Exception as e:
                        log_message(log_file, f"Error reading source file {file_path}: {str(e)}")
    
    # ------------------------------------------------------------------
    # Also look in pkgs/ directories and archives (NEW)
    # ------------------------------------------------------------------
    fuzz_dirs: List[str] = []
    pkgs_dir = os.path.join(project_path, "pkgs")
    if os.path.isdir(pkgs_dir):
        # 1) already-unpacked “…_fuzzer/” directories
        for entry in os.listdir(pkgs_dir):
            abs_entry = os.path.join(pkgs_dir, entry)
            if os.path.isdir(abs_entry) and "fuzzer" in entry.lower():
                fuzz_dirs.append(abs_entry)
                log_message(log_file, f"Added extracted pkg dir: {abs_entry}")

        # 2) *_fuzzer.tar.gz archives
        for entry in os.listdir(pkgs_dir):
            if entry.endswith((".tar.gz", ".tgz")) and "fuzzer" in entry.lower():
                archive_path = os.path.join(pkgs_dir, entry)
                try:
                    with tarfile.open(archive_path, "r:gz") as tar:
                        # Remember every distinct top-level directory the archive creates
                        top_dirs = set(m.name.split("/")[0] for m in tar.getmembers())
                        tar.extractall(path=pkgs_dir)

                    for td in top_dirs:
                        extracted_dir = os.path.join(pkgs_dir, td)
                        if os.path.isdir(extracted_dir):
                            fuzz_dirs.append(extracted_dir)
                            log_message(
                                log_file,
                                f"Extracted {archive_path} into {extracted_dir}",
                            )
                        else:
                            # Archive contained loose files; fall back to pkgs_dir
                            if pkgs_dir not in fuzz_dirs:
                                fuzz_dirs.append(pkgs_dir)
                    # Optional: delete the tarball after successful extraction
                    # os.remove(archive_path)
                except Exception as exc:
                    log_message(log_file, f"Error extracting {archive_path}: {exc}")

    # ------------------------------------------------------------------
    # Continue with the original fuzz-directory discovery
    # ------------------------------------------------------------------

    for script_path in build_script_paths:
        script_dir = os.path.dirname(script_path)
        fuzz_dir = os.path.join(script_dir, "fuzz")
        if os.path.exists(fuzz_dir):
            fuzz_dirs.append(fuzz_dir)
    
    # Look for any directory under the focus path that contains "fuzz" in its name
    focus_path = os.path.join(project_dir, focus)
    if os.path.exists(focus_path):
        for root, dirs, files in os.walk(focus_path):
            # Skip very deep directories to avoid excessive searching
            if root.count(os.sep) - focus_path.count(os.sep) > 5:
                continue
                
            # Add any directory with "fuzz" in its name
            for dir_name in dirs:
                if "fuzz" in dir_name.lower():
                    fuzz_dir = os.path.join(root, dir_name)
                    if fuzz_dir not in fuzz_dirs:
                        fuzz_dirs.append(fuzz_dir)
                        log_message(log_file, f"Found fuzzer directory: {fuzz_dir}")

    if len(fuzz_dirs) == 0:
        # Then search more broadly for any directory that might contain fuzzer sources
        fuzzer_related_dirs = []
        for root, dirs, files in os.walk(project_src_dir):
            # Skip very deep directories to avoid excessive searching
            if root.count(os.sep) - project_src_dir.count(os.sep) > 7:
                continue
                
            # Look for directories with fuzzer-related names
            for dir_name in dirs:
                lower_dir = dir_name.lower()
                if "fuzz" in lower_dir or "test" in lower_dir or "harness" in lower_dir:
                    fuzzer_dir = os.path.join(root, dir_name)
                    fuzzer_related_dirs.append(fuzzer_dir)
                    
            # Also look for directories containing fuzzer-related files
            has_fuzzer_files = False
            for file in files:
                lower_file = file.lower()
                if "fuzz" in lower_file or "_test" in lower_file or "test_" in lower_file:
                    has_fuzzer_files = True
                    break
            
            if has_fuzzer_files:
                fuzzer_related_dirs.append(root)
        
        # Add unique directories to our fuzz_dirs list
        for dir_path in fuzzer_related_dirs:
            if dir_path not in fuzz_dirs:
                fuzz_dirs.append(dir_path)
    
    log_message(log_file, f"Found {len(fuzz_dirs)} potential fuzzer-related directories")

    for fuzz_dir in fuzz_dirs:
        for root, dirs, files in os.walk(fuzz_dir):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    # Check if the file name matches common fuzzer naming patterns
                    file_name = os.path.basename(file_path)
                    file_base = os.path.splitext(file_name)[0]
                    # If we find a likely match, return it immediately
                    if is_likely_source_for_fuzzer(file_base, fuzzer_name, base_name):
                        try:
                            with open(file_path, 'r') as f:
                                content = f.read()
                                log_message(log_file, f"Found likely match for fuzzer source in fuzz directory: {file_path}")
                                return strip_license_text(content)
                        except Exception as e:
                            log_message(log_file, f"Error reading likely match file {file_path}: {str(e)}")

                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            if len(content) < 50000:  # Limit to ~50KB
                                source_files[file_path] = content
                    except Exception as e:
                        log_message(log_file, f"Error reading source file {file_path}: {str(e)}")

    log_message(log_file, f"Collected {len(source_files)} potential source files")

    # If we only found one source file, just return it directly
    if len(source_files) == 1:
        only_file_path = list(source_files.keys())[0]
        log_message(log_file, f"Only one source file found, returning it: {only_file_path}")
        return strip_license_text(source_files[only_file_path])
    
    # If we have too many source files, filter them to the most likely candidates
    if len(source_files) > 20:
        filtered_source_files = {}
        
        # Prioritize files with names similar to the fuzzer
        for file_path, content in source_files.items():
            file_name = os.path.basename(file_path)
            if fuzzer_name in file_name or base_name in file_name:
                filtered_source_files[file_path] = content
        
        # If we still have too few, add files that mention the fuzzer name in their content
        if len(filtered_source_files) < 5:
            for file_path, content in source_files.items():
                if file_path not in filtered_source_files and (fuzzer_name in content or base_name in content):
                    filtered_source_files[file_path] = content
                    if len(filtered_source_files) >= 10:
                        break
        
        source_files = filtered_source_files
        log_message(log_file, f"Filtered to {len(source_files)} most likely source files")
    
    # Prepare the prompt for the model
    prompt = f"""I need to identify the source code file for a fuzzer named '{fuzzer_name}' (base name: '{base_name}').
Please analyze the following build scripts and source files to determine which file is most likely the fuzzer source.

The fuzzer binary is located at: {fuzzer_path}

BUILD SCRIPTS:
"""
    
    # Add build scripts to the prompt
    for script_path, content in build_script_contents.items():
        prompt += f"\n--- {script_path} ---\n{content}\n"
    
    prompt += "\nSOURCE FILES:\n"
    
    # Add source files to the prompt
    for file_path, content in source_files.items():
        # Add a short preview of each file
        lines = content.split('\n')
        preview = '\n'.join(lines[:20]) + ('\n... (file continues)' if len(lines) > 20 else '')
        prompt += f"\n--- {file_path} ---\n{preview}\n"
    
    prompt += """
Based on the build scripts and source files, which file is most likely the source code for the fuzzer?
Please respond with just the full path to the file you believe is the fuzzer source code.
"""
    
    # Call the model to identify the fuzzer source
    messages = [{"role": "user", "content": prompt}]
    response, success = call_llm(log_file, messages, GEMINI_MODEL)
    
    if not success:
        log_message(log_file, "Failed to get model response for fuzzer source identification")
        # Fall back to the most likely file based on name
        for file_path in source_files.keys():
            file_name = os.path.basename(file_path)
            if file_name == f"{fuzzer_name}.c" or file_name == f"{fuzzer_name}.cc" or file_name == f"{fuzzer_name}.cpp" or \
               file_name == f"{base_name}.c" or file_name == f"{base_name}.cc" or file_name == f"{base_name}.cpp" or \
               file_name == f"{fuzzer_name}.java" or file_name == f"{base_name}.java":
                log_message(log_file, f"Falling back to likely fuzzer source: {file_path}")
                return strip_license_text(source_files[file_path])
        
        log_message(log_file, "Could not identify fuzzer source")
        return "// Could not find the source code for the fuzzer"
    
    # Parse the model's response to get the file path
    response = response.strip()
    
    # Extract the file path from the response
    file_path_match = re.search(r'(/[^\s]+)', response)
    if file_path_match:
        identified_path = file_path_match.group(1)
        log_message(log_file, f"Model identified fuzzer source as: {identified_path}")
        
        # Check if the identified path is in our collected source files
        if identified_path in source_files:
            return strip_license_text(source_files[identified_path])
        
        # If not, try to read the file directly
        if os.path.exists(identified_path):
            try:
                with open(identified_path, 'r') as f:
                    content = f.read()
                    log_message(log_file, f"Successfully read identified fuzzer source")
                    return strip_license_text(content)
            except Exception as e:
                log_message(log_file, f"Error reading identified source: {str(e)}")
    
    # If the model couldn't identify the file or we couldn't read it, fall back to our original approach
    log_message(log_file, "Model couldn't identify the fuzzer source or the identified file couldn't be read")
    
    # Fall back to the most likely file based on name
    for file_path in source_files.keys():
        file_name = os.path.basename(file_path)
        if file_name == f"{fuzzer_name}.c" or file_name == f"{fuzzer_name}.cc" or file_name == f"{fuzzer_name}.cpp" or \
           file_name == f"{base_name}.c" or file_name == f"{base_name}.cc" or file_name == f"{base_name}.cpp" or \
           file_name == f"{fuzzer_name}.java" or file_name == f"{base_name}.java":
            log_message(log_file, f"Falling back to likely fuzzer source: {file_path}")
            return strip_license_text(source_files[file_path])
    
    log_message(log_file, "Could not identify fuzzer source")
    return "// Could not find the source code for the fuzzer"

if False:
    log_file = setup_logging('libpng_read_fuzzer')
    fuzzer_path="/crs-workdir/55ffd8f9-0dc5-43f4-b03a-0b1af3c04740/fuzz-tooling/build/out/libpng/libpng_read_fuzzer"
    project_name="libpng"
    focus="example-libpng"
    language="c"
    # log_file = setup_logging('dns_qp_fuzzer')
    # fuzzer_path="/crs-workdir/dbeeb9bf-ae31-4699-8198-ef1ab6dd6d66-bind9-sample/fuzz-tooling/build/out/bind9/dns_qp_fuzzer"
    # project_name="bind9"
    # focus="bind9"
    # log_file = setup_logging('format_command_fuzzer')
    # fuzzer_path="/crs-workdir/random/fuzz-tooling/build/out/hiredis/format_command_fuzzer"
    # project_name="hiredis"
    # focus="hiredis"
    # log_file = setup_logging('AsyncHttpClientFuzzer')
    # fuzzer_path="/crs-workdir/random1/fuzz-tooling/build/out/hiredis/AsyncHttpClientFuzzer"
    # project_name="async-http-client"
    # focus="async-http-client"
    # log_file = setup_logging('ImageMetadataReaderFuzzer')
    # fuzzer_path="/crs-workdir/random2/fuzz-tooling/build/out/metadata-extractor/ImageMetadataReaderFuzzer"
    # project_name="metadata-extractor"
    # focus="metadata-extractor"
    # language="jvm"
    
    source_code = find_fuzzer_source(log_file, fuzzer_path, project_name, focus,language)
    print(f"find_fuzzer_source:\n{source_code}")
    exit(0)

def run_python_code(log_file, code, xbin_dir,blob_path):
    """Run the generated Python code to create x.bin"""
    log_message(log_file, f"run_python_code under: {xbin_dir}")
    # Validate xbin_dir
    if not xbin_dir or not os.path.isdir(xbin_dir):
        log_message(log_file, f"Invalid project directory: '{xbin_dir}'")
        return False, "", f"Invalid project directory: '{xbin_dir}'"
    
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as temp_file:
        temp_file.write(code.encode('utf-8'))
        temp_file_path = temp_file.name
    
    try:
        # log_message(log_file, f"Running generated Python code from {temp_file_path}")
        result = subprocess.run(
            ["python3", temp_file_path],
            cwd=xbin_dir,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        log_message(log_file, f"Python code execution stdout: {result.stdout}")
        if result.stderr:
            log_message(log_file, f"Python code execution stderr: {result.stderr}")
        
        # Check if x.bin was created
        if os.path.exists(blob_path):
            log_message(log_file, f"x.bin was created successfully ({os.path.getsize(blob_path)} bytes)")
            return True, result.stdout, result.stderr
        else:
            log_message(log_file, f"x.bin was not created")
            return False, result.stdout, result.stderr
    
    except subprocess.TimeoutExpired:
        log_message(log_file, f"Python code execution timed out")
        return False, "", "Execution timed out"
    except Exception as e:
        log_message(log_file, f"Error running Python code: {str(e)}")
        return False, "", str(e)
    finally:
        # Clean up the temporary file
        os.unlink(temp_file_path)

def filter_instrumented_lines(text, max_line_length=200):
    if not text:
        return text
    
    filtered_lines = []
    for line in text.splitlines():
        # Skip lines containing "INFO: Instrumented"
        if line.startswith("INFO: ") or "Server VM warning:" in line:
            continue
        # Drop noisy sanitizer/SQLite warnings
        if line.lstrip().startswith("WARNING:"):
            continue                        
        # Truncate long lines
        if len(line) > max_line_length:
            truncated = line[:max_line_length] + f" ... (truncated, full length: {len(line)})"
            filtered_lines.append(truncated)
        else:
            filtered_lines.append(line)
            
    return '\n'.join(filtered_lines)

def run_fuzzer_with_input_for_c_coverage(
        log_file,
        fuzzer_path: str,
        project_dir: str,
        project_name: str,
        focus: str,
        blob_path: str,
) -> Tuple[bool, str, str]:
    """
    Execute the *coverage* build of a libFuzzer target with an input blob and
    produce /out/coverage.lcov inside the xp0 directory.

    Returns (success, message)
    """
    try:
        # ------------------------------------------------------------
        # 0.  Derive paths / names
        # ------------------------------------------------------------
        cov_fuzzer_path = fuzzer_path + "-coverage"
        log_message(log_file, f"[coverage] fuzzer   : {cov_fuzzer_path}")
        log_message(log_file, f"[coverage] input blob: {blob_path}")

        fuzzer_dir  = os.path.dirname(cov_fuzzer_path)       # …/out/<project>
        fuzzer_name = os.path.basename(cov_fuzzer_path)      # html-coverage
        out_dir     = os.path.join(fuzzer_dir, "xp0")        # same convention used elsewhere

        os.makedirs(out_dir, exist_ok=True)
        lcov_host = os.path.join(out_dir, "coverage.lcov")

        # ------------------------------------------------------------
        # 1.  Copy the blob into xp0
        # ------------------------------------------------------------
        unique_blob = f"x_{uuid.uuid4().hex[:8]}.bin"
        host_blob   = os.path.join(out_dir, unique_blob)
        shutil.copy(blob_path, host_blob)
        log_message(log_file, f"[coverage] blob copied to {host_blob}")

        # ------------------------------------------------------------
        # 2.  Run the coverage fuzzer once (records to /out/coverage.profraw)
        # ------------------------------------------------------------
        docker_run = [
            "docker", "run", "--rm", "--platform", "linux/amd64",
            "-e", "FUZZING_ENGINE=libfuzzer",
            "-e", "ARCHITECTURE=x86_64",
            # LLVM_PROFILE_FILE tells the binary where to dump coverage
            "-e", "LLVM_PROFILE_FILE=/out/coverage.profraw",
            "-v", f"{out_dir}:/out",
            f"aixcc-afc/{project_name}",
            f"/out/{fuzzer_name}",
            "-runs=1",
            f"/out/{unique_blob}",
        ]

        log_message(log_file, "[coverage] " + " ".join(docker_run))
        res = subprocess.run(docker_run, capture_output=True, text=True, timeout=120)
        log_message(log_file, res.stdout)
        if res.stderr:
            log_message(log_file, res.stderr)

        if res.returncode not in (0, 77, 99):
            return False, lcov_host, f"fuzzer exited with code {res.returncode}"

        profraw_host = os.path.join(out_dir, "coverage.profraw")
        if not os.path.exists(profraw_host) or os.path.getsize(profraw_host) == 0:
            return False, lcov_host, "coverage.profraw was not produced"

        # ------------------------------------------------------------
        # 3.  Merge & export LCOV
        # ------------------------------------------------------------
        merge_and_export = (
            "llvm-profdata merge -sparse /out/coverage.profraw -o /out/coverage.profdata && "
            f"llvm-cov export /out/{fuzzer_name} "
            "-instr-profile=/out/coverage.profdata "
            "-format=lcov > /out/coverage.lcov"
        )

        docker_cov = [
            "docker", "run", "--rm", "--platform", "linux/amd64",
            "-v", f"{out_dir}:/out",
            f"aixcc-afc/{project_name}",
            "bash", "-c", merge_and_export,
        ]
        log_message(log_file, "[coverage] " + " ".join(docker_cov))
        res2 = subprocess.run(docker_cov, capture_output=True, text=True, timeout=120)
        if res2.stderr:
            log_message(log_file, res2.stderr)
        if res2.returncode != 0:
            return False, lcov_host, "llvm-profdata/llvm-cov failed"

        if not os.path.exists(lcov_host):
            return False, lcov_host, "coverage.lcov was not created"
        log_message(log_file, f"[coverage] coverage.lcov size={os.path.getsize(lcov_host)} bytes")

        return True, lcov_host, "coverage.lcov generated successfully"

    except subprocess.TimeoutExpired:
        log_message(log_file, "[coverage] execution timed out")
        return False, "", "Timeout"
    except Exception as exc:
        log_message(log_file, f"[coverage] error: {exc}")
        return False, "", str(exc)


def get_same_project_fuzzers(fuzzer_path):
    """Find all fuzzers from the same project and sanitizer as the given fuzzer"""
    fuzzer_dir = os.path.dirname(fuzzer_path)

    # Get all files in the same directory that are executable
    same_project_fuzzers = []
    if os.path.isdir(fuzzer_dir):
        for item in os.listdir(fuzzer_dir):
            item_path = os.path.join(fuzzer_dir, item)
            # Check if it's a file and executable
            if os.path.isfile(item_path) and os.access(item_path, os.X_OK):
                # Skip coverage builds and other non-fuzzer executables
                if not item.endswith('-coverage') and not item in ['llvm-symbolizer', 'clang']:
                    same_project_fuzzers.append(item_path)

    return same_project_fuzzers


def run_fuzzer_with_input(log_file, fuzzer_path, project_dir, focus, blob_path, is_c_project=True):
    try:
        log_message(log_file, f"Running fuzzer {fuzzer_path} with blob {blob_path}")
        
        # Get the directory containing the fuzzer
        fuzzer_dir = os.path.dirname(fuzzer_path)
        fuzzer_name = os.path.basename(fuzzer_path)

        # For testing Nginx only
        if TEST_NGINX == True:
            run_pov_command = ["./run.sh", "run_pov", blob_path, "pov_harness"]
            # Run the fuzzer with the test input
            result = subprocess.run(
                run_pov_command,
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
        else:
            # Extract project name and sanitizer from the fuzzer path
            # Example path: /app/7d1205de-e1b8-4979-877d-a560e5b3cf0a/fuzz-tooling/build/out/libpng-address/libpng_read_fuzzer
            path_parts = fuzzer_dir.split('/')
            
            # Find the part that contains project-sanitizer (e.g., "libpng-address" or "metadata-extractor-address")
            project_sanitizer = None
            for part in path_parts:
                if '-' in part and any(san in part for san in ['address', 'undefined', 'memory']):
                    project_sanitizer = part
                    break
            
            if not project_sanitizer:
                log_message(log_file, f"Could not determine project and sanitizer from path: {fuzzer_path}")
                return False, f"Could not determine project and sanitizer from path: {fuzzer_path}"
            
            # Split into project and sanitizer - handle project names that may contain hyphens
            # The sanitizer is always the last part after the last hyphen
            parts = project_sanitizer.split('-')
            sanitizer = parts[-1]  # Last part is the sanitizer
            project_name = '-'.join(parts[:-1])  # Everything before the last hyphen is the project name
            
            # log_message(log_file, f"Extracted project name: '{project_name}' and sanitizer: '{sanitizer}'")
            
            sanitizer_project_dir = os.path.join(project_dir, focus+"-"+sanitizer)
            out_dir = os.path.dirname(fuzzer_path)
            out_dir_x = os.path.join(out_dir, f"xp0")

            work_dir = os.path.join(project_dir, "fuzz-tooling", "build", "work", f"{project_name}-{sanitizer}")
            
            unique_id = str(uuid.uuid4())[:8]  # Use first 8 chars of UUID for brevity
            unique_blob_name = f"x_{unique_id}.bin"
            # Try multiple approaches to make the blob accessible to Docker
            docker_blob_path = os.path.join(out_dir_x, unique_blob_name)            
            # Approach 1: Try direct copy
            try:
                shutil.copy(blob_path, docker_blob_path)
                log_message(log_file, f"Copied blob to {docker_blob_path}")
            except Exception as e:
                log_message(log_file, f"Direct copy failed: {str(e)}")

            # If we haven't defined docker_cmd yet (because we successfully copied to out_dir)
            if not 'docker_cmd' in locals():

                # find aixcc-afc/{project_name} first in docker images, if not found, then use the  gcr.io/oss-fuzz/ {project_name}
                docker_image = None

                # Check aixcc-afc/{project_name}
                try:
                    result = subprocess.run(["docker", "images", f"aixcc-afc/{project_name}", "--format", "{{.Repository}}:{{.Tag}}"], capture_output=True, text=True, timeout=60)
                    if result.returncode == 0 and result.stdout.strip():
                        docker_image = result.stdout.strip().split('\n')[0]  # Get first line
                except Exception as e:
                    log_message(log_file, f"Failed to find docker image for aixcc-afc/{project_name}: {str(e)}")

                # If not found, check gcr.io/oss-fuzz/{project_name}
                if not docker_image:
                    try:
                        result = subprocess.run(["docker", "images", f"gcr.io/oss-fuzz/{project_name}", "--format", "{{.Repository}}:{{.Tag}}"], capture_output=True, text=True, timeout=60)
                        if result.returncode == 0 and result.stdout.strip():
                            docker_image = result.stdout.strip().split('\n')[0]  # Get first line
                    except Exception as e:
                        log_message(log_file, f"Failed to find docker image for gcr.io/oss-fuzz/{project_name}: {str(e)}")

                if not docker_image:
                    log_message(log_file, f"Failed to find docker image for {project_name}")
                    return False, f"Failed to find docker image for {project_name}"
                
                log_message(log_file, f"Found docker image for {project_name}: {docker_image}")

                docker_cmd = [
                    "docker", "run", "--rm",
                    "--platform", "linux/amd64",
                    "-e", "FUZZING_ENGINE=libfuzzer",
                    "-e", f"SANITIZER={sanitizer}",
                    # "-e", "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1",
                    "-e", "ARCHITECTURE=x86_64",
                    "-e", f"PROJECT_NAME={project_name}",
                    "-v", f"{sanitizer_project_dir}:/src/{project_name}",
                    "-v", f"{out_dir_x}:/out",
                    "-v", f"{work_dir}:/work",
                    docker_image,
                    f"/out/{fuzzer_name}",
                    # f"--instrumentation_includes=org.apache.zookeeper.**",
                    # f"--coverage_dump=coverage.exec",
                    "-timeout=30",           # Add libFuzzer timeout parameter
                    "-timeout_exitcode=99",  # Set specific exit code for timeouts
                    f'/out/{unique_blob_name}'
                ]
                
                # Only add instrumentation and coverage options if USE_CONTROL_FLOW is True
                if USE_CONTROL_FLOW:
                    if not is_c_project:
                        # for Java projects, e.g.,  ZOOKEEPER
                        if project_name == "zookeeper":
                            docker_cmd.insert(-3, f"--instrumentation_includes=org.apache.zookeeper.**")
                        docker_cmd.insert(-3, f"--coverage_dump=/out/coverage.exec")

            log_message(log_file, f"Running Docker command: {' '.join(docker_cmd)}")
            
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
        
        #quick path
        combined_output = result.stderr + "\n" + result.stdout
        if result.returncode == 0 and ("ABORTING" not in combined_output):
            log_message(log_file, "Fuzzer ran successfully without crashing")
            return False, combined_output

        if result.returncode == 77 and "Java Exception: java.lang.NoClassDefFoundError:" in combined_output:
            log_message(log_file, f"Fuzzer exited with non-zero code {result.returncode}, but no crash indicators found")
            return False, combined_output
        
        combined_output_lower = combined_output.lower()
        if "assertion failed" in combined_output_lower:
            log_message(log_file, f"Fuzzer crashed with assertion failed")
            return True, combined_output

        # log_message(log_file, f"Fuzzer stdout: {result.stdout}")
        if result.stderr:
            log_message(log_file, f"Fuzzer stderr: {result.stderr}")
        

        crash_indicators = [
            "ERROR: AddressSanitizer:",
            # "ERROR: LeakSanitizer:",
            "ERROR: MemorySanitizer:",
            "WARNING: MemorySanitizer:",
            "ERROR: ThreadSanitizer:",
            "ERROR: UndefinedBehaviorSanitizer:",
            "SEGV on unknown address",
            "Segmentation fault",
            "runtime error:",
            "AddressSanitizer: heap-buffer-overflow",
            "AddressSanitizer: heap-use-after-free",
            "UndefinedBehaviorSanitizer: undefined-behavior",
            "AddressSanitizer:DEADLYSIGNAL",
            "Java Exception: com.code_intelligence.jazzer",
            "ERROR: HWAddressSanitizer:",
            "WARNING: ThreadSanitizer:",
            "libfuzzer exit=1"
        ]
        sentinel =  Path(project_dir) / DETECT_TIMEOUT_CRASH_SENTINEL
        if os.environ.get("DETECT_TIMEOUT_CRASH") == "1" or sentinel.exists():
            crash_indicators.append("ERROR: libFuzzer: timeout")
            crash_indicators.append("libfuzzer exit=99")

        # Check if the fuzzer crashed (non-zero exit code often indicates a crash/vulnerability found)
        if result.returncode != 0 or "ABORTING" in combined_output:
            # Check for actual crash indicators vs warnings
            if any(indicator in combined_output for indicator in crash_indicators):
                log_message(log_file, f"Fuzzer crashed with exit code {result.returncode} - potential vulnerability triggered!")
                return True, combined_output
            else:
                log_message(log_file, f"Fuzzer exited with non-zero code {result.returncode}, but no crash indicators found")
                return False, combined_output
    
    except subprocess.TimeoutExpired:
        log_message(log_file, "Fuzzer execution timed out")
        return False, "Execution timed out"
    except Exception as e:
        log_message(log_file, f"Error running fuzzer: {str(e)}")
        return False, str(e)


def generate_pov(log_file, project_dir, messages, model_name):
    """Generate a Proof of Vulnerability payload"""
   
    function_start_time = time.time()
    pprint.pprint(messages)
    response, success = call_llm(log_file, messages, model_name)
    if (not success) or (response is None) or (not response.strip()):
        log_message(log_file, f"Failed to get valid response from {model_name}")
        return None

    log_message(log_file, f"generate_pov response:\n{response}")

    if "infinite loop" in response:
        log_message(log_file, f"infinite loop detected in the pov response. setting DETECT_TIMEOUT_CRASH")
        # create file "detect_timeout_crash" under project_dir to sync w/ other parallel patchers
        try:
            sentinel = Path(project_dir) / DETECT_TIMEOUT_CRASH_SENTINEL
            sentinel.touch(exist_ok=True)
        except Exception as e:
            log_message(log_file, f"unable to create sentinel detect_timeout_crash file: {e}")

        os.environ["DETECT_TIMEOUT_CRASH"] = "1"

    # Check if the response is a refusal or non-compliance message
    refusal_phrases = [
       "cannot comply", "can't comply", 
        "against my", 
        "ethical guidelines"
    ]
    
    is_refusal = False
    response_lower = response.lower()
        

    for phrase in refusal_phrases:
        if phrase in response_lower:
            is_refusal = True
            log_message(log_file, f"Model refused to generate PoV with message: '{response[:100]}...'")
            break
    
    # Only append to message history if it's not a refusal
    if not is_refusal:
        messages.append({"role": "assistant", "content": response})
    else:
        # If it's a refusal, don't add it to the conversation history
        log_message(log_file, "Skipping refusal response - not adding to message history")
        # Return None to indicate failure
        return None

    function_end_time = time.time()
    log_time(log_file, function_start_time, function_end_time, "generate_pov", f"Time for PoV generation by {model_name}")
        
    code = extract_python_code_from_response(log_file, response)
    if code:
        return code
    else:
        log_message(log_file, "No Python code found in the response")
        return None

def extract_java_fallback_location(output):
    """Return 'pkg.Class.method:LINE' from a Java stack trace."""
    for line in output.split('\n'):
        line = line.strip()
        # Matches: at org.foo.Bar.baz(Bar.java:42)
        m = re.match(r'at\s+([\w\.$]+)\(([^:]+):(\d+)\)', line)
        if m:
            qualified_method = m.group(1)   # org.foo.Bar.baz
            line_no          = m.group(3)   # 42
            return f"{qualified_method}:{line_no}"
    return ""
    
def extract_crash_location(output, sanitizer):
    """
    Extract the crash location from the output.
    
    Args:
        output: The crash output
        sanitizer: The sanitizer type
        
    Returns:
        str: The crash location or empty string if not found
    """
    import re
    
    # Look for the #0 line in the stack trace which indicates the crash point
    lines = output.split('\n')
    
    # First try to find the #0 line which is the most reliable indicator
    for line in lines:
        line = line.strip()
        if line.startswith('#0 '):
            # Extract the function and location after "in"
            parts = line.split(' in ', 1)
            if len(parts) < 2:
                continue
            
            # Get the function name and file location
            func_info = parts[1]
            
            # Clean up any extra information in parentheses
            if ' (' in func_info:
                func_info = func_info.split(' (', 1)[0]
            
            # Remove column information (e.g., ":13" in "file.c:123:13")
            last_colon_idx = func_info.rfind(':')
            if last_colon_idx != -1:
                # Check if there's another colon before this one (for the line number)
                prev_colon_idx = func_info[:last_colon_idx].rfind(':')
                if prev_colon_idx != -1:
                    # This is likely a column number, remove it
                    func_info = func_info[:last_colon_idx]

            return func_info

    if ".java" in output:
        java_loc = extract_java_fallback_location(output)
        if java_loc:
            return java_loc

    # If we couldn't find a #0 line, look for sanitizer-specific patterns
    sanitizer = sanitizer.lower()
    if sanitizer in ["address", "asan"]:
        return extract_asan_fallback_location(output)
    elif sanitizer in ["undefined", "ubsan"]:
        return extract_ubsan_fallback_location(output)
    elif sanitizer in ["memory", "msan"]:
        return extract_msan_fallback_location(output)
    
    # If all else fails, look for any file path with a line number
    for line in lines:
        if '/src/' in line and '.c:' in line:
            # This might be a file reference
            match = re.search(r'(/src/[^:]+:\d+)', line)
            if match:
                return match.group(1)
    
    return ""

def extract_asan_fallback_location(output):
    """Extract location from ASAN output if #0 line isn't found."""
    import re
    # Look for "SUMMARY: AddressSanitizer: <type> <location>"
    match = re.search(r'SUMMARY: AddressSanitizer: \w+ ([^(]+)', output)
    if match:
        return match.group(1).strip()
    
    return ""

def extract_ubsan_fallback_location(output):
    """Extract location from UBSAN output."""
    import re
    # Look for the file and line where UBSAN detected the issue
    match = re.search(r'([^:]+:\d+:\d+): runtime error:', output)
    if match:
        return match.group(1)
    
    return ""

def extract_msan_fallback_location(output):
    """Extract location from MSAN output."""
    import re
    # Look for "WARNING: MemorySanitizer: <description> <location>"
    match = re.search(r'MemorySanitizer:.*? at ([^:]+:\d+)', output)
    if match:
        return match.group(1)
    
    return ""


def generate_vulnerability_signature(output, sanitizer):
    """
    Create a unique signature for a vulnerability to identify duplicates
    based on the crash output and sanitizer.
    
    Args:
        output: The crash output
        sanitizer: The sanitizer type (address, undefined, memory, etc.)
        
    Returns:
        str: A unique signature for the vulnerability
    """
    import hashlib
    import re
    
    def hash_string(s):
        """Create a hash of a string."""
        return hashlib.md5(s.encode()).hexdigest()
    
    # Extract the crash location from the stack trace
    crash_location = extract_crash_location(output, sanitizer)
    
    # If we couldn't extract a specific location, fall back to a hash
    if not crash_location:
        return f"{sanitizer.upper()}:generic:{hash_string(output)}"
    
    # Create a signature with the sanitizer type and crash location
    return f"{crash_location}"


def extract_crash_trace(fuzzer_output):
    """
    Extract crash trace from fuzzer output.
    Handles C/C++ ASAN errors and Java exceptions.
    """
    # Define patterns to look for
    patterns = [
        # C/C++ ASAN errors
        {"marker": "ERROR:", "end_marker": None},
        # Standard Jazzer format
        {"marker": "Uncaught exception:", "end_marker": "Reproducer file written to:"},
        # Alternative Java exception format
        {"marker": "Java Exception:", "end_marker": "Reproducer file written to:"},
        # Generic Java exception format (fallback)
        {"marker": "Exception in thread", "end_marker": None}
    ]
    
    # Try each pattern
    for pattern in patterns:
        marker_index = fuzzer_output.find(pattern["marker"])
        if marker_index != -1:
            # Found a match
            if pattern["end_marker"]:
                end_index = fuzzer_output.find(pattern["end_marker"], marker_index)
                if end_index != -1:
                    return fuzzer_output[marker_index:end_index].strip()
            
            # If no end marker or end marker not found, take everything to the end
            return fuzzer_output[marker_index:].strip()
    
    return fuzzer_output

def submit_pov_to_endpoint(log_file, project_dir, pov_metadata):
    """
    Submit the POV to the submission endpoint.
    
    Args:
        log_file: Log file handle
        project_dir: Project directory
        pov_metadata: Metadata about the successful POV
        
    Returns:
        bool: True if submission was successful, False otherwise
    """

    log_message(log_file, "Submitting POV to submission endpoint")
    
    # Get API credentials from environment
    api_key_id = os.environ.get("COMPETITION_API_KEY_ID")
    api_token = os.environ.get("COMPETITION_API_KEY_TOKEN")
    submission_endpoint = os.environ.get("SUBMISSION_ENDPOINT")
    task_id = os.environ.get("TASK_ID")

    if not submission_endpoint:
        log_message(log_file, "SUBMISSION_ENDPOINT environment variable not set, skipping submission")
        return False
        
    if not task_id:
        log_message(log_file, "TASK_ID environment variable not set, skipping submission")
        return False
        
    if not api_key_id or not api_token:
        api_key_id = os.environ.get("CRS_KEY_ID")
        api_token = os.environ.get("CRS_KEY_TOKEN")
        if not api_key_id or not api_token:
            log_message(log_file, "API credentials not set, skipping submission")
            return False
    
    # Read the blob file
    blob_path = os.path.join(POV_SUCCESS_DIR, pov_metadata.get("blob_file", ""))
    if not os.path.exists(blob_path):
        log_message(log_file, f"Blob file {blob_path} does not exist, skipping submission")
        return False
        
    with open(blob_path, "rb") as f:
        blob_data = f.read()
    
    # Read the fuzzer output
    fuzzer_output_path = os.path.join(POV_SUCCESS_DIR, pov_metadata.get("fuzzer_output", ""))
    if not os.path.exists(fuzzer_output_path):
        log_message(log_file, f"Fuzzer output file {fuzzer_output_path} does not exist, skipping submission")
        return False
        
    with open(fuzzer_output_path, "r") as f:
        fuzzer_output = f.read()
    
    crash_trace = ""
    
    # Check for UndefinedBehaviorSanitizer errors
    ubsan_match = re.search(r'(.*runtime error:.*)', fuzzer_output)
    if ubsan_match:
        ubsan_error = ubsan_match.group(1).strip()
        crash_trace = f"UndefinedBehaviorSanitizer Error: {ubsan_error}\n\n"
        
        # Extract stack trace - look for lines starting with #
        stack_lines = re.findall(r'(#\d+.*)', fuzzer_output)
        if stack_lines:
            crash_trace += "Stack Trace:\n"
            for line in stack_lines:
                crash_trace += f"{line}\n"
        
        # Extract summary
        summary_match = re.search(r'SUMMARY: UndefinedBehaviorSanitizer: (.*)', fuzzer_output)
        if summary_match:
            crash_trace += f"\nSummary: {summary_match.group(1)}\n"
    
    # If no UBSan error found, fall back to the original ERROR: pattern
    if not crash_trace:
        crash_trace = extract_crash_trace(fuzzer_output)
    
    # Limit size if needed
    if len(crash_trace) > 10000:
        crash_trace = crash_trace[:10000] + "... (truncated)"
    
    # Generate vulnerability signature using the same logic as the Go code
    sanitizer = pov_metadata.get("sanitizer", "")
    vuln_signature = pov_metadata.get("pov_signature", "")
    fuzzer_name = pov_metadata.get("fuzzer_name", "")
    # Create the submission payload
    submission = {
        "task_id": task_id,
        "architecture": "x86_64",
        "engine": "libfuzzer",
        "fuzzer_name": fuzzer_name,
        "sanitizer": pov_metadata.get("sanitizer", ""),
        "testcase": base64.b64encode(blob_data).decode('utf-8'),  # Base64 encode the binary data
        "signature": vuln_signature,  # Include signature for deduplication
    }

    NEW_FUZZER_SRC_PATH = os.environ.get("NEW_FUZZER_SRC_PATH", "")
    # If we have a generated fuzzer, attach its location and contents
    if NEW_FUZZER_SRC_PATH:
        submission["fuzzer_file"] = NEW_FUZZER_SRC_PATH
        try:
            with open(NEW_FUZZER_SRC_PATH, "r", encoding="utf-8", errors="backslashreplace") as fp:
                submission["fuzzer_source"] = fp.read()
        except Exception as e:
            log_message(log_file, f"Failed to read fuzzer source at {NEW_FUZZER_SRC_PATH}: {e}")   

    # Add crash trace if available
    if crash_trace:
        submission["crash_trace"] = crash_trace
    
    # Add strategy information
    submission["strategy"] = "xs0_delta"
    submission["strategy_version"] = "1.0"
    
    try:
        # Create the request
        url = f"{submission_endpoint}/v1/task/{task_id}/pov/"
        if NEW_FUZZER_SRC_PATH:
            url = f"{submission_endpoint}/v1/task/{task_id}/freeform/pov/"
 
        headers = {
            "Content-Type": "application/json",
        }
        
        # Add authentication if available
        auth = None
        if api_key_id and api_token:
            auth = (api_key_id, api_token)
        
        # Send the request
        response = requests.post(
            url,
            headers=headers,
            auth=auth,
            json=submission,
            timeout=60  # 30 second timeout
        )
        
        # Check response
        if response.status_code in [200, 201]:
            log_message(log_file, f"Successfully submitted POV to submission endpoint: {response.status_code}")
            
            # Try to parse and log the response
            try:
                response_data = response.json()
                log_message(log_file, f"Response: {json.dumps(response_data, indent=2)}")
            except:
                log_message(log_file, f"Raw response: {response.text}")
                
            return True
        else:
            log_message(log_file, f"Submission endpoint returned non-OK status: {response.status_code}")
            log_message(log_file, f"Response: {response.text}")
            return False
            
    except Exception as e:
        log_message(log_file, f"Error submitting POV to endpoint: {str(e)}")
        return False

def check_for_successful_patches(log_file, project_dir):
    """
    Check if any successful patches have been created.
    
    Args:
        log_file: Log file path
        project_dir: Project directory
        
    Returns:
        bool: True if successful patches found, False otherwise
    """
    # Check for successful_patch_metadata.json in the project directory
    success_file = os.path.join(PATCH_SUCCESS_DIR, SUCCESS_PATCH_METADATA_FILE)
    if os.path.exists(success_file):
        try:
            with open(patch_metadata_path, 'r') as f:
                metadata = json.load(f)
                log_message(log_file, f"Found successful patch metadata: {metadata}")
                return True
        except Exception as e:
            log_message(log_file, f"Error reading patch metadata: {str(e)}")
    

    # Check for successful_patches directory with content
    if os.path.isdir(PATCH_SUCCESS_DIR):
        patches = os.listdir(patches_dir)
        if patches:
            log_message(log_file, f"Found successful patches: {patches}")
            return True
    
    return False

def extract_crash_output(output):
    """
    Extract the relevant crash output from fuzzer output.
    Handles various sanitizer errors, libFuzzer crashes, and Java exceptions.
    Returns up to MAX_SIZE bytes of the most relevant part of the crash.
    """
    # Maximum size to return (4KB)
    MAX_SIZE = 4096
    
    # Define patterns to look for, in order of priority
    patterns = [
        # AddressSanitizer errors
        {"marker": "ERROR: AddressSanitizer", "backtrack": False},
        # UndefinedBehaviorSanitizer errors
        {"marker": "ERROR: UndefinedBehaviorSanitizer", "backtrack": False},
        # MemorySanitizer errors
        {"marker": "ERROR: MemorySanitizer", "backtrack": False},
        {"marker": "WARNING: MemorySanitizer", "backtrack": False},
        # ThreadSanitizer errors
        {"marker": "ERROR: ThreadSanitizer", "backtrack": False},
        # LeakSanitizer errors
        {"marker": "ERROR: LeakSanitizer", "backtrack": False},
        # libFuzzer crash indicator
        {"marker": "==ERROR: libFuzzer", "backtrack": False},
        # SEGV indicator (with backtracking to find the start of the report)
        {"marker": "SUMMARY: AddressSanitizer: SEGV", "backtrack": True},
        # Generic sanitizer summary (with backtracking)
        {"marker": "SUMMARY: ", "backtrack": True},
        # Java exceptions - Jazzer format
        {"marker": "Uncaught exception:", "backtrack": False},
        # Alternative Java exception format
        {"marker": "Java Exception:", "backtrack": False},
        # Generic Java exception format
        {"marker": "Exception in thread", "backtrack": False}
    ]
    
    # Try each pattern
    for pattern in patterns:
        marker_index = output.find(pattern["marker"])
        if marker_index != -1:
            # Found a match
            start_idx = marker_index
            
            # If backtracking is enabled, try to find the start of the error report
            if pattern["backtrack"]:
                # Look for the nearest "==" before the marker
                error_start = output[:marker_index].rfind("==")
                if error_start != -1:
                    start_idx = error_start
                else:
                    error_start = output[:marker_index].rfind("runtime error:")
                    if error_start != -1:
                        start_idx = error_start
                                    
            # Extract up to MAX_SIZE bytes
            if len(output) - start_idx > MAX_SIZE:
                return output[start_idx:start_idx + MAX_SIZE]
            else:
                return output[start_idx:]
    
    # If no specific error marker found, return the last 4KB of output
    if len(output) > MAX_SIZE:
        return output[-MAX_SIZE:]
    
    return output


def has_successful_pov(fuzzer_path):
    
    fuzzer_dir = os.path.dirname(fuzzer_path)
    pattern = os.path.join(fuzzer_dir, "successful_povs*")
    matches = glob.glob(pattern)
    for match in matches:
        if os.path.isfile(match) or os.path.isdir(match):
            print(f"Found successful POV ({match}).")
            return True
    return False


def extract_diff_functions_using_funtarget(project_src_dir: str, out_dir: str) -> Union[List[Dict[str, Any]], None]:
    # output file path
    output_file = os.path.join(out_dir,"diff_functions.json")
    # Read the JSON file
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            try:
                functions = json.load(f)
                if functions:        
                    return functions
            except Exception as e:
                    print(f"Unexpected error in json load output_file {output_file}: {e}")

    try:
        # Assuming it's in the same directory as the script or in PATH
        funtarget_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "funtarget")
        if not os.path.exists(funtarget_path):
            # Try to find it in PATH
            funtarget_path = "funtarget"

        cmd = [funtarget_path, "-dir", project_src_dir, "-output", output_file]
        subprocess.run(cmd, check=True)
        
        # Read the JSON file
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                functions = json.load(f)
            
            if not functions:
                return None
            
            return functions
        else:
            print(f"Output file {output_file} not found - likely the target function was not found")
            return None
        
    except subprocess.CalledProcessError as e:
        print(f"Error running funtarget: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON file: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error in extract_diff_functions_using_funtarget: {e}")
        return None

def extract_control_flow_for_c(
        log_file,
        lcov_path: str,
        project_src_dir: str,
        project_name: str) -> str:
    """
    Reduce LCOV data to only the diff-touched C files and return the compact
    control-flow text produced by c_coverage.py.

    Parameters
    ----------
    log_file         : open file-like object used by log_message(…)
    lcov_path        : path to coverage.lcov (host side)
    project_src_dir  : root of the project's source tree
    project_name     : project_name

    Returns
    -------
    str : stdout produced by c_coverage.py  ('' on error)
    """

    log_message(log_file, f"[extract_control_flow_for_c] lcov      : {lcov_path}")
    log_message(log_file, f"[extract_control_flow_for_c] src-root  : {project_src_dir}")

    out_dir_x = os.path.dirname(lcov_path)

    # ------------------------------------------------------------
    # 1. Determine files changed by the diff analysis helper
    # ------------------------------------------------------------
    diff_funcs = extract_diff_functions_using_funtarget(project_src_dir,out_dir_x) or []
    target_files = sorted(
        {os.path.basename(d.get("file", "")) for d in diff_funcs if d.get("file")}
    )
    log_message(log_file, f"[extract_control_flow_for_c] target_files: {target_files}")

    # ------------------------------------------------------------
    # 2. Locate c_coverage.py
    # ------------------------------------------------------------
    helper_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "c_coverage.py")
    if not os.path.exists(helper_script):
        helper_script = "c_coverage.py"   # hope it is on PATH

    # ------------------------------------------------------------
    # 3. Build command line
    # ------------------------------------------------------------
    cmd = [
        "python3", helper_script,
        "--lcov", lcov_path,
        "--src-root", project_src_dir,
        "--project-name", project_name,
    ]
    if target_files:
        cmd.extend(["--files", *target_files])

    # ------------------------------------------------------------
    # 4. Run helper
    # ------------------------------------------------------------
    try:
        log_message(log_file, f"[extract_control_flow_for_c] Running: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            cwd=out_dir_x,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.stdout:
            log_message(log_file, f"[c_coverage] stdout:\n{result.stdout}")
        if result.stderr:
            log_message(log_file, f"[c_coverage] stderr:\n{result.stderr}")

        if result.returncode != 0:
            log_message(log_file, f"[extract_control_flow_for_c] helper exited with {result.returncode}")
            return ""

        return result.stdout

    except subprocess.TimeoutExpired:
        log_message(log_file, "[extract_control_flow_for_c] c_coverage.py timed out")
    except Exception as exc:
        log_message(log_file, f"[extract_control_flow_for_c] error: {exc}")

    return ""


def _pick_fallback_jar(jar_dir: str) -> str | None:
    """Return a plausible project jar from jar_dir, skipping helper jars."""
    helper_patterns = ("jacoco", "jazzer", "metrics-")
    for jar in sorted(glob.glob(os.path.join(jar_dir, "*.jar"))):
        base = os.path.basename(jar)
        if not any(base.startswith(p) for p in helper_patterns):
            return jar
    return None

def extract_control_flow_from_coverage_exec(log_file,project_src_dir,project_jar,coverage_exec_dir):
    print(f"project_src_dir: {project_src_dir}")
    print(f"project_jar: {project_jar}")
    print(f"coverage_exec_dir: {coverage_exec_dir}")

    # ── ensure the jar really exists ──────────────────────────────────
    jar_path = os.path.join(coverage_exec_dir, project_jar)
    if not os.path.isfile(jar_path):
        fallback = _pick_fallback_jar(coverage_exec_dir)
        if fallback:
            log_message(log_file,
                        f"[java_coverage] {project_jar} not found – "
                        f"using fallback jar {fallback}")
            jar_path = fallback
        else:
            log_message(log_file,
                        "[java_coverage] no suitable *.jar found; aborting")
            return ""

    # Assuming it's in the same directory as the script or in PATH
    compact_branches_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "java_coverage.py")
    if not os.path.exists(compact_branches_path):
        # Try to find it in PATH
        compact_branches_path = "java_coverage.py"

    coverage_exec_path = os.path.join(coverage_exec_dir,"coverage.exec")

    try:
        cmd = [
            "python3",
            compact_branches_path,
            coverage_exec_path,
            jar_path,
            project_src_dir,
        ]
        log_message(log_file,
                    "extract_control_flow_from_coverage_exec CMD: " + " ".join(cmd))

        result = subprocess.run(
            cmd,
            cwd=coverage_exec_dir,
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        log_message(log_file, f"extract_control_flow_from_coverage_exec stdout: {result.stdout}")
        if result.stderr:
            log_message(log_file, f"Python code execution stderr: {result.stderr}")
        
        return result.stdout
    
    except subprocess.TimeoutExpired:
        log_message(log_file, f"Python code execution timed out")
        
    except Exception as e:
        log_message(log_file, f"Error running Python code: {str(e)}")

    return ""

SYSTEM_PROMPT="""
You are a world-leading top software vulnerability detection expert, which helps to find vulnerabilities. 
Do not aplogize when you are wrong. Just keep optimizing the result directly and proceed the progress. Do not lie or guess when you are unsure about the answer.
If possible, show the information needed to make the response better apart from the answer given. """


def cleanup_seed_corpus(dir_path, max_age_minutes=10):
    cutoff = time.time() - max_age_minutes * 60
    for path in glob.glob(os.path.join(dir_path, "*")):
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
        except OSError:
            pass   # ignore files that disappear meanwhile

def doPoV(log_file, initial_msg, fuzzer_path, fuzzer_name, sanitizer, project_dir, project_name, focus, language='c', check_patch_success=False) -> bool:

    pov_id = str(uuid.uuid4())[:8]

    if check_patch_success == True:
        log_message(log_file, "Will check for successful patches periodically")
       
    start_time = time.time()
    end_time = start_time + (FUZZING_TIMEOUT_MINUTES * 60)
    
    print(f"start_time: {start_time} end_time: {end_time} FUZZING_TIMEOUT_MINUTES: {FUZZING_TIMEOUT_MINUTES}")
    
    # Track if we've found at least one successful POV
    found_pov = False
    successful_pov_metadata = {}
    
    # Try with different models
    for model_name in MODELS:
        log_message(log_file, f"Attempting with model: {model_name}")
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        messages.append({"role": "user", "content": initial_msg})
        
        # Track successful POVs for this model
        model_success_count = 0

        for iteration in range(1, MAX_ITERATIONS + 1):
            current_time = time.time()
            if current_time > end_time:
                log_message(log_file, f"Timeout reached after {iteration-1} iterations with {model_name}")
                break
            
            if check_patch_success:
                if check_for_successful_patches(log_file, project_dir):
                    log_message(log_file, "Successful patch detected, stopping POV generation")
                    return True, {} # Return empty metadata since we're stopping early

            if has_successful_pov(fuzzer_path):
                return True, {}
                
            log_message(log_file, f"Iteration {iteration} with {model_name}")
            
            # Generate PoV
            code = generate_pov(log_file, project_dir, messages, model_name)
            
            if not code:
                log_message(log_file, "No valid Python code generated, continuing to next iteration")
                continue

            unique_id = str(uuid.uuid4())[:8]  #add unique id to avoid race condition
            xbin_dir = os.path.join(project_dir, "xp0", unique_id)
            log_message(log_file, f"Creating xbin_dir: {xbin_dir}")
            # Create the directory if it doesn't exist
            os.makedirs(xbin_dir, exist_ok=True)

            blob_path = os.path.join(xbin_dir, "x.bin")
            # Run the generated code
            success, stdout, stderr = run_python_code(log_file, code, xbin_dir,blob_path)

            if not success:
                log_message(log_file, "Failed to create x.bin, adding error to context and continuing")
                if stderr:
                    messages.append({"role": "user", "content": f"Python code failed with error: {stderr}\n\nPlease try again."})
                else:
                    messages.append({"role": "user", "content":  "Python code failed to create x.bin, please try again."})
                continue
            
            # Run the fuzzer with the generated input
            is_c_project = language.startswith('c')

            

            # Get all fuzzers from the same project (same directory)

            same_project_fuzzers = get_same_project_fuzzers(fuzzer_path)

            if not hasattr(update_blob_testing, 'logged_fuzzers'):

                log_message(log_file, f"[INFO] Found {len(same_project_fuzzers)} fuzzer(s) in same project:")

                for spf in same_project_fuzzers:

                    log_message(log_file, f"  - {os.path.basename(spf)}")

                update_blob_testing.logged_fuzzers = True

            

            # Test this blob against ALL fuzzers in the same project

            crash_detected = False

            fuzzer_output = ""

            for test_fuzzer_path in same_project_fuzzers:

                crash, output = run_fuzzer_with_input(log_file, test_fuzzer_path, project_dir, focus, blob_path, is_c_project)

                if crash:

                    crash_detected = True

                    fuzzer_output = output

                    log_message(log_file, f"  [+] CRASH with fuzzer: {os.path.basename(test_fuzzer_path)}")

                    break

                else:

                    log_message(log_file, f"  [-] No crash with: {os.path.basename(test_fuzzer_path)}")
            fuzzer_output = filter_instrumented_lines(fuzzer_output)
            if crash_detected:
                found_pov = True
                model_success_count += 1

                # Define a more accessible directory for saving POVs
                pov_base_dir = os.environ.get('POV_OUTPUT_DIR', '/tmp/povs')
                pov_success_dir = os.path.join(pov_base_dir, os.path.basename(POV_SUCCESS_DIR))
                save_dir = POV_SUCCESS_DIR
                try:
                    # Try to create the original directory first
                    os.makedirs(POV_SUCCESS_DIR, exist_ok=True)
                except PermissionError:
                    # If permission denied, use the alternative directory
                    log_message(log_file, f"Warning: Cannot write to {POV_SUCCESS_DIR}, using {pov_success_dir} instead")
                    os.makedirs(pov_success_dir, exist_ok=True)
                    save_dir = pov_success_dir
                
                # Save the successful test case
                pov_file_path = os.path.join(save_dir, f"pov_{pov_id}_{model_name}_{iteration}.py")
                try:
                    # Save the Python code that generated the successful test case
                    with open(pov_file_path, "w") as f:
                        f.write(code)
                    log_message(log_file, f"Saved POV to {pov_file_path}")
                except Exception as e:
                    log_message(log_file, f"Error saving POV: {str(e)}")
                    
                # Save the x.bin
                blob_file = f"test_blob_{pov_id}_{model_name}_{iteration}.bin"
                if os.path.exists(blob_path):
                    shutil.copy(blob_path, os.path.join(save_dir, blob_file))
                
                # Save the fuzzer output
                crash_output = extract_crash_output(fuzzer_output)
                fuzzer_output_file = f"fuzzer_output_{pov_id}_{model_name}_{iteration}.txt"
                with open(os.path.join(save_dir, fuzzer_output_file), "w") as f:
                    f.write(crash_output)
                
                # Save the conversation history as JSON
                conversation_file = f"conversation_{pov_id}_{model_name}_{iteration}.json"
                with open(os.path.join(save_dir, conversation_file), "w") as f:
                    json.dump(messages, f, indent=2)
                
                log_message(log_file, f"Saved successful PoV artifacts to {save_dir}")

                # Also save to main pov folder (same level as workspace)
                # Extract workspace name from project_dir (e.g., libpng_20251215_164844)
                workspace_name = os.path.basename(project_dir.rstrip('/'))
                # Get parent directory of workspace
                workspace_parent = os.path.dirname(project_dir.rstrip('/'))
                # Create pov directory at same level as workspace
                pov_parent = os.path.join(os.path.dirname(workspace_parent), "pov")
                workspace_pov_base = os.path.join(pov_parent, workspace_name)

                # Create a separate folder for each POV
                pov_folder_name = f"pov_{pov_id}_{model_name}_{iteration}"
                main_pov_dir = os.path.join(workspace_pov_base, pov_folder_name)

                try:
                    os.makedirs(main_pov_dir, exist_ok=True)

                    # Copy all POV artifacts to dedicated pov folder
                    main_pov_file = os.path.join(main_pov_dir, f"pov.py")
                    main_blob_file = os.path.join(main_pov_dir, "test_blob.bin")
                    main_output_file = os.path.join(main_pov_dir, "fuzzer_output.txt")
                    main_conv_file = os.path.join(main_pov_dir, "conversation.json")

                    shutil.copy(pov_file_path, main_pov_file)
                    if os.path.exists(os.path.join(save_dir, blob_file)):
                        shutil.copy(os.path.join(save_dir, blob_file), main_blob_file)
                    shutil.copy(os.path.join(save_dir, fuzzer_output_file), main_output_file)
                    shutil.copy(os.path.join(save_dir, conversation_file), main_conv_file)

                    log_message(log_file, f"Copied POV artifacts to: {main_pov_dir}")
                except Exception as e:
                    log_message(log_file, f"Warning: Failed to copy POV to main folder: {str(e)}")

                vuln_signature = fuzzer_name+"-"+generate_vulnerability_signature(crash_output, sanitizer)
                # Create POV metadata
                pov_metadata = {
                    "conversation": conversation_file,
                    "fuzzer_output": fuzzer_output_file,
                    "blob_file": blob_file,
                    "fuzzer_name": fuzzer_name,
                    "sanitizer": sanitizer,
                    "project_name": project_name,
                    "pov_signature": vuln_signature,
                }

                # Save pov_metadata to disk
                metadata_file = f"pov_metadata_{pov_id}_{model_name}_{iteration}.json"
                metadata_path = os.path.join(save_dir, metadata_file)
                with open(metadata_path, "w") as f:
                    json.dump(pov_metadata, f, indent=2)

                log_message(log_file, f"Saved PoV metadata to {metadata_path}")

                # Also save metadata to main pov folder
                try:
                    main_metadata_path = os.path.join(main_pov_dir, "pov_metadata.json")
                    with open(main_metadata_path, "w") as f:
                        json.dump(pov_metadata, f, indent=2)
                    log_message(log_file, f"Saved PoV metadata to: {main_metadata_path}")
                except Exception as e:
                    log_message(log_file, f"Warning: Failed to save metadata to main folder: {str(e)}")
                log_message(log_file, f"POV SUCCESS! Vulnerability triggered with {model_name} on iteration {iteration}")
                
                # Submit POV to endpoint
                submission_result = submit_pov_to_endpoint(log_file, project_dir, pov_metadata)
                if submission_result or True: # for local test w/o submission endpoint
                    log_message(log_file, "Successfully submitted POV to endpoint")
                else:
                    log_message(log_file, "Failed to submit POV to endpoint")
                
                successful_pov_metadata = pov_metadata
                
                # Continue with a new prompt to find a different POV
                user_message = f"""
Great job! You've successfully triggered the vulnerability. 

Now, let's try to find a different way to trigger a different vulnerability in the code.
Can you create a different test case that might trigger the vulnerability through a different code path or with different input values?

Focus on:
1. Different input formats or values
2. Alternative code paths that might reach the vulnerable function
3. Edge cases that weren't covered by your previous solution
4. Other potential vulnerabilities in the code

Please provide a new Python script that creates a different x.bin file. Only output the Python script, no other text.
"""
                messages.append({"role": "user", "content": user_message})
                
                # If we've found 2 successful POVs with this model, move to the next model
                if model_success_count >= 1:
                    log_message(log_file, f"Found {model_success_count} successful POVs with {model_name}, moving to next model")
                    break
            else:
                log_message(log_file, "Fuzzer did not crash, enhancing context and continuing")
                # Save x.bin to the fuzzer's seed corpus for future fuzzing
                if os.path.exists(blob_path):
                    seed_corpus_dir = os.path.join(project_dir, f"{fuzzer_name}_seed_corpus")
                    os.makedirs(seed_corpus_dir, exist_ok=True)
                    cleanup_seed_corpus(seed_corpus_dir, max_age_minutes=10)

                    # Use a timestamp to ensure unique filenames
                    timestamp = int(time.time())
                    seed_file_path = os.path.join(seed_corpus_dir, f"seed_{model_name}_{iteration}_{timestamp}.bin")
                    
                    # Copy the test case to the seed corpus
                    shutil.copy(blob_path, seed_file_path)
                    log_message(log_file, f"Saved test case to seed corpus: {seed_file_path}")

                if iteration == 1:
                    user_message = f"""
Fuzzer output:
{truncate_output(fuzzer_output, 200)}

The test case did not trigger the vulnerability. Please analyze the fuzzer output and try again with an improved approach. Consider:
1. Different input formats or values
2. Edge cases that might trigger the vulnerability
3. Focusing on the specific functions modified in the commit
4. Pay attention to details
5. Think step by step
"""
                else:
                    user_message = f"""
Fuzzer output:
{truncate_output(fuzzer_output, 200)}

The test case did not trigger the vulnerability. Please analyze the fuzzer output and try again with a different approach.
"""
                if iteration == MAX_ITERATIONS-1:
                    user_message = user_message + "\nThis is your last attempt. This task is very very important to me. If you generate a successful blob, I will tip you 2000 dollars."
                
                if USE_CONTROL_FLOW and iteration < MAX_ITERATIONS:   
                    covered_control_flow = ""
                    project_src_dir = os.path.join(project_dir, focus)

                    if is_c_project:
                        # 1. get coverage.profraw, coverage.profdata, coverage.lcov
                        # -e LLVM_PROFILE_FILE=/out/coverage.profraw 
                        success, lcov_path, debugmsg= run_fuzzer_with_input_for_c_coverage(log_file, fuzzer_path, project_dir, project_name, focus,blob_path)    
                        # 2. get covered_control_flow
                        if success == True:
                            covered_control_flow = extract_control_flow_for_c(log_file, lcov_path, project_src_dir,project_name)                
                    else:                                  
                        fuzz_dir = os.path.dirname(fuzzer_path)
                        coverage_exec_dir = os.path.join(fuzz_dir, "xp0")
                        project_jar =f"{project_name}.jar"                        
                        covered_control_flow = extract_control_flow_from_coverage_exec(log_file,project_src_dir,project_jar,coverage_exec_dir)
                    
                    if covered_control_flow:
                        cf_lines = covered_control_flow.splitlines()
                        if len(cf_lines) > 200:
                            compressed_cf = (
                                "\n".join(cf_lines[:100]) +
                                "\n...[truncated]...\n" +
                                "\n".join(cf_lines[-100:])
                            )
                        else:
                            compressed_cf = covered_control_flow
                        user_message = user_message + f"\n\nThe following shows the executed code path of the fuzzer with input x.bin. You should generate a new x.bin to execute a different code path\n{compressed_cf}"
                    
                messages.append({"role": "user", "content": user_message})
                if os.path.exists(blob_path):
                    os.remove(blob_path)


        if model_success_count >= 1:
            log_message(log_file, f"Found {model_success_count} successful POVs! Break model loop.")
            break

    # Final summary
    total_time = time.time() - start_time
    log_message(log_file, f"Strategy xs0_delta completed in {total_time:.2f} seconds")
    
    # Check if any successful PoVs were found
    if os.path.exists(POV_SUCCESS_DIR) and len(os.listdir(POV_SUCCESS_DIR)) > 0:
        pov_count = len([f for f in os.listdir(POV_SUCCESS_DIR) if f.startswith("pov_metadata_")])
        log_message(log_file, f"Found {pov_count} successful PoVs")
        return found_pov, successful_pov_metadata
    else:
        log_message(log_file, "No successful PoVs found")
        return False, {}

if False:
    log_file = setup_logging('test_extract_control_flow_from_coverage_exec')
    project_dir = "/crs-workdir/3267a826-7d98-4710-bbc1-4bcaf4ca46c3-20250506-195030/"
    project_src_dir = project_dir+"afc-zookeeper-address"
    fuzz_dir = "/crs-workdir/3267a826-7d98-4710-bbc1-4bcaf4ca46c3-20250506-195030/fuzz-tooling/build/out/zookeeper-address"
    project_jar = "zookeeper.jar"
    covered_control_flow = extract_control_flow_from_coverage_exec(log_file,project_src_dir,project_jar,fuzz_dir)
    print(f"covered_control_flow:{covered_control_flow}")
    exit(0)

if False:
    log_file = setup_logging('test_extract_control_flow_for_c')
    project_dir = "/crs-workdir/0196b135-fb7d-7635-9f9c-2c4b0733b438-20250519-174317/"
    lcov_path = project_dir+"fuzz-tooling/build/out/libxml2/coverage.lcov"
    project_src_dir = project_dir+"round-exhibition2-libxml2"
    project_name = "libxml2"
    covered_control_flow = extract_control_flow_for_c(log_file, lcov_path, project_src_dir,project_name) 
    print(f"covered_control_flow:{covered_control_flow}")
    exit(0)



import clang.cindex
# Try to set the library path explicitly
clang.cindex.Config.set_library_file('/usr/lib/llvm18/lib/libclang.so')

def extract_function_name_from_code(code_block):
    """
    Attempts to extract a function name from a code block.
    Returns the function name if found, None otherwise.
    """
    import re
    
    # Common patterns for function definitions in various languages
    patterns = [
        r'(?:static\s+)?(?:void|int|char|double|float|size_t|png_\w+)\s+(\w+)\s*\(',  # C/C++ style
        r'(?:static\s+)?(?:\w+)\s+(?:\*\s*)?(\w+)\s*\(',  # More general C/C++ pattern
        r'function\s+(\w+)\s*\(',  # JavaScript style
        r'def\s+(\w+)\s*\(',  # Python style
        # Java patterns
        r'(?:public|private|protected|static|final|native|synchronized|abstract|transient)?\s*(?:<.*>)?\s*(?:(?:\w+)(?:<.*>)?(?:\[\])?\s+)?(\w+)\s*\(',  # Java method
        r'(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*(?:\w+)(?:<.*>)?\s+(\w+)\s*\(',  # Simplified Java method
    ]
    
    for pattern in patterns:
        match = re.search(pattern, code_block)
        if match:
            return match.group(1)
    
    return None

def create_commit_based_prompt(fuzzer_code, commit_diff, sanitizer, language):
    """
    Create a prompt for the LLM based on the fuzzer code, commit diff, language, and sanitizer.
    Handles C/C++ and Java projects differently and targets specific sanitizers.
    """
    # Base prompt that applies to all languages
    base_prompt = f"""
The provided commit introduces a vulnerability. Your job is to find the correct input to trigger the vulnerability.
Please output a Python script that creates a x.bin file. Your blob file will be run by this fuzzer code:
{fuzzer_code}

# Commit Diff
{commit_diff}
"""

    # C/C++ specific prompt with sanitizer targeting
    if language.startswith('c'):
        # Define sanitizer-specific guidance
        sanitizer_guidance = {
            "address": """
The target project uses AddressSanitizer, which detects:
- Buffer overflows (stack, heap, global)
- Use-after-free errors
- Use-after-return bugs
- Use-after-scope bugs
- Double-free errors

Your goal is to trigger an AddressSanitizer error by crafting an input that exploits the vulnerability.
""",
            "memory": """
The target project uses MemorySanitizer, which detects:
- Uninitialized memory reads
- Use of uninitialized values in conditional operations
- Passing uninitialized values to library functions

Your goal is to trigger a MemorySanitizer error by crafting an input that causes the program to use uninitialized memory.
""",
            "undefined": """
The target project uses UndefinedBehaviorSanitizer, which detects:
- Integer overflow/underflow
- Signed integer overflow
- Division by zero
- Null pointer dereference
- Misaligned pointer dereference
- Unreachable code
- Invalid enum values
- Floating-point errors

Your goal is to trigger an UndefinedBehaviorSanitizer error by crafting an input that causes undefined behavior.
"""
        }
        
        # Get the guidance for the specified sanitizer, or use a generic one if not found
        sanitizer_specific = sanitizer_guidance.get(sanitizer.lower(), """
The target project uses sanitizers that can detect various types of errors. Your goal is to trigger a sanitizer error by crafting an input that exploits the vulnerability.
""")
        
        language_specific = f"""
IMPORTANT: Read the harness code carefully to understand how inputs are processed. You need to generate a complete blob that will trigger a sanitizer error.

Think through these steps:
1. What function contains the vulnerability? How do you reach this function?
2. What input will trigger the vulnerability?
3. Are there any other inputs required before reaching the target function?
4. How does the harness code process inputs? Follow the instructions in the harness.
5. Combine all this information to generate a complete blob.
{sanitizer_specific}
"""

    # Java specific prompt
    else:
        language_specific = """
IMPORTANT: Read the harness code carefully to understand how inputs are processed. You need to generate a complete blob that will trigger a Jazzer sanitizer error or Java exception.

Think through these steps:
1. What method contains the vulnerability? How do you reach this method?
2. What input will trigger the vulnerability?
3. Are there any other inputs required before reaching the target method?
4. How does the harness code process inputs? Follow the instructions in the harness.
5. Combine all this information to generate a complete blob.

The target project uses Jazzer sanitizers that can detect various types of vulnerabilities:
- ClojureLangHooks: detects vulnerabilities in Clojure code
- Deserialization: detects unsafe deserialization
- ExpressionLanguageInjection: detects expression language injection
- FilePathTraversal: detects path traversal vulnerabilities
- LdapInjection: detects LDAP injection
- NamingContextLookup: detects JNDI injection
- OsCommandInjection: detects OS command injection
- ReflectiveCall: detects unsafe reflection
- RegexInjection: detects regex injection
- RegexRoadblocks: detects regex denial of service
- ScriptEngineInjection: detects script engine injection
- ServerSideRequestForgery: detects SSRF vulnerabilities
- SqlInjection: detects SQL injection
- XPathInjection: detects XPath injection

Your goal is to trigger any of these sanitizer errors or a Java exception (like NullPointerException, ArrayIndexOutOfBoundsException, etc.) by crafting an input that exploits the vulnerability.
"""

    # Common ending for both languages
    ending = """
Limit the blob size to 2MiB max

Your output must be a Python script that creates a file named exactly "x.bin" with a short description of the vulnerability and the target function.
"""

    # Combine the parts to create the final prompt
    return base_prompt + language_specific + ending



def load_task_detail(fuzz_dir):
    """
    Load TaskDetail from the task_detail.json file in the fuzzing directory.
    
    Args:
        fuzz_dir (str): Path to the fuzzing directory
        
    Returns:
        dict: The TaskDetail as a dictionary, or None if the file doesn't exist or can't be parsed
    """
    import os
    import json
    import logging
    
    task_detail_path = os.path.join(fuzz_dir, "task_detail.json")
    
    if not os.path.exists(task_detail_path):
        logging.warning(f"Task detail file not found at {task_detail_path}")
        return None
    
    try:
        with open(task_detail_path, 'r') as f:
            task_detail = json.load(f)
            
        # Validate required fields
        required_fields = ["task_id", "type", "metadata", "deadline", "focus", "project_name"]
        for field in required_fields:
            if field not in task_detail:
                logging.warning(f"Required field '{field}' missing from task_detail.json")
        
        logging.info(f"Successfully loaded task detail for project: {task_detail.get('project_name', 'unknown')}")
        return task_detail
        
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse task_detail.json: {str(e)}")
        return None
    except Exception as e:
        logging.error(f"Error loading task_detail.json: {str(e)}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Strategy 0: LLM-guided POV Generation")
    parser.add_argument("fuzzer_path", help="Path to the fuzzer")
    parser.add_argument("project_name", help="Project name")
    parser.add_argument("focus", help="Focus")
    parser.add_argument("language", help="Language")

    # Optional arguments to override default constants
    parser.add_argument("--test-nginx", dest="test_nginx", type=lambda x: x.lower() == 'true', 
                    default=False, help="Whether to test Nginx (true/false)")
    parser.add_argument("--do-patch", dest="do_patch", type=lambda x: x.lower() == 'true', 
                        default=False, help="Whether to apply patches (true/false)")
    parser.add_argument("--do-patch-only", dest="do_patch_only", type=lambda x: x.lower() == 'true', 
                        default=False, help="Whether to only run patching (true/false)")
    parser.add_argument("--full-scan", dest="full_scan", type=lambda x: x.lower() == 'true', 
                        default=False, help="Whether full scan (default is delta-scan (true/false)")
    parser.add_argument("--max-iterations", dest="max_iterations", type=int,
                        default=5, help="Maximum number of iterations")
    parser.add_argument("--fuzzing-timeout", dest="fuzzing_timeout", type=int,
                        default=30, help="Fuzzing timeout in minutes")
    parser.add_argument("--patching-timeout", dest="patching_timeout", type=int,
                        default=30, help="Patching timeout in minutes")
    parser.add_argument("--pov-metadata-dir", dest="pov_metadata_dir", type=str,
                        default="successful_povs", help="Directory to store POV metadata")
    parser.add_argument("--patch-workspace-dir", help="Directory for patch workspace", default="patch_workspace")
    parser.add_argument("--check-patch-success", action="store_true", 
                        help="Check for successful patches and exit early if found")
    parser.add_argument("--model", type=str, default="", help="Specify the model to use")

    parser.add_argument("--cpv", type=str, default="cpv12",
                        help="CPV number to test (e.g., cpv3, cpv5, cpv9)")

    parser.add_argument("--pov-phase", type=int, default=0, help=argparse.SUPPRESS)

    args = parser.parse_args()
    # Set global variables
    global TEST_NGINX, DO_PATCH, DO_PATCH_ONLY, MAX_ITERATIONS, FUZZING_TIMEOUT_MINUTES
    global PATCHING_TIMEOUT_MINUTES, POV_METADATA_DIR, PATCH_WORKSPACE_DIR, MODELS, CPV
    global FULL_SCAN
    global GLOBAL_FUNCTION_METADATA
    global CLAUDE_MODEL, OPENAI_MODEL

    TEST_NGINX = args.test_nginx
    DO_PATCH = args.do_patch
    DO_PATCH_ONLY = args.do_patch_only
    FULL_SCAN = args.full_scan
    MAX_ITERATIONS = args.max_iterations
    FUZZING_TIMEOUT_MINUTES = args.fuzzing_timeout
    PATCHING_TIMEOUT_MINUTES = args.patching_timeout
    POV_METADATA_DIR = args.pov_metadata_dir
    PATCH_WORKSPACE_DIR = args.patch_workspace_dir
    global CLAUDE_MODEL, OPENAI_MODEL
    if args.model:
        CLAUDE_MODEL = args.model
        OPENAI_MODEL = args.model
        MODELS = [args.model]
    print(f"DEBUG: Global MODELS = {MODELS}")
    if TEST_NGINX== True:
        MODELS = [args.model]
        CPV = args.cpv

    if args.model:
        CLAUDE_MODEL = args.model
        OPENAI_MODEL = args.model
        MODELS = [args.model]
    print(f"DEBUG: Global MODELS = {MODELS}")

    # Add debug output after setting globals
    print(f"DEBUG: Global TEST_NGINX = {TEST_NGINX}")
    print(f"DEBUG: Global DO_PATCH = {DO_PATCH}")
    print(f"DEBUG: Global DO_PATCH_ONLY = {DO_PATCH_ONLY}")
    print(f"DEBUG: Global FULL_SCAN = {FULL_SCAN}")
    print(f"DEBUG: Global MAX_ITERATIONS = {MAX_ITERATIONS}")
    print(f"DEBUG: Global FUZZING_TIMEOUT_MINUTES = {FUZZING_TIMEOUT_MINUTES}")
    print(f"DEBUG: Global PATCHING_TIMEOUT_MINUTES = {PATCHING_TIMEOUT_MINUTES}")
    print(f"DEBUG: Global POV_METADATA_DIR = {POV_METADATA_DIR}")

    fuzzer_path = args.fuzzer_path
    project_name = args.project_name
    focus = args.focus
    language = args.language
    if not language.startswith('c'):
        language = "java"
    else:
        language = "c"

    print(f"DEBUG: language = {language}")

    fuzzer_name = os.path.basename(fuzzer_path)
    fuzz_dir = os.path.dirname(fuzzer_path)

    global POV_SUCCESS_DIR, PATCH_SUCCESS_DIR
    POV_SUCCESS_DIR = os.path.join(fuzz_dir, POV_METADATA_DIR)
    PATCH_SUCCESS_DIR = os.path.join(fuzz_dir, PATCH_METADATA_DIR)
    print(f"DEBUG: Global POV_SUCCESS_DIR = {POV_SUCCESS_DIR}")
    print(f"DEBUG: Global PATCH_SUCCESS_DIR = {PATCH_SUCCESS_DIR}")

    base_name = os.path.basename(fuzz_dir)
    parts = base_name.split("-")
    sanitizer = parts[-1]  # "address" in this example
    if sanitizer == project_name:
        sanitizer = "address"

    if "/fuzz-tooling/build/out" in fuzzer_path:
        project_dir = fuzzer_path.split("/fuzz-tooling/build/out")[0] + "/"
    else:
        project_dir = os.path.dirname(os.path.dirname(fuzzer_path))
    
    project_src_dir = os.path.join(project_dir, focus+"-"+sanitizer)
    print(f"DEBUG: project_dir = {project_dir}")
    print(f"DEBUG: project_src_dir = {project_src_dir}")

    log_file = setup_logging(fuzzer_name)


    task_detail = load_task_detail(fuzz_dir)

    if TEST_NGINX == True:
        fuzzer_path="/home/jeff/challenge-004-nginx-cp/"
        project_dir="/home/jeff/challenge-004-nginx-cp/"
        fuzzer_name="pov_harness"
        # build the project
        log_message(log_file, f"Building the initial Nginx project")
        try:
            subprocess.run(
                ["git", "reset", "--hard", "HEAD"],
                cwd=os.path.join(project_dir, focus),
                check=True,
                capture_output=True
            )
            subprocess.run(["./run.sh", "build"], cwd=project_dir, capture_output=True, text=True)
        except Exception as e:
            log_message(log_file, f"Exception building initial project: {str(e)}")

    pov_success = False  # Default value in case the block below doesn't set it

    # Wrap your entire main execution in a root span
    with tracer.start_as_current_span("basic_fuzzing") as span:
        span.set_attribute("crs.action.category", "fuzzing")
        span.set_attribute("crs.action.name", "basic_fuzzing_delta_scan")
        span.set_attribute("service.name", "xs0_delta")
        span.set_attribute("fuzzer.path", f"{fuzzer_path}")

        if task_detail:
            for key, value in task_detail["metadata"].items():
                span.set_attribute(key, value)   
        
        fuzzer_code = find_fuzzer_source(log_file, fuzzer_path, project_name, project_src_dir, focus, language)

        log_message(log_file, f"Starting Strategy xs0_delta for fuzzer: {fuzzer_path}")
        log_message(log_file, f"Project directory: {project_dir}")

        try:
            # Get commit information
            commit_msg, commit_diff = get_commit_info(log_file, project_dir,language)
            initial_msg = create_commit_based_prompt(fuzzer_code, commit_diff,sanitizer,language)
            # print(f"initial_msg: {initial_msg}")
            pov_success, pov_metadata = doPoV(log_file,initial_msg,fuzzer_path,fuzzer_name,sanitizer,project_dir,project_name,focus,language, args.check_patch_success)
        
        except Exception as e:
            span.record_exception(e)

        span.set_attribute("crs.pov.success", pov_success)
        
    
    return 0 if pov_success else 1

if __name__ == "__main__":
    sys.exit(main())