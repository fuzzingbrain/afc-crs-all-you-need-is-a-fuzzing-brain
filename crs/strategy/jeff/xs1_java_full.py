# strategy 0
#!/usr/bin/env python3
"""
Strategy 0 (FULL SCAN): LLM-guided test harness generation for vulnerability triggering
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
import textwrap

load_dotenv()

# for testing only on Nginx
TEST_NGINX = False

DO_PATCH = False
DO_PATCH_ONLY = False
FULL_SCAN = False
USE_CONTROL_FLOW = False
GLOBAL_FUNCTION_METADATA = {}

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
OPENAI_MODEL_O3_PRO = "o3-pro"
OPENAI_MODEL_O3_MINI = "o3-mini"
OPENAI_MODEL_O4_MINI = "o4-mini"
OPENAI_MODEL_41 = "gpt-4.1"
# OPENAI_MODEL = "chatgpt-4o-latest"
# CLAUDE_MODEL = "gpt-4o-mini"
CLAUDE_MODEL = "claude-3-7-sonnet-latest"
CLAUDE_MODEL_35 = "claude-3-5-sonnet-20241022"
GEMINI_MODEL_PRO_25_0325 = "gemini-2.5-pro-preview-03-25"
GEMINI_MODEL_PRO_25_0506 = "gemini-2.5-pro-preview-05-06"
GEMINI_MODEL_PRO_25_0605 ="gemini-2.5-pro-preview-06-05"

GEMINI_MODEL_PRO_25 = "gemini-2.5-pro"
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_MODEL_PRO = "gemini-2.0-pro-exp-02-05"
GEMINI_MODEL_FLASH = "gemini-2.5-flash"
GEMINI_MODEL_FLASH_LITE = "gemini-2.5-flash-lite-preview-06-17"
GROK_MODEL = "xai/grok-3-beta"
CLAUDE_MODEL_SONNET_4 = "claude-sonnet-4-20250514"
CLAUDE_MODEL_OPUS_4 = "claude-opus-4-20250514"
MODELS = [CLAUDE_MODEL_OPUS_4, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25]
CLAUDE_MODEL = CLAUDE_MODEL_SONNET_4
OPENAI_MODEL = CLAUDE_MODEL_SONNET_4
MODELS = [CLAUDE_MODEL_SONNET_4, CLAUDE_MODEL_OPUS_4]

def get_fallback_model(current_model, tried_models):
    """Get a fallback model that hasn't been tried yet"""
    # Define model fallback chains
    fallback_chains = {
        GEMINI_MODEL_PRO_25: [CLAUDE_MODEL, CLAUDE_MODEL_35, OPENAI_MODEL_41, OPENAI_MODEL_O3],   
        OPENAI_MODEL_41: [OPENAI_MODEL_O4_MINI, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25],   
        OPENAI_MODEL: [GEMINI_MODEL_PRO_25, GEMINI_MODEL_FLASH, GEMINI_MODEL_FLASH_LITE],             
        CLAUDE_MODEL: [CLAUDE_MODEL_SONNET_4,OPENAI_MODEL, CLAUDE_MODEL_35, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25],        
        CLAUDE_MODEL_OPUS_4: [OPENAI_MODEL, CLAUDE_MODEL_35, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25],        
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
    patch_status = "patch_only" if DO_PATCH_ONLY else "basic_pov_full_strategy"
    scan_type = "full_scan" if FULL_SCAN else "delta_scan"
    
    timestamp = int(time.time())
    log_file = os.path.join(LOG_DIR, f"xs1_java_full_{fuzzer_name}_{patch_status}_{scan_type}_{timestamp}.log")
    
    # Log initial configuration
    with open(log_file, "w") as f:
        f.write(f"Strategy: XS1_JAVA_FULL\n")
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

    print(f"truncate_output: {output}")

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
    #skip gemini -- too slow
    tried_models_in_this_call.add(GEMINI_MODEL_PRO_25)

    for attempt in range(max_retries):
        try:
            if attempt > 0:
                log_message(log_file, f"Retry attempt {attempt+1}/{max_retries} using model {current_model}...")
            
            response = completion(
                model=current_model,
                messages=messages,
                temperature=1.0,
                timeout=900,
                max_tokens=8192
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
            is_auth_error = "AuthenticationError" in error_str
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
                        response = call_gemini_api(log_file, messages, current_model)
                        return response
                        
                    except Exception as e:  
                        error_str = str(e)
                        log_message(log_file, f"Gemini Attempt {attempt+1}/{max_retries} failed with model {current_model}: {error_str}")
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

def extract_python_code_from_response(log_file, text, max_retries=2, timeout=30):
    """    
    Args:
        text: The text containing code to extract
        max_retries: Maximum number of retry attempts
        timeout: Timeout in seconds for each API call
        
    Returns:
        str: Extracted Python code or None if extraction failed
    """
    # ─── quick path ────────────────────────────────────────────────
    # If the text already embeds a Python Markdown fence,
    # grab the first block and return it straight away.
    quick_pattern = r"```(?:python)?\s*([\s\S]*?)```"
    m = re.search(quick_pattern, text)
    if m:
        candidate = m.group(1).strip()
        if candidate:                     # non-empty code
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

def find_fuzzer_source(log_file, fuzzer_path, project_name, project_src_dir, language='c'):
    """Find the source code of the fuzzer by using the model to analyze build scripts and source files"""

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
        if os.path.exists(project_src_dir):
            for root, dirs, files in os.walk(project_src_dir):
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
    extensions = ['.c', '.cc']
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
                                return strip_license_text(content), file_path
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
    
    if os.path.exists(project_src_dir):
        for root, dirs, files in os.walk(project_src_dir):                
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
                
            # Look for directories with fuzzer-related names
            for dir_name in dirs:
                lower_dir = dir_name.lower()
                if "fuzz" in lower_dir or "harness" in lower_dir:
                    fuzzer_dir = os.path.join(root, dir_name)
                    fuzzer_related_dirs.append(fuzzer_dir)
                    
            # Also look for directories containing fuzzer-related files
            has_fuzzer_files = False
            for file in files:
                lower_file = file.lower()
                if "fuzz" in lower_file:
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
                                return strip_license_text(content), file_path
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
        return strip_license_text(source_files[only_file_path]), only_file_path
    
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
                return strip_license_text(source_files[file_path]), file_path
        
        log_message(log_file, "Could not identify fuzzer source")
        return "// Could not find the source code for the fuzzer", ""
    
    # Parse the model's response to get the file path
    response = response.strip()
    
    # Extract the file path from the response
    file_path_match = re.search(r'(/[^\s]+)', response)
    if file_path_match:
        identified_path = file_path_match.group(1)
        log_message(log_file, f"Model identified fuzzer source as: {identified_path}")
        
        # Check if the identified path is in our collected source files
        if identified_path in source_files:
            return strip_license_text(source_files[identified_path]), identified_path
        
        # If not, try to read the file directly
        if os.path.exists(identified_path):
            try:
                with open(identified_path, 'r') as f:
                    content = f.read()
                    log_message(log_file, f"Successfully read identified fuzzer source")
                    return strip_license_text(content), identified_path
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
            return strip_license_text(source_files[file_path]), file_path
    
    log_message(log_file, "Could not identify fuzzer source")
    return "// Could not find the source code for the fuzzer", ""


def run_python_code(log_file, code, xbin_dir):
    """Run the generated Python code to create x.bin"""
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
        for i in range(6):  # 0 through 5
            blob_name = "x.bin" if i == 0 else f"x{i}.bin"
            blob_path = os.path.join(xbin_dir, blob_name)
            
            if os.path.exists(blob_path):
                log_message(log_file, f"{blob_name} was created successfully ({os.path.getsize(blob_path)} bytes)")
                return True, result.stdout, result.stderr
        
        # If we get here, no blob file was found
        log_message(log_file, f"No blob file (x.bin through x5.bin) was created")
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
        # Find Docker image: try aixcc-afc first, then gcr.io/oss-fuzz
        docker_image = None
        try:
            result_check = subprocess.run(["docker", "images", f"aixcc-afc/{project_name}", "--format", "{{.Repository}}:{{.Tag}}"], capture_output=True, text=True, timeout=60)
            if result_check.returncode == 0 and result_check.stdout.strip():
                docker_image = result_check.stdout.strip().split('\n')[0]
                log_message(log_file, f"Using Docker image: {docker_image}")
        except Exception as e:
            log_message(log_file, f"Failed to find docker image for aixcc-afc/{project_name}: {str(e)}")

        if not docker_image:
            try:
                result_check = subprocess.run(["docker", "images", f"gcr.io/oss-fuzz/{project_name}", "--format", "{{.Repository}}:{{.Tag}}"], capture_output=True, text=True, timeout=60)
                if result_check.returncode == 0 and result_check.stdout.strip():
                    docker_image = result_check.stdout.strip().split('\n')[0]
                    log_message(log_file, f"Using Docker image: {docker_image}")
            except Exception as e:
                log_message(log_file, f"Failed to find docker image for gcr.io/oss-fuzz/{project_name}: {str(e)}")

        if not docker_image:
            log_message(log_file, f"Failed to find docker image for {project_name}")
            return False, lcov_host, f"Failed to find docker image for {project_name}"

        docker_run = [
            "docker", "run", "--rm", "--platform", "linux/amd64",
            "-e", "FUZZING_ENGINE=libfuzzer",
            "-e", "ARCHITECTURE=x86_64",
            # LLVM_PROFILE_FILE tells the binary where to dump coverage
            "-e", "LLVM_PROFILE_FILE=/out/coverage.profraw",
            "-v", f"{out_dir}:/out",
            docker_image,
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
            docker_image,
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

            # Find Docker image: try aixcc-afc first, then gcr.io/oss-fuzz
            docker_image = None
            try:
                result_check = subprocess.run(["docker", "images", f"aixcc-afc/{project_name}", "--format", "{{.Repository}}:{{.Tag}}"], capture_output=True, text=True, timeout=60)
                if result_check.returncode == 0 and result_check.stdout.strip():
                    docker_image = result_check.stdout.strip().split('\n')[0]
                    log_message(log_file, f"Using Docker image: {docker_image}")
            except Exception as e:
                log_message(log_file, f"Failed to find docker image for aixcc-afc/{project_name}: {str(e)}")

            if not docker_image:
                try:
                    result_check = subprocess.run(["docker", "images", f"gcr.io/oss-fuzz/{project_name}", "--format", "{{.Repository}}:{{.Tag}}"], capture_output=True, text=True, timeout=60)
                    if result_check.returncode == 0 and result_check.stdout.strip():
                        docker_image = result_check.stdout.strip().split('\n')[0]
                        log_message(log_file, f"Using Docker image: {docker_image}")
                except Exception as e:
                    log_message(log_file, f"Failed to find docker image for gcr.io/oss-fuzz/{project_name}: {str(e)}")

            if not docker_image:
                log_message(log_file, f"Failed to find docker image for {project_name}")
                return False, f"Failed to find docker image for {project_name}"

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
                docker_cmd = [
                    "docker", "run", "--rm",
                    "--platform", "linux/amd64",
                    "-e", "FUZZING_ENGINE=libfuzzer",
                    "-e", f"SANITIZER={sanitizer}",
                    "-e", "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1",
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

        # log_message(log_file, f"Fuzzer stdout: {result.stdout}")
        if result.stderr:
            log_message(log_file, f"Fuzzer stderr: {result.stderr}")
        

        crash_indicators = [
            "ERROR: AddressSanitizer:",
            "ERROR: LeakSanitizer:",
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
    
    response, success = call_llm(log_file, messages, model_name)
    if (not success or response is None or (isinstance(response, str) and not response.strip())):
        log_message(log_file, f"Failed to get valid response from {model_name}")
        return None

    log_message(log_file, f"generate_pov response:\n{response}")

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
    submission["strategy"] = "xs1_java_full"
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

def doPoV_full(log_file, initial_msg, fuzzer_path, fuzzer_name, sanitizer, project_dir, project_name, focus, language='c', check_patch_success=False) -> bool:

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
            
            log_message(log_file, f"Iteration {iteration} with {model_name}")

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
            
            # Generate PoV
            code = generate_pov(log_file, project_dir, messages, model_name)
            
            if not code:
                log_message(log_file, "No valid Python code generated, continuing to next iteration")
                continue

            xbin_dir = os.path.join(project_dir, "xp0")
            log_message(log_file, f"Creating xbin_dir: {xbin_dir}")
            # Create the directory if it doesn't exist
            os.makedirs(xbin_dir, exist_ok=True)                
            # Run the generated code
            success, stdout, stderr = run_python_code(log_file, code, xbin_dir)

            if not success:
                log_message(log_file, f"Failed to create x.bin or x1.bin, adding error to context and continuing. Error: {stderr}")
                if stderr:
                    messages.append({"role": "user", "content": f"Python code failed with error: {stderr}\n\nPlease try again."})
                else:
                    messages.append({"role": "user", "content":  "Python code failed to create x.bin or x1.bin, please try again."})
                continue
            
            # Run the fuzzer with the generated input
            # ------------------------------------------------------------
            # ʟᴏᴏᴘ over blob files   x.bin  x1.bin  x2.bin …
            # ------------------------------------------------------------
            MAX_BLOBS = 6
            crash_detected = False
            fuzzer_output  = ""
            all_blob_paths = set()
            for idx in range(MAX_BLOBS):
                blob_name = "x.bin" if idx == 0 else f"x{idx}.bin"

                # Stop if the file does not exist
                blob_path = os.path.join(xbin_dir, blob_name)
                if not os.path.exists(blob_path):
                    log_message(log_file, f"[INFO] {blob_name} not found; nothing to run.")
                    continue

                log_message(log_file, f"[INFO] Running fuzzer with {blob_name} (attempt {idx})")
                is_c_project = language.startswith('c')
                crash_detected, fuzzer_output = run_fuzzer_with_input(
                    log_file, fuzzer_path, project_dir, focus, blob_path, is_c_project
                )
                fuzzer_output = filter_instrumented_lines(fuzzer_output)
                if crash_detected:
                    log_message(log_file, f"[+] Crash detected with {blob_name}")
                    break  # success - stop looping

                log_message(log_file, "Fuzzer did not crash, adding output to context and continuing")
                # Save x.bin to the fuzzer's seed corpus for future fuzzing
                if os.path.exists(blob_path):
                    # log_message(log_file, f"[blob_path] {blob_path}")
                    seed_corpus_dir = os.path.join(project_dir, f"{fuzzer_name}_seed_corpus")
                    os.makedirs(seed_corpus_dir, exist_ok=True)
                    cleanup_seed_corpus(seed_corpus_dir, max_age_minutes=10)
                    # log_message(log_file, f"[seed_corpus_dir] {seed_corpus_dir}")
                    # Use a timestamp to ensure unique filenames
                    timestamp = int(time.time())
                    seed_file_path = os.path.join(seed_corpus_dir, f"seed_{model_name}_{iteration}_{timestamp}.bin")
                    
                    # Copy the test case to the seed corpus
                    shutil.copy(blob_path, seed_file_path)
                    log_message(log_file, f"Saved test case to seed corpus: {seed_file_path}")
                    #remove blob file if fail to trigger crash
                    all_blob_paths.add(blob_path)
                    # log_message(log_file, f"[all_blob_paths] {all_blob_paths}")

            if crash_detected:
                log_message(log_file, f"[crash_detected] {crash_detected}.")

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

Please provide a new Python script that creates a different x.bin file.
"""
                messages.append({"role": "user", "content": user_message})
                
                # If we've found 2 successful POVs with this model, move to the next model
                # For full-scan model, there may exist multiple vulnerabilities?
                if model_success_count >= 1:
                    log_message(log_file, f"Found {model_success_count} successful POVs with {model_name}, moving to next model")
                    break
            else:
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
                if iteration == MAX_ITERATIONS - 1:
                    user_message = user_message + "\nThis is your last attempt. This task is very very important to me. If you generate a successful blob, I will tip you 2000 dollars."
 
                if USE_CONTROL_FLOW and iteration < MAX_ITERATIONS:
                    covered_control_flow = ""
                    project_src_dir = os.path.join(project_dir, focus)

                    if is_c_project:
                        # 1. get coverage.profraw, coverage.profdata, coverage.lcov
                        # -e LLVM_PROFILE_FILE=/out/coverage.profraw 
                        if not os.path.exists(blob_path):
                            blob_path = os.path.join(xbin_dir, "x1.bin") # if not exist, use x1.bin
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

                        user_message = user_message + f"\n\nThe following shows the executed code path of the fuzzer with input {blob_name}. You should generate new x.bin files to execute different code paths\n{compressed_cf}"
  
                messages.append({"role": "user", "content": user_message})
                for blob_path_x in all_blob_paths:
                    if os.path.exists(blob_path_x):
                        os.remove(blob_path_x)

        if model_success_count >= 1:
            log_message(log_file, f"Found {model_success_count} successful POVs! Break model loop.")
            break

    # Final summary
    total_time = time.time() - start_time
    log_message(log_file, f"Strategy xs0_full completed in {total_time:.2f} seconds")
    
    # Check if any successful PoVs were found
    if os.path.exists(POV_SUCCESS_DIR) and len(os.listdir(POV_SUCCESS_DIR)) > 0:
        pov_count = len([f for f in os.listdir(POV_SUCCESS_DIR) if f.startswith("pov_metadata_")])
        log_message(log_file, f"Found {pov_count} successful PoVs")
        return found_pov, successful_pov_metadata
    else:
        log_message(log_file, "No successful PoVs found")
        return False, {}

def construct_get_target_functions_prompt0(context_info: str, crash_log: str):
    prompt = f"""
Your task is to identify all potentially vulnerable functions from a code commit and a crash log.

Background:
- The vulnerability was introduced by a commit (unknown).
- The vulnerability is found by an expert, with a crash log.
"""

    # Only add the context information section if it's not empty
    if context_info and context_info.strip():
        prompt += f"""

CONTEXT INFORMATION (the conversation history with the vulnerability detection expert)
{context_info}"""

    # Add the crash log and instructions
    prompt += f"""

CRASH LOG (this vulnerability has been found with a test):
{crash_log}

Based on the above information, please extract *all potentially* vulnerable functions in JSON format, e.g.,
{{
    "file_path1":"func_name1",
    "file_path2":"func_name2",
    ...
}}

ONLY return the JSON, no comments, and nothing else.
"""
    print(f"construct_get_target_functions_prompt: {prompt}")
    return prompt

def construct_get_target_functions_prompt1(context_info: str, crash_log: str):
    prompt = f"""
Your task is to identify all potentially vulnerable functions from a crash log, focusing on the actual vulnerable function that needs patching.

Background:
- I need to fix a vulnerability that has been detected in the code.
- The vulnerability manifests itself in the provided crash log.
- I need to accurately identify the SPECIFIC function(s) that must be patched.

Key Instructions:
1. Focus on functions directly appearing in the crash call stack
2. Prioritize the deepest/lowest-level function that is likely the root cause
3. Consider ALL functions that might need patching, not just the one at the crash point
4. Pay special attention to functions handling input validation, parsing, or memory management
5. The function name should be EXACTLY as it appears in the source code (case-sensitive)
"""

    # Only add the context information section if it's not empty
    if context_info and context_info.strip():
        prompt += f"""

CONTEXT INFORMATION (provides background about the vulnerability):
{context_info}"""

    # Add the crash log and instructions
    prompt += f"""

CRASH LOG (examine carefully for function names in the call stack):
{crash_log}

Based on the crash log and context, extract ALL potentially vulnerable functions that might need patching.
IMPORTANT: Do NOT just extract functions that log errors. Look for functions that CAUSE the error, especially those:
- Handling user input
- Parsing data
- Performing validation
- Managing memory/resources
- Appearing directly in the crash stack trace

Return your results in this exact JSON format:
{{
    "file_path1":"function_name1",
    "file_path2":"function_name2",
    ...
}}

Notes:
1. The function names must match EXACTLY as they appear in the code (case-sensitive)
2. Include the full file path if shown in the crash log
3. Include ALL functions that might need patching, not just one
4. Prioritize functions from the actual call stack over functions merely mentioned in log messages

ONLY return the JSON, no explanations or comments.
"""
    print(f"construct_get_target_functions_prompt: {prompt}")
    return prompt    

def construct_get_target_functions_prompt2(context_info: str, crash_log: str):
    prompt = f"""
You are a skilled software security analyst tasked with identifying potentially vulnerable functions from a crash log. Your goal is to pinpoint the specific function(s) that require patching to address a detected vulnerability.

First, examine this crash log, paying close attention to the call stack and any mentioned functions:

<crash_log>
{crash_log}
</crash_log>

Now, carefully review the following context information about the vulnerability:

<context_information>
{context_info}
</context_information>

Your task is to identify ALL potentially vulnerable functions that might need patching based on the crash log and context information. Follow these key instructions:

1. Focus primarily on functions directly appearing in the crash call stack.
2. Prioritize the deepest/lowest-level function that is likely the root cause of the crash.
3. Consider ALL functions that might need patching, not just the one at the crash point.
4. Pay special attention to functions handling input validation, parsing, or memory management.
5. Ensure that each function name is EXACTLY as it appears in the source code (case-sensitive).

Before providing your final output, wrap your analysis inside <vulnerability_analysis> tags. In your analysis:
1. List all relevant functions you've identified from the crash log.
2. For each function:
   a. Quote the relevant part of the crash log where it appears.
   b. Explain why it might be vulnerable or related to the crash.
   c. Discuss how the context information relates to this function's potential vulnerability.
   d. Suggest potential patching strategies.
3. Prioritize the functions based on their likelihood of being the root cause.
4. Double-check that you've included all necessary functions, especially if multiple functions from the same file need patching.

It's OK for this section to be quite long.

After your analysis, provide your results in the following JSON format:

{{
    "file_path1": "function_name1",
    "file_path2": "function_name2",
    ...
}}

Important notes:
- Only include "file_path" and "function_name" in the format described above. Any other format is incorrect and will lead to an error.
- Include the full file path if shown in the crash log.
- Function names must match EXACTLY as they appear in the code (case-sensitive).
- Include ALL functions that might need patching, not just one.
- If multiple functions from the same file need patching, repeat the file path as a separate key for each function.

Only return the JSON in your final output, with no additional explanations or comments.
"""
    print(f"construct_get_target_functions_prompt: {prompt}")
    return prompt


def extract_json_from_response_with_4o(log_file,text):
    prompt=f"Please extract the JSON data from the following text. Return with markdown code blocks ```json ```. No comment. No explanation.\n\nHere is the text:\n{text}"

    messages = [{"role": "user", "content": prompt}]

    returned_json, success = call_llm(log_file, messages, OPENAI_MODEL)
    if success:
        pattern = r"```(?:json)?\s*([\s\S]*?)```"
        matches = re.findall(pattern, returned_json)
        if matches:
            return matches[0].strip()

    return None

def get_target_functions(log_file, context_info: str, crash_log: str, model_name, language):
    
    prompt = construct_get_target_functions_prompt0(context_info,crash_log)

    messages = [{"role": "system", "content": "You are a top expert in understanding code security vulnerabilities."}]
    messages.append({"role": "user", "content": prompt})
    function_start_time = time.time()
    response, success = call_llm(log_file, messages, model_name)
    if success == False:
        return None

    pattern = r"```(?:json)?\s*([\s\S]*?)```"
    matches = re.findall(pattern, response)
    if matches:
        response = matches[0].strip()
    # Try to parse the entire response as JSON
    try:
        parsed = json.loads(response)
    except json.JSONDecodeError:
        # If it fails, just return an empty list or handle error
        # use LLM to extract json and retry 
        try:
            response_refined = extract_json_from_response_with_4o(log_file,response)
            parsed = json.loads(response_refined)
        except Exception as e:
            print(f"Failed to load json from response: {e}")
            return None
    
    function_end_time = time.time()
    # log_message(log_file, f"Time taken LLM to get target functions: {function_end_time - function_start_time} seconds")
    # For Java, it might be hard to extract the target functions from crash log
    print(f"get_target_functions llm response: {parsed}")
    target_functions = []
    java_package_prefixes = ('org.', 'com.', 'net.', 'java.', 'javax.', 'io.', 'android.')
    for file_path, function_name in parsed.items():
        if file_path.startswith(java_package_prefixes):
            # Check if path ends with .java extension
            if file_path.endswith(".java"):
                # Remove .java extension before converting dots to slashes
                base_path = file_path[:-5]  # remove '.java'
                file_path = base_path.replace('.', '/') + '.java'
            else:
                # Standard dot-to-slash conversion
                file_path = file_path.replace('.', '/') + '.java'
                
        allowed_extensions = ['.java', '.c', '.h', '.cc']
        is_allowed_file = any(file_path.endswith(ext) for ext in allowed_extensions)
        if not is_allowed_file:
            java_package_path_prefixes = ('org/', 'com/', 'net/', 'java/', 'javax/', 'io/', 'android/')
            if file_path.startswith(java_package_path_prefixes):
                file_path = file_path + '.java'
            elif file_path == function_name or file_path.endswith(function_name):
                # likely both are function name
                if language.startswith('c'):
                    file_path = "unknown.c"
                else:
                    #TODO if file_path contains dot like X.Y, then set to X.java
                    if '.' in file_path:
                        class_name, method = file_path.split('.', 1) 
                        file_path = f"{class_name}.java"
                    else:
                        file_path = "Unknown.java"
            else:
                log_message(log_file, f"Skipping non-source file: {file_path}")
                continue        
        # strip OSS_FUZZ_ from function_name if exists
        # e.g., OSS_FUZZ_png_handle_iCCP -> png_handle_iCCP
        if function_name.startswith("OSS_FUZZ_"):
            function_name = function_name[9:] 
        target_functions.append(f"{file_path}:{function_name}")
    
    log_message(log_file, f"Extracted target functions: {target_functions}")
    
    return target_functions

def parse_java_code(file_path):
    """
    Parses the given Java file and returns a list of method signatures and their positions.
    Uses regex-based parsing for Java methods.
    """
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    methods = []
    
    # Pattern to match Java method declarations
    # This handles various modifiers, return types, method names, and parameters
    pattern = r'(?:public|protected|private|static|final|native|synchronized|abstract|transient)?\s*(?:<.*?>)?\s*(?:[\w\<\>\[\]]+)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w\s,]+)?\s*\{'
    
    for match in re.finditer(pattern, content):
        method_name = match.group(1)
        start_pos = match.start()
        
        # Count opening and closing braces to find the end of the method
        brace_count = 0
        in_string = False
        in_char = False
        in_line_comment = False
        in_block_comment = False
        
        for i in range(start_pos, len(content)):
            char = content[i]
            next_char = content[i+1] if i+1 < len(content) else ''
            
            # Handle comments and strings
            if in_line_comment:
                if char == '\n':
                    in_line_comment = False
                continue
            elif in_block_comment:
                if char == '*' and next_char == '/':
                    in_block_comment = False
                    i += 1  # Skip the next character
                continue
            elif in_string:
                if char == '\\' and next_char in ('"', '\\'):
                    i += 1  # Skip the escaped character
                elif char == '"':
                    in_string = False
                continue
            elif in_char:
                if char == '\\' and next_char in ("'", '\\'):
                    i += 1  # Skip the escaped character
                elif char == "'":
                    in_char = False
                continue
            elif char == '/' and next_char == '/':
                in_line_comment = True
                i += 1  # Skip the next character
                continue
            elif char == '/' and next_char == '*':
                in_block_comment = True
                i += 1  # Skip the next character
                continue
            elif char == '"':
                in_string = True
                continue
            elif char == "'":
                in_char = True
                continue
            
            # Count braces
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    # Found the end of the method
                    method_code = content[start_pos:i+1]
                    
                    # Calculate line numbers
                    start_line = content[:start_pos].count('\n') + 1
                    end_line = start_line + method_code.count('\n')
                    
                    methods.append({
                        "name": method_name,
                        "start_line": start_line,
                        "end_line": end_line,
                    })
                    break
    
    return methods

def extract_java_method(file_path, method_name):
    """
    Extracts a method by its name from the given Java file.
    Uses regex-based parsing for reliable method extraction.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
            
        # Pattern to match Java method declarations with the specific method name
        pattern = r'(?:public|protected|private|static|final|native|synchronized|abstract|transient)?\s*(?:<.*?>)?\s*(?:[\w\<\>\[\]]+)\s+' + re.escape(method_name) + r'\s*\([^)]*\)\s*(?:throws\s+[\w\s,]+)?\s*\{'
        
        matches = list(re.finditer(pattern, content))
        
        if matches:
            for match in matches:
                start_pos = match.start()
                
                # Count opening and closing braces to find the end of the method
                brace_count = 0
                in_string = False
                in_char = False
                in_line_comment = False
                in_block_comment = False
                
                for i in range(start_pos, len(content)):
                    char = content[i]
                    next_char = content[i+1] if i+1 < len(content) else ''
                    
                    # Handle comments and strings
                    if in_line_comment:
                        if char == '\n':
                            in_line_comment = False
                        continue
                    elif in_block_comment:
                        if char == '*' and next_char == '/':
                            in_block_comment = False
                            i += 1  # Skip the next character
                        continue
                    elif in_string:
                        if char == '\\' and next_char in ('"', '\\'):
                            i += 1  # Skip the escaped character
                        elif char == '"':
                            in_string = False
                        continue
                    elif in_char:
                        if char == '\\' and next_char in ("'", '\\'):
                            i += 1  # Skip the escaped character
                        elif char == "'":
                            in_char = False
                        continue
                    elif char == '/' and next_char == '/':
                        in_line_comment = True
                        i += 1  # Skip the next character
                        continue
                    elif char == '/' and next_char == '*':
                        in_block_comment = True
                        i += 1  # Skip the next character
                        continue
                    elif char == '"':
                        in_string = True
                        continue
                    elif char == "'":
                        in_char = True
                        continue
                    
                    # Count braces
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            # Found the end of the method
                            method_code = content[start_pos:i+1]
                            
                            # Calculate line numbers
                            start_line = content[:start_pos].count('\n') + 1
                            end_line = start_line + method_code.count('\n')
                            
                            return {
                                "start_line": start_line,
                                "end_line": end_line,
                                "content": method_code
                            }
        
        return None
    except Exception as e:
        print(f"Error in Java method extraction: {e}")
        return None

def extract_java_methods(file_path, method_name):
    """
    Extracts *all* methods by the given name from the specified Java file.
    Returns a list of dictionaries with the start/end lines and method content.
    """
    matched_methods = []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
            
        # Regex to match Java method declarations with the specific method name
        pattern = (
            r'(?:public|protected|private|static|final|native|synchronized|abstract|transient)?\s*'
            r'(?:<.*?>)?\s*'
            r'(?:[\w\<\>\[\]]+)\s+' + re.escape(method_name) + 
            r'\s*\([^)]*\)\s*'
            r'(?:throws\s+[\w\s,]+)?\s*\{'
        )
        
        matches = list(re.finditer(pattern, content))
        
        for match in matches:
            start_pos = match.start()
            
            # Count opening and closing braces to find the end of this method
            brace_count = 0
            in_string = False
            in_char = False
            in_line_comment = False
            in_block_comment = False
            
            for i in range(start_pos, len(content)):
                char = content[i]
                next_char = content[i+1] if (i+1 < len(content)) else ''
                
                # Handle comments and strings
                if in_line_comment:
                    if char == '\n':
                        in_line_comment = False
                    continue
                elif in_block_comment:
                    if char == '*' and next_char == '/':
                        in_block_comment = False
                        i += 1  # Skip the next character
                    continue
                elif in_string:
                    if char == '\\' and next_char in ('"', '\\'):
                        i += 1  # Skip the escaped character
                    elif char == '"':
                        in_string = False
                    continue
                elif in_char:
                    if char == '\\' and next_char in ("'", '\\'):
                        i += 1  # Skip the escaped character
                    elif char == "'":
                        in_char = False
                    continue
                elif char == '/' and next_char == '/':
                    in_line_comment = True
                    i += 1  # Skip the next character
                    continue
                elif char == '/' and next_char == '*':
                    in_block_comment = True
                    i += 1  # Skip the next character
                    continue
                elif char == '"':
                    in_string = True
                    continue
                elif char == "'":
                    in_char = True
                    continue
                
                # Count braces to find the method boundary
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        # Found the end of this method
                        method_code = content[start_pos:i+1]
                        
                        # Calculate line numbers
                        start_line = content[:start_pos].count('\n') + 1
                        end_line = start_line + method_code.count('\n')
                        
                        matched_methods.append({
                            "start_line": start_line,
                            "end_line": end_line,
                            "content": method_code
                        })
                        break

        return matched_methods if matched_methods else None

    except Exception as e:
        print(f"Error in Java method extraction: {e}")
        return None

def replace_java_method(file_path, method_name, new_method_code):
    """
    Replaces the method definition with the new method code in a Java file.
    """
    method_info = extract_java_method(file_path, method_name)
    if not method_info:
        return None
    
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    
    start_line = method_info['start_line'] - 1
    end_line = method_info['end_line']
    
    updated_lines = lines[:start_line] + [new_method_code + '\n'] + lines[end_line:]
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(updated_lines)
    
    return True

import clang.cindex
# Try to set the library path explicitly
clang.cindex.Config.set_library_file('/usr/lib/llvm18/lib/libclang.so')

def parse_c_code(file_path):
    """
    Parses the given C file and returns a list of function signatures and their positions.
    Uses Clang AST for accurate parsing.
    """
    index = clang.cindex.Index.create()
    tu = index.parse(file_path)
    functions = []
    
    for node in tu.cursor.walk_preorder():
        if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
            functions.append({
                "name": node.spelling,
                "return_type": node.result_type.spelling,
                "start_line": node.extent.start.line,
                "end_line": node.extent.end.line,
            })
    
    return functions


def extract_function_using_fundef(file_path: str, func_name: str) -> Union[Dict[str, Any], List[Dict[str, Any]], None]:
    """
    Extracts a function by its name from the given file using the fundef binary.
    Returns a dictionary with start_line, end_line, and content, or a list of such dictionaries
    if multiple functions with the same name are found.
    
    Args:
        file_path: Path to the source file
        func_name: Name of the function to extract
        
    Returns:
        Dictionary with function details, list of dictionaries if multiple matches, or None if not found
    """
    try:
        # Determine the path to the fundef binary
        # Assuming it's in the same directory as the script or in PATH
        fundef_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fundef")
        if not os.path.exists(fundef_path):
            # Try to find it in PATH
            fundef_path = "fundef"

        file_dir = os.path.dirname(file_path)

        # Create output file path
        output_file = f"{file_dir}/{func_name}.json"
        
        # Run the fundef binary
        cmd = [fundef_path, "-file", file_path, "-func", func_name, "-output", output_file]
        subprocess.run(cmd, check=True)
        
        # Read the JSON file
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                functions = json.load(f)
            
            # Clean up the file
            os.remove(output_file)
            
            if not functions:
                return None
            
            # If only one function is found, return it directly
            if len(functions) == 1:
                return functions[0]
            
            # If multiple functions are found, return the list
            return functions
        else:
            print(f"Output file {output_file} not found - likely the target function was not found")
            return None
        
    except subprocess.CalledProcessError as e:
        # print(f"Error running fundef: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON file: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error in extract_function_using_fundef: {e}")
        return None

def extract_function(file_path, func_name):
    """
    Extracts a function by its name from the given C file.
    Uses a combination of Clang AST and text-based parsing for reliable function extraction.
    """
    if file_path.endswith('.java'):
        return extract_java_method(file_path, func_name)

    try:
        # First try using Clang
        index = clang.cindex.Index.create()
        tu = index.parse(file_path)
        
        for cursor in tu.cursor.walk_preorder():
            if cursor.kind == clang.cindex.CursorKind.FUNCTION_DECL and cursor.spelling == func_name:
                if not cursor.is_definition():
                    continue

                start = cursor.extent.start.line
                end = cursor.extent.end.line
                
                with open(file_path, 'r') as f:
                    lines = f.readlines()
                    
                # Look for the actual start of the function declaration
                # which might include return type on a line before the function name
                actual_start = start
                for i in range(start-2, max(0, start-5), -1):  # Check up to 5 lines before
                    if i >= 0 and (lines[i].strip().startswith('void') or 
                                  lines[i].strip().startswith('int') or
                                  lines[i].strip().startswith('char') or
                                  lines[i].strip().startswith('static') or
                                  lines[i].strip().startswith('png_') or
                                  any(type_keyword in lines[i].strip().split() 
                                      for type_keyword in ['void', 'int', 'char', 'float', 'double', 'static'])):
                        actual_start = i + 1
                        break
                
                return {
                    "start_line": actual_start,
                    "end_line": end,
                    "content": ''.join(lines[actual_start-1:end])
                }
    except Exception as e:
        print(f"Error in Clang extraction: {e}")
    
    # Fallback to text-based parsing
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            
        # Try to find the function using regex
        # First, look for the function definition with a more precise pattern
        pattern = r'(?:void|int|char|float|double|long|unsigned|size_t|png_\w+)\s+(?:\*\s*)*' + re.escape(func_name) + r'\s*\([^)]*\)\s*(?:/\*[^*]*\*/\s*)*\{'
        matches = list(re.finditer(pattern, content))
        
        if not matches:
            # Try a more relaxed pattern
            pattern = r'\b' + re.escape(func_name) + r'\s*\([^)]*\)\s*(?:/\*[^*]*\*/\s*)*\{'
            matches = list(re.finditer(pattern, content))
        
        if matches:
            for match in matches:
                start_pos = match.start()
                
                # Count opening and closing braces to find the end of the function
                brace_count = 0
                in_string = False
                in_char = False
                in_line_comment = False
                in_block_comment = False
                
                for i in range(start_pos, len(content)):
                    char = content[i]
                    next_char = content[i+1] if i+1 < len(content) else ''
                    
                    # Handle comments and strings
                    if in_line_comment:
                        if char == '\n':
                            in_line_comment = False
                        continue
                    elif in_block_comment:
                        if char == '*' and next_char == '/':
                            in_block_comment = False
                            i += 1  # Skip the next character
                        continue
                    elif in_string:
                        if char == '\\' and next_char in ('"', '\\'):
                            i += 1  # Skip the escaped character
                        elif char == '"':
                            in_string = False
                        continue
                    elif in_char:
                        if char == '\\' and next_char in ("'", '\\'):
                            i += 1  # Skip the escaped character
                        elif char == "'":
                            in_char = False
                        continue
                    elif char == '/' and next_char == '/':
                        in_line_comment = True
                        i += 1  # Skip the next character
                        continue
                    elif char == '/' and next_char == '*':
                        in_block_comment = True
                        i += 1  # Skip the next character
                        continue
                    elif char == '"':
                        in_string = True
                        continue
                    elif char == "'":
                        in_char = True
                        continue
                    
                    # Count braces
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            # Found the end of the function
                            func_code = content[start_pos:i+1]
                            
                            # Calculate line numbers
                            start_line = content[:start_pos].count('\n') + 1
                            end_line = start_line + func_code.count('\n')
                            
                            return {
                                "start_line": start_line,
                                "end_line": end_line,
                                "content": func_code
                            }
        
        # Last resort: try to find the function with a very simple pattern
        # This might catch function declarations too, but it's a last attempt
        pattern = r'\b' + re.escape(func_name) + r'\s*\([^{]*\{[^}]*\}'
        match = re.search(pattern, content, re.DOTALL)
        if match:
            func_code = match.group(0)
            start_pos = match.start()
            start_line = content[:start_pos].count('\n') + 1
            end_line = start_line + func_code.count('\n')
            
            return {
                "start_line": start_line,
                "end_line": end_line,
                "content": func_code
            }
            
        return None
    except Exception as e:
        print(f"Error in fallback extraction: {e}")
        return None


def calculate_function_similarity(patch_code, original_code):
    """
    Calculate similarity between patch and original function code.
    
    Args:
        patch_code: The new function code (patch)
        original_code: The original function code
        
    Returns:
        float: Similarity score between 0 and 1
    """
    from difflib import SequenceMatcher
    
    # Extract function signature (first line or declaration)
    patch_lines = patch_code.strip().split('\n')
    original_lines = original_code.strip().split('\n')
    
    patch_signature = patch_lines[0]
    original_signature = original_lines[0]
    
    # Calculate signature similarity
    signature_similarity = SequenceMatcher(None, patch_signature, original_signature).ratio()
 
    def extract_params(signature):
        # Extract parameters between parentheses
        params_match = re.search(r'\((.*?)\)', signature)
        if params_match:
            params_str = params_match.group(1)
            # Split by commas, but handle complex types
            params = [p.strip() for p in re.split(r',\s*(?![^<>()]*[>)])', params_str)]
            return params
        return []
    
    patch_params = extract_params(patch_signature)
    original_params = extract_params(original_signature)
    
    # Calculate parameter count similarity
    param_count_similarity = 1.0 if len(patch_params) == len(original_params) else 0.5
    
    # Calculate overall content similarity (using first few lines for efficiency)
    content_lines = min(10, min(len(patch_lines), len(original_lines)))
    content_similarity = SequenceMatcher(
        None, 
        '\n'.join(patch_lines[:content_lines]), 
        '\n'.join(original_lines[:content_lines])
    ).ratio()
    
    # Calculate weighted similarity score
    # Signature is most important, then parameter count, then overall content
    weighted_similarity = (signature_similarity * 0.6) + (param_count_similarity * 0.3) + (content_similarity * 0.1)
    
    return {
        'signature_similarity': signature_similarity,
        'param_count_similarity': param_count_similarity,
        'content_similarity': content_similarity,
        'weighted_similarity': weighted_similarity
    }


def replace_function(log_file, file_path, func_name, new_func_code):
    """
    Replaces the function definition with the new function code in a source file.
    Uses fundef to ensure correct function replacement.
    
    Args:
        file_path: Path to the source file
        func_name: Name of the function to replace
        new_func_code: New code for the function
        
    Returns:
        bool: True if replacement was successful, False otherwise
    """
    # Get function metadata using fundef
    function_info = None
    
    # Extract the base function name (without variant suffix)
    base_func_name = func_name
    is_variant = False
    variant_index = 0
    
    if '_' in func_name:
        parts = func_name.split('_')
        if parts[-1].isdigit():
            base_func_name = '_'.join(parts[:-1])
            variant_index = int(parts[-1])
            is_variant = True
    
    # Extract all functions with this name
    metadata_list = extract_function_using_fundef(file_path, base_func_name)
    # Check if any functions were found
    if not metadata_list:
        log_message(log_file, f"Function '{base_func_name}' not found in {file_path}")
        return False

    # Convert to list if it's not already
    if not isinstance(metadata_list, list):
        metadata_list = [metadata_list]
    
    # If only one function found, use it regardless of variant name
    if len(metadata_list) == 1:
        function_info = metadata_list[0]
        log_message(log_file,f"Only one function found for '{base_func_name}', using it")
    else:
        # Multiple functions found
        if is_variant and variant_index > 0 and variant_index <= len(metadata_list):
            # If we have a specific variant index and it's valid, use it
            function_info = metadata_list[variant_index - 1]  # Convert to 0-based index
            log_message(log_file,f"Using variant {variant_index} of '{base_func_name}'")
        else:
            # Find the best matching function based on similarity
            best_index = 0
            best_score = -1
            
            for i, metadata in enumerate(metadata_list):
                original_code = metadata['content']
                similarity = calculate_function_similarity(new_func_code, original_code)
                
                log_message(log_file,f"Function variant {i+1} similarity: {similarity['weighted_similarity']:.4f}")
                log_message(log_file,f"  - Signature: {similarity['signature_similarity']:.4f}")
                log_message(log_file,f"  - Parameter count: {similarity['param_count_similarity']:.4f}")
                log_message(log_file,f"  - Content: {similarity['content_similarity']:.4f}")
                
                if similarity['weighted_similarity'] > best_score:
                    best_score = similarity['weighted_similarity']
                    best_index = i
            
            function_info = metadata_list[best_index]
            log_message(log_file,f"Using best matching variant {best_index+1} with similarity score {best_score:.4f}")
    
    # Read the file
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return False
    
    # Get line numbers
    start_line = function_info['start_line'] - 1  # Convert to 0-based indexing
    end_line = function_info['end_line']
    
    # Ensure new_func_code ends with a newline
    if not new_func_code.endswith('\n'):
        new_func_code += '\n'
    
    # Replace the function
    updated_lines = lines[:start_line] + [new_func_code] + lines[end_line:]
    
    # Write the updated file
    try:
        with open(file_path, 'w') as f:
            f.writelines(updated_lines)
        log_message(log_file,f"Successfully replaced function '{func_name}' in {file_path}")
        return True
    except Exception as e:
        log_message(log_file,f"Error writing to file {file_path}: {e}")
        return False

def try_load_function_metadata_from_analysis_service(log_file,target_functions,project_src_dir,focus):
    # Define the analysis service endpoint
    ANALYSIS_SERVICE_URL = os.environ.get("ANALYSIS_SERVICE_URL", "http://localhost:7082")
    if not "/v1/funmeta" in ANALYSIS_SERVICE_URL:
        ANALYSIS_SERVICE_URL = f"{ANALYSIS_SERVICE_URL}/v1/funmeta"
   
    payload = {
        "task_id": os.environ.get("TASK_ID"),
        "focus": focus,
        "project_src_dir": project_src_dir,
        "target_functions": target_functions,
    }
    function_metadata = {}
    
    try:
        print(f"ANALYSIS_SERVICE_URL: {ANALYSIS_SERVICE_URL} payload: {payload}")

        # Make request to analysis service
        # 5 mins at most
        response = requests.post(ANALYSIS_SERVICE_URL, json=payload, timeout=300)
        
        if response.status_code == 200:
            result = response.json()
            
            if "funmeta" in result and isinstance(result["funmeta"], dict):
                function_metadata = result["funmeta"]
        else:
            print(f"Analysis service returned non-200 status: {response.status_code}")
            try:
                error_details = response.json()
                print("Error details (JSON):", error_details)
            except Exception:
                print("Response body (not JSON):", response.text)
    
    except Exception as e:
        print(f"Error funmeta querying analysis service: {str(e)}")
    
    return function_metadata    

def apply_patch(log_file, patch_code_dict, project_dir, project_src_dir, language, pov_metadata):
    """
    Apply the patch to the target functions using clang.
    
    Args:
        log_file: Log file path
        patch_code: Dict of {function_name: new_code} or list of (function_name, new_code) tuples
        project_dir: Project directory
        
    Returns:
        tuple: (success, stdout, stderr)
    """
    
    # Initialize git repository to track changes if it doesn't exist
    if not os.path.exists(os.path.join(project_src_dir, ".git")):
        log_message(log_file, "Initializing git repository to track changes...")
        try:
            subprocess.run(["git", "init"], cwd=project_src_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "jeff@cse.tamu.edu"], cwd=project_src_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "fuzzing brain"], cwd=project_src_dir, check=True, capture_output=True)
            subprocess.run(["git", "add", "."], cwd=project_src_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "Initial commit before applying patches"], 
                          cwd=project_src_dir, check=True, capture_output=True)
            log_message(log_file, "Git repository initialized successfully")
        except subprocess.CalledProcessError as e:
            log_message(log_file, f"Warning: Failed to initialize git repository: {e}")
            # Continue even if git init fails - it's not critical

    log_message(log_file, "Applying patch...")    
    extension = '.c' if language.startswith('c') else '.java'

    # Apply patches
    for func_name, new_code in patch_code_dict.items():
        # Fast path: Check if the exact function name exists in metadata
        if func_name in GLOBAL_FUNCTION_METADATA:
            metadata = GLOBAL_FUNCTION_METADATA[func_name]
            file_path = os.path.join(project_src_dir, metadata['file_path'])
            log_message(log_file, f"Debug project_dir: '{project_dir}'")
            log_message(log_file, f"Debug project_src_dir: '{project_src_dir}'")
            log_message(log_file, f"Replacing function '{func_name}' in '{file_path}'")
            success = replace_function(log_file, file_path, func_name, new_code)
            
            if success:
                continue
            else:
                log_message(log_file, f"Failed to replace function '{func_name}' probably function_metadata is incorrect!")
                # return False, "", f"Failed to replace function '{func_name}'"
        
        # Check for function variants (func_name_1, func_name_2, etc.)
        func_variants = [k for k in GLOBAL_FUNCTION_METADATA.keys() 
                         if k.startswith(func_name + "_")]
        # If we have variants, use the file path from any variant
        # replace_function will handle finding the best match
        if func_variants:
            log_message(log_file, f"Found {len(func_variants)} variants of function '{func_name}'")
            
            # Use the file path from the first variant
            variant = func_variants[0]
            metadata = GLOBAL_FUNCTION_METADATA[variant]
            file_path = os.path.join(project_src_dir, metadata['file_path'])
            
            log_message(log_file, f"Using file path from variant '{variant}': '{file_path}'")
            success = replace_function(log_file, file_path, func_name, new_code)
            
            if success:
                continue
            else:
                log_message(log_file, f"Failed to replace function '{func_name}' for func_variants")
                # return False, "", f"Failed to replace function '{func_name}'"
     
        # If we get here, the function wasn't found in metadata, so we need to find it
        log_message(log_file, f"Function '{func_name}' not found in metadata w/ correct file_path; attempting to find it...")
         
        # Try to find the file that defines this function
        found = False
        file_path_base_name = ""
        if func_name in GLOBAL_FUNCTION_METADATA:
            metadata = GLOBAL_FUNCTION_METADATA[func_name]
            file_path_base_name = metadata.get("file_path","")
        if file_path_base_name == "":
            file_path_base_name = extension

        for root, dirs, files in os.walk(project_src_dir):
            for file in files:
                if file.endswith(file_path_base_name) and not file.startswith("Crash_"):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, project_src_dir)
                    
                    # Try to extract the function from this file using fundef
                    metadata_list = extract_function_using_fundef(file_path, func_name)
                    if metadata_list:
                        log_message(log_file, f"Found function '{func_name}' in '{rel_path}'")
                        
                        # Store metadata for future use
                        if isinstance(metadata_list, list):
                            for i, metadata in enumerate(metadata_list):
                                unique_key = f"{func_name}_{i+1}"
                                metadata['file_path'] = rel_path
                                GLOBAL_FUNCTION_METADATA[unique_key] = metadata
                        else:
                            metadata_list['file_path'] = rel_path
                            GLOBAL_FUNCTION_METADATA[func_name] = metadata_list
     
                            success = replace_function(log_file,file_path, func_name, new_code)
                            
                            if success:
                                found = True
                                break
                            else:
                                log_message(log_file, f"Failed to replace function '{func_name}' file_path: {file_path}")
                                # return False, "", f"Failed to replace function '{func_name}'"
            
            if found:
                break
        
        if not found:
            log_message(log_file, f"Function '{func_name}' not found in any source file; skipping")
            if len(patch_code_dict) == 1:
                return False, "", f"Function '{func_name}' not found in any source file"
    # Rebuild the project
    if 'TEST_NGINX' in globals() and TEST_NGINX:
        log_message(log_file, "Rebuilding project with ./run.sh build")
        try:
            result = subprocess.run(["./run.sh", "build"], cwd=project_dir, capture_output=True, text=True)
            if result.returncode != 0:
                log_message(log_file, f"Build failed: {result.stderr}")
                return False, result.stdout, result.stderr
            log_message(log_file,"Build succeeded")
            return True, result.stdout, result.stderr
        except Exception as e:
            log_message(log_file, f"Error rebuilding project: {str(e)}")
            return False, "", str(e)
    else:
        # Build OSS-Fuzz project fuzzers
        log_message(log_file, "Building OSS-Fuzz project fuzzers...")
        
        project_name = pov_metadata["project_name"]
        sanitizer = pov_metadata["sanitizer"]
        
        build_success = True
        build_output = ""
        build_error = ""

        log_message(log_file, f"Building with {sanitizer} sanitizer...")
        
        project_sanitizer_name=f"{project_name}-{sanitizer}"

        # Create sanitizer-specific directories
        out_dir = os.path.join(project_dir, "fuzz-tooling", "build", "out", project_sanitizer_name)
        try:
            os.makedirs(out_dir, exist_ok=True)
        except PermissionError:
            log_message(log_file, f"Warning: Permission denied when creating directory: {out_dir}")
            log_message(log_file, "Using temporary directory instead")
            # Create a temporary directory that we have permission to write to
            temp_out_dir = os.path.join(project_dir, "temp_out_" + project_sanitizer_name)
            os.makedirs(temp_out_dir, exist_ok=True)
            out_dir = temp_out_dir
        
        # Create work directory
        work_dir = os.path.join(project_dir, "fuzz-tooling", "build", "work", project_sanitizer_name)
        try:
            os.makedirs(work_dir, exist_ok=True)
        except PermissionError:
            log_message(log_file, f"Warning: Permission denied when creating directory: {work_dir}")
            log_message(log_file, "Using temporary directory instead")
            # Create a temporary directory that we have permission to write to
            temp_work_dir = os.path.join(project_dir, "temp_work_" + project_sanitizer_name)
            os.makedirs(temp_work_dir, exist_ok=True)
            work_dir = temp_work_dir

        fuzz_language = "jvm"
        if language.startswith('c'):
           fuzz_language = "c++"

        # Find Docker image: try aixcc-afc first, then gcr.io/oss-fuzz
        docker_image = None
        try:
            result_check = subprocess.run(["docker", "images", f"aixcc-afc/{project_name}", "--format", "{{.Repository}}:{{.Tag}}"], capture_output=True, text=True, timeout=60)
            if result_check.returncode == 0 and result_check.stdout.strip():
                docker_image = result_check.stdout.strip().split('\n')[0]
                log_message(log_file, f"Using Docker image: {docker_image}")
        except Exception as e:
            log_message(log_file, f"Failed to find docker image for aixcc-afc/{project_name}: {str(e)}")

        if not docker_image:
            try:
                result_check = subprocess.run(["docker", "images", f"gcr.io/oss-fuzz/{project_name}", "--format", "{{.Repository}}:{{.Tag}}"], capture_output=True, text=True, timeout=60)
                if result_check.returncode == 0 and result_check.stdout.strip():
                    docker_image = result_check.stdout.strip().split('\n')[0]
                    log_message(log_file, f"Using Docker image: {docker_image}")
            except Exception as e:
                log_message(log_file, f"Failed to find docker image for gcr.io/oss-fuzz/{project_name}: {str(e)}")

        if not docker_image:
            log_message(log_file, f"Failed to find docker image for {project_name}")
            return False, "", f"Failed to find docker image for {project_name}"

        # Build Docker command
        cmd_args = [
            "docker", "run",
            "--privileged",
            "--shm-size=8g",
            "--platform", "linux/amd64",
            "--rm",
            "-e", "FUZZING_ENGINE=libfuzzer",
            "-e", f"SANITIZER={sanitizer}",
            "-e", "ARCHITECTURE=x86_64",
            "-e", f"PROJECT_NAME={project_name}",
            "-e", "HELPER=True",
            "-e", f"FUZZING_LANGUAGE={fuzz_language}",
            "-v", f"{project_src_dir}:/src/{project_name}",
            "-v", f"{out_dir}:/out",
            "-v", f"{work_dir}:/work",
            docker_image
        ]
        
        try:
            result = subprocess.run(
                cmd_args,
                shell=False,
                env=os.environ.copy(),
                cwd=project_dir,
                capture_output=True,
                text=True
            )
            # log_message(log_file, f"Build output for {sanitizer} sanitizer:\n{result.stdout}")
            
            if result.returncode != 0:
                log_message(log_file, f"Build failed for {sanitizer} sanitizer: {result.stderr}")
                build_success = False
                build_error += f"\n{sanitizer} build error: {result.stderr}"
            else:
                build_output += f"\n{sanitizer} build output: {result.stdout}"
        except Exception as e:
            log_message(log_file, f"Error building with {sanitizer} sanitizer: {str(e)}")
            build_success = False
            build_error += f"\n{sanitizer} build error: {str(e)}" 

        return build_success, build_output, build_error

def generate_diff(log_file, project_src_dir, focus, function_metadata):
    """
    Generate a diff of the changes made to the target functions.
    
    Args:
        log_file: Log file handle
        project_src_dir: Project source directory
        function_metadata: Metadata about the target functions
        
    Returns:
        str: The diff of the changes
    """
    # log_message(log_file, "Generating diff of changes")
    
    if not function_metadata:
        log_message(log_file, "No function metadata provided, generating full diff")
        result = subprocess.run(
            ["git", "diff"],
            cwd=project_src_dir,
            capture_output=True,
            text=True
        )
        return result.stdout
    
    # Get unique file paths from function metadata
    file_paths = set()
    for func_name, metadata in function_metadata.items():
        if isinstance(metadata, dict) and 'file_path' in metadata:
            file_paths.add(metadata['file_path'])
    
    if not file_paths:
        log_message(log_file, "No file paths found in function metadata, generating full diff")
        result = subprocess.run(
            ["git", "diff"],
            cwd=project_src_dir,
            capture_output=True,
            text=True
        )
        return result.stdout
    
    # Generate diff for each file
    combined_diff = ""
    # Keep track of processed paths
    processed_paths = set()
    for file_path in file_paths:
        # Get the relative path if the file_path is absolute
        if os.path.isabs(file_path):
            try:
                rel_path = os.path.relpath(file_path, project_src_dir)
            except ValueError:
                # If the file is on a different drive (Windows), use the absolute path
                rel_path = file_path
        else:
            rel_path = file_path
        
        # Check if the path exists under project_src_dir
        full_path = os.path.join(project_src_dir, rel_path)
        if not os.path.exists(full_path):
            if rel_path.startswith(focus + '/'):
                rel_path = rel_path[len(focus) + 1:]  # Remove 'focus/' from the beginning
        
        # Skip if we've already processed this rel_path
        if rel_path in processed_paths:
            continue
        processed_paths.add(rel_path)
                
        log_message(log_file, f"Generating diff file_path: {file_path}")
        log_message(log_file, f"Generating diff project_src_dir: {project_src_dir}")
        log_message(log_file, f"Generating diff rel_path: {rel_path}")

        result = subprocess.run(
            ["git", "diff", "--", rel_path],
            cwd=project_src_dir,
            capture_output=True,
            text=True
        )
        
        if result.stdout:
            combined_diff += result.stdout + "\n"
    
    if not combined_diff:
        log_message(log_file, "No changes detected in the specified files")
            
        # Fall back to full diff if no specific changes were found
        log_message(log_file, "Falling back to full repository diff")
        result = subprocess.run(
            ["git", "diff"],
            cwd=project_src_dir,
            capture_output=True,
            text=True
        )
        return result.stdout

    return combined_diff

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

def extract_json_data_from_response(log_file,response):
    """
    Extracts code from various response formats:
    
    1. JSON dictionary where keys are function names and values are code blocks:
       {
         "ngx_mail_smtp_noop": "static ngx_int_t\\nngx_mail_smtp_noop(...) { ... }",
         "ngx_mail_smtp_auth_state": "static ngx_int_t\\nngx_mail_smtp_auth_state(...) { ... }"
       }
    
    2. JSON with file changes:
       {
         "file": "pngrutil.c",
         "changes": [
           {"line": 1422, "old": "...", "new": "..."},
           ...
         ]
       }
    
    Returns a list of (function_name, code_block) or (file_name, changes_dict).
    """
    import json

    # Try to parse the entire response as JSON
    try:
        parsed = json.loads(response)
    except json.JSONDecodeError:
        # If it fails, try to extract JSON and retry
        try:
            response_refined = extract_json_from_response_with_4o(log_file,response)
            parsed = json.loads(response_refined)
        except Exception as e:
            print(f"Failed to load json from response: {e}")
            return None

    # Check what format we're dealing with
    results = []
    
    # Format 1: Function name -> code block mapping
    if isinstance(parsed, dict) and not any(key in parsed for key in ["file", "changes"]):
        for key, code_block in parsed.items():
            if isinstance(code_block, str):
                # Unescape special sequences if needed:
                # More careful unescaping that preserves literal escape sequences in code
                # First, handle double backslashes (\\) to temporarily mark them
                # code_block = code_block.replace("\\\\", "___DOUBLE_BACKSLASH___")
                
                # # Then handle actual JSON escape sequences we want to convert
                # code_block = (
                #     code_block.replace("\\n", "\n")
                #               .replace("\\t", "\t")
                #               .replace("\\r", "\r")
                #               .replace("\\\"", "\"")
                # )
                
                # # Finally, restore the literal backslashes for escape sequences in the code
                # code_block = code_block.replace("___DOUBLE_BACKSLASH___", "\\")
                
                # Check if the key is likely a filename (contains a dot)
                if "." in key:
                    # Extract function name from the code block
                    func_name = extract_function_name_from_code(code_block)
                    if func_name:
                        results.append((func_name, code_block))
                    else:
                        # If we can't extract a function name, use the filename as a fallback
                        results.append((key, code_block))
                else:
                    # Handle the original case for function names
                    if key.startswith("OSS_FUZZ_"):
                        key = key[9:]
                    results.append((key, code_block))
            else:
                print(f"Warning: Expected string for key {key} (supposed to be a function name), got {type(code_block)}")                
    
    # Format 2: File changes format
    elif isinstance(parsed, dict) and "file" in parsed and "changes" in parsed:
        file_name = parsed.get("file", "unknown_file")
        changes = parsed.get("changes", [])
        
        # Return the file name and the entire changes dictionary
        results.append((file_name, parsed))
        
    # Unknown format
    else:
        print(f"Warning: Unknown JSON format: {parsed.keys() if isinstance(parsed, dict) else type(parsed)}")
        # Try to extract something useful anyway
        if isinstance(parsed, dict):
            for key, value in parsed.items():
                results.append((key, value))
    
    return results

def generate_patch(log_file, messages, model_name):
    """Generate a patch using the specified model"""
    patch_start_time = time.time()
    response, success = call_llm(log_file, messages, model_name)
    if success == False:
        return None
    else:
        messages.append({"role": "assistant", "content": response})
    patch_end_time = time.time()
    log_message(log_file, f"Time taken to generate patch: {patch_end_time - patch_start_time} seconds")
    
    log_message(log_file, f"====generate_patch response====\n{response}")

    if response is None:
        return None

    # Extract code from the response
    # Strip away markdown code block markers before parsing JSON
    response_text = response
    if "```json" in response_text and "```" in response_text:
        # Extract content between ```json and the last ```
        start_marker = "```json"
        end_marker = "```"
        start_idx = response_text.find(start_marker)
        if start_idx != -1:
            start_idx += len(start_marker)
            end_idx = response_text.rfind(end_marker)
            if end_idx > start_idx:
                response_text = response_text[start_idx:end_idx].strip()

    # Now parse the cleaned response
    extracted_data = extract_json_data_from_response(log_file,response_text)
    if not extracted_data:
        log_message(log_file, "Failed to extract code from response")
        return None
    
    patch_code_dict = {}
    
    for key, value in extracted_data:
        # Handle function name -> code block format
        if isinstance(value, str):
            patch_code_dict[key] = value
            log_message(log_file, f"Extracted patch for function: {key}")
        
        # Handle file changes format
        elif isinstance(value, dict) and "changes" in value:
            file_name = value.get("file", key)
            changes = value.get("changes", [])
            
            # Convert changes to a patch format your system can understand
            patch_text = f"--- a/{file_name}\n+++ b/{file_name}\n"
            for change in changes:
                line_num = change.get("line", 0)
                old_line = change.get("old", "")
                new_line = change.get("new", "")
                
                if old_line and not new_line:
                    # Line removal
                    patch_text += f"@@ -{line_num},1 +{line_num},0 @@\n-{old_line}\n"
                elif not old_line and new_line:
                    # Line addition
                    patch_text += f"@@ -{line_num},0 +{line_num},1 @@\n+{new_line}\n"
                else:
                    # Line modification
                    patch_text += f"@@ -{line_num},1 +{line_num},1 @@\n-{old_line}\n+{new_line}\n"
            
            patch_code_dict[file_name] = patch_text
            log_message(log_file, f"Extracted patch for file: {file_name} with {len(changes)} changes")
    
    return patch_code_dict

def reset_project_source_code(log_file,project_src_dir):
    # Reset source code to original state
    try:
        log_message(log_file, "Resetting source code to original state...")
        
        # Unstage any staged changes
        subprocess.run(
            ["git", "reset", "--hard", "HEAD"],
            cwd=project_src_dir,
            check=True,
            capture_output=True
        )
        
        log_message(log_file, "Source code reset successful")
    
    except Exception as e:
        log_message(log_file, f"Unexpected error resetting source code: {str(e)}")

INITIAL_PATCH_TEMPLATE = """# Vulnerability Patching Task

## Your Role
You are a world-leading security engineer tasked with fixing a vulnerability in code. Your goal is to generate minimal, precise patches that address only the vulnerability without changing other functionality.
Do not aplogize when you are wrong. Just keep optimizing the result directly and proceed the progress. Do not lie or guess when you are unsure about the answer.

## Input Information
### Vulnerability Report
{crash_log}

### Relevant Functions
{functions_metadata_str}

Please return the fixed functions to patch the vulnerability. 

## Requirements
1. Fix ONLY the vulnerability - do not add features or refactor code
2. Preserve all existing functionality and logic
3. Make minimal changes (fewest lines of code possible)
4. Focus on security best practices

## Output Format
Return ONLY a JSON dictionary where keys are function names and values are code blocks:
{{
"function_name1": "function_content_with_fix",
"function_name2": "function_content_with_fix",
...
}}

IMPORTANT:
- Return the fixed content for each changed function
- Do NOT return diffs, patches, or partial code snippets
- Do NOT include explanations or comments outside the JSON
- Include ALL lines of the original function in your response, with your fixes applied

Return ONLY the JSON dictionary described above.
"""

def format_function_metadata(log_file, function_metadata, project_src_dir):
    """
    Format function metadata for the prompt, intelligently handling large files and functions.
    
    Args:
        log_file: File to write logs to
        function_metadata: Dictionary mapping function names to their metadata
        
    Returns:
        Formatted string containing function metadata
    """
    # Group functions by file to avoid duplicating file content
    functions_by_file = {}
    for func_name, metadata in function_metadata.items():
        file_path = metadata['file_path']
        if file_path not in functions_by_file:
            functions_by_file[file_path] = []
        functions_by_file[file_path].append((func_name, metadata))
    
    # Format the function metadata for the prompt
    functions_metadata_str = ""
    max_total_length = 300000  # Maximum total length for all content
    max_file_length = 30000   # Maximum length for a single file
    remaining_length = max_total_length
    
    # First, try to include entire files when they're not too large
    files_included = set()
    file_contents = {}
    
    for file_path in functions_by_file.keys():
        try:
            # Check if the file exists and read its content
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    file_content = f.read()
                    file_content = strip_license_text(file_content)
                    file_contents[file_path] = file_content
                    
                    # If file is small enough, we'll include the whole file
                    if len(file_content) <= max_file_length and len(file_content) <= remaining_length:
                        functions_metadata_str += f"File: {file_path}\nContent:\n{file_content}\n\n"
                        files_included.add(file_path)
                        remaining_length -= len(file_content)
                        log_message(log_file, f"Including entire file: {file_path} ({len(file_content)} chars)")
        except Exception as e:
            log_message(log_file, f"Error reading file {file_path}: {str(e)}")
    
    # For files that were too large to include entirely, include just the relevant functions
    for file_path, functions in functions_by_file.items():
        if file_path in files_included:
            continue  # Skip files we've already included in full
            
        # Strip project_src_dir from file_path to make it more concise
        relative_file_path = file_path
        # Check if file_path contains patch_workspace and the project directory
        patch_workspace_index = file_path.find("patch_workspace")
        if patch_workspace_index != -1:
            # Find the project directory after patch_workspace
            parts = file_path[patch_workspace_index:].split('/')
            if len(parts) >= 2:  # At least "patch_workspace" and "example-libpng"
                # Get everything after the project name
                project_name_index = file_path.find(parts[1], patch_workspace_index)
                if project_name_index != -1:
                    # Skip past the project name to get the relative path
                    relative_path_start = project_name_index + len(parts[1]) + 1  # +1 for the trailing slash
                    if relative_path_start < len(file_path):
                        relative_file_path = file_path[relative_path_start:]
        # If the above didn't work, try a simpler approach with project_src_dir
        elif project_src_dir and file_path.startswith(project_src_dir):
            relative_file_path = file_path[len(project_src_dir):]
            # Remove leading slash if present
            relative_file_path = relative_file_path.lstrip('/')

        functions_metadata_str += f"File: {relative_file_path}\n\n"
        
        for func_name, metadata in functions:
            # Check if we have enough space left
            if len(metadata['content']) > remaining_length:
                # Need to truncate
                if remaining_length < 500:
                    # Not enough space for meaningful content
                    functions_metadata_str += f"Function: {func_name} (omitted due to space constraints)\n\n"
                    if metadata.get('class'):
                        functions_metadata_str += f"Class: {metadata.get('class')}\n"

                    continue
                
                # Extract function signature
                content = metadata['content']
                signature_end = content.find('{') + 1
                if signature_end > 0:
                    signature = content[:signature_end]
                else:
                    signature = content[:min(200, len(content))]
                
                truncated_content = signature + "\n    // ... [function body omitted due to length] ...\n}"
                functions_metadata_str += f"Function: {func_name}\n{truncated_content}\n\n"
                if len(metadata['class']) > 0:
                    functions_metadata_str += f"Class: {metadata['class']}\n"
                remaining_length -= len(truncated_content) + len(func_name) + 20
            else:
                # Include the full function
                functions_metadata_str += f"Function: {func_name}\n{metadata['content']}\n\n"
                if metadata.get('class'):
                    functions_metadata_str += f"Class: {metadata.get('class')}\n"

                remaining_length -= len(metadata['content']) + len(func_name) + 20
    
    # log_message(log_file, f"Prepared metadata for {len(function_metadata)} functions from {len(functions_by_file)} files")
    return functions_metadata_str


def create_full_scan_prompt(
        fuzzer_code: str,
        sanitizer: str,
        language: str,
        call_path_prompt: str,
        reachable_funcs: list[dict] | None = None,
        vulnerable_funcs: list[dict] | None = None,
        max_blob_mb: int = 2,
) -> str:
    """
    Build a rich prompt for FULL_SCAN mode.

    """

    # ──────────────────────────────────────────────────────────────────────
    base_prompt = f"""
You are an elite software-vulnerability researcher specialising in {language}.
The target binary is built with sanitizers; your goal is to craft **input(s)**
that crash the program (ASan/MSan/UBSan/Jazzer, etc.).  The harness that feeds
data into the target looks like:

```{language}
{fuzzer_code}
```
(Study how the input is read!)

"""
    entrypoint = "fuzzerTestOneInput"
    if language.startswith('c'):
        entrypoint = "LLVMFuzzerTestOneInput"

    if reachable_funcs:
        # reachable_funcs format: [{"Name": "...", "SourceCode": "..."} , …]
        func_snippets = []
        for f in reachable_funcs:
            name = f.get("name") or f.get("Name") or "<unknown>"
            body = (f.get("body") or f.get("Body") or
                    f.get("sourceCode") or f.get("SourceCode") or "")
            snippet = f"Function: {name}\n{body}"
            func_snippets.append(snippet)

        funcs_block = "\n\n".join(func_snippets) if func_snippets else "<call-graph unavailable>"

        base_prompt += f"""
We have pre-analysed the call-graph.  The entry point is `{entrypoint}`.
The following reachable functions might be risky (full bodies included):

{funcs_block}
"""

    if vulnerable_funcs:
        vf_lines = []
        for vf in vulnerable_funcs:
            name   = vf.get("name") or vf.get("Name") or "<unknown>"
            score  = vf.get("score", "?")
            reason = vf.get("reason", "").strip()
            vf_lines.append(f"• {name} - {reason}")
        vf_block = "\n".join(vf_lines)

        base_prompt += f"""
Here are the reasons why these functions are risky, per static heuristics:

{vf_block}
"""

    # ── sanitizer guidance (C/C++) ───────────────────────────────────────
    if language.startswith('c'):
        san_guide = {
            "address": (
                "AddressSanitizer reports buffer overflows, use-after-free, "
                "double-free, etc.  Classic triggers:\n"
                "• Oversized length fields\n"
                "• Negative indices casted to large unsigned values\n"
                "• String without null-terminator\n"
            ),
            "memory": (
                "MemorySanitizer flags reads of uninitialised memory.  Classic "
                "triggers:\n"
                "• Partially initialised structs\n"
                "• Checksum fields that skip bytes\n"
            ),
            "undefined": (
                "UndefinedBehaviorSanitizer catches UB: integer overflow, "
                "division by zero, invalid shift, mis-aligned pointer, etc.\n"
                "Classic triggers: 0-byte allocations, INT_MAX+1 lengths, "
                "null deref, etc.\n"
            ),
        }.get(sanitizer.lower(), "")
        language_block = f"""
### Sanitizer Focus  ({sanitizer})
{san_guide}

### Plan
1. Map input bytes → parser structure (see harness).
2. Choose a vulnerable target function.
3. Devise an input to reach and corrupt it.
4. Comment the reasoning before writing code.

"""
    else:  # Java / Jazzer
        language_block = """
### Jazzer Focus
Try to trigger Jazzer crash with "Java Exception: com.code_intelligence.jazzer", e.g. deserialization-based RCE, backdoor, regex DoS, path traversal,
reflection misuse, SQL/LDAP/XPath injection, etc.
"""

    ending = f"""
### Deliverable
• Produce a **single Python 3 script** that writes **x.bin** (binary mode).
• If you have multiple candidate payloads, emit them all (x1.bin, x2.bin, ..., x5.bin, at most five).
• Max size per blob: **{max_blob_mb} MiB**.
• Put a short header comment explaining the vulnerability.

Write nothing except the Python script (with embedded comments)."""

    # IDEA (tested on zookeeper full, not very effective)
    # try to load sample x.bin from /app/strategy/jeff/{project_name}/*.bin
    # add the sample bins to prompt if available
    # here are some sample bin files for {project_name} 
    # project_name = "zookeeper"
    # sample_section = ""
    # try:
    #     sample_dir  = os.path.join(os.path.dirname(__file__), project_name)
    #     bin_paths   = glob.glob(os.path.join(sample_dir, "*.bin"))[:5]  # cap at 5

    #     def _looks_like_text(b: bytes, thresh: float = 0.85) -> bool:
    #         """
    #         Treat as 'text' if ≥ `thresh` fraction of bytes decode to printable
    #         Unicode (ignoring undecodable sequences).
    #         """
    #         try:
    #             decoded = b.decode("utf-8", errors="ignore")
    #         except Exception:
    #             return False
    #         if not decoded:
    #             return False
    #         printable = sum(ch.isprintable() for ch in decoded)
    #         return printable / len(decoded) >= thresh

    #     if bin_paths:
    #         lines = []
    #         for p in bin_paths:
    #             with open(p, "rb") as fp:
    #                 blob = fp.read(1024)  # we only need a small peek

    #             if _looks_like_text(blob):
    #                 preview_txt = blob.decode("utf-8", errors="ignore")[:200]
    #                 lines.append(
    #                     f"• {os.path.basename(p)} (text preview ≤200 chars)\n"
    #                     f"```text\n{preview_txt}\n```"
    #                 )
    #             else:
    #                 preview_b = base64.b64encode(blob[:40]).decode("ascii")
    #                 lines.append(
    #                     f"• {os.path.basename(p)}  (first-40 bytes, base64: {preview_b})"
    #                 )
    #         sample_section = "\n### Sample Inputs\n" + "\n".join(lines) + "\n"
    # except Exception as exc:     # silently ignore any IO issues
    #     pass

    return base_prompt + call_path_prompt + language_block + ending

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


def extract_reachable_functions_from_analysis_service_for_c(fuzzer_path,fuzzer_src_path, focus, project_src_dir):
    # Define the analysis service endpoint
    ANALYSIS_SERVICE_URL = os.environ.get("ANALYSIS_SERVICE_URL", "http://localhost:7082")
    if not "/v1/reachable" in ANALYSIS_SERVICE_URL:
        ANALYSIS_SERVICE_URL = f"{ANALYSIS_SERVICE_URL}/v1/reachable"

    payload = {
        "task_id": os.environ.get("TASK_ID"),
        "focus": focus,
        "project_src_dir": project_src_dir,
        "fuzzer_path": fuzzer_path,
        "fuzzer_source_path": fuzzer_src_path,
    }
    max_tries   = 60          # total attempts
    backoff_sec = 30          # initial back-off

    reachable_functions = []
    for attempt in range(1, max_tries + 1):
        try:
            print(f"[try {attempt}/{max_tries}] ANALYSIS_SERVICE_URL: {ANALYSIS_SERVICE_URL} payload: {payload}")
            resp = requests.post(ANALYSIS_SERVICE_URL, json=payload, timeout=60)

            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data.get("reachable"), list):
                    reachable_functions = data["reachable"]
                break  # success - exit retry loop
            else:
                print(f"Analysis service returned {resp.status_code} for {ANALYSIS_SERVICE_URL}")
                try:
                    error_details = resp.json()
                    print("Error details (JSON):", error_details)
                except Exception:
                    print("Response body (not JSON):", resp.text)

        except Exception as e:
            print(f"Error querying analysis service on attempt {attempt}: {e}")

        # only sleep if we will retry again
        if attempt < max_tries:
            time.sleep(backoff_sec)  
    
    return reachable_functions


def extract_reachable_functions_from_analysis_service(fuzzer_path,fuzzer_src_path, focus, project_src_dir, use_qx=True):
    # Define the analysis service endpoint
    ANALYSIS_SERVICE_URL = os.environ.get("ANALYSIS_SERVICE_URL", "http://localhost:7082")
    if not "/v1/reachable" in ANALYSIS_SERVICE_URL:
        ANALYSIS_SERVICE_URL = f"{ANALYSIS_SERVICE_URL}/v1/reachable"
    ANALYSIS_SERVICE_URL_QX = f"{ANALYSIS_SERVICE_URL}_qx"

    if not use_qx:
        ANALYSIS_SERVICE_URL_QX = ANALYSIS_SERVICE_URL

    payload = {
        "task_id": os.environ.get("TASK_ID"),
        "focus": focus,
        "project_src_dir": project_src_dir,
        "fuzzer_path": fuzzer_path,
        "fuzzer_source_path": fuzzer_src_path,
    }
    max_tries   = 60          # total attempts
    backoff_sec = 30          # initial back-off

    reachable_functions = []
    for attempt in range(1, max_tries + 1):
        try:
            print(f"[try {attempt}/{max_tries}] ANALYSIS_SERVICE_URL_QX: {ANALYSIS_SERVICE_URL_QX} payload: {payload}")
            resp = requests.post(ANALYSIS_SERVICE_URL_QX, json=payload, timeout=60)

            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data.get("reachable"), list):
                    reachable_functions = data["reachable"]
                    if len(reachable_functions) >0:
                        return reachable_functions
            else:
                print(f"Analysis service returned {resp.status_code} for {ANALYSIS_SERVICE_URL_QX}")
                try:
                    error_details = resp.json()
                    print("Error details (JSON):", error_details)
                except Exception:
                    print("Response body (not JSON):", resp.text)
                
        except Exception as e:
            print(f"Error querying analysis service on attempt {attempt}: {e}")

        # only sleep if we will retry again
        if attempt < max_tries:
            time.sleep(backoff_sec)  
    
    return reachable_functions


MAX_INPUT_TOKENS = 100_000          # <- new: hard ceiling per call

def _count_tokens(text: str) -> int:    # <- new helper
    """
    Best-effort Anthropic token counter.
    Uses anthropic.count_tokens if present; otherwise
    falls back to a 4-chars ≈ 1 token heuristic.
    """
    try:
        import anthropic
        return anthropic.Anthropic().count_tokens(text)
    except Exception:
        return max(1, len(text) // 4)   # rough upper bound


def find_most_likely_vulnerable_functions(log_file,reachable_funcs,language,model_name,
                                          top_k=10,
                                          timeout_sec=300):
    """
    reachable_funcs - list[dict]  each dict has `name` and `body`
    language        : "c" or "java"
    returns list[dict]  (name, score, reason)  or [] on failure
    """
    if not reachable_funcs:
        return []

    overhead_tokens = 2_000        # reserve budget for the rubric + system msg
    current_tokens  = overhead_tokens

    # 1. Build a concise catalogue of reachable functions
    func_catalog = []
    for f in reachable_funcs:
        name = f.get("name") or f.get("Name") or "<unknown>"
        body = (f.get("body") or f.get("Body") or
                f.get("sourceCode") or f.get("SourceCode") or "")
        snippet = f"Function: {name}\n{body}"
        func_catalog.append(snippet)

    catalog_text = "\n".join(func_catalog)

    # Count words
    word_count = len(re.findall(r'\w+', catalog_text))
    if word_count > 50_000:
        # Rebuild catalog, skipping functions with more than 500 lines
        func_catalog = []
        for f in reachable_funcs:
            name = f.get("name") or f.get("Name") or "<unknown>"
            body = (f.get("body") or f.get("Body") or
                    f.get("sourceCode") or f.get("SourceCode") or "")
            # Only include if <= 5000 lines
            if body.count('\n') <= 500:
                snippet = f"Function: {name}\n{body}"
                
                snippet_tokens = _count_tokens(snippet)
                if current_tokens + snippet_tokens > MAX_INPUT_TOKENS:
                    break                    # budget exhausted – stop adding functions

                func_catalog.append(snippet)
                current_tokens += snippet_tokens

        catalog_text = "\n".join(func_catalog)

    # 2. Construct the prompt
    prompt = textwrap.dedent(f"""
You are a world-class software security vulnerability researcher specialising in {language}.

Task
-----
Inspect **every** function reachable from the fuzzer entry-point and decide whether it *likely* contains intentionally malicious logic
(e.g. backdoors, command injection, data exfiltration, privilege escalation, kill-switches).  
Ignore ordinary accidental bugs unless they serve a malicious goal.

Scoring rubric
---------------
10  — Certain: unmistakable malicious intent (e.g. hard-coded admin password, encoded C2 URL).  
7-9 — Strong indicators but not iron-clad (obfuscation, suspicious crypto, hidden network I/O).  
4-6 — Weak or indirect hints; warrants manual review.  
1-3 — No sign of malicious intent.

Return **JSON only**, no markdown, in this exact schema:

[
    {{"name":"<funcName>", "score":<1-10>, "reason":"<short>"}},
    ...
]

Provide at most {top_k} entries, sorted by descending score.
If **no** function merits a score ≥ 4, return an empty array: `[ ]`.  

Reachable functions:
{catalog_text}
""")

    # 3. Query the model
    messages = [
        {"role": "system", "content": "You are an expert in code security."},
        {"role": "user",   "content": prompt}
    ]
    start = time.time()
    raw, ok = call_llm(log_file, messages, model_name)
    duration = time.time() - start
    if not ok:
        log_message(log_file, f"[WARN] {model_name} failed in {duration:.1f}s\n")
        return []
 
    # Strip markdown fences if present
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
    if m:
        raw = m.group(1).strip()

    try:
        parsed = json.loads(raw)
        # basic sanity-check
        if isinstance(parsed, list) and parsed:
            log_message(log_file, f"top_k: {top_k} [parsed] {parsed}\n")
            return parsed[:top_k]
    except json.JSONDecodeError:
        log_message(log_file, f"[WARN] JSON parse failed for {model_name}: {raw}\n")

    return []

def get_vulnerable_functions(model_to_vulnerable_functions,model_name):
        # Guard-clause: make sure the dict exists and contains the key
    if (model_to_vulnerable_functions and
            isinstance(model_to_vulnerable_functions, dict) and
            model_name in model_to_vulnerable_functions and
            model_to_vulnerable_functions[model_name]):

        vulnerable_functions = model_to_vulnerable_functions[model_name]

        return vulnerable_functions
    else:
        print("[WARN] No vulnerable-function list returned for", model_name)
    return None

def extract_vulnerable_functions(reachable_funcs, vulnerable_functions, limit=10):
    """
    reachable_funcs      - list[dict]  each with Name/body/…
    vulnerable_functions - list[dict]  each with "name" (plus score, reason…)
    Returns a filtered list (≤ limit) containing only the vulnerable funcs.
    
    Args:
        reachable_funcs (list): List of dictionaries containing reachable functions
        vulnerable_functions (list): List of dictionaries containing vulnerable functions with scores and reasons
        limit (int): Maximum number of functions to return
        
    Returns:
        list: Filtered list of reachable functions with added score and reason from vulnerable_functions
    """
    if not vulnerable_functions:
        # nothing to filter by → return at most `limit` reachables
        return reachable_funcs[:limit]

    # Create a mapping of name to (score, reason) from vulnerable functions
    vuln_info = {}
    for vf in vulnerable_functions[:limit]:
        name = (vf.get("name") or vf.get("Name") or "").strip()
        if name:
            vuln_info[name] = {
                'score': vf.get('score', 0),
                'reason': vf.get('reason', '')
            }

    # Take the top `limit` vulnerable names
    wanted = set(vuln_info.keys())

    filtered = []
    for f in reachable_funcs:
        name = (f.get("name") or f.get("Name") or "").strip()
        if name in wanted:
            # Copy the function dict to avoid modifying the original
            func_with_info = f.copy()
            # Add score and reason from the corresponding vulnerable function
            func_with_info["score"] = vuln_info[name]['score']
            func_with_info["reason"] = vuln_info[name]['reason']
            filtered.append(func_with_info)

    return filtered


def extract_reachable_functions_from_all_java_source_code(
        fuzzer_path: str,
        fuzzer_src_path: str,
        focus: str,
        project_src_dir: str,
        max_snippet_lines: int = 200
) -> list[dict]:
    """
    Exhaustive fallback for Java projects: mark every *non-test* method that
    appears in any .java file under `project_src_dir` as reachable.

    Returns
    -------
    list[dict] – each element contains
        • name : "ClassName.methodName"
        • file : absolute path to the .java source
        • body : first `max_snippet_lines` lines of the method (comments removed)
    """
    import os
    import re
    import itertools

    # ───────────────────────────── helpers ──────────────────────────────
    def _is_test_file(path: str) -> bool:
        """Heuristically decide whether *path* belongs to tests / samples."""
        p_norm = os.path.normpath(path).lower()
        parts = p_norm.split(os.sep)

        if any(seg in {"test", "tests", "testing", "unittests", "fuzz"} for seg in parts):
            return True

        base = os.path.basename(p_norm)
        if base.startswith(("test", "tests", "check", "sample", "example", "bench", "perf", "fuzz")):
            return True
        if base.endswith(("_test.java", "_tests.java", "test.java")):
            return True
        return False

    def _strip_java_comments(text: str) -> str:
        """Remove //-line and /* ... */ comments from *text*."""
        comment_re = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
        return comment_re.sub("", text)

    # Very loose pattern that captures most normal Java method declarations.
    # It intentionally ignores interface/abstract methods that end with ';'.
    method_re = re.compile(
        r"""^[ \t]*                                  # indent
             (?:@\w+[ \t]*)*                         # annotations
             (?:public|protected|private)?[ \t]*     # access
             (?:static|final|synchronized|abstract|native|strictfp|default|transient|volatile|sealed|non-sealed|private)?[ \t]*
             [\w\<\>\[\]]+[ \t]+                     # return type
             (?P<name>[A-Za-z_]\w*)[ \t]*            # method name
             \([^)]*\)[ \t]*                         # parameter list
             (?:throws[^{]*)?                        # optional throws
             \{                                      # opening brace
        """,
        re.MULTILINE | re.VERBOSE,
    )

    reachable: dict[str, dict] = {}

    for root, _, files in os.walk(project_src_dir):
        for fname in files:
            if not fname.endswith(".java"):
                continue

            path = os.path.join(root, fname)
            if _is_test_file(path):
                continue

            try:
                with open(path, "r", errors="ignore") as fp:
                    src = fp.read()
            except Exception:
                continue  # unreadable – skip

            class_name = os.path.splitext(os.path.basename(path))[0]

            for m in method_re.finditer(src):
                method_name = m.group("name")
                fq_name = f"{class_name}.{method_name}"
                if fq_name in reachable:
                    continue  # first occurrence wins

                # grab a small snippet for context
                start = m.start()
                raw_snippet = "\n".join(
                    itertools.islice(src[start:].splitlines(), max_snippet_lines)
                )
                snippet = _strip_java_comments(raw_snippet).strip()

                reachable[fq_name] = {
                    "name": fq_name,
                    "file": path,
                    "body": snippet,
                }

    return list(reachable.values())

def extract_reachable_functions_from_all_c_source_code(
        fuzzer_path: str,
        fuzzer_src_path: str,
        focus: str,
        project_src_dir: str,
        max_snippet_lines: int = 40
) -> list[dict]:
    """
    Exhaustive fallback for C projects: treat every *non-test* function
    definition that appears anywhere under `project_src_dir` as reachable.

    Returns
    -------
    A list[dict] with keys
      • name : function identifier
      • file : absolute path to the source file
      • body : first `max_snippet_lines` lines of the function, with comments
               stripped (useful context for LLM prompts)
    """
    import os
    import re
    import itertools

    def _is_test_file(path: str) -> bool:
        """
        Heuristically decide whether `path` points to a test / benchmark /
        example file that should be ignored.
        """
        p_norm = os.path.normpath(path).lower()
        parts = p_norm.split(os.sep)

        # Skip obvious test-related directories
        if any(seg in {"test", "tests", "testing", "unittests", "fuzz"} for seg in parts):
            return True

        base = os.path.basename(p_norm)
        if base.startswith(
            ("test", "tests", "check", "bench", "perf", "sample", "example", "fuzz")
        ):
            return True
        if base.endswith(
            ("_test.c", "_tests.c", ".test.c", "_bench.c", "_perf.c", "_example.c")
        ):
            return True
        return False

    def _compact(text: str) -> str:
        text = comment_re.sub("", text)                       # drop comments
        text = re.sub(r"\s+", " ", text).strip()              # collapse spaces
        return text[:max_body_chars]
        
    def _strip_c_comments(text: str) -> str:
        """
        Remove /* block */ and // line comments from `text`.
        """
        comment_re = re.compile(
            r"/\*.*?\*/|//[^\n]*", re.DOTALL,
        )
        return comment_re.sub("", text)

    func_re = re.compile(
        r"""^[\t ]*                       # optional indent
             (?:static[\t ]+)?            # optional 'static'
             (?:inline[\t ]+)?            # optional 'inline'
             [A-Za-z_][\w\s\*\(\)]*?      # return type
             \s+                          # at least one space
             (?P<name>[A-Za-z_]\w*)       # function name
             \s*\(                        # opening parenthesis
             [^;]*?                       # parameter list (greedy but safe)
             \)\s*\{                      # closing parenthesis and '{'
        """,
        re.MULTILINE | re.VERBOSE,
    )

    reachable: dict[str, dict] = {}

    for root, _, files in os.walk(project_src_dir):
        for fname in files:
            if not fname.endswith(".c"):
                continue

            path = os.path.join(root, fname)
            if _is_test_file(path):
                continue  # skip test / example sources

            try:
                with open(path, "r", errors="ignore") as fp:
                    src = fp.read()
            except Exception:
                continue  # unreadable file – skip

            for m in func_re.finditer(src):
                name = m.group("name")
                if name in reachable:
                    continue  # first occurrence wins

                start = m.start()
                raw_snippet = "\n".join(
                    itertools.islice(src[start:].splitlines(), max_snippet_lines)
                )
                snippet = _strip_c_comments(raw_snippet).strip()

                reachable[name] = {
                    "name": name,
                    "file": path,
                    "body": snippet,
                }

    return list(reachable.values())

def get_vulnerable_function_entry(vulnerable_functions, vul_name):
    """
    Find and return the vulnerable function entry that matches the given name.
    
    Args:
        vulnerable_functions (list): List of dictionaries containing vulnerable function entries
        vul_name (str): Name of the vulnerable function to find
        
    Returns:
        dict: Matching vulnerable function entry or None if not found
    """
    for vf in vulnerable_functions:
        # Check both 'name' and 'Name' keys, consistent with the usage in the main code
        current_name = (vf.get('name') or vf.get('Name') or '').strip()
        if current_name == vul_name:
            return vf
    return None
    
def _iter_chunks(seq, chunk_size: int):
    """Yield successive *chunk_size*-long slices from *seq*."""
    for i in range(0, len(seq), chunk_size):
        yield seq[i : i + chunk_size]

def create_call_path_info_prompt(main_call_path,language):
    """
    Create a prompt focused on call path.
    Args:
        main_call_path: a list of function info dictionaries
    """
    call_path_info = "# Vulnerability Call Path\n\n"
    call_path_info += "The following call path leads to the vulnerability:\n\n"
     
    # Create a visual representation of the call path
    call_path_diagram = "## Call Sequence\n\n"
    call_path_diagram += "```\n"
    
    for i, node_data in enumerate(main_call_path):
        function_name = node_data.get('function', 'unknown')
        file_name = os.path.basename(node_data.get('file', 'unknown'))
        is_modified = node_data.get('is_modified', False)

        prefix = "→ " if i > 0 else ""
        highlight = "**" if is_modified else ""
        
        call_path_diagram += f"{prefix}{highlight}{function_name}(){highlight} ({file_name})\n"
        
        if i < len(main_call_path) - 1:
            call_path_diagram += "    |\n    ↓\n"
    
    call_path_diagram += "```\n\n"
    call_path_info += call_path_diagram
    
    # Add detailed information about each function in the call path
    call_path_info += "## Function Details\n\n"
    for i, node_data in enumerate(main_call_path):
        file_path = node_data.get('file', 'unknown')
        function_name = node_data.get('function', 'unknown')
        function_body = node_data.get('body', '')
        is_modified = node_data.get('is_modified', False)
        
        # Add information about whether this function was modified
        modification_status = " (**MODIFIED in commit**)" if is_modified else ""
        
        call_path_info += f"{i+1}. {function_name}(){modification_status}\n"
        call_path_info += f"- **File**: {file_path}\n"
        if function_name == "fuzzerTestOneInput" or function_name == "LLVMFuzzerTestOneInput":
            call_path_info +="\n"
            continue
        
        # # Only show code for non-empty function bodies
        # if function_body.strip():
        #     call_path_info += f"- **Code**:\n```{language.lower()}\n{function_body.strip()}\n```\n\n"
        # else:
        #     call_path_info += f"- **Code**: (not available)\n\n"
  
    return call_path_info


def covert_target_functions_format(reachable_funcs):
    """
    Convert reachable_funcs (list of FunctionDefinition) into simplified_modified_functions format:
    {
        file_path1: [{"name": func_name1, "start_line": line1}, ...],
        file_path2: [{"name": func_name2, "start_line": line2}, ...],
        ...
    }
    """
    simplified_modified_functions = {}

    for func in reachable_funcs:
        file_path = func.get("FilePath") or func.get("file_path")
        name = func.get("Name") or func.get("name")
        start_line = func.get("StartLine") or func.get("start_line")

        if not file_path or not name or start_line is None:
            continue  # Skip incomplete entries

        if file_path not in simplified_modified_functions:
            simplified_modified_functions[file_path] = []

        simplified_modified_functions[file_path].append({
            "name": name,
            "start_line": start_line
        })

    return simplified_modified_functions


def extract_call_paths_from_analysis_service(fuzzer_path,fuzzer_src_path, focus, project_src_dir, target_functions, use_qx):
    """
    Extract call paths leading to vulnerable functions by querying an analysis service.
    
    Args:
        fuzzer_src_path (str): Path to the fuzzer file that triggered the crash
        modified_functions (dict): Dictionary of modified functions from the commit
        project_src_dir (str, optional): Project source directory for resolving paths
        
    Returns:
        list: List of call paths, where each call path is a list of function info dictionaries
    """    
    # Define the analysis service endpoint
    ANALYSIS_SERVICE_URL = os.environ.get("ANALYSIS_SERVICE_URL", "http://localhost:7082")

    if use_qx == True:
        if not "/v1/analysis_qx" in ANALYSIS_SERVICE_URL:
            ANALYSIS_SERVICE_URL = f"{ANALYSIS_SERVICE_URL}/v1/analysis_qx"
    else:
        if not "/v1/analysis" in ANALYSIS_SERVICE_URL:
            ANALYSIS_SERVICE_URL = f"{ANALYSIS_SERVICE_URL}/v1/analysis"
   
    payload = {
        "task_id": os.environ.get("TASK_ID"),
        "focus": focus,
        "project_src_dir": project_src_dir,
        "fuzzer_path": fuzzer_path,
        "fuzzer_source_path": fuzzer_src_path,
        "target_functions": target_functions,
    }
    # List to hold the extracted call paths
    call_paths = []
    
    try:
        print(f"ANALYSIS_SERVICE_URL: {ANALYSIS_SERVICE_URL} payload: {payload}")

        # Make request to analysis service
        response = requests.post(ANALYSIS_SERVICE_URL, json=payload, timeout=60)
        
        if response.status_code == 200:
            result = response.json()
            
            if "call_paths" in result and isinstance(result["call_paths"], list):
                raw_call_paths = result["call_paths"]
        
                # Process each call path
                for call_path_obj in raw_call_paths:
                    processed_path = []
                    
                    # Extract the nodes array from the call path object
                    if "nodes" not in call_path_obj or not isinstance(call_path_obj["nodes"], list):
                        continue  # Skip if no nodes array
                        
                    for func_info in call_path_obj["nodes"]:
                        file_path = func_info.get("file", "")
                        function_name = func_info.get("function", "")
                        func_body = func_info.get("body", "")
                        line = func_info.get("line", "")
                        
                        # Construct processed function info
                        processed_func = {
                            "file": file_path,
                            "function": function_name,
                            "body": func_body,
                            "line": line,
                            "is_modified": func_info.get("is_modified", False),
                            "is_vulnerable": func_info.get("is_vulnerable", False),  # Include if present
                        }
                        
                        processed_path.append(processed_func)
                    
                    # Only add non-empty paths
                    if processed_path:
                        call_paths.append(processed_path)
        else:
            print(f"Analysis service returned non-200 status: {response.status_code}")
            try:
                error_details = response.json()
                print("Error details (JSON):", error_details)
            except Exception:
                print("Response body (not JSON):", response.text)
    
    except Exception as e:
        print(f"Error querying analysis service: {str(e)}")
    
    print(f"Received {len(call_paths)} call_paths\n")
    return call_paths



import multiprocessing
from functools import partial

def process_vulnerable_function(vf, reachable_vul_funcs, fuzzer_code, sanitizer, language, 
                              log_file, fuzzer_path, fuzzer_src_path, fuzzer_name, project_dir, project_name, 
                              focus, project_src_dir, check_patch_success):
    """Helper function to process a single vulnerable function"""
    vul_name = vf.get('name') or vf.get('Name')
    # for debug 
    # if vul_name != "DataTree.verifyDataIntegrity":
    #     print(f"skip vul_name: {vul_name}")
    #     return vul_name, False, {}

    log_message(log_file, f"Attempting PoV for vulnerable function: {vul_name}")
    
    single_reachable = [vf]
    vf_entry = get_vulnerable_function_entry(reachable_vul_funcs, vul_name)
    single_vulnerable = [vf_entry]

    target_functions = covert_target_functions_format(single_reachable)
    log_message(log_file, f"[process_vulnerable_function] target_functions: {target_functions}")

    if language.startswith('c'):
        call_paths = extract_call_paths_from_analysis_service(fuzzer_path,fuzzer_src_path,focus,project_src_dir,target_functions,False)
    else:
        call_paths = extract_call_paths_from_analysis_service(fuzzer_path,fuzzer_src_path,focus,project_src_dir,target_functions,True)
    if len(call_paths) == 0:
        call_paths = extract_call_paths_from_analysis_service(fuzzer_path,fuzzer_src_path,focus,project_src_dir,target_functions,False) 
    # just for testing
    # call_paths = TEST_CALL_PATHS
    # for each call path, doPOV
    MAX_CALL_PATHS = 10
    if len(call_paths) > MAX_CALL_PATHS:
        log_message(log_file, f"Too many call paths ({len(call_paths)}), limiting to first {MAX_CALL_PATHS}")
        call_paths = call_paths[:MAX_CALL_PATHS]

    pov_success = False
    pov_metadata = {}

    if len(call_paths) >0:
        for call_path in call_paths:
            
            call_path_prompt = create_call_path_info_prompt(call_path,language)
            log_message(log_file, f"call_path_prompt: {call_path_prompt}")

            initial_msg = create_full_scan_prompt(
                fuzzer_code,
                sanitizer,
                language,
                call_path_prompt,
                single_reachable,
                single_vulnerable,
            )
            log_message(log_file, f"process_vulnerable_function: {vul_name}\ninitial_msg: {initial_msg}")
            
            pov_success, pov_metadata = doPoV_full(
                log_file, initial_msg, fuzzer_path, fuzzer_name, 
                sanitizer, project_dir, project_name, focus, 
                language, check_patch_success
            )
            if pov_success:
                log_message(log_file, f"pov_success: {pov_success} pov_metadata: {pov_metadata}\ncall_path: {call_path}") 
                break
    else:
        call_path_prompt=""
        initial_msg = create_full_scan_prompt(
                fuzzer_code,
                sanitizer,
                language,
                call_path_prompt,
                single_reachable,
                single_vulnerable,
            )
        log_message(log_file, f"process_vulnerable_function: {vul_name}\ninitial_msg: {initial_msg}")
        
        pov_success, pov_metadata = doPoV_full(
            log_file, initial_msg, fuzzer_path, fuzzer_name, 
            sanitizer, project_dir, project_name, focus, 
            language, check_patch_success
        )

    return vul_name, pov_success, pov_metadata

def main():
    global CLAUDE_MODEL, OPENAI_MODEL
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
    parser.add_argument("--model", type=str, default=CLAUDE_MODEL,
                        help="Model to use for generation")
    parser.add_argument("--cpv", type=str, default="cpv12",
                        help="CPV number to test (e.g., cpv3, cpv5, cpv9)")
                        
    args = parser.parse_args()
    # Set global variables
    global TEST_NGINX, DO_PATCH, DO_PATCH_ONLY, MAX_ITERATIONS, FUZZING_TIMEOUT_MINUTES
    global PATCHING_TIMEOUT_MINUTES, POV_METADATA_DIR, PATCH_WORKSPACE_DIR, MODELS, CPV
    global FULL_SCAN
    global GLOBAL_FUNCTION_METADATA

    TEST_NGINX = args.test_nginx
    DO_PATCH = args.do_patch
    DO_PATCH_ONLY = args.do_patch_only
    FULL_SCAN = args.full_scan
    MAX_ITERATIONS = args.max_iterations
    FUZZING_TIMEOUT_MINUTES = args.fuzzing_timeout
    PATCHING_TIMEOUT_MINUTES = args.patching_timeout
    POV_METADATA_DIR = args.pov_metadata_dir
    PATCH_WORKSPACE_DIR = args.patch_workspace_dir
    if args.model:
        CLAUDE_MODEL = args.model
        OPENAI_MODEL = args.model
        MODELS = [args.model]
    print(f"DEBUG: Global MODELS = {MODELS}")
    if TEST_NGINX== True:
        MODELS = [args.model]
        CPV = args.cpv
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
    print(f"DEBUG: fuzzer_path = {fuzzer_path}")

    task_detail = load_task_detail(fuzz_dir)

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
    
    if DO_PATCH_ONLY:
        patch_success = False
        # move to patch_full.py
        return patch_success

    pov_success = False  # Default value in case the block below doesn't set it

        
    fuzzer_code, fuzzer_src_path = find_fuzzer_source(log_file, fuzzer_path, project_name, project_src_dir, language)

    log_message(log_file, f"Starting Strategy xs1_java_full for fuzzer: {fuzzer_path}")
    log_message(log_file, f"Project directory: {project_dir}")

    try:
        # ───────────────────────────── Reachability sets ─────────────────────────────
        if language.startswith("j"):
            analysis_reachable_funcs = extract_reachable_functions_from_analysis_service(
                fuzzer_path, fuzzer_src_path, focus, project_src_dir
            )
            all_reachable_funcs = extract_reachable_functions_from_all_java_source_code(
                fuzzer_path, fuzzer_src_path, focus, project_src_dir
            )
        else:
            analysis_reachable_funcs = extract_reachable_functions_from_analysis_service_for_c(
                fuzzer_path, fuzzer_src_path, focus, project_src_dir
            )
            all_reachable_funcs = extract_reachable_functions_from_all_c_source_code(
                fuzzer_path, fuzzer_src_path, focus, project_src_dir
            )

        if analysis_reachable_funcs:
            log_message(
                log_file,
                f"Total {len(analysis_reachable_funcs)} analysis_reachable_funcs"
            )
            reachable_funcs = analysis_reachable_funcs
        else:
            log_message(
                log_file,
                f"Analysis service returned 0 functions – using exhaustive list "
                f"({len(all_reachable_funcs)} funcs)."
            )
            reachable_funcs = all_reachable_funcs

        # ───────────────────── Vulnerable-function ranking helper ───────────────────
        models_to_try = [
            OPENAI_MODEL_O3,
            CLAUDE_MODEL_OPUS_4,
            CLAUDE_MODEL,
            CLAUDE_MODEL_SONNET_4,
        ]

        def _find_vulns(candidates: list[dict]) -> list[dict]:
            """
            Query *all* models; return the first non-empty, deduped list of functions
            whose score ≥ 5.  Returns [] if every model yields nothing.
            """
            for model_name in models_to_try:
                found: list[dict] = []
                for chunk in _iter_chunks(candidates, 100):
                    filtered_chunk = [
                        c for c in chunk 
                        if not any(x in (c.get("FilePath", "") or "").lower() 
                                 for x in ["fuzz", "/test", "tests/"])
                    ]
                    if not filtered_chunk:
                        continue
                        
                    top_k = max(1, min(5, len(filtered_chunk) // 10))                    
                    chunk_vulns = find_most_likely_vulnerable_functions(
                        log_file, chunk, language, model_name, top_k
                    )
                    found.extend(v for v in chunk_vulns if float(v.get("score", 0)) >= 5)
                    if len(found) >= top_k * 10:
                        break

                # de-duplicate by function name
                seen, deduped = set(), []
                for vf in found:
                    n = (vf.get("name") or vf.get("Name") or "").strip()
                    if n and n not in seen:
                        deduped.append(vf)
                        seen.add(n)

                if deduped:
                    log_message(
                        log_file,
                        f"[{model_name}] → {len(deduped)} candidate vulnerable functions"
                    )
                    return deduped

            return []  # none of the models produced output

        # ─────────────────── First pass (analysis reachability) ────────────────────
        vulnerable_functions = _find_vulns(reachable_funcs)

        # ─────────────────── Fallback (exhaustive reachability) ───────────────────
        if not vulnerable_functions and reachable_funcs is analysis_reachable_funcs:
            log_message(
                log_file,
                f"[INFO] No candidates from analysis set – retrying with exhaustive list ({len(all_reachable_funcs)} all_reachable_funcs)."
            )
            reachable_funcs = all_reachable_funcs
            # keep the LLM prompt manageable – cap to 1 000 random functions
            if len(reachable_funcs) > 1000:
                reachable_funcs = random.sample(reachable_funcs, 1000)
                log_message(log_file,
                            f"[INFO] Down-sampled exhaustive set to {len(reachable_funcs)} functions.")
            vulnerable_functions = _find_vulns(reachable_funcs)

        # Abort early if *still* nothing found
        if not vulnerable_functions:
            log_message(
                log_file,
                "[INFO] No vulnerable functions discovered after both passes – exiting."
            )
            return 1  # nothing to test

        # ─────────────────── Proceed with PoV generation (unchanged) ──────────────
        reachable_vul_funcs = extract_vulnerable_functions(
            reachable_funcs, vulnerable_functions, limit=5
        )

        log_message(
            log_file,
            f"Total {len(vulnerable_functions)} vulnerable_functions; "
            f"{len(reachable_vul_funcs)} after filtering."
        )

        try:
            vul_json_path = os.path.join(project_dir, "vul_funcs.json")
            # Load existing list (if any)
            if os.path.exists(vul_json_path):
                with open(vul_json_path, "r", encoding="utf-8") as fp:
                    try:
                        existing = json.load(fp)
                    except Exception:
                        existing = []
                if not isinstance(existing, list):
                    existing = []
            else:
                existing = []

            # Merge while keeping uniqueness by function name
            seen = { (v.get("name") or v.get("Name") or "").strip() for v in existing }
            for vf in reachable_vul_funcs:
                n = (vf.get("name") or vf.get("Name") or "").strip()
                if n and n not in seen:
                    existing.append(vf)
                    seen.add(n)

            with open(vul_json_path, "w", encoding="utf-8") as fp:
                json.dump(existing, fp, indent=2)

            log_message(
                log_file,
                f"Saved {len(reachable_vul_funcs)} (merged ⇒ {len(existing)}) "
                f"reachable vulnerable functions to {vul_json_path}"
            )
        except Exception as e:
            log_message(
                log_file,
                f"[WARN] Could not write vul_funcs.json: {e}"
            )

        MAX_ITERATIONS = 3
        num_processes = min(multiprocessing.cpu_count(), len(reachable_vul_funcs))

        with multiprocessing.Pool(processes=num_processes) as pool:
            process_func = partial(
                process_vulnerable_function,
                reachable_vul_funcs=reachable_vul_funcs,
                fuzzer_code=fuzzer_code,
                sanitizer=sanitizer,
                language=language,
                log_file=log_file,
                fuzzer_path=fuzzer_path,
                fuzzer_src_path=fuzzer_src_path,
                fuzzer_name=fuzzer_name,
                project_dir=project_dir,
                project_name=project_name,
                focus=focus,
                project_src_dir=project_src_dir,
                check_patch_success=args.check_patch_success,
            )

            results = []
            for result in pool.imap_unordered(process_func, reachable_vul_funcs):
                vul_name, pov_success, pov_metadata = result
                results.append((vul_name, pov_success, pov_metadata))

                if pov_success or len(reachable_vul_funcs) <= 10:
                    pool.terminate()
                    break

        pov_success = any(success for _, success, _ in results)
        if pov_success:
            log_message(log_file, "xs1_java_full POV success!")

    except Exception as e:
        log_message(log_file, f"xs1_java_full error: {e}")

    return 0 if pov_success else 1

if __name__ == "__main__":
    sys.exit(main())