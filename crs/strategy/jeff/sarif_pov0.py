# strategy 0
#!/usr/bin/env python3
"""
Advanced Strategy 0: LLM-guided test harness generation for vulnerability triggering
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

# Add repository root to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))
import tempfile
import shutil
import glob
import tarfile
from litellm import completion
from dotenv import load_dotenv
from typing import Optional, Dict, List, Any, Union, Tuple

from crs.strategy.common.utils.code_analysis import (
    run_static_analysis_local,
    load_qx_analysis_results,
    get_reachable_functions_qx,
    find_task_directory
)
import concurrent.futures
import uuid

load_dotenv()

import openlit
from opentelemetry import trace
# Initialize openlit
openlit.init(application_name="afc-crs-all-you-need-is-a-fuzzing-brain")
# Acquire a tracer
tracer = trace.get_tracer(__name__)

DO_PATCH_ONLY = False
FULL_SCAN = False

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
# OPENAI_MODEL = "chatgpt-4o-latest"
# CLAUDE_MODEL = "gpt-4o-mini"
CLAUDE_MODEL = "claude-3-7-sonnet-latest"
CLAUDE_MODEL_35 = "claude-3-5-sonnet-20241022"
GEMINI_MODEL_PRO_25_0325 = "gemini-2.5-pro-preview-03-25"
GEMINI_MODEL_PRO_25_0506 = "gemini-2.5-pro-preview-05-06"
GEMINI_MODEL_PRO_25 = "gemini-2.5-pro"
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_MODEL_PRO = "gemini-2.0-pro-exp-02-05"
GEMINI_MODEL_FLASH = "gemini-2.0-flash"
GEMINI_MODEL_FLASH_LITE = "gemini-2.5-flash-lite-preview-06-17"
GROK_MODEL = "xai/grok-3-beta"
CLAUDE_MODEL_SONNET_45 = "claude-sonnet-4-5-20250929"
CLAUDE_MODEL_OPUS_4 = "claude-opus-4-20250514"
MODELS = [CLAUDE_MODEL, OPENAI_MODEL, CLAUDE_MODEL_OPUS_4, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25]
CLAUDE_MODEL = CLAUDE_MODEL_SONNET_45
OPENAI_MODEL = CLAUDE_MODEL_SONNET_45
OPENAI_MODEL_O3 = CLAUDE_MODEL_SONNET_45
MODELS = [CLAUDE_MODEL_SONNET_45, CLAUDE_MODEL_OPUS_4]

def get_fallback_model(current_model, tried_models):
    """Get a fallback model that hasn't been tried yet"""
    # Define model fallback chains
    fallback_chains = {
        GEMINI_MODEL_PRO_25: [CLAUDE_MODEL, CLAUDE_MODEL_35, OPENAI_MODEL_41, OPENAI_MODEL_O3],   
        OPENAI_MODEL_41: [OPENAI_MODEL_O4_MINI, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25],   
        OPENAI_MODEL: [GEMINI_MODEL_PRO_25, GEMINI_MODEL_FLASH, GEMINI_MODEL_FLASH_LITE],             
        CLAUDE_MODEL: [CLAUDE_MODEL_SONNET_45,OPENAI_MODEL, CLAUDE_MODEL_35, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25],        
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


# Logging setup
LOG_DIR = os.environ.get("LOG_DIR", "/tmp/strategy_logs")
os.makedirs(LOG_DIR, exist_ok=True)

def setup_logging(fuzzer_name):
    """Set up logging for the strategy"""
    # Include DO_PATCH_ONLY and FULL_SCAN in the log filename
    patch_status = "patch_only" if DO_PATCH_ONLY else "sarif_pov_strategy"
    scan_type = "full_scan" if FULL_SCAN else "delta_scan"
    
    timestamp = int(time.time())
    log_file = os.path.join(LOG_DIR, f"as0_{fuzzer_name}_{patch_status}_{scan_type}_phase{POV_PHASE}_{timestamp}.log")
    
    # Log initial configuration
    with open(log_file, "w") as f:
        f.write(f"Strategy: AS0\n")
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

def call_gemini_api(log_file, messages, model_name="gemini-2.5-pro-preview-03-25") -> (str, bool):
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
    

def call_llm(log_file, messages, model_name):
    """Call LLM with telemetry tracking."""    
    with tracer.start_as_current_span("genai") as span:
        span.set_attribute("crs.action.category", "fuzzing")
        span.set_attribute("crs.action.name", "call_llm")
        span.set_attribute("genai.model.name", f"{model_name}")

        try:
            if model_name.startswith("gemini"):
                response = call_gemini_api(log_file, messages, model_name)
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
    
    use_another_model = CLAUDE_MODEL_SONNET_45
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

def get_commit_info(log_file, project_dir, language):
    """Get information about the commit that introduced the vulnerability"""
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
        blob_path = os.path.join(xbin_dir, "x.bin")
        blob_path1 = os.path.join(xbin_dir, "x1.bin")
        if os.path.exists(blob_path1):
            log_message(log_file, f"x1.bin was created successfully ({os.path.getsize(blob_path1)} bytes)")
            return True, result.stdout, result.stderr
        elif os.path.exists(blob_path):
            log_message(log_file, f"x.bin was created successfully ({os.path.getsize(blob_path)} bytes)")
            return True, result.stdout, result.stderr
        else:
            log_message(log_file, f"x1.bin was not created")
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
        if "INFO: Instrumented" in line:
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

def run_fuzzer_with_input(log_file, fuzzer_path, project_dir, focus, blob_path):

    try:
        log_message(log_file, f"Running fuzzer {fuzzer_path} with blob {blob_path}")
        
        # Get the directory containing the fuzzer
        fuzzer_dir = os.path.dirname(fuzzer_path)
        fuzzer_name = os.path.basename(fuzzer_path)

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
        
        sanitizer_project_dir = os.path.join(project_dir, focus)
        out_dir = os.path.dirname(fuzzer_path)
        out_dir_x = os.path.join(out_dir, f"sarif0")

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
                f"aixcc-afc/{project_name}",
                f"/out/{fuzzer_name}",
                "-timeout=30",           # Add libFuzzer timeout parameter
                "-timeout_exitcode=99",  # Set specific exit code for timeouts                
                f'/out/{unique_blob_name}'
            ]

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


def extract_and_save_crash_input(log_file, crash_dir, fuzzer_name, out_dir_x, project_name, sanitizer, project_dir, sanitizer_project_dir):
    """Extract and save crash input from fuzzer output, finding the latest that actually triggers a crash"""
    
    def get_crash_files(pattern):
        """Get all crash files matching the pattern, sorted by creation time (newest first)"""
        crash_files = glob.glob(pattern)
        # Sort by creation time, newest first
        crash_files.sort(key=os.path.getctime, reverse=True)
        return crash_files
    
    def test_crash_file(crash_file, project_name, sanitizer):
        """Test if a crash file actually triggers a crash when run with the fuzzer"""
        log_message(log_file, f"Testing crash file: {crash_file}")
        
        # Get just the "crashes/crash-xxx" part correctly
        if "crashes/" in crash_file:
            # Extract just the "crashes/crash-xxx" part
            relative_path = "crashes/" + os.path.basename(crash_file)
        else:
            # Fallback if crashes/ isn't in the path
            relative_path = os.path.basename(crash_file)
        
        # Set up the Docker command to test the crash
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
            "-v", f"{os.path.dirname(crash_file)}:/crashes",
            f"aixcc-afc/{project_name}",
            f"/out/{fuzzer_name}",
            "-timeout=30",
            "-timeout_exitcode=99",
            f"/out/{relative_path}"
        ]
        
        try:
            log_message(log_file, f"Running crash test: {' '.join(docker_cmd)}")
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Check if the output indicates a crash
            crash_indicators = [
                "==ERROR:", 
                "WARNING: MemorySanitizer:",
                "SUMMARY: AddressSanitizer:",
                "Segmentation fault",
                "AddressSanitizer: heap-use-after-free",
                "AddressSanitizer: heap-buffer-overflow",
                "AddressSanitizer: SEGV",
                "UndefinedBehaviorSanitizer: undefined-behavior",
                "Java Exception: com.code_intelligence.jazzer",
            ]
            
            for indicator in crash_indicators:
                if indicator in result.stdout or indicator in result.stderr:
                    log_message(log_file, f"Crash confirmed for {crash_file}")
                    return True, result.stdout + result.stderr
            
            log_message(log_file, f"No crash detected for {crash_file}")
            return False, ""
            
        except subprocess.TimeoutExpired:
            log_message(log_file, f"Timeout while testing {crash_file}")
            return False, ""
        except Exception as e:
            log_message(log_file, f"Error testing crash file: {str(e)}")
            return False, ""
    
    # Step 1: Find all potential crash files
    # Step 1: Find all potential crash files
    crash_patterns = [
        os.path.join(crash_dir, "crash-*")
    ]

    sentinel =  Path(project_dir) / DETECT_TIMEOUT_CRASH_SENTINEL
    if os.environ.get("DETECT_TIMEOUT_CRASH") == "1" or sentinel.exists():
        crash_patterns.append(os.path.join(crash_dir, "timeout-*"))
    
    all_crash_files = []
    for pattern in crash_patterns:
        all_crash_files.extend(get_crash_files(pattern))
    
    if not all_crash_files:
        log_message(log_file, "No crash files found in any location")
        return None, None
    
    log_message(log_file, f"Found {len(all_crash_files)} potential crash files")
    
    # Step 2: Test each crash file from newest to oldest
    for crash_file in all_crash_files:
        crashes, crash_output = test_crash_file(crash_file, project_name, sanitizer)
        
        if crashes:
            # Found a valid crash file
            try:
                with open(crash_file, 'rb') as f:
                    crash_data = f.read()
                    if crash_data:
                        log_message(log_file, f"Found valid crash data in: {crash_file}")
                        return crash_data, crash_file
            except Exception as e:
                log_message(log_file, f"Error reading crash file {crash_file}: {str(e)}")
                continue
    
    log_message(log_file, "No valid crash files found that trigger crashes")
    return None, None
    
def log_fuzzer_output(log_file, combined_output, max_line_length=200):
    # Split output into lines
    lines = combined_output.splitlines()
    
    # Get first 200 lines and truncate each line if too long
    start_lines = []
    for line in lines[:200]:
        if len(line) > max_line_length:
            truncated = line[:max_line_length] + f" ... (truncated, full length: {len(line)})"
            start_lines.append(truncated)
        else:
            start_lines.append(line)
    
    # Get last 200 lines and truncate each line if too long
    end_lines = []
    if len(lines) > 200:
        for line in lines[-200:]:
            if len(line) > max_line_length:
                truncated = line[:max_line_length] + f" ... (truncated, full length: {len(line)})"
                end_lines.append(truncated)
            else:
                end_lines.append(line)
    
    # Join the lines back together
    start_output = '\n'.join(start_lines)
    end_output = '\n'.join(end_lines)

    log_message(log_file, f"Fuzzer output START (first 200 lines):\n{start_output}")
    if len(lines) > 200:
        log_message(log_file, f"\n... ({len(lines) - 400} lines skipped) ...\n")
    if end_lines:
        log_message(log_file, f"Fuzzer output END (last 200 lines):\n{end_output}")

def run_fuzzer_with_coverage(log_file, fuzzer_path, project_dir, focus, sanitizer, project_name, seed_corpus_dir):
    """Run the fuzzer with seed corpus dir containing generated blob file"""    
    try:
        log_message(log_file, f"Running fuzzer {fuzzer_path} with {seed_corpus_dir}")
        # Get the directory containing the fuzzer
        fuzzer_name = os.path.basename(fuzzer_path) 
        sanitizer_project_dir = os.path.join(project_dir, focus)
        out_dir = os.path.dirname(fuzzer_path)
        out_dir_x = os.path.join(out_dir, f"sarif0")

        work_dir = os.path.join(project_dir, "fuzz-tooling", "build", "work", f"{project_name}-{sanitizer}")
        
        # Create a directory for crash inputs if it doesn't exist
        crash_dir = os.path.join(out_dir_x, "crashes")
        os.makedirs(crash_dir, exist_ok=True)
        
        corpus_container_path = "/corpus"
        
        # Set a shorter timeout for the fuzzer itself to ensure we get coverage output
        # Make this less than the subprocess timeout
        fuzzer_timeout = 55  # 55 seconds for the fuzzer
        subprocess_timeout = 60  # 60 seconds for the subprocess

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
            "-v", f"{seed_corpus_dir}:{corpus_container_path}",
            f"aixcc-afc/{project_name}",
            f"/out/{fuzzer_name}",
            "-print_coverage=1",
            f"-max_total_time={fuzzer_timeout}",  # Use the shorter timeout for the fuzzer
            "-max_len=262144",
            "-verbosity=0",
            "-detect_leaks=0",
            "-artifact_prefix=/out/crashes/",
            corpus_container_path,
        ]

        log_message(log_file, f"Running Docker command: {' '.join(docker_cmd)}")
        
        # Use a process with pipes to capture output in real-time
        process = subprocess.Popen(
            docker_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            errors="backslashreplace",   # or "ignore" / "backslashreplace"                        
            encoding="utf-8",   # enables text-mode
            text=True,
            bufsize=1
        )
        
        stdout_data = []
        stderr_data = []
        
        # Set up non-blocking reads
        import select
        import time
        
        start_time = time.time()
        timed_out = False
        
        # Read output until process completes or times out
        while process.poll() is None:
            # Check if we've exceeded our timeout
            if time.time() - start_time > subprocess_timeout:
                log_message(log_file, "Subprocess timeout reached, terminating process")
                process.terminate()
                timed_out = True
                # Give it a moment to terminate gracefully
                time.sleep(10)
                if process.poll() is None:
                    process.kill()
                break
                
            # Check if there's data to read (with a small timeout)
            reads = [process.stdout, process.stderr]
            readable, _, _ = select.select(reads, [], [], 0.1)
            
            for stream in readable:
                line = stream.readline()
                if line.startswith("Error: in prepare") or "unknown option" in line:
                   continue      # skip parse errors
                if line:
                    if stream == process.stdout:
                        stdout_data.append(line)
                    else:
                        stderr_data.append(line)
        
        # Get any remaining output
        stdout, stderr = process.communicate()
        if stdout:
            stdout_data.append(stdout)
        if stderr:
            stderr_data.append(stderr)
            
        stdout_text = ''.join(stdout_data)
        stderr_text = ''.join(stderr_data)
        combined_output = stdout_text + "\n" + stderr_text
        
        # Filter out REDUCE lines from fuzzer output
        filtered_output_lines = []
        max_line_length = 200
        for line in combined_output.split('\n'):
            # Check if line starts with # followed by a number (fuzzer progress lines)
            if line.strip().startswith('#') and any(x in line for x in ["REDUCE cov:", "INITED cov:", "NEW    cov:"]):
                # Only keep NEW lines that contain NEW_FUNC (important function discoveries)
                if "NEW_FUNC" in line:
                    filtered_output_lines.append(line)
            elif len(line) > max_line_length:
                truncated = line[:max_line_length] + f" ... (truncated, full length: {len(line)})"
                filtered_output_lines.append(truncated)
            else:
                if not line.lstrip().startswith("WARNING:"):
                    filtered_output_lines.append(line)

        filtered_output = '\n'.join(filtered_output_lines)
        
        # Extract coverage information
        coverage_output = ""
        fuzzer_output = filtered_output

        log_fuzzer_output(log_file, fuzzer_output)

        # Check if "COVERAGE:" is in the output
        if "COVERAGE:" in filtered_output:
            parts = filtered_output.split("COVERAGE:", 1)
            fuzzer_output = parts[0].strip()
            full_coverage = parts[1].strip()
            
            # Process coverage output to make it more concise
            coverage_lines = full_coverage.split('\n')
            condensed_coverage_lines = []
            
            # Keep track of covered and uncovered functions
            covered_funcs = []
            uncovered_funcs = []
            
            current_func = None
            seen_uncovered_pcs = set()  # Track unique uncovered PCs to avoid duplicates
            
            for line in coverage_lines:
                if line.startswith("COVERED_FUNC:") and "/src/" in line:
                    current_func = line
                    covered_funcs.append(line)
                    condensed_coverage_lines.append(line)
                elif line.startswith("UNCOVERED_FUNC:") and "/src/" in line:
                    uncovered_funcs.append(line)
                    # Don't add to condensed output yet
                elif line.startswith("  UNCOVERED_PC:"):
                    # Skip lines with line number 0
                    if ":0" in line or not line.startswith("  UNCOVERED_PC: /src/"):
                        continue
                    
                    # Only add unique uncovered PCs and limit to 3 per function
                    if (line not in seen_uncovered_pcs and 
                        current_func and 
                        sum(1 for l in condensed_coverage_lines if l.startswith("  UNCOVERED_PC:")) < 3):
                        seen_uncovered_pcs.add(line)
                        condensed_coverage_lines.append(line)

            # Add a summary of uncovered functions
            condensed_coverage_lines.append(f"\nUNCOVERED FUNCTIONS SUMMARY: {len(uncovered_funcs)} functions")
            # Add first 10 uncovered functions as examples
            for func in uncovered_funcs[:10]:
                condensed_coverage_lines.append(func)
            if len(uncovered_funcs) > 10:
                condensed_coverage_lines.append(f"... and {len(uncovered_funcs) - 10} more uncovered functions")
            
            coverage_output = "COVERAGE:\n" + '\n'.join(condensed_coverage_lines)
        
        # Check if the fuzzer crashed
        crash_detected = False
        crash_input = None
        
        log_message(log_file, f"Fuzzer exited with returncode: {process.returncode}")            
        if "runtime error:" in combined_output:
            timed_out = False

        if process.returncode == 77 and "Java Exception: java.lang.NoClassDefFoundError:" in combined_output:
            log_message(log_file, f"Fuzzer exited with non-zero code {process.returncode}, but no crash indicators found")            
        elif (process.returncode != 0 and not timed_out) or "ABORTING" in combined_output:
            # Check for actual crash indicators vs warnings
            if any(indicator in combined_output for indicator in [
                "ERROR: AddressSanitizer:",
                # "ERROR: LeakSanitizer:",
                "ERROR: MemorySanitizer:",
                "WARNING: MemorySanitizer:",
                "ERROR: ThreadSanitizer:",
                "ERROR: UndefinedBehaviorSanitizer:",
                "SEGV on unknown address",
                "Segmentation fault",
                "runtime error:"
                "AddressSanitizer: heap-buffer-overflow",
                "AddressSanitizer: heap-use-after-free",
                "UndefinedBehaviorSanitizer: undefined-behavior",
                "AddressSanitizer:DEADLYSIGNAL",
                "Java Exception: com.code_intelligence.jazzer",
                "ERROR: HWAddressSanitizer:",
                "WARNING: ThreadSanitizer:",
                "libfuzzer exit=1"
            ]):
                log_message(log_file, f"Fuzzer crashed with exit code {process.returncode} - potential vulnerability triggered!")
                crash_detected = True
                
                # Extract and save the crash input
                crash_input, crash_input_filepath = extract_and_save_crash_input(log_file, crash_dir, fuzzer_name, out_dir_x, project_name, sanitizer, project_dir, sanitizer_project_dir)
                # log_message(log_file, f"crash_input_filepath: {crash_input_filepath}")
                # log_message(log_file, f"crash_input: {crash_input}")
            else:
                log_message(log_file, f"Fuzzer exited with non-zero code {process.returncode}, but no crash indicators found")
        elif timed_out:
            log_message(log_file, "Fuzzer execution timed out, but we captured available output")
            fuzzer_output = "Execution timed out, partial output:\n" + fuzzer_output
        else:
            log_message(log_file, "Fuzzer ran successfully without crashing")
        
        return crash_detected, fuzzer_output, coverage_output, crash_input
    
    except Exception as e:
        log_message(log_file, f"Error running fuzzer: {str(e)}")
        return False, str(e), "", None

def generate_pov(log_file, project_dir, messages, model_name):
    """Generate a Proof of Vulnerability payload"""
   
    function_start_time = time.time()
    
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

def has_pov_submitted_for_task(log_file):
    """
    Return True iff at least one PoV has already been submitted for the
    current task.

    If anything goes wrong (missing env-vars, network issues, bad JSON, …)
    we conservatively return False so the caller can attempt a new PoV.
    """
    # Endpoint & task information ------------------------------------------------
    submission_endpoint = os.environ.get("SUBMISSION_ENDPOINT")
    task_id            = os.environ.get("TASK_ID")
    if not submission_endpoint or not task_id:
        log_message(log_file,
                    "SUBMISSION_ENDPOINT or TASK_ID not set – skipping PoV status check")
        return False

    # Credentials (fall back to CRS_* when COMPETITION_* are absent) -------------
    api_key_id = (
        os.environ.get("COMPETITION_API_KEY_ID")
        or os.environ.get("CRS_KEY_ID")
    )
    api_token  = (
        os.environ.get("COMPETITION_API_KEY_TOKEN")
        or os.environ.get("CRS_KEY_TOKEN")
    )
    auth = (api_key_id, api_token) if api_key_id and api_token else None

    # ---------------------------------------------------------------------------
    url = f"{submission_endpoint}/v1/task/{task_id}/pov_stats/"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",   # harmless for GET
    }

    try:
        response = requests.get(url, headers=headers, auth=auth, timeout=60)
    except Exception as exc:
        log_message(log_file, f"Network error while querying {url}: {exc}")
        return False

    if response.status_code != 200:
        log_message(
            log_file,
            f"POV-stats endpoint returned {response.status_code}: {response.text}"
        )
        return False

    try:
        data = response.json()
    except ValueError as exc:
        log_message(log_file, f"Failed to decode JSON from POV-stats response: {exc}")
        return False

    log_message(log_file,
                f"Successfully received POV status: {json.dumps(data, indent=2)}")

    return int(data.get("count", 0)) > 0
           
def submit_pov_to_endpoint(log_file, project_dir, blob_path, fuzzer_output,sanitizer, vuln_signature, fuzzer_name):
    """
    Submit the POV to the submission endpoint.
    
    Args:
        log_file: Log file handle
        project_dir: Project directory
        
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
    if not os.path.exists(blob_path):
        log_message(log_file, f"Blob file {blob_path} does not exist, skipping submission")
        return False
        
    with open(blob_path, "rb") as f:
        blob_data = f.read()
        
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
        
    # Create the submission payload
    submission = {
        "task_id": task_id,
        "architecture": "x86_64",
        "engine": "libfuzzer",
        "fuzzer_name": fuzzer_name,
        "sanitizer": sanitizer,
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
    submission["strategy"] = "sarif"
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
                response_status = response_data["status"]
                if response_status == "duplicate":
                    log_message(log_file, f"SARIF POV duplicated!")
                    # return True

                if any(err in fuzzer_output for err in [
                    "ERROR: AddressSanitizer: ",
                    "Java Exception: com.code_intelligence.jazzer"
                ]):
                    return True

                pov_id = response_data["pov_id"]
                api_url = f"https://api.tail7e9b4c.ts.net/v1/task/{task_id}/pov/{pov_id}"

                max_wait_sec = 900          # 5 min
                poll_interval = 30           # 5 s
                deadline = time.time() + max_wait_sec

                while time.time() < deadline:
                    try:
                        pov_response = requests.get(
                            api_url,
                            headers=headers,
                            auth=auth,
                            timeout=30,
                        )
                        pov_response.raise_for_status()
                        status = pov_response.json().get("status", "").lower()
                        log_message(log_file, f"POV status = {status}")

                        if status == "passed":
                            # Create a sentinel file so the rest of the pipeline can
                            # notice the PoV succeeded and terminate early.
                            try:
                                sentinel_name = f"successful_povs_{pov_id}"
                                sentinel_path = Path(project_dir) / sentinel_name
                                sentinel_path.touch(exist_ok=True)
                                log_message(log_file, f"Created POV success sentinel: {sentinel_path}")
                            except Exception as exc:
                                log_message(log_file, f"Unable to create POV success sentinel: {exc}")
                            return True
                        if status == "failed":
                            log_message(log_file, f"POV failed: {api_url}")
                            if "libFuzzer: timeout" in fuzzer_output:
                                # Clear the env-var entirely (instead of leaving an empty string)
                                os.environ.pop("DETECT_TIMEOUT_CRASH", None)
                                sentinel = Path(project_dir) / DETECT_TIMEOUT_CRASH_SENTINEL
                                try:                                
                                    # pathlib-friendly removal; missing_ok=True avoids race conditions
                                    sentinel.unlink(missing_ok=True)
                                except Exception as exc:
                                    log_message(log_file, f"Unable to remove sentinel detect_timeout_crash file: {exc}")
                                
                            return False
                    except Exception as exc:      # network / parsing errors
                        log_message(log_file, f"POV poll error: {exc}")

                    time.sleep(poll_interval)

                # Timed out
                log_message(log_file, f"POV status check timed out after {max_wait_sec}s: {api_url}")
                return False

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
    
def after_pov_crash_detected(log_file,model_name,iteration,fuzzer_name,sanitizer,project_name,crash_output,vuln_signature,code,blob_path,messages):
    pov_id = str(uuid.uuid4())[:8]
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
        
    blob_file = f"test_blob_{pov_id}_{model_name}_{iteration}.bin"
    if os.path.exists(blob_path):
        shutil.copy(blob_path, os.path.join(save_dir, blob_file))
    
    # Save the crash output
    fuzzer_output_file = f"fuzzer_output_{pov_id}_{model_name}_{iteration}.txt"
    with open(os.path.join(save_dir, fuzzer_output_file), "w") as f:
        f.write(crash_output)
    
    # Save the conversation history as JSON
    conversation_file = f"conversation_{pov_id}_{model_name}_{iteration}.json"
    with open(os.path.join(save_dir, conversation_file), "w") as f:
        json.dump(messages, f, indent=2)
    
    log_message(log_file, f"Saved successful PoV artifacts to {save_dir}")
    
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
    
    return pov_metadata


def cleanup_seed_corpus(dir_path, max_age_minutes=10):
    cutoff = time.time() - max_age_minutes * 60
    for path in glob.glob(os.path.join(dir_path, "*")):
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
        except OSError:
            pass   # ignore files that disappear meanwhile

def doAdvancedPoV0(log_file, initial_msg, fuzzer_path, fuzzer_name, sanitizer, project_dir, project_name, focus, language='c', check_patch_success=False) -> bool:
    log_message(log_file, f"POV_PHASE: {POV_PHASE} doAdvancedPoV0") 

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
        messages = [{"role": "system", "content": "You are a security expert specializing in vulnerability detection."}]
        messages.append({"role": "user", "content": initial_msg})
        
        for iteration in range(1, MAX_ITERATIONS + 1):
            current_time = time.time()
            if current_time > end_time:
                log_message(log_file, f"Timeout reached after {iteration-1} iterations with {model_name}")
                break
            
            if check_patch_success:
                if check_for_successful_patches(log_file, project_dir):
                    log_message(log_file, "Successful patch detected, stopping POV generation")
                    return True, {} # Return empty metadata since we're stopping early
                
            log_message(log_file, f"Iteration {iteration} with {model_name}")
            
            # Generate PoV
            code = generate_pov(log_file, project_dir, messages, model_name)
            
            if not code:
                log_message(log_file, "No valid Python code generated, continuing to next iteration")
                messages.append({"role": "user", "content":  "No valid Python code generated, please try again"})
                continue
                
            # Run the generated code
            unique_id = str(uuid.uuid4())[:8]  #add unique id to avoid race condition
            xbin_dir = os.path.join(project_dir, f"sarif",unique_id)
            log_message(log_file, f"Creating xbin_dir: {xbin_dir}")
            # Create the directory if it doesn't exist
            os.makedirs(xbin_dir, exist_ok=True)
            success, stdout, stderr = run_python_code(log_file, code, xbin_dir)

            if not success:
                log_message(log_file, "Failed to create x1.bin, adding error to context and continuing")
                if stderr:
                    messages.append({"role": "user", "content": f"Python code failed with error: {stderr}\n\nPlease try again."})
                else:
                    messages.append({"role": "user", "content":  "Python code failed to create x1.bin, please try again."})
                continue
            
            blob_files = [f"x{i}.bin" for i in range(1, 6)]  # x1.bin to x5.bin
            for blob_num, blob_file in enumerate(blob_files, 1):
                blob_path = os.path.join(xbin_dir, blob_file)
                if not os.path.exists(blob_path):
                    log_message(log_file, f"Blob file {blob_file} does not exist, skipping...")
                    continue

                log_message(log_file, f"Testing blob {blob_file}...")
                crash_detected, fuzzer_output = run_fuzzer_with_input(log_file, fuzzer_path, project_dir, focus, blob_path)
                if not crash_detected:
                    log_message(log_file, f"Blob {blob_file} did not trigger a crash, trying next blob...")
                    # Save x.bin to the fuzzer's seed corpus for future fuzzing
                    seed_corpus_dir = os.path.join(project_dir, f"{fuzzer_name}_seed_corpus")
                    os.makedirs(seed_corpus_dir, exist_ok=True)
                    cleanup_seed_corpus(seed_corpus_dir, max_age_minutes=10)

                    unique_id = str(uuid.uuid4())[:8]  # Use first 8 chars of UUID for brevity
                    seed_file_path = os.path.join(seed_corpus_dir, f"seed_{model_name}_{iteration}_{unique_id}.bin")
                    
                    # Copy the test case to the seed corpus
                    shutil.copy(blob_path, seed_file_path)
                    log_message(log_file, f"Saved test case to seed corpus: {seed_file_path}")
                    os.remove(blob_path)
                    continue
                else:
                    found_pov = True
                    break
            
            if not found_pov:
                log_message(log_file, f"Trying libfuzzer print_coverage running for 60s")
                found_pov, fuzzer_output, coverage_output, blob_data = run_fuzzer_with_coverage(log_file, fuzzer_path, project_dir, focus,sanitizer,project_name, seed_corpus_dir)
                if blob_data:
                    log_message(log_file, f"blob_data: {blob_data}")
                    # Generate a unique filename using UUID
                    unique_id = str(uuid.uuid4())
                    # Create filename with meaningful prefix and unique identifier
                    blob_filename = f"blob_{sanitizer}_{unique_id}.bin"
                    blob_path = os.path.join(xbin_dir, blob_filename)
                    
                    try:
                        # Write the binary data to file
                        with open(blob_path, 'wb') as f:
                            f.write(blob_data)
                        log_message(log_file, f"Saved blob data to: {blob_path}")
                    except Exception as e:
                        log_message(log_file, f"Error saving blob data: {str(e)}")
                        blob_path = None
                        found_pov = False
                else:
                    log_message(log_file, "No blob data to save")
                    blob_path = None
                    found_pov = False

                # print(f"fuzzer_output_x:{fuzzer_output_x}")
            if found_pov and blob_path:
                crash_output = extract_crash_output(fuzzer_output)
                vuln_signature = fuzzer_name+"-"+generate_vulnerability_signature(crash_output, sanitizer)    
                # Submit POV to endpoint
                submission_result = submit_pov_to_endpoint(log_file, project_dir,blob_path,fuzzer_output,sanitizer, vuln_signature, fuzzer_name)
                if submission_result or True: # for local test w/o submission endpoint
                    pov_metadata = after_pov_crash_detected(log_file,model_name,iteration,fuzzer_name,sanitizer,project_name,crash_output,vuln_signature,code,blob_path,messages)
                    successful_pov_metadata = pov_metadata
                    log_message(log_file, f"POV SUCCESS! Vulnerability triggered with {model_name} on iteration {iteration}")
                    break
                else:
                    log_message(log_file, "Failed to submit POV to endpoint")
            else:
                fuzzer_output = filter_instrumented_lines(fuzzer_output)
                if iteration == 1:
                    user_message = f"""
Fuzzer output:
{truncate_output(fuzzer_output, 500)}

Fuzzer coverage after running 60s with the blob files as seeds:
{truncate_output(coverage_output, 2000)}

The test cases did not trigger the vulnerability. Please analyze the fuzzer output and try again with an improved approach. Consider:
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

The test cases did not trigger the vulnerability. Please analyze the fuzzer output and try again with a different approach.
"""
                if iteration == MAX_ITERATIONS-1:
                    user_message = user_message + "\nThis is your last attempt. This task is very very important to me. If you generate a successful blob, I will tip you 2000 dollars."
                messages.append({"role": "user", "content": user_message})

        if found_pov:
            break
    # Final summary
    total_time = time.time() - start_time
    log_message(log_file, f"Advanced Strategy as0_full.py completed in {total_time:.2f} seconds")
    
    # Check if any successful PoVs were found
    if os.path.exists(POV_SUCCESS_DIR) and len(os.listdir(POV_SUCCESS_DIR)) > 0:
        pov_count = len([f for f in os.listdir(POV_SUCCESS_DIR) if f.startswith("pov_metadata_")])
        log_message(log_file, f"Found {pov_count} successful PoVs")
        return found_pov, successful_pov_metadata
    else:
        log_message(log_file, "No successful PoVs found")
        return False, {}


# Define vulnerability categories for C
vul_categories_c = [
    "CWE-119",  # Buffer Overflow
    "CWE-416",  # Use After Free
    "CWE-476",  # NULL Pointer Dereference
    "CWE-190",  # Integer Overflow
    "CWE-122",  # Heap-based Buffer Overflow
    "CWE-787",  # Out-of-bounds Write
    "CWE-125",  # Out-of-bounds Read
    "CWE-134",  # Format String
    # "CWE-401",  # Memory Leak
    "CWE-121",  # Stack-based Buffer Overflow
    "CWE-369"   # Divide by Zero
]
# Updated vul_categories_java list
vul_categories_java = [
    "CWE-22",   # Path Traversal (more generic than CWE-601)
    "CWE-77",   # Command Injection
    "CWE-78",   # OS Command Injection
    "CWE-601",  # Path Traversal (URL)
    "CWE-79",   # Cross-Site Scripting (XSS)
    "CWE-89",   # SQL Injection
    "CWE-200",  # Information Exposure
    "CWE-306",  # Missing Authentication
    "CWE-502",  # Deserialization
    "CWE-611",  # XXE Processing
    "CWE-776",  # Recursive Entity References
    "CWE-400",  # Resource Consumption
    "CWE-755",  # Exception Handling
    "CWE-347",  # Cryptographic Verification
    "CWE-918"   # Server-Side Request Forgery (SSRF)
]

def parse_commit_diff(project_src_dir, commit_diff):
    """
    Parse a commit diff in unified diff format and extract modified functions.
    
    Args:
        project_src_dir (str): Path to the project source directory
        commit_diff (str): Commit diff in unified diff format
        
    Returns:
        dict: A dictionary mapping file paths to modified functions with their details
    """
    import re
    
    # Initialize result dictionary
    modified_functions = {}
    
    # Split the diff by file
    file_diffs = re.split(r'diff --git ', commit_diff)
    if file_diffs[0] == '':
        file_diffs = file_diffs[1:]
    else:
        file_diffs[0] = file_diffs[0].lstrip()
    
    for file_diff in file_diffs:
        # Skip empty diffs
        if not file_diff:
            continue
            
        # Extract file path
        file_path_match = re.search(r'a/(.*) b/', file_diff)
        if not file_path_match:
            continue
            
        file_path = file_path_match.group(1)
        
        # Skip test files or non-source files
        if '/test/' in file_path or not any(file_path.endswith(ext) for ext in ['.java', '.c', '.h']):
            continue
            
        # Check if the file exists in the project
        full_file_path = os.path.join(project_src_dir, file_path)
        if not os.path.exists(full_file_path):
            continue
            
        # Initialize entry for this file
        if file_path not in modified_functions:
            modified_functions[file_path] = {
                "file_path": file_path,
                "modified_functions": []
            }
            
        # Extract hunk headers and changed lines
        hunks = re.finditer(r'@@ -(\d+),(\d+) \+(\d+),(\d+) @@(.*?)(?=\n@@|\Z)', 
                           file_diff, re.DOTALL)
        
        for hunk in hunks:
            start_line = int(hunk.group(3))  # New file start line
            hunk_text = hunk.group(0)
            
            # Find function definitions in the hunk context
            if file_path.endswith('.java'):
                # For Java files
                function_matches = re.finditer(
                    r'(?:public|private|protected|static|\s) +(?:[a-zA-Z0-9_<>]+) +([a-zA-Z0-9_]+) *\([^)]*\) *(?:\{|throws|$)',
                    hunk_text
                )
                
                for match in function_matches:
                    function_name = match.group(1)
                    
                    # Skip constructor definitions
                    if '.' in file_path:
                        class_name = file_path.split('/')[-1].split('.')[0]
                        if function_name == class_name:
                            continue
                    
                    # Find the function's position in the hunk
                    function_pos = match.start()
                    
                    # Count lines to get the function's start line
                    lines_before = hunk_text[:function_pos].count('\n')
                    function_start_line = start_line + lines_before
                    
                    # Extract the function body
                    function_body = extract_function_body(full_file_path, function_name)
                    
                    # Add to the list of modified functions
                    if function_name not in [f["name"] for f in modified_functions[file_path]["modified_functions"]]:
                        modified_functions[file_path]["modified_functions"].append({
                            "name": function_name,
                            "start_line": function_start_line,
                            "body": function_body
                        })
            
            elif file_path.endswith(('.c', '.h')):
                # For C/C++ files
                # Match both standard C function definitions and function definitions with return type on a separate line
                function_matches = re.finditer(
                    r'(?:(?:static|inline|extern)?\s+(?:[a-zA-Z0-9_]+\s+)*([a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:\{|$))|(?:^([a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:\{|$))',
                    hunk_text, re.MULTILINE
                )
                
                for match in function_matches:
                    # Either group 1 or group 2 will have the function name
                    function_name = match.group(1) if match.group(1) else match.group(2)
                    
                    # Skip if function name is None or a C keyword
                    if not function_name or function_name in ['if', 'while', 'for', 'switch', 'return']:
                        continue
                    
                    # Find the function's position in the hunk
                    function_pos = match.start()
                    
                    # Count lines to get the function's start line
                    lines_before = hunk_text[:function_pos].count('\n')
                    function_start_line = start_line + lines_before
                    
                    # Extract the function body
                    function_body = extract_function_body(full_file_path, function_name)
                    
                    # Add to the list of modified functions
                    if function_name not in [f["name"] for f in modified_functions[file_path]["modified_functions"]]:
                        modified_functions[file_path]["modified_functions"].append({
                            "name": function_name,
                            "start_line": function_start_line,
                            "body": function_body
                        })        

    return modified_functions

def extract_function_body(file_path, function_name):
    """
    Extract the full function body from a file.
    
    Args:
        file_path (str): Path to the file
        function_name (str): Name of the function
        
    Returns:
        str: Function body or empty string if not found
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            
        # For Java, look for the function definition and extract its body
        if file_path.endswith('.java'):
            import re
            pattern = r'(?:public|private|protected|static|\s) +(?:[a-zA-Z0-9_<>]+) +' + re.escape(function_name) + r' *\([^)]*\) *(?:\{[^}]*\}|\{(?:\{[^}]*\}|[^{}])*\})'
            match = re.search(pattern, content, re.DOTALL)
            if match:
                return match.group(0)
                
        # For C/C++ files
        elif file_path.endswith(('.c', '.cpp', '.h')):
            import re
            # More complex pattern to handle C function definitions including multi-line declarations
            # and nested curly braces
            
            # First try to find the function declaration
            decl_pattern = r'(?:(?:static|inline|extern)?\s+(?:[a-zA-Z0-9_]+\s+)*' + re.escape(function_name) + r'\s*\([^)]*\)\s*(?:\{|$))|(?:^' + re.escape(function_name) + r'\s*\([^)]*\)\s*(?:\{|$))'
            decl_match = re.search(decl_pattern, content, re.MULTILINE)
            
            if decl_match:
                start_pos = decl_match.start()
                
                # Find the opening brace
                opening_brace_pos = content.find('{', start_pos)
                if opening_brace_pos == -1:
                    return ""  # Function declaration without implementation
                
                # Now find the matching closing brace
                brace_count = 1
                pos = opening_brace_pos + 1
                
                while brace_count > 0 and pos < len(content):
                    if content[pos] == '{':
                        brace_count += 1
                    elif content[pos] == '}':
                        brace_count -= 1
                    pos += 1
                
                if brace_count == 0:
                    # Extract the full function including declaration and body
                    return content[start_pos:pos]
                   
    except Exception as e:
        print(f"Error extracting function body: {e}")
        
    return ""


def extract_call_paths_from_analysis_service(project_name,fuzzer_path,fuzzer_src_path, focus, project_src_dir, target_functions, use_qx):
    """
    Extract call paths leading to vulnerable functions using local static analysis.

    Wrapper function that delegates to the imported local analysis function.

    Args:
        project_name (str): Project name (not used, kept for compatibility)
        fuzzer_path (str): Path to the compiled fuzzer binary
        fuzzer_src_path (str): Path to the fuzzer source file
        focus (str): Focus area identifier
        project_src_dir (str): Project source directory
        target_functions (dict): Dictionary of target functions
        use_qx (bool): Whether to use CodeQL analysis

    Returns:
        list: List of call paths
    """
    # Delegate to the imported local analysis function
    return extract_call_paths_local(fuzzer_path, fuzzer_src_path, focus, project_src_dir, target_functions, use_qx)


# Sample call path
TEST_CALL_PATHS = [
    [
        {
            "file": "MessageTrackerPeekReceivedFuzzer.java",
            "function": "fuzzerTestOneInput",
            "body": "public static void fuzzerTestOneInput(FuzzedDataProvider data) {\n    String sid = data.consumeRemainingAsString();\n    MessageTracker messageTracker = new MessageTracker(10);\n    messageTracker.dumpToLog(sid);\n}",
            "line": "31",
            "is_modified": False
        },
        {
            "file": "zookeeper-server/src/main/java/org/apache/zookeeper/server/util/MessageTracker.java",
            "function": "dumpToLog",
            "body": "public void dumpToLog(String serverAddress) {\n    if (!enabled) {\n        return;\n    }\n    logMessages(serverAddress, receivedBuffer, Direction.RECEIVED);\n    logMessages(serverAddress, sentBuffer, Direction.SENT);\n}",
            "line": "98",
            "is_modified": False
        },
        {
            "file": "zookeeper-server/src/main/java/org/apache/zookeeper/server/util/MessageTracker.java",
            "function": "logMessages",
            "body": "private static void logMessages(\n    String serverAddr,\n    CircularBuffer<BufferedMessage> messages,\n    Direction direction) {\n    String sentOrReceivedText = direction == Direction.SENT ? \"sentBuffer to\" : \"receivedBuffer from\";\n    if (serverAddr.contains(\":\")) {\n        verifyIPv6(serverAddr);\n    }\n    if (messages.isEmpty()) {\n        LOG.info(\"No buffered timestamps for messages {} {}\", sentOrReceivedText, serverAddr);\n    } else {\n        LOG.warn(\"Last {} timestamps for messages {} {}:\", messages.size(), sentOrReceivedText, serverAddr);\n        while (!messages.isEmpty()) {\n            LOG.warn(\"{} {}  {}\", sentOrReceivedText, serverAddr, messages.take().toString());\n        }\n    }\n}",
            "line": "105",
            "is_modified": True
        },
        {
            "file": "zookeeper-server/src/main/java/org/apache/zookeeper/server/util/MessageTracker.java",
            "function": "verifyIPv6",
            "body": "private static void verifyIPv6(String serverAddr) {\n    int maxColons = 8;\n    int cntColons = 0;\n    int i = serverAddr.indexOf(':');\n    while (i > -1 && i < serverAddr.length() && cntColons < maxColons) {\n        cntColons++;\n        i = serverAddr.indexOf(':', i + 1);\n    }\n    //is there an extra?\n    int extraColons = countExtraColons(i, serverAddr);\n    //count extras\n    if (cntColons > 0 && (cntColons < maxColons || extraColons == 0)) {\n        return;\n    }\n    throw new IllegalArgumentException(\"bad ipv6: \" + serverAddr + \" too many colons=\" + extraColons);\n}",
            "line": "122",
            "is_modified": True
        },
        {
            "file": "zookeeper-server/src/main/java/org/apache/zookeeper/server/util/MessageTracker.java",
            "function": "countExtraColons",
            "body": "private static int countExtraColons(int i, String serverAddr) {\n    if (i == -1) {\n        return 1;\n    }\n    int cnt = 1;\n    while (i > 0) {\n        cnt++;\n        i = serverAddr.indexOf(':');\n    }\n    return cnt;\n}",
            "line": "139",
            "is_modified": False
        }
    ]
]


def extract_reachable_functions_from_analysis_service(fuzzer_path, fuzzer_src_path, focus, project_src_dir, use_qx=True):
    """Extract reachable functions using local static analysis"""
    task_id = os.environ.get("TASK_ID")
    if not task_id:
        print("Warning: TASK_ID environment variable not set")
        return []

    # Find the actual task directory
    task_dir = find_task_directory(task_id)
    if not task_dir:
        print(f"Could not find task directory for task_id {task_id}")
        return []

    # Run analysis if results don't exist
    if use_qx:
        results_file = os.path.join(task_dir, f"{focus}_qx.json")
    else:
        results_file = os.path.join(task_dir, f"{focus}.json")

    if not os.path.exists(results_file):
        print(f"[try 1/1] Running local static analysis for {focus}")
        print(f"  task_id: {task_id}")
        print(f"  task_dir: {task_dir}")
        print(f"  fuzzer_source_path: {fuzzer_src_path}")

        success = run_static_analysis_local(task_id, task_dir, focus)
        if not success:
            print("Failed to run static analysis")
            return []

        # Wait for results
        import time
        time.sleep(2)

    # Load results
    if use_qx:
        results = load_qx_analysis_results(task_id, focus, task_dir)
        if results:
            reachable_funcs = get_reachable_functions_qx(fuzzer_src_path, results)
            return reachable_funcs
    else:
        # For non-QX, load regular results
        if os.path.exists(results_file):
            import json
            with open(results_file, 'r') as f:
                results = json.load(f)

            # Normalize fuzzer path
            fuzzer_key = fuzzer_src_path.replace(os.sep, '/')
            entry_point = f"{fuzzer_key}.fuzzerTestOneInput" if fuzzer_src_path.endswith('.java') else f"{fuzzer_key}.LLVMFuzzerTestOneInput"

            reachable_names = results.get('reachable', {}).get(entry_point, [])
            functions_map = results.get('functions', {})

            reachable_funcs = []
            for func_name in reachable_names:
                func_def = functions_map.get(func_name, {})
                reachable_funcs.append({
                    'name': func_def.get('Name', func_name),
                    'file_path': func_def.get('FilePath', ''),
                    'start_line': func_def.get('StartLine', 0),
                    'end_line': func_def.get('EndLine', 0),
                    'body': func_def.get('SourceCode', '')  # Use 'body' for consistency
                })
            return reachable_funcs

    return []



def extract_vulnerable_functions(reachable_funcs, vulnerable_functions, limit=10):
    """
    reachable_funcs      - list[dict]  each with Name/body/…
    vulnerable_functions - list[dict]  each with "name" (plus score, reason…)
    Returns a filtered list (≤ limit) containing only the vulnerable funcs.
    """
    if not vulnerable_functions:
        # nothing to filter by → return at most `limit` reachables
        return reachable_funcs[:limit]

    # Take the top `limit` vulnerable names
    top_names = [
        (vf.get("name") or vf.get("Name") or "").strip()
        for vf in vulnerable_functions[:limit]
    ]
    wanted = {name for name in top_names if name}

    filtered = []
    for f in reachable_funcs:
        name = (f.get("name") or f.get("Name") or "").strip()
        if name in wanted:
            filtered.append(f)

    return filtered

def create_target_functions_prompt(reachable_funcs,language,
        max_func_lines: int = 500,  # Limit lines per function
) -> str:

    if len(reachable_funcs) == 0:
        return ""

    entrypoint = "fuzzerTestOneInput"
    if language.startswith('c'):
        entrypoint = "LLVMFuzzerTestOneInput"

    func_snippets = []
    included_funcs = 0

    for f in reachable_funcs:

        name = f.get("name") or f.get("Name") or "<unknown>"
        body = (f.get("body") or f.get("Body") or
                f.get("sourceCode") or f.get("SourceCode") or "")
        
        lines = body.splitlines()
        if len(lines) > max_func_lines:
            body = "\n".join(lines[:max_func_lines]) + f"\n... (truncated, total {len(lines)} lines)"
        
        snippet = f"### Function: {name}\n```{language}\n{body}\n```"
        func_snippets.append(snippet)
        included_funcs += 1

    funcs_block = "\n\n".join(func_snippets) if func_snippets else "<call-graph unavailable>"

    return f"""
We have pre-analyzed the call-graph. The entry point is `{entrypoint}`.
Below are {included_funcs} reachable functions that might be risky (limited to {max_func_lines} lines each):

{funcs_block}
"""


def create_full_scan_prompt(
        fuzzer_code: str,
        sanitizer: str,
        language: str,
        reachable_funcs: list[dict] | None = None,
        vulnerable_funcs: list[dict] | None = None,
        max_blob_mb: int = 2,
        max_total_funcs: int = 20,  # Limit total number of functions included
        max_func_lines: int = 500,  # Limit lines per function
) -> str:
    """
    Build a rich prompt for FULL_SCAN mode with improved readability and size control.
    """

    base_prompt = f"""
You are an elite software-vulnerability researcher.
The target binary is built with sanitizers; your goal is to craft **input(s)**
that crash the program (ASan/MSan/UBSan/Jazzer, etc.). The harness that feeds
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
        func_snippets = []
        included_funcs = 0
        skipped_funcs = 0

        for f in reachable_funcs:
            if included_funcs >= max_total_funcs:
                skipped_funcs += 1
                continue

            name = f.get("name") or f.get("Name") or "<unknown>"
            body = (f.get("body") or f.get("Body") or
                    f.get("sourceCode") or f.get("SourceCode") or "")
            
            lines = body.splitlines()
            if len(lines) > max_func_lines:
                body = "\n".join(lines[:max_func_lines]) + f"\n... (truncated, total {len(lines)} lines)"
            
            snippet = f"### Function: {name}\n```{language}\n{body}\n```"
            func_snippets.append(snippet)
            included_funcs += 1

        funcs_block = "\n\n".join(func_snippets) if func_snippets else "<call-graph unavailable>"

        base_prompt += f"""
We have pre-analyzed the call-graph. The entry point is `{entrypoint}`.
Below are {included_funcs} reachable functions that might be risky (limited to {max_func_lines} lines each):

{funcs_block}
"""

        if skipped_funcs > 0:
            base_prompt += f"\n(Note: {skipped_funcs} additional functions were skipped to limit prompt size.)\n"

    if vulnerable_funcs:
        vf_lines = []
        for vf in vulnerable_funcs:
            name = vf.get("name") or vf.get("Name") or "<unknown>"
            reason = vf.get("reason", "").strip()
            vf_lines.append(f"- **{name}**: {reason}")
        vf_block = "\n".join(vf_lines)

        base_prompt += f"""
### Vulnerability Heuristics
Static analysis identified these functions as particularly risky:

{vf_block}
"""

    # Sanitizer guidance (C/C++)
    if language.startswith('c'):
        san_guide = {
            "address": (
                "AddressSanitizer reports buffer overflows, use-after-free, "
                "double-free, etc. Classic triggers:\n"
                "- Oversized length fields\n"
                "- Negative indices casted to large unsigned values\n"
                "- Strings without null-terminators\n"
            ),
            "memory": (
                "MemorySanitizer flags reads of uninitialized memory. Classic triggers:\n"
                "- Partially initialized structs\n"
                "- Checksum fields that skip bytes\n"
            ),
            "undefined": (
                "UndefinedBehaviorSanitizer catches UB: integer overflow, "
                "division by zero, invalid shift, misaligned pointers, etc.\n"
                "Classic triggers: 0-byte allocations, INT_MAX+1 lengths, "
                "null dereferences, etc.\n"
            ),
        }.get(sanitizer.lower(), "")
        language_block = f"""
### Sanitizer Focus ({sanitizer})
{san_guide}

### Recommended Plan
1. Map input bytes → parser structure (see harness).
2. Identify a vulnerable target function.
3. Craft input to reach and exploit it.
4. Clearly comment your reasoning before writing code.
"""
    else:  # Java / Jazzer
        language_block = """
### Jazzer Focus
Aim to trigger vulnerabilities such as deserialization-based RCE, regex DoS, path traversal,
reflection misuse, SQL/LDAP/XPath injection, or simply crash with an exception
(NullPointerException, ArrayIndexOutOfBounds, etc.).
"""

    ending = f"""
### Deliverable
- Produce a **single Python 3 script** that writes **x.bin** (binary mode).
- If multiple candidate payloads exist, emit them all (x1.bin, x2.bin, ..., x5.bin, at most five).
- Max size per blob: **{max_blob_mb} MiB**.
- Include a concise header comment explaining the vulnerability.

Write nothing except the Python script (with embedded comments).
"""

    return base_prompt + language_block + ending


# Helper function to extract vulnerabilities from SARIF data (similar to analyzeSarifVulnerabilities in Go)
def extract_vulnerabilities(sarif_broadcast):
    """
    Extract vulnerabilities from a SARIF broadcast.
    
    Args:
        sarif_broadcast (dict): The SARIF broadcast
        
    Returns:
        list: A list of vulnerability dictionaries
    """
    vulnerabilities = []
    
    sarif_data = sarif_broadcast.get("sarif", {})
    
    # Extract runs from SARIF data
    runs = sarif_data.get("runs", [])
    if not runs:
        logging.warning("No runs found in SARIF data")
        return vulnerabilities
    
    # Process each run
    for run in runs:
        # Extract results from run
        results = run.get("results", [])
        
        # Get the rules from the run to look up detailed info
        rule_metadata = {}
        if "tool" in run and "driver" in run["tool"] and "rules" in run["tool"]["driver"]:
            for rule in run["tool"]["driver"]["rules"]:
                if "id" in rule:
                    rule_metadata[rule["id"]] = rule
        
        # Process each result
        for result in results:
            try:
                # Extract basic info
                rule_id = result.get("ruleId", "unknown")
                
                # Get rule info
                rule_info = rule_metadata.get(rule_id, {})
                
                # Extract description
                description = ""
                if "message" in result:
                    if "text" in result["message"]:
                        description = result["message"]["text"]
                
                # Extract severity
                severity = "unknown"
                if "level" in result:
                    severity = result["level"]
                elif "properties" in rule_info and "security-severity" in rule_info["properties"]:
                    severity = rule_info["properties"]["security-severity"]
                
                # Extract location
                location = {
                    "file_path": "",
                    "start_line": 0,
                    "end_line": 0,
                    "start_col": 0,
                    "end_col": 0
                }
                
                if "locations" in result and len(result["locations"]) > 0:
                    loc = result["locations"][0]
                    if "physicalLocation" in loc:
                        physical = loc["physicalLocation"]
                        if "artifactLocation" in physical and "uri" in physical["artifactLocation"]:
                            location["file_path"] = physical["artifactLocation"]["uri"]
                        
                        if "region" in physical:
                            region = physical["region"]
                            location["start_line"] = region.get("startLine", 0)
                            location["end_line"] = region.get("endLine", location["start_line"])
                            location["start_col"] = region.get("startColumn", 0)
                            location["end_col"] = region.get("endColumn", 0)
                
                # Extract code flows
                code_flows = []
                if "codeFlows" in result:
                    for flow in result["codeFlows"]:
                        thread_flows = []
                        if "threadFlows" in flow:
                            for thread_flow in flow["threadFlows"]:
                                thread_locs = []
                                if "locations" in thread_flow:
                                    for loc in thread_flow["locations"]:
                                        if "location" in loc and "physicalLocation" in loc["location"]:
                                            physical = loc["location"]["physicalLocation"]
                                            file_path = ""
                                            if "artifactLocation" in physical and "uri" in physical["artifactLocation"]:
                                                file_path = physical["artifactLocation"]["uri"]
                                            
                                            start_line = 0
                                            end_line = 0
                                            if "region" in physical:
                                                region = physical["region"]
                                                start_line = region.get("startLine", 0)
                                                end_line = region.get("endLine", start_line)
                                            
                                            message = ""
                                            if "message" in loc["location"] and "text" in loc["location"]["message"]:
                                                message = loc["location"]["message"]["text"]
                                            
                                            thread_locs.append({
                                                "file_path": file_path,
                                                "start_line": start_line,
                                                "end_line": end_line,
                                                "message": message
                                            })
                                
                                thread_flows.append({"locations": thread_locs})
                        
                        code_flows.append({"thread_flows": thread_flows})
                
                # Create the vulnerability
                vulnerability = {
                    "rule_id": rule_id,
                    "description": description,
                    "severity": severity,
                    "location": location,
                    "code_flows": code_flows
                }
                
                vulnerabilities.append(vulnerability)
                
            except Exception as e:
                logging.error(f"Error extracting vulnerability from result: {e}")
                continue
    
    logging.info(f"Extracted {len(vulnerabilities)} vulnerabilities from SARIF data")
    return vulnerabilities

# Function to display vulnerability details (similar to showVulnerabilityDetail in Go)
def show_vulnerability_details(task_id, vulnerabilities):
    """
    Display details of the vulnerabilities extracted from SARIF data.
    
    Args:
        task_id (str): The task ID
        vulnerabilities (list): The list of vulnerabilities
    """
    for i, vuln in enumerate(vulnerabilities):
        logging.info(f"Vulnerability {i+1} details for task {task_id}:")
        logging.info(f"  - Rule ID: {vuln['rule_id']}")
        logging.info(f"  - Description: {vuln['description']}")
        logging.info(f"  - Severity: {vuln['severity']}")
        
        # Print location information
        loc = vuln['location']
        logging.info(f"  - Location: {loc['file_path']} (lines {loc['start_line']}-{loc['end_line']}, columns {loc['start_col']}-{loc['end_col']})")
        
        # Print code flows if available
        if vuln['code_flows']:
            logging.info("  - Code Flows:")
            for i, flow in enumerate(vuln['code_flows']):
                logging.info(f"    - Flow #{i+1}:")
                for j, thread_flow in enumerate(flow['thread_flows']):
                    logging.info(f"      - Thread Flow #{j+1}:")
                    for k, loc in enumerate(thread_flow['locations']):
                        logging.info(f"        - Step {k+1}: {loc['file_path']} (lines {loc['start_line']}-{loc['end_line']}) - {loc['message']}")
        
        logging.info("  -----------------------------")

def doSarifPoV(log_file, sarif_broadcast, fuzzer_src_path, fuzzer_code, fuzzer_path, fuzzer_name, sanitizer, project_dir, project_name, focus, reachable_targets, language='c', check_patch_success=False) -> bool:
    log_message(log_file, f"POV_PHASE: {POV_PHASE} doSarifPoV") 
    project_src_dir = os.path.join(project_dir, focus+"-"+sanitizer) 
    commit_diff = ""
    pov_success = False
    pov_metadata = {}
    if POV_PHASE == 0:
        # reachable targets prompts
        initial_msg = create_full_scan_prompt(
            fuzzer_code,
            sanitizer,
            language,
            reachable_targets,
        )
        print(f"initial_msg: {initial_msg}")
        return doAdvancedPoV0(log_file,initial_msg,fuzzer_path,fuzzer_name,sanitizer,project_dir,project_name,focus,language, check_patch_success)
    elif POV_PHASE == 1:
        vulnerabilities = extract_vulnerabilities(sarif_broadcast)
        target_functions_prompt = create_target_functions_prompt(reachable_targets,language)
        # print(f"[DEBUG] target_functions_prompt: {target_functions_prompt}")

        if language.startswith('c'):
            for i, vuln in enumerate(vulnerabilities):
                print(f"[DEBUG] Processing vulnerability {i}: {vuln}")
                category = vuln.get('rule_id', '')
                print(f"[DEBUG] Extracted category: {category}")
                if category.startswith('CWE-') and category in vul_categories_c:
                    initial_msg = create_commit_vul_category_based_prompt_for_c(project_name,fuzzer_code, target_functions_prompt,sanitizer, category)
                    print(f"vul_category_c: {category} initial_msg: {initial_msg}")
                    pov_success, pov_metadata = doAdvancedPoV0(log_file,initial_msg,fuzzer_path,fuzzer_name,sanitizer,project_dir,project_name,focus,language, check_patch_success)
                    if pov_success:
                        log_message(log_file, f"category: {category} pov_success: {pov_success}") 
                        break
        else:
            for i, vuln in enumerate(vulnerabilities):
                print(f"[DEBUG] Processing vulnerability {i}: {vuln}")
                category = vuln.get('rule_id', '')
                print(f"[DEBUG] Extracted category: {category}")
                if category.startswith('CWE-') and category in vul_categories_java:
                    initial_msg = create_commit_vul_category_based_prompt_for_java(project_name,fuzzer_code, target_functions_prompt,sanitizer, category)
                    print(f"vul_category_java: {category} initial_msg: {initial_msg}")
                    pov_success, pov_metadata = doAdvancedPoV0(log_file,initial_msg,fuzzer_path,fuzzer_name,sanitizer,project_dir,project_name,focus,language, check_patch_success)
                    if pov_success:
                        log_message(log_file, f"category: {category} pov_success: {pov_success}") 
                        break
        return pov_success, pov_metadata
    elif POV_PHASE == 2:
        target_functions = covert_target_functions_format(reachable_targets)
        call_paths = extract_call_paths_from_analysis_service(project_name,fuzzer_path,fuzzer_src_path,focus,project_src_dir,target_functions,False) 
        # Debug: print all call paths
        print(f"[DEBUG] Extracted {len(call_paths)} call paths:")
        for idx, path in enumerate(call_paths):
            print(f"[DEBUG] Call path {idx}: {path}")

        # just for testing
        # call_paths = TEST_CALL_PATHS
        # for each call path, doPOV
        MAX_CALL_PATHS = 10
        if len(call_paths) > MAX_CALL_PATHS:
            log_message(log_file, f"Too many call paths ({len(call_paths)}), limiting to first {MAX_CALL_PATHS}")
            call_paths = call_paths[:MAX_CALL_PATHS]

        for call_path in call_paths:
            # construct initial_msg from fuzzer_code commit_diff and modified_functions
            initial_msg = create_commit_call_paths_based_prompt(project_name,fuzzer_code, commit_diff, project_src_dir,call_path,sanitizer,language)
            line_count = initial_msg.count('\n') + 1
            char_length = len(initial_msg)
            print(f"initial_msg: {line_count} lines, {char_length} characters")
            print(f"{initial_msg}")
            pov_success, pov_metadata = doAdvancedPoV0(log_file,initial_msg,fuzzer_path,fuzzer_name,sanitizer,project_dir,project_name,focus,language, check_patch_success)
            if pov_success:
                log_message(log_file, f"pov_success: {pov_success} pov_metadata: {pov_metadata}\ncall_path: {call_path}") 
                break

        return pov_success, pov_metadata
    
    else:
        log_message(log_file, f"POV_PHASE: {POV_PHASE} doAdvancedPoV does not exist") 
    
    return pov_success, pov_metadata


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

        if not file_path or not name:
            continue  # Skip incomplete entries

        if file_path not in simplified_modified_functions:
            simplified_modified_functions[file_path] = []

        simplified_modified_functions[file_path].append({
            "name": name,
            "start_line": start_line
        })

    return simplified_modified_functions

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

def get_target_functions(log_file, context_info: str, crash_log: str, model_name):
    prompt = f"""
Your task is to identify all potentially vulnerable functions from a code commit and a crash log.

Background:
- The commit introduces a vulnerability.
- The vulnerability is found by an expert, with a crash log.

CONTEXT INFORMATION (the conversation history with the vulnerability detection expert)
{context_info}

CRASH LOG (this vulnerability has been found with a test):
{crash_log}

Based on the above information, please extract *all potentially* vulnerable functions in JSON format, e.g.,
{{
    "file_path1":"func_name1",
    ...
}}

ONLY return the JSON, no comments, and nothing else.
"""
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
    
    target_functions = []
    for file_path, function_name in parsed.items():
        # strip OSS_FUZZ_ from function_name if exists
        # e.g., OSS_FUZZ_png_handle_iCCP -> png_handle_iCCP
        if function_name.startswith("OSS_FUZZ_"):
            function_name = function_name[9:] 
        target_functions.append(f"{file_path}:{function_name}")
    
    log_message(log_file, f"Extracted target functions: {target_functions}")
    
    return target_functions

import clang.cindex
# Try to set the library path explicitly
clang.cindex.Config.set_library_file('/usr/lib/llvm18/lib/libclang.so')



def create_commit_based_prompt(project_name,fuzzer_code, commit_diff, sanitizer, language):
    # Base prompt that applies to all languages
    base_prompt = f"""
You are a top software vulnerability detection expert, which helps to find vulnerabilities. 
The {project_name} project contains a vulnerability introduced by a commit. Your job is to find the correct input to trigger the vulnerability.

Please output a Python script that creates five blob files (name as xi.bin with i=1..5). Each blob file will be run by this fuzzer code:
```{language}
{fuzzer_code}
```

"""

    # C/C++ specific prompt with sanitizer targeting
    if language.startswith('c'):
        # Define sanitizer-specific guidance
        sanitizer_guidance = {
            "address": """
The project uses AddressSanitizer, which detects:
- Buffer overflows (stack, heap, global)
- Use-after-free errors
- Use-after-scope bugs
- Double-free errors

Your goal is to trigger an AddressSanitizer error by crafting an input that exploits the vulnerability.
""",
            "memory": """
The project uses MemorySanitizer, which detects:
- Uninitialized memory reads
- Use of uninitialized values in conditional operations
- Passing uninitialized values to library functions

Your goal is to trigger a MemorySanitizer error by crafting an input that causes the program to use uninitialized memory.
""",
            "undefined": """
The project uses UndefinedBehaviorSanitizer, which detects:
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
The project uses sanitizers that can detect various types of errors. Your goal is to trigger a sanitizer error by crafting an input that exploits the vulnerability.
""")
        
        language_specific = f"""
IMPORTANT: Read the harness code carefully to understand how inputs are processed. In each xi.bin, you need to generate a complete blob that will trigger a sanitizer error.

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
IMPORTANT: Read the harness code carefully to understand how inputs are processed. In each xi.bin, you need to generate a complete blob that will trigger a Jazzer sanitizer error or Java exception.

Think through these steps:
1. What method contains the vulnerability? How do you reach this method?
2. What input will trigger the vulnerability?
3. Are there any other inputs required before reaching the target method?
4. How does the harness code process inputs? Follow the instructions in the harness.
5. Combine all this information to generate a complete blob.

The project uses Jazzer sanitizers that can detect various types of vulnerabilities:
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
- SQLInjection: detects SQL injection
- XPathInjection: detects XPath injection

Your goal is to trigger any of these sanitizer errors or a Java exception (like NullPointerException, ArrayIndexOutOfBoundsException, etc.) by crafting an input that exploits the vulnerability.
"""

    # Common ending for both languages
    ending = """
Limit the blob size to 2MiB max

Your output must be a single Python script that creates five files named exactly x1.bin, x2.bin, x3.bin, x4.bin, and x5.bin. Each file should include a brief description of the targeted vulnerability and the function it affects. The vulnerability can be challenging to trigger, so diversify the contents of the .bin files to maximize the likelihood of success. It's acceptable if only one of the files successfully triggers the vulnerability.
"""

    # Combine the parts to create the final prompt
    return base_prompt +commit_diff+ language_specific + ending


def strip_comments_and_license(source_code, file_path):
    """
    Strip comments and license headers from source code.
    
    Args:
        source_code (str): The raw source code
        file_path (str): Path to the source file (used to determine language)
        
    Returns:
        str: The source code with comments and license headers removed
    """    
    # Identify the language from file extension
    if file_path.endswith('.java'):
        # 1. Remove license header (typically a multi-line comment at the top)
        # Look for the first multi-line comment that contains typical license keywords
        license_pattern = r'^\s*/\*.*?(?:license|copyright|apache|mit|gpl|bsd|gnu).*?\*/\s*'
        source_code = re.sub(license_pattern, '', source_code, flags=re.IGNORECASE | re.DOTALL)
        
        # 2. Remove all multi-line comments
        source_code = re.sub(r'/\*.*?\*/', '', source_code, flags=re.DOTALL)
        
        # 3. Remove all single-line comments
        source_code = re.sub(r'//.*?$', '', source_code, flags=re.MULTILINE)
    
    elif file_path.endswith(('.c', '.cpp', '.h', '.hpp')):
        # 1. Remove license header (typically a multi-line comment at the top)
        license_pattern = r'^\s*/\*.*?(?:license|copyright|apache|mit|gpl|bsd|gnu).*?\*/\s*'
        source_code = re.sub(license_pattern, '', source_code, flags=re.IGNORECASE | re.DOTALL)
        
        # 2. Remove all multi-line comments
        source_code = re.sub(r'/\*.*?\*/', '', source_code, flags=re.DOTALL)
        
        # 3. Remove all single-line comments
        source_code = re.sub(r'//.*?$', '', source_code, flags=re.MULTILINE)
        
    elif file_path.endswith('.py'):
        # 1. Remove module docstring (license often goes here)
        source_code = re.sub(r'^\s*""".*?"""\s*', '', source_code, flags=re.DOTALL)
        source_code = re.sub(r"^\s*'''.*?'''\s*", '', source_code, flags=re.DOTALL)
        
        # 2. Remove all # comments
        source_code = re.sub(r'#.*?$', '', source_code, flags=re.MULTILINE)
        
    # 4. Remove excessive blank lines (more than 2 consecutive)
    source_code = re.sub(r'\n{3,}', '\n\n', source_code)
    
    return source_code

def create_commit_call_paths_based_prompt(project_name,fuzzer_code, commit_diff, project_src_dir, main_call_path, sanitizer, language):
    """
    Create a prompt focused on call path.
    
    Args:
        fuzzer_code (str): The fuzzer code that found the issue
        commit_diff (str): The commit diff as a string
        project_src_dir (str): Path to the project source directory
        main_call_path: a list of function info dictionaries
        sanitizer (str): The sanitizer used (e.g., 'address', 'undefined')
        language (str): The programming language
        
    Returns:
        str: A prompt focused on the modified functions
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
        
        # Only show code for non-empty function bodies
        if function_body.strip():
            lines = function_body.strip().splitlines()
            if len(lines) > 100:
                function_body_text = "\n".join(lines[:100]) + "\n... (truncated for brevity)"
            else:
                function_body_text = "\n".join(lines)
            call_path_info += (
                f"- **Code**:\n```{language.lower()}\n"
                f"{function_body_text}\n```\n\n"
            )
        else:
            call_path_info += f"- **Code**: (not available)\n\n"
  
    # Combine the modified functions info with the commit diff
    enriched_commit_diff = f"{commit_diff}\n\n{call_path_info}"
    
    # Create the final prompt using the base function
    return create_commit_based_prompt(project_name,fuzzer_code, enriched_commit_diff, sanitizer, language)
    

def create_commit_combine_all_call_paths_based_prompt(project_name,fuzzer_code, commit_diff, project_src_dir, call_paths, sanitizer, language):

    call_path_info = "# Vulnerability Call Paths\n\n"
    call_path_info += "Some of the following call paths lead to the vulnerability:\n\n"
     
    # Process each call path
    for path_index, call_path in enumerate(call_paths):
        # Skip empty call paths
        if not call_path:
            continue
            
        call_path_info += f"## Call Path {path_index + 1}\n\n"
        
        # Create a visual representation of the call path
        call_path_info += "```\n"
        
        for i, node_data in enumerate(call_path):
            function_name = node_data.get('function', 'unknown')
            file_name = os.path.basename(node_data.get('file', 'unknown'))
            is_modified = node_data.get('is_modified', False)

            prefix = "→ " if i > 0 else ""
            highlight = "**" if is_modified else ""
            
            call_path_info += f"{prefix}{highlight}{function_name}(){highlight} ({file_name})\n"
            
            if i < len(call_path) - 1:
                call_path_info += "    |\n    ↓\n"
        
        call_path_info += "```\n\n"

    call_path_info += "### Function Details\n\n"

    displayed_functions = set()
    for path_index, call_path in enumerate(call_paths):
        # Add detailed information about each function in the call path
        k = 0
        for i, node_data in enumerate(call_path):
            k = k+1
            file_path = node_data.get('file', 'unknown')
            function_name = node_data.get('function', 'unknown')
            function_body = node_data.get('body', '')
            is_modified = node_data.get('is_modified', False)
            
            # Create a unique function identifier combining file and function name
            function_id = f"{file_path}:{function_name}"
            
            # Skip if this function has already been displayed
            if function_id in displayed_functions:
                continue

            displayed_functions.add(function_id)

            # Add information about whether this function was modified
            modification_status = " (**MODIFIED in commit**)" if is_modified else ""
            
            call_path_info += f"{k}. {function_name}{modification_status}\n"
            call_path_info += f"- **File**: {file_path}\n"
            
            # Skip showing code for fuzzer entry points
            if function_name == "fuzzerTestOneInput" or function_name == "LLVMFuzzerTestOneInput":
                call_path_info += "\n"
                continue
            
            # Only show code for non-empty function bodies
            if function_body and function_body.strip():
                # Truncate very long function bodies
                lines = function_body.strip().splitlines()
                if len(lines) > 100:
                    function_body_text = "\n".join(lines[:100]) + "\n... (truncated for brevity)"
                else:
                    function_body_text = "\n".join(lines)
                
                call_path_info += f"- **Code**:\n```{language.lower()}\n{function_body_text}\n```\n\n"
            else:
                call_path_info += f"- **Code**: (not available)\n\n"
        
    # Add a separator between call paths
    if path_index < len(call_paths) - 1:
        call_path_info += "---\n\n"

    # Combine the call path info with the commit diff
    enriched_commit_diff = f"{commit_diff}\n\n{call_path_info}"
    # Create the final prompt using the base function
    return create_commit_based_prompt(project_name,fuzzer_code, enriched_commit_diff, sanitizer, language)


def create_commit_vul_category_based_prompt_for_c(project_name,fuzzer_code, target_functions_prompt, sanitizer, category):
    category_desc = {
        "CWE-119": "Buffer Overflow - Writing or reading beyond buffer boundaries",
        "CWE-416": "Use After Free - Referencing memory after it has been freed",
        "CWE-476": "NULL Pointer Dereference - Dereferencing a null pointer",
        "CWE-190": "Integer Overflow - Arithmetic operations exceeding integer bounds",
        "CWE-122": "Heap-based Buffer Overflow - Overflow of heap-allocated memory",
        "CWE-787": "Out-of-bounds Write - Writing beyond array boundaries",
        "CWE-125": "Out-of-bounds Read - Reading beyond array boundaries",
        "CWE-134": "Format String - Uncontrolled format string vulnerabilities",
        "CWE-401": "Memory Leak - Failure to free allocated memory",
        "CWE-121": "Stack-based Buffer Overflow - Writing outside the bounds of a stack-allocated buffer",
        "CWE-369": "Divide by Zero - Division or modulo by zero"
    }.get(category, "Unknown vulnerability type")

    # Base prompt that applies to all languages
    base_prompt = f"""
You are a top software vulnerability detection expert, which helps to find vulnerabilities, in particular, {category_desc} in C code.
The {project_name} project contains a vulnerability introduced by a commit. Your job is to find the correct input to trigger the vulnerability.

Please output a Python script that creates five blob files (name as xi.bin with i=1..5). Each blob file will be run by this fuzzer code:
{fuzzer_code}

"""

    sanitizer_guidance = {
        "address": {
            "CWE-119": """
The project uses AddressSanitizer which is excellent for detecting buffer overflows:
- Stack buffer overflow (both read and write)
- Heap buffer overflow (both read and write)
- Global buffer overflow
- Buffer overflow in C++ containers
Focus on:
1. Writing/reading beyond array bounds
2. Off-by-one errors
3. Stack buffer overruns
4. Heap buffer overruns""",
            
            "CWE-416": """
The project uses AddressSanitizer which is specifically designed to catch Use-After-Free bugs:
- Use of freed heap memory
- Use of stack memory after function return
- Use of stack memory after scope exit
Focus on:
1. Double-free scenarios
2. Accessing freed memory
3. Dangling pointers
4. Memory reuse patterns""",
            
            "CWE-476": """
The project uses AddressSanitizer which can detect NULL pointer dereferences:
- Direct NULL pointer access
- Access through NULL pointer arithmetic
Focus on:
1. Function pointers that could be NULL
2. Uninitialized pointer access
3. Error conditions leading to NULL""",
            
            "DEFAULT": """
AddressSanitizer is active and can detect:
- Buffer overflows (stack, heap, global)
- Use-after-free errors
- Use-after-return and use-after-scope
- Memory leaks
- Double-free and invalid-free
- Initialization order bugs
Focus on memory corruption scenarios."""
        },
        "undefined": {
            "CWE-190": """
The project uses UndefinedBehaviorSanitizer which excels at detecting integer-based issues:
- Signed integer overflow
- Unsigned integer wraparound
- Integer division overflow
- Conversion between types
Focus on:
1. Large integer calculations
2. Sign conversion edge cases
3. Array index calculations
4. Memory allocation sizes""",
            "CWE-121": """
The project uses AddressSanitizer which is highly effective at detecting stack-based buffer overflows:
- Writing past the end of a local (stack) array
- Overwriting stack variables or return addresses
- Corrupting control data on the stack

Focus on:
1. Functions that use fixed-size local arrays (e.g., char buf[128])
2. Unsafe string or memory operations (e.g., strcpy, strcat, sprintf, memcpy, gets)
3. Loops or functions that write to buffers without proper bounds checking
4. User-controlled input copied to stack buffers
5. Recursion or deep call stacks that may lead to stack exhaustion

Edge cases:
- Off-by-one errors in loops
- Calculating buffer sizes incorrectly
- Mixing up buffer sizes and input lengths""",
            "CWE-369": """
The project uses UndefinedBehaviorSanitizer which catches division by zero:
- Integer division by zero
- Floating-point division by zero
- Modulo by zero
Focus on:
1. User-controlled divisors
2. Error conditions leading to zero
3. Integer overflow leading to zero
4. Edge cases in calculations""",
            
            "DEFAULT": """
UndefinedBehaviorSanitizer is active and detects:
- Integer overflow/underflow
- Misaligned pointer dereference
- NULL pointer dereference
- Shift-base/exponent overflow
- Division by zero
- Invalid enum values
- Floating-point errors
- Invalid boolean values
Focus on undefined behavior scenarios."""
        },
        "memory": {
            "CWE-457": """
The project uses MemorySanitizer which specializes in uninitialized memory usage:
- Reading uninitialized stack variables
- Using uninitialized heap memory
- Passing uninitialized values to system calls
Focus on:
1. Variables used before initialization
2. Partial structure initialization
3. Complex data structure handling
4. Error paths skipping initialization""",
            
            "CWE-125": """
The project uses MemorySanitizer which can detect reads from uninitialized memory:
- Out-of-bounds reads leading to uninitialized data
- Use of uninitialized values in conditions
- Propagation of uninitialized values
Focus on:
1. Buffer boundary conditions
2. Array access patterns
3. String operations
4. Memory copying functions""",
            
            "DEFAULT": """
MemorySanitizer is active and detects:
- Use of uninitialized memory
- Use of uninitialized bits in partially initialized values
- Propagation of uninitialized values through memory and arithmetic operations
- Use of uninitialized values in conditional operations
Focus on uninitialized memory scenarios."""
        }
    }
        
    # Get sanitizer-specific guidance based on both sanitizer and CWE
    sanitizer_specific = sanitizer_guidance.get(sanitizer.lower(), {}).get(category, 
                        sanitizer_guidance.get(sanitizer.lower(), {}).get("DEFAULT", 
                        "The project uses sanitizers to detect various types of errors."))

    language_specific = f"""
IMPORTANT: Read the harness code carefully to understand how inputs are processed. In each xi.bin, you need to generate a complete blob that will trigger a sanitizer error.

Think through these steps:
1. What function contains the vulnerability? How do you reach this function?
2. What input will trigger the vulnerability?
3. Are there any other inputs required before reaching the target function?
4. How does the harness code process inputs? Follow the instructions in the harness.
5. Combine all this information to generate a complete blob.

{sanitizer_specific}

For this specific vulnerability category ({category}), consider:
1. What input patterns typically trigger this type of vulnerability?
2. How can you craft inputs that bypass normal validation?
3. What edge cases might the code not handle properly?
4. Are there specific size or value boundaries to test?


"""

    ending = """
Limit the blob size to 2MiB max

Your output must be a single Python script that creates five files named exactly x1.bin, x2.bin, x3.bin, x4.bin, and x5.bin. Each file should include a brief description of the targeted vulnerability and the function it affects. The vulnerability can be challenging to trigger, so diversify the contents of the .bin files to maximize the likelihood of success. It's acceptable if only one of the files successfully triggers the vulnerability.
"""

    # Combine the parts to create the final prompt
    return base_prompt + language_specific +target_functions_prompt+ ending


def create_commit_vul_category_based_prompt_for_java(project_name,fuzzer_code, target_functions_prompt, sanitizer, category):
    category_desc = {
        "CWE-601": "Path Traversal - Improper restriction of file path traversal",
        "CWE-22": "Path Traversal - Improper limitation of a pathname to a restricted directory",
        "CWE-77": "Command Injection - Improper neutralization of special elements in commands",
        "CWE-78": "OS Command Injection - Improper neutralization of special elements in OS commands",
        "CWE-918": "Server-Side Request Forgery (SSRF) - Improper control of server-side requests",
        "CWE-79": "Cross-Site Scripting (XSS) - Injection of malicious scripts",
        "CWE-89": "SQL Injection - Manipulation of SQL queries",
        "CWE-200": "Information Exposure - Leakage of sensitive information",
        "CWE-306": "Missing Authentication - Lack of proper authentication",
        "CWE-502": "Deserialization - Unsafe deserialization of data",
        "CWE-611": "XXE Processing - XML External Entity vulnerabilities",
        "CWE-776": "Recursive Entity References - XML entity expansion",
        "CWE-400": "Resource Consumption - Denial of service through resource exhaustion",
        "CWE-755": "Exception Handling - Improper exception handling",
        "CWE-347": "Cryptographic Verification - Improper verification of signatures"
    }.get(category, "Unknown vulnerability type")

    jazzer_guidance = {
        "CWE-79": {  # XSS
            "sanitizer": "ScriptEngineInjection",
            "guidance": """
The target uses Jazzer's ScriptEngineInjection sanitizer which detects:
- JavaScript injection vulnerabilities
- Template injection
- Expression evaluation issues
Focus on:
1. Malformed script inputs
2. JavaScript escape sequences
3. Template expression injection
4. Mixed content scenarios"""
        },
        "CWE-776": {  # XML Entity Expansion
            "sanitizer": "XPathInjection",
            "guidance": """
The target uses Jazzer's XPathInjection sanitizer which detects:
- XML entity expansion vulnerabilities
- Recursive entity references
- XML billion laughs attacks
- XML quadratic blowup attacks

Key focus areas:
1. XML entity definitions
2. Nested entity references
3. Recursive expansion patterns
4. DTD processing
5. XML parser configurations
6. Entity reference chains
7. Memory consumption patterns
8. Processing time attacks

Test cases should include:
1. Nested entity declarations
2. Recursive entity references
3. Large expansion ratios
4. Multiple reference layers
5. Mixed internal/external entities
6. Custom entity definitions
7. Complex expansion patterns
8. Memory exhaustion scenarios

Common attack patterns:
1. Billion laughs attack structure
2. Quadratic blowup patterns
3. Nested reference chains
4. Hybrid expansion techniques
5. Parser-specific triggers
6. Custom entity combinations
7. Resource consumption vectors
8. Processing loop triggers"""
        },
        "CWE-22": {  # Generic Path Traversal
            "sanitizer": "FilePathTraversal",
            "guidance": """
The target uses Jazzer's FilePathTraversal sanitizer which detects:
- Directory traversal across all file operations
- Path manipulation in system operations
- Resource access control bypass
- File system permission violations

Key focus areas:
1. File system operations
2. Resource loading and access
3. Path concatenation and normalization
4. Directory operations
5. File streams and channels
6. NIO operations
7. ClassLoader resource access
8. File permissions and security checks

Test cases should include:
1. Multiple path separator styles
2. Unicode normalization bypasses
3. Path canonicalization tricks
4. Directory climbing sequences
5. Relative path manipulation
6. Absolute path injection
7. Protocol handler abuse
8. Symbolic link following"""
        },
        "CWE-77": {  # Generic Command Injection
            "sanitizer": "OsCommandInjection",
            "guidance": """
The target uses Jazzer's OsCommandInjection sanitizer which detects:
- Command string manipulation
- Shell command construction
- Process builder vulnerabilities
- Runtime execution issues

Focus on:
1. Command string concatenation
2. Shell metacharacter injection
3. Environment variable manipulation
4. Process builder argument injection
5. Runtime.exec() abuse
6. Command chaining
7. Input parameter sanitization bypass
8. Shell interpreter tricks"""
        },        
        "CWE-918": {  # SSRF
            "sanitizer": "ServerSideRequestForgery",
            "guidance": """
The target uses Jazzer's ServerSideRequestForgery sanitizer which detects:
- URL manipulation in server requests
- Protocol handler abuse
- Network access control bypass
- Service endpoint manipulation

Key focus areas:
1. URL construction and parsing
2. HTTP client operations
3. Protocol switching (http/https/file/etc)
4. Hostname resolution
5. IP address validation
6. Port scanning attempts
7. Internal network access
8. Redirect handling

Test cases should include:
1. URL encoding variations
2. Protocol handler abuse
3. DNS rebinding scenarios
4. IP address formats
5. Localhost variations
6. Private network ranges
7. URL fragments and parameters
8. Redirect chains"""
        }, 
        "CWE-89": {  # SQL Injection
            "sanitizer": "SQLInjection",
            "guidance": """
The target uses Jazzer's SQLInjection sanitizer which detects:
- SQL query manipulation
- Prepared statement bypass
- SQL syntax injection
Focus on:
1. Query string manipulation
2. SQL metacharacters
3. Comment injection
4. Union-based injection patterns"""
        },
        "CWE-502": {  # Deserialization
            "sanitizer": "Deserialization",
            "guidance": """
The target uses Jazzer's Deserialization sanitizer which detects:
- Unsafe Java object deserialization
- Gadget chain exploitation
- Type confusion during deserialization
- File-based deserialization vulnerabilities

Focus on:
1. Serialized object manipulation
2. Class loading abuse
3. Deserialization hooks
4. ObjectInputStream usage

Additional focus on file-based attacks:
5. File-based object streams
6. Path traversal in deserialization
7. Temporary file manipulation"""
        },
        
        "CWE-611": {  # XXE
            "sanitizer": "XPathInjection",
            "guidance": """
The target uses Jazzer's XPathInjection sanitizer which detects:
- XML external entity processing
- XPath expression injection
- XML parser vulnerabilities
Focus on:
1. External entity declarations
2. XPath query manipulation
3. Document type definitions
4. Parser configuration abuse"""
        },
        "CWE-78": {  # Command Injection
            "sanitizer": "OsCommandInjection",
            "guidance": """
The target uses Jazzer's OsCommandInjection sanitizer which detects:
- Shell command injection
- Process execution vulnerabilities
- Command string manipulation
Focus on:
1. Command parameter injection
2. Shell metacharacters
3. Path traversal in commands
4. Environment variable manipulation"""
        },
        "CWE-601": {  # Path Traversal
            "sanitizer": "FilePathTraversal",
            "guidance": """
The target uses Jazzer's FilePathTraversal sanitizer which is critical for detecting:
- Directory traversal vulnerabilities
- Path manipulation attacks
- File access control bypass
- Archive extraction vulnerabilities

Common attack patterns this sanitizer detects:
1. Directory traversal sequences (../, ..\\, etc.)
2. Path normalization bypass attempts
3. URL-encoded traversal sequences (%2e%2e%2f)
4. Double-encoded traversal sequences
5. Mixed encoding attacks
6. Archive path traversal (Zip/Jar slip)
7. Symbolic link following
8. Null byte injection in paths

Focus on:
1. File operations (read, write, delete)
2. Archive handling (zip, jar, tar)
3. Resource loading (classpath, file system)
4. Web resource access
5. Configuration file paths
6. Template file inclusion
7. Log file paths
8. Temporary file creation

Test cases should include:
1. Various path traversal sequences
2. Different encoding combinations
3. Mixed forward/backward slashes
4. Path normalization edge cases
5. Archive file manipulation
6. Relative/absolute path mixing
7. URL-based file access
8. Resource loading scenarios"""
        },        
        "CWE-755": {  # Exception Handling
            "sanitizer": "ReflectiveCall",
            "guidance": """
The target uses Jazzer's ReflectiveCall sanitizer which can help detect:
- Unsafe reflection usage
- Exception-triggering inputs
- Type confusion issues
Focus on:
1. Reflection parameter manipulation
2. Class loading abuse
3. Method invocation patterns
4. Exception-triggering inputs"""
        },
        
        "CWE-400": {  # Resource Consumption
            "sanitizer": "RegexRoadblocks",
            "guidance": """
The target uses Jazzer's RegexRoadblocks sanitizer which detects:
- Regular expression DoS
- Catastrophic backtracking
- Resource exhaustion patterns
Focus on:
1. Complex regex patterns
2. Nested repetition
3. Large input strings
4. Backtracking triggers"""
        }
    }

    guidance = jazzer_guidance.get(category, {
        "sanitizer": "Multiple",
        "guidance": """
The target uses multiple Jazzer sanitizers that can detect:
- Unsafe deserialization (Deserialization)
- Expression injection (ExpressionLanguageInjection)
- Path traversal (FilePathTraversal)
- LDAP injection (LdapInjection)
- JNDI lookup abuse (NamingContextLookup)
- Command injection (OsCommandInjection)
- Unsafe reflection (ReflectiveCall)
- Regex vulnerabilities (RegexInjection, RegexRoadblocks)
- Script injection (ScriptEngineInjection)
- SSRF vulnerabilities (ServerSideRequestForgery)
- SQL injection (SQLInjection)
- XPath injection (XPathInjection)"""
    })

    base_prompt = f"""
You are a top software vulnerability detection expert, specializing in finding {category_desc} vulnerabilities in Java code.
The {project_name} project contains a vulnerability introduced by a commit. Your job is to find the correct input to trigger the vulnerability.

The target is specifically monitored by Jazzer's {guidance['sanitizer']} sanitizer.

{guidance['guidance']}

Please output a Python script that creates five blob files (name as xi.bin with i=1..5). Each blob file will be run by this fuzzer code:
{fuzzer_code}

"""
    strategy_guidance = """
IMPORTANT: When crafting your test cases, consider these strategies:
1. Start with valid inputs that reach the target code
2. Gradually mutate the inputs to trigger edge cases
3. Focus on boundary conditions and error paths
4. Try different encoding schemes
5. Combine multiple attack vectors
6. Test different input sizes and patterns

For each test case (x1.bin through x5.bin):
- Include a comment explaining the attack strategy
- Vary the approach between files
- Consider different trigger conditions
- Test both direct and indirect paths to the vulnerability


"""

    ending = """
Limit the blob size to 2MiB max

Your output must be a single Python script that creates five files named exactly x1.bin, x2.bin, x3.bin, x4.bin, and x5.bin. Each file should include a brief description of the targeted vulnerability and the method it affects. The vulnerability can be challenging to trigger, so diversify the contents of the .bin files to maximize the likelihood of success. It's acceptable if only one of the files successfully triggers the vulnerability.
"""

    return base_prompt + strategy_guidance +target_functions_prompt + ending

def create_fullscan_prompt(fuzzer_code: str, suspected_vuln: Dict[str, Any]) -> str:
    """Create a prompt for full scan based on suspected vulnerability."""
    file_path = suspected_vuln.get("filePath", "Unknown")
    model = suspected_vuln.get("model", "Unknown")
    snippet = suspected_vuln.get("snippet", "")
    vuln_details = suspected_vuln.get("llmRawMessage", "")

    return f"""
You are a top software vulnerability detection expert, which helps to find vulnerabilities. 
The code snippet below may contain a security vulnerability. Your job is to analyze the code and create an input that triggers the suspected vulnerability.

# Suspected Vulnerability Information
File: {file_path}
Potential vulnerability description: {vuln_details}

# Code Snippet
{snippet}


Please output a Python script that creates a x.bin file. Your blob file will be run by this fuzzer code:
{fuzzer_code}

Think through these steps:
1. Analyze the code for the vulnerability described
2. Identify how to reach and trigger the vulnerable code path
3. Understand the input processing in the harness
4. Generate inputs that will trigger the vulnerability

Limit the blob size to 2MiB max

Your output must be a Python script that creates a file named exactly "x.bin" with a detailed description of:
1. The vulnerability type
2. The target function/location
3. How your input triggers it
"""

def load_suspected_vulns(project_dir: str) -> List[Dict[str, Any]]:
    """Load suspected vulnerabilities from JSON file."""
    vuln_file = os.path.join(project_dir, "suspected_vulns.json")
    if not os.path.exists(vuln_file):
        return []
    
    try:
        with open(vuln_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading suspected_vulns.json: {str(e)}")
        return []


def process_full_scan(log_file, fuzzer_src_path, fuzzer_code, fuzzer_path, fuzzer_name, sanitizer, 
                     project_dir, project_name, focus, language, check_patch_success):
    """
    Process vulnerabilities in FULL_SCAN mode, handling incremental updates to suspected_vulns.json.
    
    Returns:
        bool: True if at least one PoV was successful, False otherwise.
    """
    log_message(log_file, "Running in FULL_SCAN mode")
    
    # Track processed vulnerabilities by ID to avoid duplicates
    processed_vulns = set()
    successful_povs = []
    
    # Create a function to generate a unique ID for each vulnerability
    def get_vuln_id(vuln):
        file_path = vuln.get('filePath', '')
        snippet = vuln.get('snippet', '')[:50]  # Use first 50 chars of snippet
        return f"{file_path}:{hash(snippet)}"
    
    # Function to load new vulnerabilities
    def load_new_vulns():
        all_vulns = load_suspected_vulns(project_dir)
        new_vulns = []
        
        for vuln in all_vulns:
            vuln_id = get_vuln_id(vuln)
            if vuln_id not in processed_vulns:
                new_vulns.append(vuln)
                processed_vulns.add(vuln_id)
        
        return new_vulns

    # Initial load of vulnerabilities
    new_vulns = load_new_vulns()
    
    if not new_vulns:
        log_message(log_file, "No suspected vulnerabilities found in suspected_vulns.json")
        return False
    
    # Create a thread pool executor that we'll keep alive
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)
    futures = {}  # Map from Future to vulnerability
    
    try:
        # Main processing loop - continue until we've processed everything and no new vulns for a while
        consecutive_empty_checks = 0
        max_empty_checks = 5  # Stop after 5 consecutive checks with no new vulns
        
        while consecutive_empty_checks < max_empty_checks:
            # Process any new vulnerabilities
            if new_vulns:
                log_message(log_file, f"Processing {len(new_vulns)} new suspected vulnerabilities")
                consecutive_empty_checks = 0
                
                for vuln in new_vulns:
                    initial_msg = create_fullscan_prompt(fuzzer_code, vuln)
                    print(initial_msg)
                    #TODO for full-scan, commit_diff is empty
                    commit_diff=""
                    future = executor.submit(
                        doAdvancedPoV, 
                        log_file, fuzzer_src_path,fuzzer_code, commit_diff,fuzzer_path, fuzzer_name, sanitizer,
                        project_dir, project_name, focus, language, check_patch_success
                    )
                    futures[future] = vuln
            # Check for completed futures
            done_futures = []
            for future in list(futures.keys()):
                if future.done():
                    vuln = futures[future]
                    try:
                        success, metadata = future.result()
                        if success:
                            successful_povs.append((vuln, metadata))
                            log_message(log_file, f"Successfully created PoV for vulnerability in {vuln.get('filePath', 'Unknown')}")
                    except Exception as e:
                        log_message(log_file, f"Error processing vulnerability: {str(e)}")
                    
                    done_futures.append(future)
            
            # Remove completed futures
            for future in done_futures:
                del futures[future]
            
            # Check for new vulnerabilities
            new_vulns = load_new_vulns()
            if not new_vulns:
                consecutive_empty_checks += 1
                log_message(log_file, f"No new vulnerabilities found (check {consecutive_empty_checks}/{max_empty_checks})")
            
            # Sleep before checking again
            time.sleep(30)  # Check every 30 seconds
        
        log_message(log_file, "No new vulnerabilities found after multiple checks, finishing up...")
        
        # Wait for remaining futures to complete
        if futures:
            log_message(log_file, f"Waiting for {len(futures)} remaining tasks to complete...")
            for future, vuln in futures.items():
                try:
                    success, metadata = future.result()
                    if success:
                        successful_povs.append((vuln, metadata))
                        log_message(log_file, f"Successfully created PoV for vulnerability in {vuln.get('filePath', 'Unknown')}")
                except Exception as e:
                    log_message(log_file, f"Waiting Error processing vulnerability: {str(e)}")
    
    
    finally:
        # Ensure executor is shut down
        executor.shutdown(wait=False)
    
    # Check if any PoV was successful
    pov_success = len(successful_povs) > 0
    log_message(log_file, f"Completed FULL_SCAN mode with {len(successful_povs)} successful PoVs")
    
    return pov_success


def load_task_detail(fuzz_dir):
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

def load_sarif_broadcast(sarif_path):
    """
    Load a SARIF broadcast from a file.
    
    Args:
        sarif_path (str): Path to the SARIF file
        
    Returns:
        dict: A dictionary representing the SARIFBroadcastDetail structure with:
            - task_id: UUID of the task
            - sarif_id: UUID of the SARIF report
            - sarif: The parsed SARIF report
            - metadata: A dictionary of metadata
            
    Raises:
        FileNotFoundError: If the file doesn't exist
        json.JSONDecodeError: If the file contains invalid JSON
        KeyError: If required fields are missing
    """
    logging.info(f"Loading SARIF broadcast from {sarif_path}")
    
    # Check if file exists
    if not os.path.exists(sarif_path):
        logging.error(f"SARIF file not found: {sarif_path}")
        raise FileNotFoundError(f"SARIF file not found: {sarif_path}")
    
    # Read and parse the file
    try:
        with open(sarif_path, 'r') as f:
            broadcast_data = json.load(f)
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse SARIF file {sarif_path}: {e}")
        raise
        
    # Validate structure - ensure it matches the Go SARIFBroadcastDetail structure
    try:
        # Convert string UUIDs to Python UUID objects
        task_id = uuid.UUID(broadcast_data.get("task_id"))
        sarif_id = uuid.UUID(broadcast_data.get("sarif_id"))
        
        # Extract SARIF and metadata
        sarif_data = broadcast_data.get("sarif")
        metadata = broadcast_data.get("metadata", {})
        
        # Create the result matching the Go structure
        sarif_broadcast = {
            "task_id": task_id,
            "sarif_id": sarif_id,
            "sarif": sarif_data,
            "metadata": metadata
        }
        
        # Perform basic validation of SARIF data
        if sarif_data and isinstance(sarif_data, dict):
            # Check if it has required SARIF fields
            if "version" not in sarif_data:
                logging.warning(f"SARIF data in {sarif_path} doesn't have 'version' field")
            if "runs" not in sarif_data:
                logging.warning(f"SARIF data in {sarif_path} doesn't have 'runs' field")
        
        logging.info(f"Successfully loaded SARIF broadcast with ID {sarif_id}")
        return sarif_broadcast
        
    except (KeyError, TypeError, ValueError) as e:
        logging.error(f"Invalid SARIF broadcast structure in {sarif_path}: {e}")
        raise
    
def find_sarif_target_functions(sarif_broadcast):
    """
    Extract target functions from SARIF broadcast that need to be reached.
    
    Args:
        sarif_broadcast (dict): The SARIF broadcast
        
    Returns:
        list: A list of target function dictionaries with Name, FilePath, and Line information
    """
    logging.info("Finding target functions from SARIF broadcast")
    target_functions = []
    
    sarif_data = sarif_broadcast.get("sarif", {})
    metadata = sarif_broadcast.get("metadata", {})
    
    # First check if metadata contains affected function directly
    if "affected_function" in metadata and metadata["affected_function"]:
        affected_func = metadata["affected_function"]
        affected_file = metadata.get("affected_file", "")
        
        logging.info(f"Found target function in metadata: {affected_func} in file {affected_file}")
        target_functions.append({
            "Name": affected_func,
            "FilePath": affected_file,
            "StartLine": 0,  # We don't have line info in metadata
            "EndLine": 0,
            "SourceCode": ""
        })
    
    # Extract from SARIF runs results
    runs = sarif_data.get("runs", [])
    for run in runs:
        results = run.get("results", [])
        for result in results:
            # Extract locations
            locations = result.get("locations", [])
            for location in locations:
                if "physicalLocation" in location:
                    physical = location["physicalLocation"]
                    file_path = ""
                    if "artifactLocation" in physical and "uri" in physical["artifactLocation"]:
                        file_path = physical["artifactLocation"]["uri"]
                    
                    # Get region info
                    start_line = 0
                    end_line = 0
                    if "region" in physical:
                        region = physical["region"]
                        start_line = region.get("startLine", 0)
                        end_line = region.get("endLine", start_line)
                    
                    # Try to extract function name from message or other sources
                    function_name = ""
                    
                    # First try to get from message text which often has function names
                    if "message" in result and "text" in result["message"]:
                        message_text = result["message"]["text"]
                        # Look for patterns like 'in function_name' or similar
                        function_patterns = [
                            r'in\s+([a-zA-Z0-9_]+)\s+',
                            r'function\s+([a-zA-Z0-9_]+)',
                            r'([a-zA-Z0-9_]+)\(',
                        ]
                        
                        for pattern in function_patterns:
                            matches = re.findall(pattern, message_text)
                            if matches:
                                candidate_name = matches[0]
                                # Filter out common words that aren't function names
                                common_words = ['the', 'and', 'for', 'with', 'function']
                                if candidate_name.lower() not in common_words:
                                    function_name = candidate_name
                                    break
            
                    # If we couldn't find function name from message, try call stacks
                    if not function_name and "message" in result and "text" in result["message"]:
                        message_text = result["message"]["text"]
                        # Look for stack traces like '#0 0x559972f1e429 in OSS_FUZZ_png_handle_iCCP'
                        stack_pattern = r'#\d+\s+[0-9xa-f]+\s+in\s+([a-zA-Z0-9_]+)'
                        stack_matches = re.findall(stack_pattern, message_text)
                        if stack_matches:
                            function_name = stack_matches[0]
                    
                    # If we still don't have a function name but have metadata, use that
                    if not function_name and "affected_function" in metadata:
                        function_name = metadata["affected_function"]
                    
                    # Only add if we have a function name
                    if function_name:
                        target_function = {
                            "Name": function_name,
                            "FilePath": file_path,
                            "StartLine": start_line,
                            "EndLine": end_line,
                            "SourceCode": ""  # We don't have source code here
                        }
                        
                        # Avoid duplicates
                        if not any(tf["Name"] == function_name and tf["FilePath"] == file_path for tf in target_functions):
                            target_functions.append(target_function)
                            logging.info(f"Found target function from SARIF: {function_name} in {file_path} at line {start_line}")
    
    # Extract from stack traces in the message
    for run in runs:
        results = run.get("results", [])
        for result in results:
            if "message" in result and "text" in result["message"]:
                message_text = result["message"]["text"]
                
                # Look for stack traces in the format:
                # #0 0x559972f1e429 in OSS_FUZZ_png_handle_iCCP /src/libpng/pngrutil.c:1457:13
                stack_lines = re.findall(r'#\d+\s+[0-9xa-f]+\s+in\s+([a-zA-Z0-9_]+)\s+([^:]+):(\d+)', message_text)
                
                for match in stack_lines:
                    function_name, file_path, line_num = match
                    try:
                        line_num = int(line_num)
                    except ValueError:
                        line_num = 0
                        
                    target_function = {
                        "Name": function_name,
                        "FilePath": file_path.strip(),
                        "StartLine": line_num,
                        "EndLine": line_num,
                        "SourceCode": ""
                    }
                    
                    # Avoid duplicates
                    if not any(tf["Name"] == function_name and tf["FilePath"] == file_path.strip() for tf in target_functions):
                        target_functions.append(target_function)
                        logging.info(f"Found target function from stack trace: {function_name} in {file_path.strip()} at line {line_num}")
    
    # If we still don't have any target functions but have rule metadata, try to extract from there
    if len(target_functions) == 0:
        for run in runs:
            if "tool" in run and "driver" in run["tool"] and "rules" in run["tool"]["driver"]:
                for rule in run["tool"]["driver"]["rules"]:
                    if "shortDescription" in rule and "text" in rule["shortDescription"]:
                        text = rule["shortDescription"]["text"]
                        # Look for patterns like "buffer overflow in function_name"
                        func_matches = re.findall(r'in\s+([a-zA-Z0-9_]+)', text)
                        if func_matches:
                            function_name = func_matches[0]
                            target_functions.append({
                                "Name": function_name,
                                "FilePath": metadata.get("affected_file", ""),
                                "StartLine": 0,
                                "EndLine": 0,
                                "SourceCode": ""
                            })
                            logging.info(f"Found target function from rule description: {function_name}")
    
    logging.info(f"Found {len(target_functions)} target functions from SARIF broadcast")
    return target_functions

def check_if_targets_reachable(sarif_targets, reachable_functions):
    """
    Check if any of the SARIF target functions are reachable from the fuzzer.
    
    Args:
        sarif_targets (list): List of target functions from SARIF
        reachable_functions (list): List of functions reachable from the fuzzer
        
    Returns:
        tuple: (is_reachable, reachable_targets)
            - is_reachable: True if any target is reachable
            - reachable_targets: List of reachable target functions
    """
    logging.info(f"Checking if {len(sarif_targets)} target functions are reachable from {len(reachable_functions)} reachable functions")
    

    # Debug: Print out details of SARIF targets
    logging.info("===== SARIF Target Functions =====")
    for i, target in enumerate(sarif_targets):
        logging.info(f"Target #{i+1}:")
        logging.info(f"  Name: {target['Name']}")
        logging.info(f"  FilePath: {target['FilePath']}")
        logging.info(f"  Lines: {target['StartLine']}-{target['EndLine']}")
        if 'SourceCode' in target and target['SourceCode']:
            source_preview = target['SourceCode'].replace('\n', ' ')[:100] + '...' if len(target['SourceCode']) > 100 else target['SourceCode']
            logging.info(f"  Source preview: {source_preview}")
        logging.info("----------------------------")
    
        
    # Debug: Print sample of reachable functions (first 10 and last 10 if more than 20)
    logging.info("===== Sample of Reachable Functions =====")
    if len(reachable_functions) <= 20:
        sample_funcs = reachable_functions
        logging.info(f"Showing all {len(sample_funcs)} reachable functions:")
    else:
        sample_funcs = reachable_functions[:10] + reachable_functions[-10:]
        logging.info(f"Showing 20 sample functions out of {len(reachable_functions)} total:")
    
    for i, func in enumerate(sample_funcs):
        if i == 10 and len(reachable_functions) > 20:
            logging.info("  ... (skipping middle functions) ...")
        
        func_index = i if i < 10 else len(reachable_functions) - (20 - i)
        logging.info(f"Function #{func_index+1}:")
        logging.info(f"  Name: {func['Name']}")
        logging.info(f"  FilePath: {func['FilePath']}")
        logging.info(f"  Lines: {func['StartLine']}-{func['EndLine']}")
        if 'SourceCode' in func and func['SourceCode']:
            source_preview = func['SourceCode'].replace('\n', ' ')[:100] + '...' if len(func['SourceCode']) > 100 else func['SourceCode']
            logging.info(f"  Source preview: {source_preview}")
        logging.info("----------------------------")
    
    # Also log all function names (without details) for easier searching
    logging.info("===== All Reachable Function Names =====")
    all_func_names = [func["Name"] for func in reachable_functions]
    all_func_names_str = ", ".join(all_func_names)
    
    # Split into chunks if too long for log
    chunk_size = 1000
    if len(all_func_names_str) > chunk_size:
        chunks = [all_func_names_str[i:i+chunk_size] for i in range(0, len(all_func_names_str), chunk_size)]
        for i, chunk in enumerate(chunks):
            logging.info(f"Names chunk {i+1}/{len(chunks)}: {chunk}")
    else:
        logging.info(f"All function names: {all_func_names_str}")
    

    reachable_targets = []
    
    # Create a set of reachable function names for faster lookup
    reachable_func_names = {func["Name"] for func in reachable_functions}
    
    # For more precise matching with file paths
    reachable_func_map = {}
    for func in reachable_functions:
        key = (func["Name"], os.path.basename(func["FilePath"]))
        reachable_func_map[key] = func
    
    for target in sarif_targets:
        target_name = target["Name"]
        target_file = os.path.basename(target["FilePath"]) if target["FilePath"] else ""
        
        # Simple check by function name first
        if target_name in reachable_func_names:
            logging.info(f"Target function {target_name} is reachable by name")
            reachable_targets.append(target)
            continue
            
        # More specific check with file path if available
        if target_file and (target_name, target_file) in reachable_func_map:
            logging.info(f"Target function {target_name} in {target_file} is reachable")
            reachable_targets.append(target)
            continue
            
        # Fallback: try to find partial matches
        for func_name in reachable_func_names:
            # Check if the target name is part of a longer function name
            # This handles cases like 'handle_iCCP' vs 'png_handle_iCCP'
            if target_name in func_name:
                logging.info(f"Target function {target_name} might be reachable as part of {func_name}")
                reachable_targets.append(target)
                break
    
    is_reachable = len(reachable_targets) > 0
    logging.info(f"Target reachability: {is_reachable} ({len(reachable_targets)} reachable targets)")
    
    return is_reachable, reachable_targets

# Main function to find SARIF targets and check reachability
def analyze_sarif_reachability(sarif_path, fuzzer_path, fuzzer_src_path, focus, project_src_dir, is_java=False):
    """
    Load SARIF broadcast, find target functions, and check if they're reachable.
    
    Args:
        sarif_path (str): Path to the SARIF file
        fuzzer_path (str): Path to the fuzzer executable
        fuzzer_src_path (str): Path to the fuzzer source code
        focus (str): Focus function name
        project_src_dir (str): Project source directory
        is_java (bool): Whether the project is Java
        
    Returns:
        tuple: (is_reachable, reachable_targets, all_targets)
    """
    try:
        # Load SARIF broadcast
        sarif_broadcast = load_sarif_broadcast(sarif_path)
        
        # Find target functions from SARIF
        sarif_targets = find_sarif_target_functions(sarif_broadcast)
        
        # Find reachable functions
        all_reachable_funcs = extract_reachable_functions_from_analysis_service(
            fuzzer_path, fuzzer_src_path, focus, project_src_dir, is_java)
        
        # Check if targets are reachable
        is_reachable, reachable_targets = check_if_targets_reachable(sarif_targets, all_reachable_funcs)
        
        if not is_reachable:
            logging.warning("Fuzzer cannot reach any of the target functions described in SARIF broadcast")
            # You can add additional handling here based on what you want to do when targets aren't reachable
        else:
            logging.info(f"Fuzzer can reach {len(reachable_targets)} target functions")
            # Print reachable targets for debugging
            for i, target in enumerate(reachable_targets):
                logging.info(f"Reachable target {i+1}: {target['Name']} in {target['FilePath']}")
        
        return is_reachable, reachable_targets, sarif_targets
        
    except Exception as e:
        logging.error(f"Error analyzing SARIF reachability: {e}")
        import traceback
        traceback.print_exc()
        return False, [], []

if False:
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Example path
    sarif_path = "/crs-workdir/sarif_reports/680b7d48-d5d5-4419-8d14-e0767b1a00fd.json"
    fuzzer_path = "/crs-workdir/b520b678-f27f-4e94-b36f-ccc1c2779594-20250426-033923/fuzz-tooling/build/out/libpng-address/libpng_read_fuzzer"
    fuzzer_src_path = "/crs-workdir/b520b678-f27f-4e94-b36f-ccc1c2779594/example-libpng-address/contrib/oss-fuzz/libpng_read_fuzzer.cc"
    focus = "example-libpng"
    project_src_dir = "/crs-workdir/b520b678-f27f-4e94-b36f-ccc1c2779594-20250426-033923/example-libpng/"
    os.environ["TASK_ID"] = "b520b678-f27f-4e94-b36f-ccc1c2779594"

    try:
        analyze_sarif_reachability(sarif_path, fuzzer_path, fuzzer_src_path, focus, project_src_dir)
    except Exception as e:
        logging.error(f"Error analyze_sarif_reachability: {e}")
    exit(0)



def find_file_path(project_src_dir: str, base_name: str) -> str:
    """
    Find a file with the given base name in the project directory.
    
    Args:
        project_src_dir: The root directory to search in
        base_name: The base name of the file to find
        
    Returns:
        Full path to the file if found, empty string otherwise
    """
    logging.info(f"Searching for file {base_name} in {project_src_dir}")
    
    # Check if the directory exists
    if not os.path.exists(project_src_dir) or not os.path.isdir(project_src_dir):
        logging.warning(f"Project source directory {project_src_dir} does not exist")
        return ""
    
    # Walk through the directory and find any file matching the base name
    for root, _, files in os.walk(project_src_dir):
        for file in files:
            if file == base_name:
                full_path = os.path.join(root, file)
                logging.info(f"Found file: {full_path}")
                return full_path
    
    # If we can't find an exact match, look for files with the same name but different extensions
    base_without_ext = os.path.splitext(base_name)[0]
    for root, _, files in os.walk(project_src_dir):
        for file in files:
            if os.path.splitext(file)[0] == base_without_ext:
                full_path = os.path.join(root, file)
                logging.info(f"Found file with matching name: {full_path}")
                return full_path
    
    logging.warning(f"Could not find file {base_name} in {project_src_dir}")
    return ""


def extract_function_source_code(file_path: str, start_line: int, end_line: int) -> str:
    """
    Extract source code between start_line and end_line from file_path.
    
    Args:
        file_path: Path to the source file
        start_line: Starting line number (1-based)
        end_line: Ending line number (1-based)
        
    Returns:
        Source code as a string
    """
    if not file_path or not os.path.isfile(file_path):
        return ""
    
    if start_line <= 0 or end_line <= 0 or start_line > end_line:
        return ""
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
            
        # Adjust to 0-based indexing
        start_idx = start_line - 1
        end_idx = end_line - 1
        
        # Make sure we don't go out of bounds
        start_idx = max(0, start_idx)
        end_idx = min(len(lines) - 1, end_idx)
        
        # Extract and join the lines
        return ''.join(lines[start_idx:end_idx + 1])
    except Exception as e:
        logging.error(f"Error extracting source code from {file_path}: {e}")
        return ""

def extract_c_function_info(file_path: str, source_lines: List[str], vuln_start_line: int, vuln_end_line: int) -> Tuple[str, str, int, int]:
    """
    Extract function information from C/C++ source code.
    
    Args:
        file_path: Path to the source file
        source_lines: List of source code lines
        vuln_start_line: Starting line of the vulnerability (1-based)
        vuln_end_line: Ending line of the vulnerability (1-based)
        
    Returns:
        Tuple of (file_path, function_name, function_start_line, function_end_line)
    """
    # Adjust to 0-based indexing
    start_idx = vuln_start_line - 1
    end_idx = vuln_end_line - 1
    
    if start_idx < 0 or start_idx >= len(source_lines) or end_idx >= len(source_lines):
        logging.warning(f"Invalid line numbers for file {file_path}: {vuln_start_line}-{vuln_end_line}")
        return file_path, "", 0, 0
    
    # Search backwards from the vulnerability to find function signature
    func_start_idx = start_idx
    func_name = ""
    brace_level = 0
    
    # First look for a proper function signature within 100 lines before the vulnerability
    signature_pattern = r'^\s*(static\s+|inline\s+|extern\s+)*(\w+\s+)*(\w+)\s*\([^;{]*\)\s*({)?'
    
    for i in range(start_idx, max(0, start_idx - 100), -1):
        line = source_lines[i].strip()
        
        # Skip preprocessor directives, comments, and empty lines
        if line.startswith('#') or line.startswith('//') or line.startswith('/*') or not line:
            continue
        
        # Look for a proper function signature
        match = re.search(signature_pattern, line)
        if match:
            candidate = match.group(3)
            
            # Skip if it's a C/C++ keyword
            c_keywords = ['if', 'for', 'while', 'switch', 'return', 'sizeof', 'typedef', 
                          'struct', 'union', 'enum', 'class', 'else', 'do', 'case']
            if candidate not in c_keywords:
                # Verify it's not a variable declaration or other non-function construct
                line_with_next = line
                # Check next few lines if this line doesn't have an opening brace
                if '{' not in line:
                    for j in range(i+1, min(i+5, len(source_lines))):
                        next_line = source_lines[j].strip()
                        line_with_next += " " + next_line
                        if '{' in next_line:
                            break
                        if ';' in next_line:  # Not a function definition
                            line_with_next = ""
                            break
                
                # If we have a line with an opening brace, it's likely a function definition
                if '{' in line_with_next and ';' not in line_with_next.split('{')[0]:
                    func_name = candidate
                    func_start_idx = i
                    break
    
    # If we couldn't find a proper function name, try in stack traces or error messages
    if not func_name:
        # Look for function names in comments or error messages in the vicinity
        error_context = []
        for i in range(max(0, start_idx - 20), min(len(source_lines), end_idx + 20)):
            error_context.append(source_lines[i])
        
        error_text = ''.join(error_context)
        
        # Look for function names in stack traces
        stack_pattern = r'(?:in|at)\s+([a-zA-Z][a-zA-Z0-9_]+(?:_[a-zA-Z0-9_]+)+)\s*\('
        stack_matches = re.finditer(stack_pattern, error_text)
        
        for match in stack_matches:
            func_name = match.group(1)
            if func_name and func_name not in ['if', 'for', 'while', 'switch', 'return']:
                break
    
    # If still no function name, use basename minus extension as a last resort
    if not func_name or func_name in ['if', 'for', 'while', 'switch', 'return']:
        func_name = os.path.splitext(os.path.basename(file_path))[0]
    
    # If we found a function name but not its start, try to find it
    if func_name and func_start_idx == start_idx:
        # Look for the function name in the file
        for i in range(len(source_lines)):
            line = source_lines[i].strip()
            if line.startswith(func_name) and '(' in line and ')' in line and '{' in line:
                func_start_idx = i
                break
            elif func_name in line and '(' in line and ')' in line and '{' in line:
                # Check if it's a proper function definition
                match = re.search(r'\b' + re.escape(func_name) + r'\s*\(', line)
                if match:
                    func_start_idx = i
                    break
    
    # Now scan forward to find function end
    func_end_idx = end_idx
    brace_level = 0
    
    # Initialize brace level by counting from function start to vulnerability start
    for i in range(func_start_idx, start_idx + 1):
        line = source_lines[i].strip()
        for char in line:
            if char == '{':
                brace_level += 1
            elif char == '}':
                brace_level -= 1
    
    # Continue scanning from vulnerability end to find function end
    for i in range(end_idx, len(source_lines)):
        line = source_lines[i].strip()
        for char in line:
            if char == '{':
                brace_level += 1
            elif char == '}':
                brace_level -= 1
                if brace_level == 0:
                    func_end_idx = i
                    break
        if brace_level == 0:
            break
    
    # Sanity check - if function boundaries seem unreasonable, use a fixed window
    if func_end_idx - func_start_idx > 1000 or func_end_idx <= func_start_idx:
        # Use a reasonable context window around the vulnerability
        func_start_idx = max(0, start_idx - 30)
        func_end_idx = min(len(source_lines) - 1, end_idx + 30)
    
    # Convert back to 1-based indexing
    return file_path, func_name, func_start_idx + 1, func_end_idx + 1

def extract_java_function_info(file_path: str, source_lines: List[str], vuln_start_line: int, vuln_end_line: int) -> Tuple[str, str, int, int]:
    """
    Extract function information from Java source code.
    
    Args:
        file_path: Path to the source file
        source_lines: List of source code lines
        vuln_start_line: Starting line of the vulnerability (1-based)
        vuln_end_line: Ending line of the vulnerability (1-based)
        
    Returns:
        Tuple of (file_path, function_name, function_start_line, function_end_line)
    """
    # Adjust to 0-based indexing
    start_idx = vuln_start_line - 1
    end_idx = vuln_end_line - 1
    
    if start_idx < 0 or start_idx >= len(source_lines) or end_idx >= len(source_lines):
        logging.warning(f"Invalid line numbers for file {file_path}: {vuln_start_line}-{vuln_end_line}")
        return file_path, "", 0, 0
    
    # Search backwards from the vulnerability to find method signature
    func_start_idx = start_idx
    func_name = ""
    brace_level = 0
    
    # First, scan backward to find the method start
    for i in range(start_idx, -1, -1):
        line = source_lines[i].strip()
        
        # Count closing braces when going backward
        brace_level += line.count('}')
        brace_level -= line.count('{')
        
        # If we find an opening brace and we're at level 1, we've found the method start
        if '{' in line and brace_level == 1:
            # Look for method signature above this line
            for j in range(i, max(0, i-15), -1):
                signature_line = source_lines[j].strip()
                # Method signature typically contains parameters and might have annotations
                if (')' in signature_line and '(' in signature_line and 
                    not signature_line.startswith('//') and 
                    not signature_line.startswith('*') and
                    not signature_line.startswith('/*')):
                    
                    # Extract method name - takes the word before the opening parenthesis
                    match = re.search(r'(?:public|private|protected|static|\s) +[\w\<\>\[\]]+\s+(\w+)\s*\(', signature_line)
                    if match:
                        func_name = match.group(1)
                        func_start_idx = j
                        break
                    else:
                        # Simpler fallback pattern
                        match = re.search(r'(\w+)\s*\(', signature_line)
                        if match:
                            func_name = match.group(1)
                            func_start_idx = j
                            break
            break
    
    # If we couldn't find a method name, use class name or file basename
    if not func_name:
        # Try to find class name in the file
        for i in range(len(source_lines)):
            line = source_lines[i].strip()
            match = re.search(r'class\s+(\w+)', line)
            if match:
                func_name = match.group(1) + ".unknown"
                break
        
        # If still no name, use file basename
        if not func_name:
            func_name = os.path.splitext(os.path.basename(file_path))[0] + ".unknown"
    
    # Now scan forward to find method end
    func_end_idx = end_idx
    brace_level = 0
    
    # First, count braces up to start_idx to determine current nesting level
    for i in range(func_start_idx, start_idx + 1):
        line = source_lines[i].strip()
        brace_level += line.count('{')
        brace_level -= line.count('}')
    
    # Continue scanning from end_idx to find method end
    for i in range(end_idx, len(source_lines)):
        line = source_lines[i].strip()
        brace_level += line.count('{')
        brace_level -= line.count('}')
        
        # If we reach brace level 0, we've found the end of the method
        if brace_level <= 0 and '}' in line:
            func_end_idx = i
            break
    
    # Convert back to 1-based indexing
    return file_path, func_name, func_start_idx + 1, func_end_idx + 1
           
     
def extract_function_info_from_path(file_path: str, vuln_start_line: int, vuln_end_line: int) -> Tuple[str, int, int]:
    """
    Extract function information from a source file.
    
    Args:
        file_path: Path to the source file
        vuln_start_line: Starting line of the vulnerability (1-based)
        vuln_end_line: Ending line of the vulnerability (1-based)
        
    Returns:
        Tuple of (function_name, function_start_line, function_end_line)
    """
    # Check if file exists
    if not file_path or not os.path.isfile(file_path):
        logging.warning(f"Invalid file path: {file_path}")
        return "", 0, 0
    
    # Get file extension to determine language
    _, ext = os.path.splitext(file_path)
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            source_lines = f.readlines()
    except Exception as e:
        logging.error(f"Error reading source file {file_path}: {e}")
        return "", 0, 0
    
    # Format source lines with line numbers
    total_lines = len(source_lines)
    
    # If file is less than 2000 lines, include the whole file
    if total_lines <= 2000:
        formatted_source = ""
        for i, line in enumerate(source_lines, start=1):
            formatted_source += f"{i}: {line}"
    else:
        # Otherwise, include 1000 lines before and after the vulnerability
        context_start = max(0, vuln_start_line - 1000 - 1)  # Convert to 0-indexed
        context_end = min(total_lines, vuln_end_line + 1000)
        
        formatted_source = ""
        if context_start > 0:
            formatted_source += f"[Lines 1-{context_start} omitted for brevity]\n"
            
        for i, line in enumerate(source_lines[context_start:context_end], start=context_start+1):
            formatted_source += f"{i}: {line}"
            
        if context_end < total_lines:
            formatted_source += f"[Lines {context_end+1}-{total_lines} omitted for brevity]\n"
    
    # Build the prompt
    prompt = f"""
From the source code below, extract the function that contains the source lines {vuln_start_line}-{vuln_end_line}.

Source code:

{formatted_source}

Please identify:
1. The function name
2. The function's start line number
3. The function's end line number

IMPORTANT: Return your answer as a valid JSON object with these exact fields:
- "Name": function name (string)
- "StartLine": function start line number (integer)
- "EndLine": function end line number (integer)

IMPORTANT: The response must be a JSON object containing only "Name", "StartLine", and "EndLine".
"""
    
    # Call the model to identify the function
    log_file = f"llm_extract_{os.path.basename(file_path)}_{time.time()}.log"
    messages = [{"role": "user", "content": prompt}]
    
    print(f"prompt: {prompt}")
    for model_name in MODELS:
        returned_text, success = call_llm(log_file, messages, model_name)
        print(f"returned_text: {returned_text}")
        if success:
            # Extract JSON from the response
            pattern = r"```(?:json)?\s*([\s\S]*?)```"
            matches = re.findall(pattern, returned_text)
            
            if not matches:
                # Try to find JSON without code blocks
                json_pattern = r'(\{\s*"Name"\s*:.+?\s*"StartLine"\s*:.+?\s*"EndLine"\s*:.+?\})'
                matches = re.findall(json_pattern, returned_text, re.DOTALL)
            
            if matches:
                try:
                    json_str = matches[0].strip()
                    # Handle potential issues with single quotes instead of double quotes
                    json_str = json_str.replace("'", "\"")
                    extracted_json = json.loads(json_str)
                    
                    if "Name" in extracted_json and "StartLine" in extracted_json and "EndLine" in extracted_json:
                        func_name = extracted_json["Name"]
                        func_start = int(extracted_json["StartLine"])
                        func_end = int(extracted_json["EndLine"])
                        
                        # Sanity check the results
                        if (func_start <= vuln_start_line and 
                            vuln_end_line <= func_end and
                            func_start > 0 and func_end <= total_lines):
                            
                            return func_name, func_start, func_end
                        
                        logging.warning(f"LLM returned invalid function boundaries: {func_start}-{func_end} for vulnerability at {vuln_start_line}-{vuln_end_line}")
                except (json.JSONDecodeError, ValueError) as e:
                    logging.error(f"Error parsing LLM response: {e}, text: {matches[0]}")
            else:
                logging.warning("Could not extract JSON from LLM response")
    
    # Fall back to language-specific extraction if LLM approach fails
    logging.warning("Falling back to heuristic-based function extraction")
    
    if ext.lower() in ['.c', '.cpp', '.cc', '.h', '.hpp', '.in']:
        _fp, fname, fstart, fend = extract_c_function_info(file_path, source_lines, vuln_start_line, vuln_end_line)
        return fname, fstart, fend
    elif ext.lower() in ['.java']:
        _fp, fname, fstart, fend = extract_java_function_info(file_path, source_lines, vuln_start_line, vuln_end_line)
        return fname, fstart, fend
    else:
        logging.warning(f"Unsupported file extension for parsing: {ext}")
        return os.path.splitext(os.path.basename(file_path))[0], vuln_start_line, vuln_end_line


import re
import os
import json
import logging
from typing import List, Dict, Any, Optional

def find_sarif_target_functions_with_llm(project_src_dir: str, sarif_broadcast: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts target functions from SARIF report using a combination of regex patterns
    and source code analysis.
    
    Args:
        sarif_broadcast: Dictionary containing SARIF report data
        
    Returns:
        List of dictionaries containing target function data
    """
    logging.info("Extracting target functions from SARIF using enhanced parsing")
    sarif_targets = []
    
    if not sarif_broadcast or "sarif" not in sarif_broadcast:
        logging.warning("Invalid SARIF broadcast format - missing 'sarif' field")
        return []
    
    sarif = sarif_broadcast["sarif"]
    if "runs" not in sarif or not sarif["runs"]:
        logging.warning("Invalid SARIF format - missing or empty 'runs' field")
        return []
    
    # Extract results from the first run
    results = sarif["runs"][0].get("results", [])
    if not results:
        logging.warning("No results found in SARIF report")
        return []
    
    # Process each result to extract target functions
    for result in results:
        # Extract locations
        locations = result.get("locations", [])
        if not locations:
            continue
            
        # Find file paths and line numbers from locations
        for location in locations:
            physical_location = location.get("physicalLocation", {})
            artifact_location = physical_location.get("artifactLocation", {})
            region = physical_location.get("region", {})
            
            file_path = artifact_location.get("uri", "")
            start_line = region.get("startLine", 0)
            end_line = region.get("endLine", start_line)
            
            if not file_path or start_line <= 0:
                continue
            
            # TODO search under project_src_dir for any .c or .java file matches with file_path basename
            # send its full source code, vuln start_line, vuln end_line, to LLM, ask to return the function name, the functin's start line and endline
            # Find the actual source file
            base_name = os.path.basename(file_path)
            fpath = find_file_path(project_src_dir, base_name)
            if not fpath:
                logging.warning(f"Could not find source file: {file_path}")
                continue

            (fname, fstartline, fendline) = extract_function_info_from_path(fpath, start_line, end_line)
            # source_code = extract_function_source_code(fpath, fstartline, fendline)
            target = {
                "Name": fname,
                "FilePath": fpath,
                "StartLine": fstartline,
                "EndLine": fendline,
                # "SourceCode": source_code
            }
            
            # Only add if we have a valid function name and it's not already in targets
            if fname and not any(t["Name"] == fname and t["FilePath"] == fpath for t in sarif_targets):
                sarif_targets.append(target)
                
    logging.info(f"Extracted {len(sarif_targets)} target functions from SARIF")
    return sarif_targets

if False: 
    sarif_path = "/crs-workdir/sarif_reports/680b7d48-d5d5-4419-8d14-e0767b1a00fd.json"
    project_dir = "/crs-workdir/b520b678-f27f-4e94-b36f-ccc1c2779594"
    focus = "example-libpng"
    sanitizer ="address"
    project_src_dir = os.path.join(project_dir, focus+"-"+sanitizer)
    # sarif_path = "/crs-workdir/sarif_reports/sample.json"
    sarif_broadcast = load_sarif_broadcast(sarif_path)
    sarif_targets = find_sarif_target_functions(sarif_broadcast)
    print(f"sarif_targets: {sarif_targets}")
    if len(sarif_targets) == 0:
        sarif_targets = find_sarif_target_functions_with_llm(project_src_dir,sarif_broadcast)
    
    print(f"find_sarif_target_functions_with_llm sarif_targets: {sarif_targets}")

    exit(0)

if False:          
    # project_dir = "/crs-workdir/xe969f7bb-7257-4505-b1b8-23af68fedb01-20250406-133710"
    # focus="round-exhibition1-libxml2"
    # sanitizer="address"
    # project_name="libxml2"
    # fuzzer_name="html"
    # language = 'c'

    # project_dir = "/crs-workdir/x1ab6c80d-9f71-444d-a6b7-feddd6007d66-20250407-215414"
    # focus="round-exhibition1-zookeeper"
    # sanitizer="address"
    # project_name="zookeeper"
    # fuzzer_name="MessageTrackerPeekReceivedFuzzer"
    # language = 'java'

    # project_dir = "/crs-workdir/1ab6c80d-9f71-444d-a6b7-feddd6007d66"
    # focus="round-exhibition1-zookeeper"
    # sanitizer="address"
    # project_name="zookeeper"
    # fuzzer_name="MessageTrackerPeekReceivedFuzzer"
    # language = 'java'
    # os.environ["TASK_ID"] = "1ab6c80d-9f71-444d-a6b7-feddd6007d66"

    # project_dir = "/crs-workdir/b28ef27f-d9b9-426c-84c8-094916a3b8a6-20250420-163730"
    # focus="afc-zookeeper"
    # sanitizer="address"
    # project_name="zookeeper"
    # fuzzer_name="MessageTrackerPeekReceivedFuzzer"
    # language = 'java'
    # os.environ["TASK_ID"] = "b28ef27f-d9b9-426c-84c8-094916a3b8a6"

    #sarif for libpng 
    project_dir = "/crs-workdir/b520b678-f27f-4e94-b36f-ccc1c2779594"
    focus="example-libpng"
    sanitizer="address"
    project_name="libpng"
    fuzzer_name="libpng_read_fuzzer"
    language = 'c'
    os.environ["TASK_ID"] = "b520b678-f27f-4e94-b36f-ccc1c2779594"
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    sarif_path = "/crs-workdir/sarif_reports/680b7d48-d5d5-4419-8d14-e0767b1a00fd.json"
    try:
        # Load the SARIF broadcast
        sarif_broadcast = load_sarif_broadcast(sarif_path)
        # Extract and display vulnerabilities
        vulnerabilities = extract_vulnerabilities(sarif_broadcast)
        # show_vulnerability_details(str(sarif_broadcast["task_id"]), vulnerabilities)
        
    except Exception as e:
        logging.error(f"Error processing SARIF broadcast: {e}")

    seed_corpus_dir=f"{project_dir}/{fuzzer_name}_seed_corpus"
    fuzzer_path=f"{project_dir}/fuzz-tooling/build/out/{project_name}-{sanitizer}/{fuzzer_name}"
    project_src_dir = os.path.join(project_dir, focus+"-"+sanitizer)

    log_file = setup_logging(fuzzer_name)    
    # crash_detected, fuzzer_output, coverage_output, blob_data = run_fuzzer_with_coverage(log_file, fuzzer_path, project_dir, focus,sanitizer,project_name, seed_corpus_dir)
    # print(f"crash_detected:{crash_detected}")
    # print(f"fuzzer_output:{fuzzer_output}")
    # print(f"coverage_output:{coverage_output}")
    # print(f"crash input:{blob_data}")

    # crash_detected, fuzzer_output, coverage_output, blob_data = run_fuzzer_with_coverage(log_file, fuzzer_path, project_dir, focus,sanitizer,project_name, seed_corpus_dir)
    # print(f"crash_detected:{crash_detected}")
    # print(f"fuzzer_output:{fuzzer_output}")
    # print(f"coverage_output:{coverage_output}")
    # print(f"crash input:{blob_data}")

    fuzzer_code, fuzzer_src_path= find_fuzzer_source(log_file, fuzzer_path, project_name, project_src_dir, language)
    POV_PHASE =2

    sarif_targets = find_sarif_target_functions(sarif_broadcast)
    if len(sarif_targets) == 0:
        sarif_targets = find_sarif_target_functions_with_llm(project_src_dir,sarif_broadcast)


    if False:
        for func in sarif_targets:
            source_code = func.get("SourceCode", "")
            file_path = func.get("FilePath", "")
            start_line = func.get("StartLine", 0)
            end_line = func.get("EndLine", 0)

            # If source code is missing, try to extract it from the file
            if not source_code and file_path:
                # Handle both absolute paths and paths relative to project_src_dir
                file_path_x = file_path
                if not os.path.exists(file_path_x):
                    file_path_x = os.path.join(project_src_dir, file_path)
                
                if os.path.exists(file_path_x):
                    try:
                        with open(file_path_x, "r", encoding="utf-8", errors="ignore") as fh:
                            lines = fh.readlines()
                            
                        # Extract source code based on line numbers
                        if start_line > 0 and end_line >= start_line:
                            source_code = "".join(lines[start_line - 1 : end_line])
                        else:
                            # If no valid line numbers, take a reasonable chunk
                            source_code = "".join(lines[:1000])  # Cap at 1000 lines for safety
                            
                        # Update the function dict with the extracted source code
                        func["SourceCode"] = source_code
                        
                    except Exception as e:
                        log_message(log_file, f"Failed to load source for {file_path_x}: {e}")
                        func["SourceCode"] = ""  # Mark as empty if failed
                else:
                    log_message(log_file, f"Source file not found: {file_path_x}")
                    func["SourceCode"] = ""  # Mark as empty if file not found

            # Validate the source code is non-empty
            if not func["SourceCode"].strip():
                log_message(log_file, f"Warning: Empty source code for function in {file_path}")

        # Filter out entries with empty source code
        sarif_targets = [func for func in sarif_targets if func["SourceCode"].strip()]

    # find reachable functions 
    all_reachable_funcs = extract_reachable_functions_from_analysis_service(fuzzer_path,fuzzer_src_path,focus,project_src_dir,language.startswith('j'))

    # Check if targets are reachable
    is_reachable, reachable_targets = check_if_targets_reachable(sarif_targets, all_reachable_funcs)

    if not is_reachable:
        logging.warning("Fuzzer cannot reach the target functions described in SARIF broadcast")
        exit(0)  # Early return if not reachable

    if False:
        print(f"reachable_targets: {reachable_targets}")
        target_functions = covert_target_functions_format(reachable_targets)
        print(f"target_functions: {target_functions}")
        exit(0)

    pov_success, pov_metadata = doSarifPoV(log_file, sarif_broadcast, fuzzer_src_path,fuzzer_code,fuzzer_path,fuzzer_name,sanitizer,project_dir,project_name,focus, reachable_targets, language, False)
    print(f"pov_success: {pov_success}")
    print(f"pov_metadata: {pov_metadata}")
    exit(0)

def main():
    parser = argparse.ArgumentParser(description="Sarif POV Strategy 0: LLM-guided POV")
    parser.add_argument("fuzzer_path", help="Path to the fuzzer")
    parser.add_argument("sarif_path", help="Path to the sarif broadcast file")
    parser.add_argument("project_name", help="Project name")
    parser.add_argument("focus", help="Focus")
    parser.add_argument("language", help="Language")

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
    parser.add_argument("--pov-phase", dest="pov_phase", type=int,
                        default=0, help="PoV generation phase")
    parser.add_argument("--patch-phase", dest="patch_phase", type=int,
                        default=0, help="Patch generation phase")
    parser.add_argument("--pov-metadata-dir", dest="pov_metadata_dir", type=str,
                        default="successful_povs", help="Directory to store POV metadata")
    parser.add_argument("--patch-workspace-dir", help="Directory for patch workspace", default="patch_workspace")
    parser.add_argument("--check-patch-success", action="store_true", 
                        help="Check for successful patches and exit early if found")
    parser.add_argument("--model", type=str, default="", help="Specify the model to use")
                        
    args = parser.parse_args()
    # Set global variables
    global DO_PATCH_ONLY, MAX_ITERATIONS, FUZZING_TIMEOUT_MINUTES, POV_PHASE, PATCH_PHASE
    global PATCHING_TIMEOUT_MINUTES, POV_METADATA_DIR, PATCH_WORKSPACE_DIR, MODELS
    global FULL_SCAN
    DO_PATCH_ONLY = args.do_patch_only
    FULL_SCAN = args.full_scan
    MAX_ITERATIONS = args.max_iterations
    FUZZING_TIMEOUT_MINUTES = args.fuzzing_timeout
    PATCHING_TIMEOUT_MINUTES = args.patching_timeout
    POV_PHASE=args.pov_phase
    PATCH_PHASE=args.patch_phase
    POV_METADATA_DIR = args.pov_metadata_dir
    PATCH_WORKSPACE_DIR = args.patch_workspace_dir
    global CLAUDE_MODEL, OPENAI_MODEL
    if args.model:
        CLAUDE_MODEL = args.model
        OPENAI_MODEL = args.model
        MODELS = [args.model]
    print(f"DEBUG: Global MODELS = {MODELS}")
    print(f"DEBUG: Global DO_PATCH_ONLY = {DO_PATCH_ONLY}")
    print(f"DEBUG: Global FULL_SCAN = {FULL_SCAN}")
    print(f"DEBUG: Global MAX_ITERATIONS = {MAX_ITERATIONS}")
    print(f"DEBUG: Global FUZZING_TIMEOUT_MINUTES = {FUZZING_TIMEOUT_MINUTES}")
    print(f"DEBUG: Global PATCHING_TIMEOUT_MINUTES = {PATCHING_TIMEOUT_MINUTES}")
    print(f"DEBUG: Global POV_METADATA_DIR = {POV_METADATA_DIR}")

    fuzzer_path = args.fuzzer_path
    sarif_path = args.sarif_path
    project_name = args.project_name
    focus = args.focus
    language = args.language
    print(f"DEBUG: fuzzer_path = {fuzzer_path}")
    print(f"DEBUG: sarif_path = {sarif_path}")
    print(f"DEBUG: project_name = {project_name}")
    print(f"DEBUG: focus = {focus}")
    print(f"DEBUG: language = {language}")

    fuzzer_name = os.path.basename(fuzzer_path)
    fuzz_dir = os.path.dirname(fuzzer_path)

    task_detail = load_task_detail(fuzz_dir)
    sarif_broadcast = load_sarif_broadcast(sarif_path)

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

    log_file = setup_logging(fuzzer_name)    
    
    pov_success = False  # Default value in case the block below doesn't set it

    # Wrap your entire main execution in a root span
    with tracer.start_as_current_span("sarif_pov_fuzzing") as span:
        span.set_attribute("crs.action.category", "fuzzing")
        span.set_attribute("crs.action.name", "sarif_fuzzing")
        span.set_attribute("service.name", "sarif_pov0")
        span.set_attribute("fuzzer.path", f"{fuzzer_path}")

        if task_detail:
            for key, value in task_detail["metadata"].items():
                span.set_attribute(key, value)   
        
        fuzzer_code, fuzzer_src_path = find_fuzzer_source(log_file, fuzzer_path, project_name, project_src_dir, language)
        
        sarif_targets = find_sarif_target_functions(sarif_broadcast)
        if len(sarif_targets) == 0:
            sarif_targets = find_sarif_target_functions_with_llm(project_src_dir,sarif_broadcast)

        all_reachable_funcs = extract_reachable_functions_from_analysis_service(fuzzer_path,fuzzer_src_path,focus,project_src_dir,language.startswith('j'))

        # Check if targets are reachable
        is_reachable, reachable_targets = check_if_targets_reachable(sarif_targets, all_reachable_funcs)
        log_message(log_file, f"sarif_targets: {sarif_targets}")
        log_message(log_file, f"reachable_targets: {reachable_targets}")

        if not is_reachable:
            log_message(log_file, f"sarif_targets are not reachable by fuzzer, let's try another method...")
            # it could be the case that, let's try again with llm 
            sarif_targets_x = find_sarif_target_functions_with_llm(project_src_dir,sarif_broadcast)
            log_message(log_file, f"sarif_targets_x: {sarif_targets_x}")
            is_reachable, reachable_targets = check_if_targets_reachable(sarif_targets_x, all_reachable_funcs)
            log_message(log_file, f"reachable_targets_x: {reachable_targets}")

        if not is_reachable:
            log_message(log_file, f"Fuzzer cannot reach the target functions described in SARIF broadcast")
            # log_message(log_file, f"all_reachable_funcs: {all_reachable_funcs}")
            # it's possible that reachable analysis is incorrect
            # if No POV has been found, then set reachable_targets to sarif_targets
            if not has_pov_submitted_for_task(log_file):
                log_message(log_file, f"[SARIF] setting reachable_targets to sarif_targets: {sarif_targets}")
                reachable_targets = sarif_targets
            else:
                log_message(log_file, f"[SARIF] Early return because target function not reachable and POV already found!")
                return 0  # Early return if not reachable

        log_message(log_file, f"Starting Sarif POV Strategy sarif_pov0.py for fuzzer: {fuzzer_path}")
        log_message(log_file, f"Project directory: {project_dir}")

        try:
            pov_success, pov_metadata = doSarifPoV(log_file, sarif_broadcast, fuzzer_src_path,fuzzer_code,fuzzer_path,fuzzer_name,sanitizer,project_dir,project_name,focus, reachable_targets, language, args.check_patch_success)

        except Exception as e:
            span.record_exception(e)

        span.set_attribute("crs.pov.success", pov_success)
    
    return 0 if pov_success else 1

if __name__ == "__main__":
    sys.exit(main())
