# patch strategies for delta scan
#!/usr/bin/env python3
"""
Patch Strategy: LLM-guided patch generation for delta scans
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

# TAMU AI support
try:
    from tamu_ai import USE_TAMU_AI, setup_tamu_env, to_tamu_model, get_tamu_fallback, call_tamu_api
    if USE_TAMU_AI:
        setup_tamu_env()
except ImportError:
    USE_TAMU_AI = False

import openlit
from opentelemetry import trace
# Initialize openlit
openlit.init(application_name="afc-crs-all-you-need-is-a-fuzzing-brain")
# Acquire a tracer
tracer = trace.get_tracer(__name__)

UNHARNESSED = False

GLOBAL_FUNCTION_METADATA = {}
GLOBAL_RELEVANT_SOURCE_FILES = set()
USE_CONTROL_FLOW = False
POV_METADATA_DIR = "successful_povs"
POV_SUCCESS_DIR = f"/tmp/{POV_METADATA_DIR}"
PATCH_METADATA_DIR = "successful_patches"
PATCH_SUCCESS_DIR = f"/tmp/{PATCH_METADATA_DIR}"

PATCH_WORKSPACE_DIR = "patch_workspace"
SUCCESS_PATCH_METADATA_FILE="successful_patch_metadata.json"

# Constants
MAX_ITERATIONS = 5
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
GEMINI_MODEL_FLASH_LITE = "gemini-2.5-flash-lite-preview-06-17"
GROK_MODEL = "xai/grok-3-beta"
MODELS = [CLAUDE_MODEL, OPENAI_MODEL, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25]
CLAUDE_MODEL_SONNET_45 = "claude-sonnet-4-5-20250929"
CLAUDE_MODEL_OPUS_4 = "claude-opus-4-20250514"
MODELS = [CLAUDE_MODEL_OPUS_4, CLAUDE_MODEL, OPENAI_MODEL, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25]
CLAUDE_MODEL = CLAUDE_MODEL_SONNET_45
OPENAI_MODEL = CLAUDE_MODEL_SONNET_45
MODELS = [CLAUDE_MODEL_SONNET_45, CLAUDE_MODEL_OPUS_4]

def get_fallback_model(current_model, tried_models):
    """Get a fallback model that hasn't been tried yet"""
    # Define model fallback chains
    fallback_chains = {
        GEMINI_MODEL_PRO_25: [OPENAI_MODEL_O3, CLAUDE_MODEL, CLAUDE_MODEL_35, OPENAI_MODEL_41],   
        OPENAI_MODEL_41: [OPENAI_MODEL_O4_MINI, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25],   
        OPENAI_MODEL: [GEMINI_MODEL_PRO_25, OPENAI_MODEL_41, OPENAI_MODEL_O3],             
        CLAUDE_MODEL: [CLAUDE_MODEL_SONNET_45,OPENAI_MODEL, OPENAI_MODEL_O3, GEMINI_MODEL_PRO_25],   
        OPENAI_MODEL_O3: [CLAUDE_MODEL_OPUS_4, CLAUDE_MODEL, GEMINI_MODEL_PRO_25],             
        # Default fallbacks
        "default": [CLAUDE_MODEL, OPENAI_MODEL, CLAUDE_MODEL_SONNET_45, OPENAI_MODEL_41, CLAUDE_MODEL_OPUS_4, OPENAI_MODEL_O3,GEMINI_MODEL_PRO_25]
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
    patch_status = "patch_only"
    scan_type = "delta_scan"
    
    timestamp = int(time.time())
    log_file = os.path.join(LOG_DIR, f"xs0_{fuzzer_name}_{patch_status}_{scan_type}_{timestamp}.log")
    
    # Log initial configuration
    with open(log_file, "w") as f:
        f.write(f"Patching Strategy: Delta Scan\n")
        f.write(f"Fuzzer: {fuzzer_name}\n")
        f.write(f"Timestamp: {timestamp} ({datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')})\n")
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

def call_gemini_api(log_file, messages, model_name) -> (str, bool):
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

    # TAMU AI: bypass litellm, call TAMU API directly
    if USE_TAMU_AI:
        tamu_model = to_tamu_model(model_name)
        log_message(log_file, f"TAMU AI mode: using {tamu_model} via direct HTTP")
        max_retries = 5
        tried = {tamu_model}
        for attempt in range(max_retries):
            try:
                text, ok = call_tamu_api(messages, tamu_model)
                end_time = time.time()
                log_message(log_file, f"TAMU API call to {tamu_model} took {end_time - start_time:.1f}s")
                return text, ok
            except Exception as e:
                log_message(log_file, f"TAMU API attempt {attempt+1}/{max_retries} failed: {e}")
                fallback = get_tamu_fallback(tamu_model, tried)
                if fallback and attempt < max_retries - 1:
                    log_message(log_file, f"TAMU AI: switching to {fallback}")
                    tamu_model = fallback
                    tried.add(tamu_model)
                elif attempt >= max_retries - 1:
                    log_message(log_file, f"TAMU AI: all attempts failed")
                    return f"TAMU API error: {e}", False
        return "TAMU API error: all retries failed", False
    
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
                if USE_TAMU_AI:
                    fallback_model = get_tamu_fallback(current_model, tried_models_in_this_call)
                else:
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
    """Call LLM with telemetry tracking."""    
    with tracer.start_as_current_span("genai") as span:
        span.set_attribute("crs.action.category", "patch_generation")
        span.set_attribute("crs.action.name", "call_llm")
        span.set_attribute("genai.model.name", f"{model_name}")

        try:
            if USE_TAMU_AI:
                response = call_litellm(log_file, messages, model_name)
            elif model_name.startswith("gemini"):
                response = call_gemini_api(log_file, messages, model_name)
            else:
                response = call_litellm(log_file, messages, model_name)
            
            return response

        except Exception as e:
            logging.error(f"Error in LLM call: {str(e)}")
            return "", False

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

def run_fuzzer_with_input(log_file, fuzzer_path, project_dir, project_name, focus, sanitizer, blob_path, is_c_project, patch_id):
    try:
        log_message(log_file, f"Running fuzzer {fuzzer_path} with blob {blob_path}")
        
        # Get the directory containing the fuzzer
        fuzzer_dir = os.path.dirname(fuzzer_path)
        fuzzer_name = os.path.basename(fuzzer_path)

        if True:
            out_dir = os.path.join(project_dir, "fuzz-tooling", "build", "out", f"{project_name}-{sanitizer}-{patch_id}")
            work_dir = os.path.join(project_dir, "fuzz-tooling", "build", "work", f"{project_name}-{sanitizer}-{patch_id}")
            
            unique_id = str(uuid.uuid4())[:8]  # Use first 8 chars of UUID for brevity
            unique_blob_name = f"x_{unique_id}.bin"
            # Try multiple approaches to make the blob accessible to Docker
            docker_blob_path = os.path.join(out_dir, unique_blob_name)            
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
                    "-v", f"{out_dir}:/out",
                    "-v", f"{work_dir}:/work",
                    f"aixcc-afc/{project_name}",
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
        # Add timeout indicator only if DETECT_TIMEOUT_CRASH=1
        if os.environ.get("DETECT_TIMEOUT_CRASH") == "1":
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

def submit_patch_to_endpoint(log_file, pov_signature, patch_diff):
    """
    Submit a patch to the competition API.
    
    Args:
        log_file: Log file handle
        patch_diff: The patch diff as a string
        
    Returns:
        bool: True if submission was successful, False otherwise
    """    
    log_message(log_file, "Submitting patch to competition API")
    
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
    
    # Encode the patch diff as base64
    patch_bytes = patch_diff.encode('utf-8')
    patch_base64 = base64.b64encode(patch_bytes).decode('utf-8')
    
    # Create the patch submission payload
    submission = {
        "pov_signature": pov_signature,
        "diff": patch_diff,
        "patch": patch_base64,
    }
        
    try:
        # Create the request
        url = f"{submission_endpoint}/v1/task/{task_id}/patch/"
        NEW_FUZZER_SRC_PATH = os.environ.get("NEW_FUZZER_SRC_PATH", "")
        if NEW_FUZZER_SRC_PATH:
            submission["unharnessed"] = True   
            url = f"{submission_endpoint}/v1/task/{task_id}/freeform/patch/"

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
            timeout=30  # 30 second timeout
        )
        
        # Check response
        if response.status_code == 200:
            log_message(log_file, f"Successfully submitted patch to competition API: {response.status_code}")
            
            # Try to parse and log the response
            try:
                response_data = response.json()
                patch_id_x = response_data.get("patch_id", "unknown")
                log_message(log_file, f"Patch ID: {patch_id_x}")
                log_message(log_file, f"Response: {json.dumps(response_data, indent=2)}")
                
                response_status = response_data["status"]
                if response_status == "duplicate":
                    log_message(log_file, f"PATCH duplicated!")
                    # return False

                api_url = f"https://api.tail7e9b4c.ts.net/v1/task/{task_id}/patch/{patch_id_x}"

                max_wait_sec = 900          # 5 min
                poll_interval = 30           # 5 s
                deadline = time.time() + max_wait_sec

                while time.time() < deadline:
                    try:
                        patch_response = requests.get(
                            api_url,
                            headers=headers,
                            auth=auth,
                            timeout=30,
                        )
                        patch_response.raise_for_status()
                        status = patch_response.json().get("status", "").lower()
                        log_message(log_file, f"PATCH status = {status}")

                        if status == "passed":
                            # Save patch ID to a file for reference
                            try:
                                with open("patch_id.txt", "w") as f:
                                    f.write(patch_id_x)
                            except Exception as e:
                                log_message(log_file, f"Warning: Failed to save patch ID to file: {str(e)}")
                            return True
                        if status == "failed":
                            log_message(log_file, f"PATCH failed: {api_url}")
                            return False
                    except Exception as exc:      # network / parsing errors
                        log_message(log_file, f"POV poll error: {exc}")

                    time.sleep(poll_interval)

                # Timed out
                log_message(log_file, f"PATCH status check timed out after {max_wait_sec}s: {api_url}")
                return True

            except Exception as e:
                log_message(log_file, f"Warning: Failed to parse response JSON: {str(e)}")
                log_message(log_file, f"Raw response: {response.text}")
                return True  # Still return True since the submission was accepted
        else:
            log_message(log_file, f"Patch submission failed with status {response.status_code}")
            log_message(log_file, f"Response: {response.text}")
            return False
            
    except Exception as e:
        log_message(log_file, f"Error submitting patch to endpoint: {str(e)}")
        return False

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

def _pick_fallback_jar(jar_dir: str) -> str | None:
    """Return a plausible project jar from jar_dir, skipping helper jars."""
    helper_patterns = ("jacoco", "jazzer", "metrics-")
    for jar in sorted(glob.glob(os.path.join(jar_dir, "*.jar"))):
        base = os.path.basename(jar)
        if not any(base.startswith(p) for p in helper_patterns):
            return jar
    return None

def construct_get_target_functions_prompt(context_info: str, crash_log: str):
    prompt = f"""
Your task is to identify all potentially vulnerable functions from a code commit and a crash log.

Background:
- The commit introduces a vulnerability.
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
    
    prompt = construct_get_target_functions_prompt(context_info,crash_log)
    
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


def replace_function(log_file, project_src_dir, file_path, func_name, new_func_code):
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

        with tracer.start_as_current_span("analysis_service.request") as span:
            span.set_attribute("crs.action.category", "static_analysis")
            span.set_attribute("crs.action.name", f"extract_function_metadata")
            span.set_attribute("payload", f"{payload}")

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

def find_function_metadata(log_file, target_functions, project_src_dir0, project_src_dir, project_name, focus="", language='c'):
    """
    Find metadata for target functions using clang.
    
    Args:
        log_file: Log file path
        target_functions: List of target function names
        project_src_dir: Project directory
        focus: Optional focus hint
        
    Returns:
        dict: Metadata for the target functions
    """
    function_metadata =  try_load_function_metadata_from_analysis_service(log_file,target_functions,project_src_dir0,focus)
    if function_metadata:
        return function_metadata
    function_metadata = {}
    
    extension = '.c' if language == 'c' else '.java'

    for target in target_functions:
        file_path, function_name = target.split(':', 1)
        log_message(log_file,f"Looking for function {function_name} in {file_path}")
        # If focus is provided, check that file first
        potential_file = os.path.join(project_src_dir, file_path)
        if not os.path.exists(potential_file) and file_path.startswith("/src/"):
            # Extract the file name after /src/project_name/
            parts = file_path.split('/')
            if len(parts) >= 3:
                # Get everything after the project name
                relative_path = '/'.join(parts[3:])
                potential_file = os.path.join(project_src_dir, relative_path)

        if not os.path.exists(potential_file):
            # Extract the basename (filename without path)
            file_basename = os.path.basename(file_path)
            found_file = False    
            for root, dirs, files in os.walk(project_src_dir):
                for file in files:
                    # log_message(log_file,f"file_basename: {file_basename} file: {file}")
                    # Check if the file matches the basename we're looking for
                    if file == file_basename:
                        potential_file = os.path.join(root, file)
                        # log_message(log_file, f"Found file by basename match: {potential_file}")
                        found_file = True
                        break
                if found_file:
                    break

        if os.path.exists(potential_file):
            log_message(log_file,f"Found file at {potential_file}")
            metadata_list = extract_function_using_fundef(potential_file, function_name)
            
            if metadata_list:
                rel_path = os.path.relpath(potential_file, project_src_dir)
                # Handle multiple functions with the same name
                if isinstance(metadata_list, list):
                    for i, metadata in enumerate(metadata_list):
                        # Create a unique key for each function with the same name
                        unique_key = f"{function_name}_{i+1}"
                        metadata['file_path'] = rel_path
                        function_metadata[unique_key] = metadata
                        log_message(log_file, f"Found function {unique_key} in {potential_file}")
                else:
                    # Single function case (though this shouldn't happen with our updated code)
                    metadata_list['file_path'] = rel_path
                    function_metadata[function_name] = metadata_list
                    log_message(log_file, f"Found function {function_name} in {potential_file}. rel_path: {rel_path}")
                continue
            else:
                log_message(log_file,f"Function {function_name} not found in {project_src_dir}")            
        else:
            # TODO first, search files in GLOBAL_RELEVANT_SOURCE_FILES
            candidate_files: list[str] = []
            for rel in GLOBAL_RELEVANT_SOURCE_FILES:
                abs_path = rel if os.path.isabs(rel) else os.path.join(project_src_dir, rel)
                if abs_path.endswith(extension) and os.path.exists(abs_path):
                    candidate_files.append(abs_path)
            
            for file_path in candidate_files:
                log_message(log_file, f"Checking candidate file {file_path}")    
                metadata_list = extract_function_using_fundef(file_path, function_name)
                if not metadata_list:
                    continue

                rel_path = os.path.relpath(file_path, project_src_dir)
                if isinstance(metadata_list, list):
                    for i, metadata in enumerate(metadata_list):
                        unique_key = f"{function_name}_{i+1}"
                        metadata['file_path'] = rel_path
                        function_metadata[unique_key] = metadata
                        log_message(log_file, f"Found function unique_key {unique_key} in {file_path}")
                else:
                    # Single function case (though this shouldn't happen with our updated code)
                    metadata_list['file_path'] = rel_path
                    function_metadata[function_name] = metadata_list
                    log_message(log_file, f"Found function {function_name} in {file_path}") 
                break

            # if not found, then search files in project_src_dir
            for root, dirs, files in os.walk(project_src_dir):
                for file in files:
                    if file.endswith(extension) and not file.startswith("Crash_"):
                        file_path = os.path.join(root, file)
                        # Skip test files
                        if any(x in file_path.lower() for x in ["/test/", "/tests/", "/docs/"]) or file.lower().startswith("test"):
                            continue

                        log_message(log_file,f"Checking file {file_path}")
                        metadata_list = extract_function_using_fundef(file_path, function_name)
                        
                        if metadata_list:
                            rel_path = os.path.relpath(file_path, project_src_dir)
                            
                            # Handle multiple functions with the same name
                            if isinstance(metadata_list, list):
                                for i, metadata in enumerate(metadata_list):
                                    # Create a unique key for each function with the same name
                                    unique_key = f"{function_name}_{i+1}"
                                    metadata['file_path'] = rel_path
                                    function_metadata[unique_key] = metadata
                                    log_message(log_file, f"Found function {unique_key} in {rel_path}")
                            else:
                                # Single function case (though this shouldn't happen with our updated code)
                                metadata_list['file_path'] = rel_path
                                function_metadata[function_name] = metadata_list
                                log_message(log_file, f"Found function {function_name} in {rel_path}")
                            break
                if function_name in function_metadata:
                    break
    
    # log_message(log_file,f"Found metadata for {len(function_metadata)} functions")
    # for func_name, metadata in function_metadata.items():
    #     log_message(log_file,f"Function: {func_name}")
    #     log_message(log_file,f"  File: {metadata['file_path']}")
    #     log_message(log_file,f"  Lines: {metadata['start_line']}-{metadata['end_line']}")
    #     log_message(log_file,f"  Content length: {len(metadata['content'])}")
    
    return function_metadata

def apply_patch(log_file, patch_code_dict, project_dir, project_src_dir, language, pov_metadata, patch_id):
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
            log_message(log_file, f"{func_name} is in GLOBAL_FUNCTION_METADATA")
            metadata = GLOBAL_FUNCTION_METADATA[func_name]
            file_path = os.path.join(project_src_dir, metadata['file_path'])
            log_message(log_file, f"Replacing function '{func_name}' in '{file_path}'")
            success = replace_function(log_file, project_src_dir, file_path, func_name, new_code)
            
            if success:
                continue
            else:
                log_message(log_file, f"Failed to replace function '{func_name}'")
                # return False, "", f"Failed to replace function '{func_name}'"
        else:
            log_message(log_file, f"{func_name} is NOT in GLOBAL_FUNCTION_METADATA!!")

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
            success = replace_function(log_file, project_src_dir, file_path, func_name, new_code)
            
            if success:
                continue
            else:
                log_message(log_file, f"Failed to replace function '{func_name}'")
                # return False, "", f"Failed to replace function '{func_name}'"
     
        # If we get here, the function wasn't found in metadata, so we need to find it
        log_message(log_file, f"Function '{func_name}' not found in metadata; attempting to find it...")
  
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
     
                            success = replace_function(log_file, project_src_dir, file_path, func_name, new_code)
                            
                            if success:
                                found = True
                                break
                            else:
                                log_message(log_file, f"Failed to replace function '{func_name}'")
                                # return False, "", f"Failed to replace function '{func_name}'"
            
            if found:
                break
        
        if not found:
            log_message(log_file, f"Function '{func_name}' not found in any source file; skipping")
            if len(patch_code_dict) == 1:
                return False, "", f"Function '{func_name}' not found in any source file"

    # Rebuild the project
    if True:        
        project_name = pov_metadata["project_name"]
        sanitizer = pov_metadata["sanitizer"]
        
        build_success = True
        build_output = ""
        build_error = ""

        log_message(log_file, f"Building with {sanitizer} sanitizer...")
        
        project_sanitizer_name=f"{project_name}-{sanitizer}-{patch_id}"

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
            f"aixcc-afc/{project_name}"
        ]

        if UNHARNESSED:
            task_dir_build_sh_path = os.path.join(project_dir,f"build-{sanitizer}.sh")
            if os.path.exists(task_dir_build_sh_path):
                log_message(log_file, f"Found build.sh at {task_dir_build_sh_path}, adding volume mount for UNHARNESSED task.")
                try:
                    image_name_index = cmd_args.index(f"aixcc-afc/{project_name}")
                    cmd_args.insert(image_name_index, f"{task_dir_build_sh_path}:/src/build.sh")
                    cmd_args.insert(image_name_index, "-v")
                except ValueError:
                        log_message(log_file, f"Warning: Could not find image name {f'aixcc-afc/{project_name}'} to insert -v for build.sh. Appending instead.")
                        cmd_args.append("-v")
                        cmd_args.append(f"{task_dir_build_sh_path}:/src/build.sh")
            else:
                log_message(log_file, f"Warning: build.sh not found at {task_dir_build_sh_path} for UNHARNESSED task. Volume mount will NOT be added.")

        # Convert array to string with proper escaping
        cmd_string = " ".join([arg if " " not in arg else f'"{arg}"' for arg in cmd_args])
        print(f"Build sanitizer cmd: {cmd_string}")
        build_start_time = time.time()

        try:
            result = subprocess.run(
                cmd_args,
                shell=False,
                env=os.environ.copy(),
                cwd=project_dir,
                capture_output=True,
                text=True
            )
            build_end_time = time.time()
            build_duration = build_end_time - build_start_time
            print(f"Fuzzer build completed in {build_duration:.2f} seconds ({build_duration/60:.2f} minutes)")
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
    Extracts code from JSON dictionary where keys are function names and values are code blocks:
       {
         "ngx_mail_smtp_noop": "static ngx_int_t\\nngx_mail_smtp_noop(...) { ... }",
         "ngx_mail_smtp_auth_state": "static ngx_int_t\\nngx_mail_smtp_auth_state(...) { ... }"
       }
    
    Returns a list of (function_name, code_block).
    """
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

### Context Information
The vulnerability is introduced by the following commit:
{commit_diff}

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
    # Strip project_src_dir from file_path to make it more concise
    relative_file_path = file_path

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
                        log_message(log_file, f"Including entire file: {file_path} ({len(file_content)} chars)")
                        if project_src_dir and file_path.startswith(project_src_dir):
                            relative_file_path = file_path[len(project_src_dir):]
                            # Remove leading slash if present
                            relative_file_path = relative_file_path.lstrip('/')

                        functions_metadata_str += f"File: {relative_file_path}\nContent:\n{file_content}\n\n"
                        files_included.add(file_path)
                        remaining_length -= len(file_content)
        except Exception as e:
            log_message(log_file, f"Error reading file {file_path}: {str(e)}")
    
    # For files that were too large to include entirely, include just the relevant functions
    for file_path, functions in functions_by_file.items():
        if file_path in files_included:
            continue  # Skip files we've already included in full
            
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

def fix_patch_file_path(project_src_dir: str, file_path: str) -> str:
    """
    Make sure `file_path` points inside the *patched* source tree
    (`project_src_dir`).  If it already does, return unchanged.
    Otherwise, rewrite it so the relative part after the common
    “patch_workspace” root is appended to `project_src_dir`.

    Examples
    --------
    project_src_dir = /…/round-exhibition2-libpng_patch_1234
    file_path       = /…/round-exhibition2-libpng/pngrutil.c
    result          = /…/round-exhibition2-libpng_patch_1234/pngrutil.c
    """
    # Already correct?
    if file_path.startswith(project_src_dir):
        return file_path

    try:
        # Common ancestor (usually “…/patch_workspace”)
        common_root = os.path.commonpath([project_src_dir, file_path])

        # Part of the path after that root, split into components
        rel_parts = os.path.relpath(file_path, common_root).split(os.sep)

        # Drop the first component (old project dir) and rebuild under patched dir
        corrected = os.path.join(project_src_dir, *rel_parts[1:]) if len(rel_parts) > 1 \
                    else os.path.join(project_src_dir, rel_parts[0])

        # Prefer the corrected path if it exists; otherwise use the basename fallback
        return corrected if os.path.exists(corrected) \
               else os.path.join(project_src_dir, os.path.basename(file_path))
    except Exception:
        # Fallback: simply put the basename in the patched tree
        return os.path.join(project_src_dir, os.path.basename(file_path))

def validate_patch_by_functionality_test(log_file, test_sh_path: str,
                                         project_src_dir: str,
                                         project_name: str) -> (bool, str):
    """
    Run <project>/test.sh inside the official OSS-Fuzz/AFC Docker image and
    decide whether the patch is functionally correct.

    Returns (True, combined_output)  if the script exits 0
            (False, combined_output) otherwise.
    """
    log_message(log_file,
                f"[FUNC-TEST] test.sh = {test_sh_path}\n"
                f"[FUNC-TEST] project_src_dir = {project_src_dir}")

    if not os.path.exists(test_sh_path):
        log_message(log_file, "[FUNC-TEST] test.sh not found → skip test")
        return True, "test.sh not present – skipped"

    # Build docker run command
    docker_cmd = [
        "docker", "run", "--rm",
        "--platform", "linux/amd64",
        "-e", "ARCHITECTURE=x86_64",
        "-v", f"{project_src_dir}:/src/{project_name}",
        "-v", f"{test_sh_path}:/src/{project_name}/test.sh",
        f"aixcc-afc/{project_name}",
        f"/src/{project_name}/test.sh",
    ]

    log_message(log_file, "[FUNC-TEST] Docker command:\n  " + " ".join(docker_cmd))

    try:
        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=180      # give test up to 3 min
        )
        combined_output = f"{result.stdout}\n{result.stderr}"
        log_message(log_file,
                    f"[FUNC-TEST] exit-code = {result.returncode}\n"
                    f"[FUNC-TEST] output-len = {len(combined_output)}")

        if result.returncode == 0:
            log_message(log_file, "[FUNC-TEST] ✅  functionality test PASSED")
            return True, combined_output
        else:
            log_message(log_file, f"[FUNC-TEST] ❌  functionality test FAILED. {combined_output}")
            return False, combined_output

    except subprocess.TimeoutExpired as e:
        log_message(log_file,
                    f"[FUNC-TEST] ⏰  timeout after {e.timeout}s; killing container")
        combined_output = f"{e.stdout or ''}\n{e.stderr or ''}"
        return False, combined_output

    except Exception as e:
        log_message(log_file, f"[FUNC-TEST] ⚠️  unexpected error: {e}")
        return False, str(e)

def doPatch(log_file, fuzzer_path, project_dir, project_name, focus, sanitizer, language, pov_metadata, model_name, attempt_dir):
    """
    Attempt to patch the vulnerability found by the PoV.
    
    Args:
        log_file: Log file handle
        fuzzer_path: Path to the fuzzer
        project_dir: Project directory
        focus: Focus area
        pov_metadata: Metadata about the successful PoV
        model_name: The AI model to use for patching
        attempt_dir: Directory to store artifacts for this patch attempt
        
    Returns:
        bool: True if patching was successful, False otherwise
    """
    log_message(log_file, f"Starting patching process for vulnerability using model {model_name}")
    # Read the conversation history and fuzzer output from the successful PoV
    conversation_file = os.path.join(POV_SUCCESS_DIR, pov_metadata.get("conversation", ""))
    fuzzer_output_file = os.path.join(POV_SUCCESS_DIR, pov_metadata.get("fuzzer_output", ""))
    test_blob_file = os.path.join(POV_SUCCESS_DIR, pov_metadata.get("blob_file", ""))
    log_message(log_file, f"test_blob_file: {test_blob_file}")
    project_src_dir0 = os.path.join(project_dir, focus)
    log_message(log_file, f"project_src_dir0: {project_src_dir0}")
    project_src_dir_x = os.path.join(project_dir, f"{focus}-{sanitizer}")
    log_message(log_file, f"project_src_dir_x: {project_src_dir_x}")
    patch_id = str(uuid.uuid4())[:8]  # Use first 8 chars of UUID for brevity
    project_src_dir = os.path.join(project_dir, f"{focus}_patch_{patch_id}")
    log_message(log_file, f"project_src_dir: {project_src_dir}")

    if not os.path.exists(project_src_dir_x):
        log_message(log_file, f"project_src_dir_x: {project_src_dir_x} does not exist!")
        return False, patch_id

    #copy all the files in project_dir0 to project_src_dir
    shutil.copytree(project_src_dir_x, project_src_dir)
    log_message(log_file, f"copied {project_src_dir_x} -> {project_src_dir}")
    context_info = ""
    crash_log = ""
    
    # conversation_file may not exist because POV is found by libfuzzer
    if pov_metadata.get("conversation") and os.path.exists(conversation_file):
        try:
            with open(conversation_file, 'r') as f:
                conversation = json.load(f)

                # Check if any message in the conversation contains "infinite loop"
                if any("infinite loop" in message.get("content", "") for message in conversation):
                    os.environ["DETECT_TIMEOUT_CRASH"] = "1"

                # Find the first user message
                first_user_message = None
                for message in conversation:
                    if message["role"] == "user":
                        first_user_message = message["content"]
                        break
                
                # Find the last assistant message
                last_assistant_message = None
                for message in reversed(conversation):
                    if message["role"] == "assistant":
                        last_assistant_message = message["content"]
                        break
                
                # Add the messages to context_info if found
                if first_user_message:
                    context_info += f"\nUSER: {first_user_message}\n\n"
                
                if last_assistant_message:
                    context_info += f"ASSISTANT: {last_assistant_message}\n\n"

            log_message(log_file, f"Read conversation history from {conversation_file}")
        except Exception as e:
            log_message(log_file, f"Error reading conversation history: {str(e)}")
    else:
        log_message(log_file, "No conversation history found or file doesn't exist")
            
    # print(f"fuzzer_output_file:{fuzzer_output_file}")

    # Read the fuzzer output
    if os.path.exists(fuzzer_output_file):
        try:
            with open(fuzzer_output_file, 'r') as f:
                crash_log = f.read()
            log_message(log_file, f"Read fuzzer output from {fuzzer_output_file}")
        except Exception as e:
            log_message(log_file, f"Error reading fuzzer output: {str(e)}")
    

    MAX_ATTEMPTS_PER_MODEL = 2
    target_functions = None

    for model_name_x in [OPENAI_MODEL, CLAUDE_MODEL]:
        for attempt in range(1, MAX_ATTEMPTS_PER_MODEL + 1):
            log_message(log_file, f"Trying {model_name_x} to identify target functions, attempt {attempt}/{MAX_ATTEMPTS_PER_MODEL}")
            
            target_functions = get_target_functions(log_file, context_info, crash_log, model_name_x, language)
            
            if target_functions and len(target_functions) > 0:
                log_message(log_file, f"Successfully identified target functions with {model_name_x} on attempt {attempt}")
                break  # Success, exit the inner loop
            
            log_message(log_file, f"Could not identify target functions with {model_name_x} (attempt {attempt})")
            
            if attempt < MAX_ATTEMPTS_PER_MODEL:
                # Optional: Add a short delay between attempts
                time.sleep(1)  # 1 second delay, adjust as needed
        
        if target_functions and len(target_functions) > 0:
            break  # Success, exit the outer loop too

    if not target_functions or len(target_functions) == 0:
        log_message(log_file, "Could not identify target functions, patching may fail")
        target_functions = []  # Initialize as empty list to avoid errors
    
    # Find metadata for the target functions
    function_metadata = find_function_metadata(log_file, target_functions, project_src_dir0, project_src_dir, project_name, focus, language)
    # Format the function metadata for the prompt
    # functions_metadata_str = ""
    # for func_name, metadata in function_metadata.items():
    #     functions_metadata_str += f"Function: {func_name} in file {metadata['file_path']}\n"
    #     functions_metadata_str += f"Content:\n{metadata['content']}\n\n"
    test_blob_dir = os.path.dirname(test_blob_file)
    diff_functions = extract_diff_functions_using_funtarget(project_src_dir,test_blob_dir)
    # log_message(log_file, f"diff_functions:{diff_functions}")

    if diff_functions:  # This checks if diff_functions is not None and not empty
        # Convert diff_functions into function_metadata format
        for func in diff_functions:
            func_name = func.get("function", "")
            class_name = func.get("class", "")
            file_path = func.get("file", "")
            start_line = func.get("start_line", 0)
            
            # Skip entries with empty function names
            if not func_name:
                continue
                
            # Add to function_metadata
            function_metadata[func_name] = {
                "file_path": file_path,
                "class": class_name,  # Fixed: was using file_path instead of class_name
                "content": func.get("content", ""),
                "start_line": start_line,
                "end_line": func.get("end_line", 0),
            }

    # fix file path in function_metadata
    if function_metadata:
        for func_name, metadata in function_metadata.items():
            file_path = metadata['file_path']
            if os.path.isabs(file_path) and not file_path.startswith(project_src_dir):
                metadata['file_path'] = fix_patch_file_path(project_src_dir, file_path)
            GLOBAL_RELEVANT_SOURCE_FILES.add(metadata['file_path'])

    function_metadata_copy = function_metadata
    if not function_metadata:
        log_message(log_file, "Could not find metadata for target functions, patching may fail")
    else:
        log_message(log_file, f"function_metadata:{function_metadata}")
        # Add the found metadata to the global dictionary
        GLOBAL_FUNCTION_METADATA.update(function_metadata)
        log_message(log_file, f"project_src_dir:{project_src_dir}")


    # log_message(log_file, f"GLOBAL_FUNCTION_METADATA:{GLOBAL_FUNCTION_METADATA}")

    functions_metadata_str = format_function_metadata(log_file, function_metadata, project_src_dir)

    commit_msg, commit_diff = get_commit_info(log_file, project_dir,language)

    initial_msg = INITIAL_PATCH_TEMPLATE.format(
        crash_log=crash_log,
        commit_diff=commit_diff,
        functions_metadata_str=functions_metadata_str
    )
    
    log_message(log_file, f"doPatch {model_name} initial_msg:\n{initial_msg}")

    start_time = time.time()
    end_time = start_time + (PATCHING_TIMEOUT_MINUTES * 60)
    
    # Create directories for storing artifacts
    patches_dir = os.path.join(attempt_dir, "patches")
    os.makedirs(patches_dir, exist_ok=True)
    
    messages = [{"role": "system", "content": "You are a software vulnerability patching expert."}]
    messages.append({"role": "user", "content": initial_msg})
    
    for iteration in range(1, MAX_ITERATIONS + 1):
        current_time = time.time()
        if current_time > end_time:
            log_message(log_file, f"Timeout reached after {iteration-1} iterations")
            break
            
        log_message(log_file, f"Patch iteration {iteration} with model {model_name}")
        
        # Generate patch
        patch_code_dict = generate_patch(log_file, messages, model_name)
        
        if not patch_code_dict:
            log_message(log_file, "No valid patch code generated, continuing to next iteration")
            continue
            
        #Check if all functions in patch_code_dict are in function_metadata, if not, try load from analysis server
        for func_name, new_code in patch_code_dict.items():
            print(f"checking {func_name} in function_metadata")
            if func_name not in function_metadata:
                log_message(log_file, f"Patch function {func_name} not in function_metadata, try loading from GLOBAL_FUNCTION_METADATA or analysis server")
                if func_name in GLOBAL_FUNCTION_METADATA:
                    function_metadata_x = GLOBAL_FUNCTION_METADATA[func_name]
                    function_metadata_copy.update(function_metadata_x)
                else:
                    target_functions = [f"MISSING:{func_name}"]
                    function_metadata_new = find_function_metadata(log_file, target_functions, project_src_dir0, project_src_dir, project_name, focus, language)
                    # fix file path in function_metadata_new
                    if function_metadata_new:
                        for func_name, metadata in function_metadata_new.items():
                            file_path = metadata['file_path']
                            if os.path.isabs(file_path) and not file_path.startswith(project_src_dir):
                                metadata['file_path'] = fix_patch_file_path(project_src_dir, file_path)
                            GLOBAL_RELEVANT_SOURCE_FILES.add(metadata['file_path'])

                    log_message(log_file, f"function_metadata_new: {function_metadata_new}")
                    GLOBAL_FUNCTION_METADATA.update(function_metadata_new)
                    function_metadata_copy.update(function_metadata_new)
            else:
                print(f"{func_name} is in function_metadata")

        # Save the generated patch
        patch_file = os.path.join(patches_dir, f"patch_{iteration}.json")
        with open(patch_file, "w") as f:
            json.dump(patch_code_dict, f, indent=2)
        
        # Apply the patch to the target functions
        success, stdout, stderr = apply_patch(log_file, patch_code_dict, project_dir, project_src_dir, language, pov_metadata, patch_id)

        if not success:
            log_message(log_file, f"Failed to apply patch: {stderr}")
            user_message = f"""
The patch could not be applied. Here's the error:
{truncate_output(stderr, 200)}

Please generate a valid patch that can be applied to the code.
"""
            # reset 
            reset_project_source_code(log_file, project_src_dir)

            messages.append({"role": "assistant", "content": json.dumps(patch_code_dict)})
            messages.append({"role": "user", "content": user_message})
            continue
        
        # Generate and save the diff before testing
        patch_diff = generate_diff(log_file, project_src_dir, focus, function_metadata_copy)

        # Skip if patch_diff is empty
        if not patch_diff:
            log_message(log_file, "No changes detected in diff, skipping this iteration")
            continue

        diff_file = os.path.join(patches_dir, f"patch_{iteration}.diff")
        with open(diff_file, "w") as f:
            f.write(patch_diff)
        
        is_c_project = language.startswith('c')
        crash_detected, fuzzer_output = run_fuzzer_with_input(log_file, fuzzer_path, project_dir, project_name, focus, sanitizer, test_blob_file, is_c_project, patch_id)
        fuzzer_output = filter_instrumented_lines(fuzzer_output)
        # Save fuzzer output
        fuzzer_output_path = os.path.join(patches_dir, f"fuzzer_output_{iteration}.txt")
        with open(fuzzer_output_path, "w") as f:
            f.write(fuzzer_output)
        
        tests_output = ''
        patch_validated_by_tests = True
        if not crash_detected:
            # if functionality test is available, check patch validity by test.sh
            test_sh_path = os.path.join(project_dir,"fuzz-tooling", "projects", project_name, "test.sh")
            if os.path.exists(test_sh_path):
                log_message(log_file, f"[FUNC-TEST] functionality test script found at: {test_sh_path}")
                # patch_validated_by_tests, tests_output = validate_patch_by_functionality_test(log_file, test_sh_path, project_src_dir, project_name)
            else:
                log_message(log_file, f"[FUNC-TEST] functionality test script did not exist at: {test_sh_path}")

        if not crash_detected and patch_validated_by_tests:            
            # Submit PATCH to endpoint
            pov_signature = pov_metadata.get("pov_signature", "")
            submission_result = submit_patch_to_endpoint(log_file, pov_signature, patch_diff)
            if submission_result or True: # for local test w/o submission endpoint
                # Save the successful patch to the main success directory
                os.makedirs(PATCH_SUCCESS_DIR, exist_ok=True)
                
                # Copy the diff to the success directory
                success_diff_path = os.path.join(PATCH_SUCCESS_DIR, f"patch_{model_name}_{time.strftime('%Y%m%d_%H%M%S')}.diff")
                shutil.copy(diff_file, success_diff_path)
                
                # Save the conversation history
                conversation_path = os.path.join(attempt_dir, "conversation.json")
                with open(conversation_path, "w") as f:
                    json.dump(messages, f, indent=2)
                
                # Save success metadata
                success_metadata = {
                    "model": model_name,
                    "iteration": iteration,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "patch_file": patch_file,
                    "diff_file": diff_file,
                    "fuzzer_output": fuzzer_output_path,
                    "pov_metadata": pov_metadata
                }
                
                success_metadata_path = os.path.join(attempt_dir, "success_metadata.json")
                with open(success_metadata_path, "w") as f:
                    json.dump(success_metadata, f, indent=2)
                
                # Also copy to the main success directory
                shutil.copy(success_metadata_path, os.path.join(PATCH_SUCCESS_DIR, f"success_metadata_{model_name}_{time.strftime('%Y%m%d_%H%M%S')}.json"))
            
                log_message(log_file, f"PATCH SUCCESS! Vulnerability patched on iteration {iteration}")
                log_message(log_file, "Successfully patched the vulnerability, exiting the process")
                return True, patch_id  # Return success status to the caller
            else:
                log_message(log_file, "Failed to submit PATCH to endpoint")
                
                user_message = f"""
    The patch still fails, though the fuzzer no longer crashes with the specific input. Please generate a correct patch that fixes the vulnerability against all crashing inputs, not only the given one.
"""
        else:
            log_message(log_file, "Patch failed - fuzzer still crashes")
            
            user_message = f"""
The patch did not fix the vulnerability. The fuzzer still crashes:

Fuzzer output:
{truncate_output(fuzzer_output, 200)}
"""
            user_message += """

Please analyze the crash and provide a better patch.
"""
        messages.append({"role": "assistant", "content": json.dumps(patch_code_dict)})
        messages.append({"role": "user", "content": user_message})
        if patch_diff:
            reset_project_source_code(log_file, project_src_dir)
    
    # If we get here, all patching attempts failed
    log_message(log_file, "All patching attempts failed")
    
    # Save the final conversation state
    conversation_path = os.path.join(attempt_dir, "failed_conversation.json")
    with open(conversation_path, "w") as f:
        json.dump(messages, f, indent=2)
    
    # Save failure metadata
    failure_metadata = {
        "model": model_name,
        "iterations_attempted": iteration,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "pov_metadata": pov_metadata,
        "reason": "Exceeded maximum iterations or timeout"
    }
    
    failure_metadata_path = os.path.join(attempt_dir, "failure_metadata.json")
    with open(failure_metadata_path, "w") as f:
        json.dump(failure_metadata, f, indent=2)
    
    return False, patch_id

def load_all_pov_metadata(log_file):
    """Load all POV metadata files from the success directory."""
    if not os.path.exists(POV_SUCCESS_DIR):
        log_message(log_file, f"POV metadata directory {POV_SUCCESS_DIR} does not exist")
        return []
    
    metadata_files = [f for f in os.listdir(POV_SUCCESS_DIR) if f.startswith("pov_metadata_") and f.endswith(".json")]
    if not metadata_files:
        log_message(log_file, "No POV metadata files found")
        return []
    
    log_message(log_file, f"Found {len(metadata_files)} POV metadata files")
    
    all_metadata = []
    for metadata_file in metadata_files:
        metadata_path = os.path.join(POV_SUCCESS_DIR, metadata_file)
        try:
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
                # Ensure the blob file exists
                blob_file = metadata.get("blob_file")
                if blob_file and os.path.exists(os.path.join(POV_SUCCESS_DIR, blob_file)):
                    all_metadata.append(metadata)
                else:
                    log_message(log_file, f"Blob file missing for metadata {metadata_file}, skipping")
        except Exception as e:
            log_message(log_file, f"Error loading metadata file {metadata_file}: {e}")
    
    log_message(log_file, f"Successfully loaded {len(all_metadata)} valid POV metadata entries")
    return all_metadata

def validate_patch_against_all_povs(log_file, fuzzer_path, project_dir, project_name, focus, sanitizer, all_povs, language='c', patch_id=''):
    """
    Validate the current state of the project against all POVs.
    Assumes the patch has already been applied and the project has been built.
    
    Args:
        log_file: Log file path
        fuzzer_path: Path to the fuzzer
        project_dir: Project directory
        focus: Focus area
        all_povs: List of POV metadata
        
    Returns:
        bool: True if all POVs are blocked, False otherwise
    """
    if not all_povs:
        log_message(log_file, "No POVs available for validation")
        return False
    
    # Limit to at most 5 POVs for efficiency
    MAX_POVS_TO_TEST = 5
    
    if len(all_povs) > MAX_POVS_TO_TEST:
        log_message(log_file, f"Found {len(all_povs)} POVs, selecting {MAX_POVS_TO_TEST} for validation")
        
        # Try to select a diverse set of POVs
        selected_povs = []
        
        # First, group POVs by their blob files to identify unique crashes
        blob_to_povs = {}
        for pov in all_povs:
            blob_file = pov.get("blob_file")
            if not blob_file:
                continue
            if blob_file not in blob_to_povs:
                blob_to_povs[blob_file] = []
            blob_to_povs[blob_file].append(pov)
        
        # If we have different types of crashes, select one from each type
        unique_blobs = list(blob_to_povs.keys())
        
        # If we have more unique crashes than our limit, select the first ones
        # (which are likely the most important ones discovered earlier)
        if len(unique_blobs) > MAX_POVS_TO_TEST:
            unique_blobs = unique_blobs[:MAX_POVS_TO_TEST]
        
        # Select one POV from each unique crash
        for blob in unique_blobs:
            selected_povs.append(blob_to_povs[blob][0])
        
        # If we still have room, add more POVs
        if len(selected_povs) < MAX_POVS_TO_TEST and len(all_povs) > len(selected_povs):
            # Add POVs that weren't already selected
            remaining_povs = [p for p in all_povs if p not in selected_povs]
            selected_povs.extend(remaining_povs[:MAX_POVS_TO_TEST - len(selected_povs)])
        
        log_message(log_file, f"Selected {len(selected_povs)} POVs for validation")
        all_povs = selected_povs
    else:
        log_message(log_file, f"Validating patch against all {len(all_povs)} POVs")
    
    # Test each POV against the patched binary
    all_povs_blocked = True
    for i, pov_metadata in enumerate(all_povs):
        log_message(log_file, f"Testing POV {i+1}/{len(all_povs)}")
        
        # Get the blob file path
        blob_file = pov_metadata.get("blob_file")
        if not blob_file:
            log_message(log_file, f"No blob file in metadata for POV {i+1}, skipping")
            continue
        
        blob_path = os.path.join(POV_SUCCESS_DIR, blob_file)
        if not os.path.exists(blob_path):
            log_message(log_file, f"Blob file {blob_file} not found, skipping")
            continue
        
        # Run the fuzzer with the POV input
        is_c_project = language.startswith('c')
        crash_detected, fuzzer_output = run_fuzzer_with_input(log_file, fuzzer_path, project_dir, project_name, focus, sanitizer, blob_path, is_c_project, patch_id)
        fuzzer_output = filter_instrumented_lines(fuzzer_output)
        if crash_detected:
            log_message(log_file, f"POV {i+1} still crashes the patched binary!")
            log_message(log_file, f"Fuzzer output: {fuzzer_output}")
            all_povs_blocked = False
            break
        else:
            log_message(log_file, f"POV {i+1} successfully blocked by the patch")
    
    if all_povs_blocked:
        log_message(log_file, "Patch successfully blocks all tested POVs!")
    else:
        log_message(log_file, "Patch does not block all tested POVs")
    
    return all_povs_blocked

def doPatchUntilSuccess(log_file, fuzzer_path, project_dir, project_name, focus, sanitizer, language, pov_metadata=None):
    """
    Repeatedly attempt to patch the vulnerability until success or max iterations reached.
    
    Args:
        log_file: Log file path
        fuzzer_path: Path to the fuzzer
        project_dir: Project directory
        focus: Focus area
        pov_metadata: Metadata about the PoV (optional, if None, all POVs will be loaded)
        
    Returns:
        bool: True if patching was successful, False otherwise
    """
    log_message(log_file, f"Starting patching process with max {MAX_ITERATIONS} iterations")
    
    # Load all POVs if not provided
    all_povs = []
    
    if pov_metadata is None:
        all_povs = load_all_pov_metadata(log_file)
        if not all_povs:
            log_message(log_file, "No POVs found for patching")
            return False
        log_message(log_file, f"Loaded {len(all_povs)} POVs for patch validation")
    else:
        # If a specific POV was provided, use it but also load others for validation
        all_povs = load_all_pov_metadata(log_file)
        if not all_povs:
            # If no other POVs were found, just use the provided one
            all_povs = [pov_metadata]
            log_message(log_file, "Using only the provided POV for patch validation")
        else:
            log_message(log_file, f"Using provided POV for patch generation and {len(all_povs)} POVs for validation")
    
    # Select a primary POV for patch generation
    primary_pov = pov_metadata if pov_metadata else all_povs[0]
    log_message(log_file, f"Using POV {primary_pov.get('blob_file', 'unknown')} as primary for patch generation")
    
    # Create a directory for patch attempts
    patch_attempts_dir = os.path.join(project_dir, "patch_attempts")
    os.makedirs(patch_attempts_dir, exist_ok=True)
    
    # Track which models we've tried
    tried_models = set()
    
    for iteration in range(1, MAX_ITERATIONS + 1):
        log_message(log_file, f"Patch attempt {iteration}/{MAX_ITERATIONS}")
        
        # Select a model to use for this iteration
        # Start with more capable models, then try others if needed
        available_models = MODELS
        
        # Filter out models we've already tried
        untried_models = [model for model in available_models if model not in tried_models]
        
        # If we've tried all models, start over
        if not untried_models:
            log_message(log_file, "All models have been tried, starting over")
            tried_models.clear()
            untried_models = available_models
        
        # Select the next model
        model_name = untried_models[0]
        tried_models.add(model_name)
        
        log_message(log_file, f"Using model {model_name} for patch attempt {iteration}")
        
        # Create a directory for this patch attempt
        attempt_dir = os.path.join(patch_attempts_dir, f"attempt_{iteration}_{model_name}")
        os.makedirs(attempt_dir, exist_ok=True)
        
        # Copy the log file to the attempt directory
        attempt_log = os.path.join(attempt_dir, "patch_log.txt")
        with open(attempt_log, "w") as f:
            f.write(f"Patch attempt {iteration} using model {model_name}\n")
            f.write(f"Primary PoV metadata: {json.dumps(primary_pov, indent=2)}\n")
            f.write(f"Total POVs for validation: {len(all_povs)}\n")
        
        # Attempt to patch using the primary POV
        patch_success, patch_id = doPatch(attempt_log, fuzzer_path, project_dir, project_name, focus, sanitizer, language, primary_pov, model_name, attempt_dir)
        
        # If patch generation was successful, validate against all POVs
        if patch_success:
            log_message(log_file, f"Patch generated successfully, validating against all {len(all_povs)} POVs")
            all_povs_blocked = validate_patch_against_all_povs(attempt_log, fuzzer_path, project_dir, project_name, focus, all_povs, language, patch_id)
            
            if all_povs_blocked:
                log_message(log_file, f"Successfully patched vulnerability on attempt {iteration} using model {model_name}")
                log_message(log_file, f"All {len(all_povs)} POVs are blocked by the patch")
                
                # Save successful patch metadata
                success_metadata = {
                    "iteration": iteration,
                    "model_name": model_name,
                    "primary_pov": primary_pov,
                    "total_povs_blocked": len(all_povs),
                    "timestamp": datetime.datetime.now().isoformat(),
                    "attempt_dir": attempt_dir
                }
                
                success_file = os.path.join(PATCH_SUCCESS_DIR, SUCCESS_PATCH_METADATA_FILE)
                with open(success_file, "w") as f:
                    json.dump(success_metadata, f, indent=2)
                    
                log_message(log_file, f"Saved successful patch metadata to {success_file}")
                
                # Append the attempt log to the main log
                with open(attempt_log, "r") as src, open(log_file, "a") as dst:
                    dst.write(f"\n--- Successful Patch Attempt {iteration} Log ---\n")
                    dst.write(src.read())
                    dst.write("\n--- End of Successful Patch Attempt Log ---\n")
                
                return True
            else:
                log_message(log_file, f"Patch blocks the primary POV but fails on other POVs, trying again")
                patch_success = False
        
        # Append the attempt log to the main log
        with open(attempt_log, "r") as src, open(log_file, "a") as dst:
            dst.write(f"\n--- Patch Attempt {iteration} Log ---\n")
            dst.write(src.read())
            dst.write("\n--- End of Patch Attempt Log ---\n")
        
        log_message(log_file, f"Patch attempt {iteration} failed, trying again")
    
    log_message(log_file, f"Failed to patch vulnerability after {MAX_ITERATIONS} attempts")
    return False

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
    parser = argparse.ArgumentParser(description="Patching Strategy Delta Scan: LLM-guided Patch Generation")
    parser.add_argument("fuzzer_path", help="Path to the fuzzer")
    parser.add_argument("project_name", help="Project name")
    parser.add_argument("focus", help="Focus")
    parser.add_argument("language", help="Language")

    parser.add_argument("--max-iterations", dest="max_iterations", type=int,
                        default=5, help="Maximum number of iterations")
    parser.add_argument("--patching-timeout", dest="patching_timeout", type=int,
                        default=30, help="Patching timeout in minutes")
    parser.add_argument("--pov-metadata-dir", dest="pov_metadata_dir", type=str,
                        default="successful_povs", help="Directory to store POV metadata")
    parser.add_argument("--patch-workspace-dir", help="Directory for patch workspace", default="patch_workspace")
    parser.add_argument("--model", type=str, default="", help="Specify the model to use")
                        
    args = parser.parse_args()
    # Set global variables
    global MAX_ITERATIONS, PATCHING_TIMEOUT_MINUTES, POV_METADATA_DIR, PATCH_WORKSPACE_DIR, MODELS
    global GLOBAL_FUNCTION_METADATA, GLOBAL_RELEVANT_SOURCE_FILES

    MAX_ITERATIONS = args.max_iterations
    PATCHING_TIMEOUT_MINUTES = args.patching_timeout
    POV_METADATA_DIR = args.pov_metadata_dir
    PATCH_WORKSPACE_DIR = args.patch_workspace_dir

    global CLAUDE_MODEL, OPENAI_MODEL, MODELS
    if args.model:
        CLAUDE_MODEL = args.model
        OPENAI_MODEL = args.model
        MODELS = [args.model]
    print(f"DEBUG: Global MODELS = {MODELS}")
    # Add debug output after setting globals
    print(f"DEBUG: Global MAX_ITERATIONS = {MAX_ITERATIONS}")
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

    task_detail = load_task_detail(fuzz_dir)
    if task_detail and task_detail["harnesses_included"] == False:
        global UNHARNESSED
        UNHARNESSED = True

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
    
    log_file = setup_logging(fuzzer_name)
    
    patch_success = False
    # Wrap your entire main execution in a root span
    with tracer.start_as_current_span("patch_delta") as span:
        span.set_attribute("crs.action.category", "patch_generation")
        span.set_attribute("crs.action.name", f"patching_delta_scan_basic_strategy")
        span.set_attribute("service.name", "patch_delta")
        span.set_attribute("fuzzer.path", f"{fuzzer_path}")
        if task_detail:
            for key, value in task_detail["metadata"].items():
                span.set_attribute(key, value)   
        try:
            patch_success = doPatchUntilSuccess(log_file,fuzzer_path,project_dir,project_name,focus,sanitizer, language)
        except Exception as e:
            span.record_exception(e)

        span.set_attribute("crs.patch.success", patch_success)
    
    return 0 if patch_success else 1

if __name__ == "__main__":
    sys.exit(main())