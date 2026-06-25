#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Clone OSS-Fuzz + main repo, apply a patch (diff) that represents the
‘target commit’, discover existing fuzzers, and create a brand-new one.
Print the absolute path to the new fuzzer on stdout.
"""
import yaml
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
LOG_DIR = os.environ.get("LOG_DIR", "/tmp/generate_fuzzer_logs")
os.makedirs(LOG_DIR, exist_ok=True)

def setup_logging(fuzzer_name):
    timestamp = int(time.time())
    scan_type = "delta_scan"
    log_file = os.path.join(LOG_DIR, f"generate_fuzzer_{fuzzer_name}_{scan_type}_{timestamp}.log")
    
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

# ----------------------------------------------------------------------
def parse_diff_get_changed_files(diff_path):
    """Return a list of source files touched by the diff/patch."""
    changed = []
    diff_re = re.compile(r'^\+\+\+\s+b?/(.+)')
    with open(diff_path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = diff_re.match(line)
            if m:
                changed.append(m.group(1).strip())
    # de-dup while preserving order
    return list(dict.fromkeys(changed))

def find_fuzzers(root_dir):
    patterns = [
        ("java", "fuzzerTestOneInput"),
        ("c",    "LLVMFuzzerTestOneInput"),
        ("cc",   "LLVMFuzzerTestOneInput"),
    ]
    fuzzers = []
    for ext, token in patterns:
        for dirpath, _, files in os.walk(root_dir):
            for f in files:
                if f.endswith(f".{ext}"):
                    try:
                        fp = os.path.join(dirpath, f)
                        with open(fp, encoding="utf-8", errors="ignore") as h:
                            if token in h.read():
                                fuzzers.append(fp)
                    except Exception as e:
                        print(f"Warn: cannot read {fp}: {e}", file=sys.stderr)
    return fuzzers
# ----------------------------------------------------------------------

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
    
    # Retry parameters
    max_retries = 2
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
    max_retries = 2
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


def construct_generate_new_fuzzer_prompt(existing_fuzzers, new_fuzzer_name, diff_content):
    """
    Construct the instruction prompt for the LLM to generate a new fuzzer harness.
    """
    # Read and embed each existing fuzzer's source
    fuzzer_sections = []
    for path in existing_fuzzers:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                content = fh.read()
        except Exception as e:
            content = f"// Error reading {path}: {e}"
        # Determine code block language by extension
        ext = os.path.splitext(path)[1].lower()
        if ext in ('.c', '.cc', '.cpp', '.h', '.hpp'):
            lang = 'c++'
        elif ext == '.java':
            lang = 'java'
        else:
            lang = ''
        # Wrap in fenced code block
        if lang:
            block = f"```{lang}\n{content}\n```"
        else:
            block = f"```\n{content}\n```"
        fuzzer_sections.append(f"# File: {path}\n{block}")

    existing_section = "\n\n".join(fuzzer_sections)

    prompt = f"""
You are an expert security researcher and fuzzer development specialist. Your task is to generate a new, high-quality fuzzer harness.

**Primary Goal:** Create a fuzzer harness specifically designed to discover and trigger potential vulnerabilities (e.g., buffer overflows, use-after-free, integer overflows, race conditions, logical errors leading to security issues) introduced by the code changes in the provided "Code changes (diff) to target".

**New Fuzzer Details:**
*   **Name:** "{new_fuzzer_name}"
*   **Target Language:** (Infer from existing fuzzers and diff, typically C, C++, or Java)

**Contextual Information:**

1.  **Existing Fuzzers (for style, common patterns, and API usage reference ONLY - do NOT simply copy):**
    {existing_section}

2.  **Code changes (diff) to target – THIS IS THE MOST IMPORTANT INPUT. Analyze these changes carefully:**
    ```diff
    {diff_content}
    ```

**Instructions for Fuzzer Generation:**

1.  **Analyze the Diff:** Thoroughly examine the provided `diff`. Identify the modified or newly added functions, data structures, and logic. Pay close attention to areas that handle external input, memory allocation/deallocation, pointers, array indexing, complex calculations, or concurrent operations, as these are common sources of vulnerabilities.
2.  **Focus on Vulnerability Triggers:** The new fuzzer `{new_fuzzer_name}` must be crafted to exercise the changed code paths in a way that is likely to reveal security flaws. Think about how an attacker might try to exploit the changes.
3.  **Input Generation:** The fuzzer should generate diverse and potentially malformed inputs that target the interfaces of the changed functions. Consider edge cases, oversized inputs, out-of-bounds values, and sequences of operations that might stress the new or modified logic.
4.  **Leverage Existing Fuzzer Structure (If Applicable):** If the target project has a common structure for fuzzers (evident from "Existing Fuzzers"), try to adhere to that for the new fuzzer's boilerplate (e.g., includes, main fuzzer entry point like `LLVMFuzzerTestOneInput` or `fuzzerTestOneInput`). However, the core fuzzing logic *must* be tailored to the diff.
5.  **No Trivial Fuzzers:** Do not generate a fuzzer that only calls a function with default or obviously safe inputs. The fuzzer must actively attempt to find bugs.
6.  **Output Format:**
    *   Produce *only* the complete source code for the new fuzzer harness named "{new_fuzzer_name}".
    *   Do not include any explanations, comments about your process, or any text other than the raw source code.
    *   Ensure the code is complete and ready to be compiled.
    *   The first line of your output should be the start of the code (e.g., an `#include` or `package` statement).

**Example Scenario (Conceptual):** If the diff introduces a new function `process_data(char* input, int size)` that copies `input` into a fixed-size buffer, the fuzzer should try to call `process_data` with `size` larger than the internal buffer to find a buffer overflow.

Generate the fuzzer now.
"""
    print(f"construct_generate_new_fuzzer_prompt: {prompt}")
    return prompt

def construct_generate_new_fuzzer_prompt_full(existing_fuzzers, new_fuzzer_name, project_name_for_context):
    """
    Construct the instruction prompt for the LLM to generate a new fuzzer harness
    when the specific vulnerability-introducing commit/diff is UNKNOWN.
    The fuzzer should aim for broad coverage of potentially vulnerable areas.
    """
    fuzzer_sections = []
    for path in existing_fuzzers:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                content = fh.read()
        except Exception as e:
            content = f"// Error reading {path}: {e}"
        ext = os.path.splitext(path)[1].lower()
        lang_map = {'.c': 'c', '.cc': 'c++', '.cpp': 'c++', '.h': 'c', '.hpp': 'c++', '.java': 'java'}
        lang = lang_map.get(ext, '')
        
        block = f"```{lang}\n{content}\n```" if lang else f"```\n{content}\n```"
        fuzzer_sections.append(f"# File: {path}\n{block}")

    existing_section = "\n\n".join(fuzzer_sections) if fuzzer_sections else "# No existing fuzzers provided as specific examples."

    prompt = f"""
You are an expert security researcher and fuzzer development specialist. Your task is to generate a new, high-quality fuzzer harness for {project_name_for_context}.

**Primary Goal:** Create a robust fuzzer harness that aims to discover potential, previously unknown vulnerabilities (e.g., buffer overflows, use-after-free, integer overflows, race conditions, logical errors leading to security issues, mishandling of complex inputs). Since the specific code change that introduced a vulnerability is unknown, this fuzzer should aim for broad yet intelligent coverage of potentially susceptible areas.

**New Fuzzer Details:**
*   **Name:** "{new_fuzzer_name}"
*   **Target Language:** (Infer from existing fuzzers or project context, typically C, C++, or Java)

**Contextual Information:**

1.  **Existing Fuzzers (for style, common patterns, and API usage reference ONLY - do NOT simply copy or trivially modify):**
    {existing_section}

**Instructions for Fuzzer Generation (General Vulnerability Discovery):**

1.  **Identify Promising Fuzz Targets:** Based on the existing fuzzers (if any) and general knowledge of {project_name_for_context} (if applicable from its name/domain), identify key APIs, data parsing routines, complex state management areas, or interfaces that handle external/untrusted data. These are often good candidates for new fuzzers.
2.  **Prioritize Common Vulnerability Patterns:** Design the fuzzer to test for common vulnerability types. For example:
    *   If targeting C/C++, focus on memory safety (buffer sizes, pointer arithmetic, allocation/deallocation).
    *   If targeting Java, consider issues like deserialization, improper exception handling, or resource leaks.
    *   For any language, consider fuzzing for logical flaws, unexpected state transitions, and mishandling of malformed or large inputs.
3.  **Comprehensive Input Generation:** The fuzzer should generate diverse and complex inputs. Think beyond simple random data. Consider structured inputs if the target API expects them (e.g., fuzzing a parser for a specific file format or network protocol). Use techniques that explore edge cases, large inputs, and sequences of API calls.
4.  **Leverage Existing Fuzzer Structure (If Applicable):** If the target project has a common structure for fuzzers (evident from "Existing Fuzzers"), adhere to that for boilerplate (includes, entry point like `LLVMFuzzerTestOneInput` or `fuzzerTestOneInput`). The core fuzzing logic and target selection should be novel and aim for new coverage.
5.  **Aim for Depth, Not Just Breadth:** While broad coverage is good, a fuzzer that deeply explores a few critical components is often more effective than one that superficially touches many.
6.  **No Trivial Fuzzers:** Do not generate a fuzzer that only calls a function with default or obviously safe inputs. The fuzzer must actively attempt to find bugs. If you cannot identify a clear, non-trivial fuzzing strategy based on the provided context, indicate that a meaningful fuzzer cannot be generated.
7.  **Output Format:**
    *   Produce *only* the complete source code for the new fuzzer harness named "{new_fuzzer_name}".
    *   Do not include any explanations, comments about your process, or any text other than the raw source code.
    *   Ensure the code is complete and ready to be compiled.
    *   The first line of your output should be the start of the code (e.g., an `#include` or `package` statement).

Generate the fuzzer now. If you determine that a meaningful new fuzzer cannot be created from the provided context (e.g., no clear new targets or strategies are apparent from existing fuzzers), please output only the following text:
NO_FUZZER_GENERATED: Insufficient context or no clear new fuzzing strategy.
"""
    print(f"construct_generate_new_fuzzer_prompt_full: {prompt}") 
    return prompt

def extract_fuzzer_source_from_response(response):
    """
    Extracts the code from an AI response, removing any code block markers.
    Handles code blocks like ```java ... ```, ```c ... ```, or just ``` ... ```.
    If no code block is found, returns the whole response.
    """
    # Regex to match code blocks with or without language specifier
    code_block_pattern = re.compile(
        r"```(?:[a-zA-Z0-9_+-]*)?\n(.*?)```", re.DOTALL
    )
    match = code_block_pattern.search(response)
    if match:
        return match.group(1).strip()
    else:
        # Fallback: return the whole response, stripped
        return response.strip()

def fix_build_script_if_necessary(log_file, oss_fuzz_project_dir, fuzz_tooling_project_dir, 
                                   fuzzer_src_dir0, fuzzer_src_dir, main_repo_dir, 
                                   fuzzer_file_name, new_fuzzer_file_name):
    """
    Finds, modifies, and saves build.sh according to specified logic.
    Returns the path to the modified build.sh if successful, else None.
    """
    build_sh_found = False
    build_sh_content = ""
    source_build_sh_path = ""
    target_build_sh_path = ""

    # 1. Check oss-fuzz project directory
    # Source: oss-fuzz/projects/<project_name>/build.sh
    # Target: fuzz-tooling/projects/<project_name>/build.sh
    current_source_build_sh = os.path.join(oss_fuzz_project_dir, "build.sh")
    current_target_build_sh = os.path.join(fuzz_tooling_project_dir, "build.sh")
    if os.path.exists(current_source_build_sh):
        source_build_sh_path = current_source_build_sh
        target_build_sh_path = current_target_build_sh
        log_message(log_file, f"Found build.sh at {source_build_sh_path}, target: {target_build_sh_path}")
        with open(source_build_sh_path, "r", encoding="utf-8") as f:
            build_sh_content = f.read()
        build_sh_found = True
     # 2. Check original fuzzer's source directory (if not found above)
    # Source: <original_fuzzer_dir>/build.sh  (fuzzer_src_dir0)
    # Target: <new_fuzzer_dir>/build.sh (fuzzer_src_dir)
    if not build_sh_found:
        current_source_build_sh = os.path.join(fuzzer_src_dir0, "build.sh")
        current_target_build_sh = os.path.join(fuzzer_src_dir, "build.sh") 
        if os.path.exists(current_source_build_sh):
            source_build_sh_path = current_source_build_sh
            target_build_sh_path = current_target_build_sh
            log_message(log_file, f"Found build.sh at {source_build_sh_path}, target: {target_build_sh_path}")
            with open(source_build_sh_path, "r", encoding="utf-8") as f:
                build_sh_content = f.read()
            build_sh_found = True

    # 3. Check main_repo_dir (if not found above)
    # Source: main_repo_dir/build.sh (or deeper if found by glob)
    # Target: <new_fuzzer_dir>/build.sh (fuzzer_src_dir)
    if not build_sh_found:
        current_source_build_sh_root = os.path.join(main_repo_dir, "build.sh")
        current_target_build_sh = os.path.join(fuzzer_src_dir, "build.sh")
        if os.path.exists(current_source_build_sh_root):
            source_build_sh_path = current_source_build_sh_root
            target_build_sh_path = current_target_build_sh
            log_message(log_file, f"Found build.sh at {source_build_sh_path}, target: {target_build_sh_path}")
            with open(source_build_sh_path, "r", encoding="utf-8") as f:
                build_sh_content = f.read()
            build_sh_found = True
        else:
            found_scripts = glob.glob(os.path.join(main_repo_dir, "**/build.sh"), recursive=True)
            if found_scripts:
                 source_build_sh_path = found_scripts[0] 
                 target_build_sh_path = current_target_build_sh 
                 log_message(log_file, f"Found build.sh at {source_build_sh_path} (fallback search), target: {target_build_sh_path}")
                 with open(source_build_sh_path, "r", encoding="utf-8") as f:
                     build_sh_content = f.read()
                 build_sh_found = True

    if build_sh_found and build_sh_content:
        fuzzer_name_for_build_sh = os.path.splitext(fuzzer_file_name)[0]
        new_fuzzer_name_for_build_sh = os.path.splitext(new_fuzzer_file_name)[0]

        log_message(log_file, f"Old fuzzer name (for build.sh replacement): {fuzzer_name_for_build_sh}")
        log_message(log_file, f"New fuzzer name (for build.sh replacement): {new_fuzzer_name_for_build_sh}")
        
        modified_build_sh_content = build_sh_content.replace(fuzzer_name_for_build_sh, new_fuzzer_name_for_build_sh)

        os.makedirs(os.path.dirname(target_build_sh_path), exist_ok=True)
        with open(target_build_sh_path, "w", encoding="utf-8") as f:
            f.write(modified_build_sh_content)
        log_message(log_file, f"Saved modified build.sh to {target_build_sh_path}")
        
        #TODO copy all the *.options and *.dict files under the source dir to target dir
        # --- Copy .dict and .options files ---
        source_aux_dir = os.path.dirname(source_build_sh_path)
        target_aux_dir = os.path.dirname(target_build_sh_path)

        if not os.path.isdir(source_aux_dir):
            log_message(log_file, f"Warning: Source directory for auxiliary files not found: {source_aux_dir}")
        else:
            if not os.path.exists(target_aux_dir):
                os.makedirs(target_aux_dir)
                log_message(log_file, f"Created target auxiliary directory: {target_aux_dir}")

            for pattern in ["*.dict", "*.options"]:
                source_files = glob.glob(os.path.join(source_aux_dir, pattern))
                if not source_files:
                    log_message(log_file, f"No files matching '{pattern}' found in {source_aux_dir}")
                    continue

                for src_file_path in source_files:
                    file_name = os.path.basename(src_file_path)
                    dst_file_path = os.path.join(target_aux_dir, file_name)
                    try:
                        shutil.copy2(src_file_path, dst_file_path)
                        log_message(log_file, f"Copied {src_file_path} to {dst_file_path}")
                    except Exception as e:
                        log_message(log_file, f"Error copying {src_file_path} to {dst_file_path}: {e}")
        # --- End of copy logic ---
                  
        return target_build_sh_path
    else:
        log_message(log_file, "Could not find a build.sh to modify.")
        return None


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


def _try_fetch_sources_via_docker_build(log_file, task_dir, project_name, target_main_repo_dir):
    """
    Tries to build the project's Dockerfile and extract the downloaded sources
    if git clone fails. Saves them to target_main_repo_dir.
    Returns True on success, False on failure.
    """
    log_message(log_file, f"Attempting to fetch sources for {project_name} via Docker build as git clone failed.")

    dockerfile_path = os.path.join(task_dir, "fuzz-tooling", "projects", project_name, "Dockerfile")
    build_context_path = os.path.join(task_dir, "fuzz-tooling", "projects", project_name)

    if not os.path.exists(dockerfile_path):
        log_message(log_file, f"Dockerfile not found at {dockerfile_path}. Cannot fetch sources via Docker.")
        return False
    if not os.path.isdir(build_context_path):
        log_message(log_file, f"Build context path not found at {build_context_path}. Cannot fetch sources via Docker.")
        return False

    temp_export_dir = None
    try:
        temp_export_dir = tempfile.mkdtemp()
        log_message(log_file, f"Created temporary export directory: {temp_export_dir}")

        # Use a project-specific temporary tag to avoid conflicts if run in parallel
        temp_docker_tag = f"aixcc-afc/{project_name}-source-fetch-{time.time_ns()}"

        docker_build_cmd = [
            "docker", "build",
            "--no-cache",
            "-t", temp_docker_tag,
            "--file", dockerfile_path,
            "--output", f"type=local,dest={temp_export_dir}",
            build_context_path
        ]
        
        env = os.environ.copy()
        log_message(log_file, f"Running Docker build command: {' '.join(docker_build_cmd)}")

        try:
            result = subprocess.run(
                docker_build_cmd,
                env=env,
                capture_output=True, # stdout and stderr will be bytes
                text=False,          # Process as bytes to reduce overhead
                check=False,
                timeout=180 # Added timeout
            )
            
            # Decode output for logging, showing only the tail end to keep logs manageable
            stdout_log = result.stdout.decode(errors='replace')[-1000:] if result.stdout else ""
            stderr_log = result.stderr.decode(errors='replace')[-1000:] if result.stderr else ""

            if result.returncode != 0:
                log_message(log_file, f"Docker build for source fetching failed. Return code: {result.returncode}")
                log_message(log_file, f"Stdout tail: {stdout_log}")
                log_message(log_file, f"Stderr tail: {stderr_log}")
                return False
        
        except subprocess.TimeoutExpired as e:
            log_message(log_file, f"Docker build command timed out after {build_timeout_seconds} seconds.")
            # Decode output from the exception object (it will be bytes)
            stdout_timeout_log = e.stdout.decode(errors='replace')[-1000:] if e.stdout else "N/A"
            stderr_timeout_log = e.stderr.decode(errors='replace')[-1000:] if e.stderr else "N/A"
            log_message(log_file, f"Timeout stdout tail: {stdout_timeout_log}")
            log_message(log_file, f"Timeout stderr tail: {stderr_timeout_log}")
            return False
        except Exception as subproc_ex: # Catch other potential errors like FileNotFoundError if docker isn't on PATH
            log_message(log_file, f"An unexpected error occurred running the docker build subprocess: {str(subproc_ex)}")
            return False

        log_message(log_file, "Docker build for source fetching successful.")

        primary_exported_sources_path = os.path.join(temp_export_dir, "src", project_name)
        generic_src_path = os.path.join(temp_export_dir, "src")
        actual_sources_to_copy_path = None
        if os.path.isdir(primary_exported_sources_path) and os.listdir(primary_exported_sources_path):
            actual_sources_to_copy_path = primary_exported_sources_path
            log_message(log_file, f"Found populated primary source path: {actual_sources_to_copy_path}")
        elif os.path.isdir(generic_src_path) and os.listdir(generic_src_path):
            log_message(log_file, f"Primary source path {primary_exported_sources_path} not found or empty. Checking generic {generic_src_path}.")
            src_contents = [d for d in os.listdir(generic_src_path) if os.path.isdir(os.path.join(generic_src_path, d))]
            if len(src_contents) == 1:
                actual_sources_to_copy_path = os.path.join(generic_src_path, src_contents[0])
                log_message(log_file, f"Found single subdirectory in /src: {actual_sources_to_copy_path}. Using it.")
            else:
                actual_sources_to_copy_path = generic_src_path 
                log_message(log_file, f"Using contents of generic source path: {actual_sources_to_copy_path} (found {len(src_contents)} subdirs or files).")
        else:
            log_message(log_file, f"Neither primary {primary_exported_sources_path} nor generic {generic_src_path} seem to contain sources, or /src is missing/empty in export.")
            if os.path.exists(temp_export_dir):
                log_message(log_file, f"Contents of {temp_export_dir}: {os.listdir(temp_export_dir)}")
            if os.path.exists(generic_src_path):
                 log_message(log_file, f"Contents of {generic_src_path}: {os.listdir(generic_src_path)}")
            else:
                log_message(log_file, f"{generic_src_path} does not exist in export.")
            return False

        if os.path.exists(target_main_repo_dir):
            shutil.rmtree(target_main_repo_dir)
        os.makedirs(target_main_repo_dir, exist_ok=True)
        
        log_message(log_file, f"Copying from '{actual_sources_to_copy_path}' to '{target_main_repo_dir}'")
        for item in os.listdir(actual_sources_to_copy_path):
            s_item = os.path.join(actual_sources_to_copy_path, item)
            d_item = os.path.join(target_main_repo_dir, item)
            if os.path.isdir(s_item):
                shutil.copytree(s_item, d_item, dirs_exist_ok=True)
            else:
                shutil.copy2(s_item, d_item)

        log_message(log_file, f"Successfully copied sources to {target_main_repo_dir}")
        return True

    except Exception as e:
        log_message(log_file, f"Error during Docker source fetching: {str(e)}")
        return False
    finally:
        if temp_export_dir and os.path.exists(temp_export_dir):
            shutil.rmtree(temp_export_dir)
            log_message(log_file, f"Cleaned up temporary export directory: {temp_export_dir}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--task_dir',      required=True)
    ap.add_argument('--focus',   required=True)
    ap.add_argument('--sanitizer_dir', required=True)
    ap.add_argument('--project_name',  required=True)
    ap.add_argument('--sanitizer',  required=True)

    args = ap.parse_args()
    project_name = args.project_name
    sanitizer = args.sanitizer
    out_dir = args.sanitizer_dir
    focus_sanitizer = f"{args.focus}-{sanitizer}"
    project_src_dir = os.path.join(args.task_dir, focus_sanitizer)

    log_file = setup_logging(project_name)
    oss_fuzz_dir = os.path.join(args.task_dir, "oss-fuzz")
    if not os.path.exists(oss_fuzz_dir):
        subprocess.run(["git", "clone", "--depth", "1",
                        "https://github.com/google/oss-fuzz", oss_fuzz_dir],
                       check=True)

    oss_fuzz_project_dir = os.path.join(oss_fuzz_dir, "projects", args.project_name)
    fuzz_tooling_project_dir = oss_fuzz_project_dir.replace("oss-fuzz", "fuzz-tooling")

    project_yaml = os.path.join(oss_fuzz_project_dir, "project.yaml")


    cfg = None
    max_yaml_attempts = 3
    yaml_attempt_delay = 5 # seconds
    for attempt in range(max_yaml_attempts):
        try:
            if os.path.exists(project_yaml):
                with open(project_yaml, "r") as f:
                    cfg = yaml.safe_load(f)
                log_message(log_file, f"Successfully loaded {project_yaml} on attempt {attempt + 1}")
                break
            else:
                log_message(log_file, f"Attempt {attempt + 1}/{max_yaml_attempts}: {project_yaml} not found. Waiting {yaml_attempt_delay}s...")
                time.sleep(yaml_attempt_delay)
        except FileNotFoundError:
            log_message(log_file, f"Attempt {attempt + 1}/{max_yaml_attempts}: FileNotFoundError for {project_yaml}. Waiting {yaml_attempt_delay}s...")
            if attempt < max_yaml_attempts - 1:
                time.sleep(yaml_attempt_delay)
            else:
                log_message(log_file, f"Failed to load {project_yaml} after {max_yaml_attempts} attempts.")
                # Propagate the error if all attempts fail
                raise 
        except Exception as e:
            log_message(log_file, f"Attempt {attempt + 1}/{max_yaml_attempts}: Error loading {project_yaml}: {e}. Waiting {yaml_attempt_delay}s...")
            if attempt < max_yaml_attempts - 1:
                time.sleep(yaml_attempt_delay)
            else:
                log_message(log_file, f"Failed to load {project_yaml} due to error: {e} after {max_yaml_attempts} attempts.")
                raise

    if cfg is None:
        log_message(log_file, f"Critical: Could not load {project_yaml} after all attempts. Exiting.")
        # Ensure the script exits if cfg couldn't be loaded, mirroring the original behavior of an unhandled exception
        sys.exit(1)


    main_repo_dir = os.path.join(args.task_dir, "main_repo")
    if not os.path.exists(main_repo_dir) or not os.listdir(main_repo_dir): # Check if already cloned and populated
        try:
            log_message(log_file, f"Attempting to clone main_repo from {cfg['main_repo']} into {main_repo_dir}")
            # If main_repo_dir exists but is empty, git clone will use it. If it's non-empty, git clone fails.
            # Ensure it's clean if it exists but is empty, or remove if clone fails into it.
            if os.path.exists(main_repo_dir) and not os.listdir(main_repo_dir):
                log_message(log_file, f"Main repo dir {main_repo_dir} exists and is empty. Proceeding with clone.")
            elif os.path.exists(main_repo_dir): # Exists and non-empty, git clone would fail.
                 log_message(log_file, f"Main repo dir {main_repo_dir} exists and is non-empty. Clearing for fresh clone.")
                 shutil.rmtree(main_repo_dir) 
                 # git clone will re-create it
            
            # For git clone, main_repo_dir should ideally not exist or be an empty directory.
            # The command itself will create main_repo_dir if it doesn't exist.

            git_clone_result = subprocess.run(
                ["git", "clone", "--depth", "1", cfg["main_repo"], main_repo_dir],
                check=False, capture_output=True, text=True # check=False to handle error manually
            )
            if git_clone_result.returncode == 0:
                log_message(log_file, f"Successfully cloned main_repo into {main_repo_dir}")
            else:
                # Raise an exception to be caught by the CalledProcessError handler or a generic one
                git_clone_result.check_returncode() # This will raise CalledProcessError if returncode is non-zero
        except subprocess.CalledProcessError as e:
            log_message(log_file, f"Failed to clone main_repo (git clone exited with code {e.returncode}): {str(e)}")
            log_message(log_file, f"Git stdout: {e.stdout[-1000:]}")
            log_message(log_file, f"Git stderr: {e.stderr[-1000:]}")
            log_message(log_file, "Attempting to fetch sources via Docker build as fallback.")
            if not _try_fetch_sources_via_docker_build(log_file, args.task_dir, args.project_name, main_repo_dir):
                log_message(log_file, "Failed to fetch sources via Docker build. Main repository may be unavailable.")
            else:
                log_message(log_file, "Successfully fetched sources via Docker build into main_repo_dir.")
        except Exception as e: # Catch other exceptions (e.g., git not found, network issues before CalledProcessError)
            log_message(log_file, f"An unexpected error occurred while trying to clone main_repo: {str(e)}")
            log_message(log_file, "Attempting to fetch sources via Docker build as fallback.")
            if not _try_fetch_sources_via_docker_build(log_file, args.task_dir, args.project_name, main_repo_dir):
                log_message(log_file, "Failed to fetch sources via Docker build. Main repository may be unavailable.")
            else:
                log_message(log_file, "Successfully fetched sources via Docker build into main_repo_dir.")
    else:
        log_message(log_file, f"Main repository at {main_repo_dir} already exists and is populated. Skipping clone/fetch.")


    # After this block, check if main_repo_dir was successfully populated before using it.
    if not os.path.exists(main_repo_dir) or not os.listdir(main_repo_dir):
        log_message(log_file, f"CRITICAL: main_repo_dir '{main_repo_dir}' is empty or does not exist after attempting clone and Docker fetch. This may cause issues for subsequent steps.")
        # Depending on how critical main_repo_dir is, you might want to exit:

    # ------------------------------------------------------------------
    # Discover existing fuzzers
    # ------------------------------------------------------------------
    existing_fuzzers = find_fuzzers(oss_fuzz_project_dir)
    existing_fuzzers += find_fuzzers(main_repo_dir)
    if not existing_fuzzers:
        #TODO maintain a database of fuzzers 
        print("No existing fuzzers found", file=sys.stderr)
        sys.exit(1)

    first_existing_fuzzer_path = existing_fuzzers[0]
    fuzzer_src_dir = os.path.dirname(first_existing_fuzzer_path)
    fuzzer_src_dir0 = os.path.dirname(first_existing_fuzzer_path)
    fuzzer_file_name = os.path.basename(first_existing_fuzzer_path)
    # replace "main_repo" by focus_sanitizer if exists in fuzzer_src_dir
    if "main_repo" in fuzzer_src_dir:
        fuzzer_src_dir = fuzzer_src_dir.replace("main_repo", focus_sanitizer)
    # replace "oss-fuzz" by "fuzz-tooling" if exists in fuzzer_src_dir
    elif "oss-fuzz" in fuzzer_src_dir:
        fuzzer_src_dir = fuzzer_src_dir.replace("oss-fuzz", "fuzz-tooling")

    ext  = os.path.splitext(first_existing_fuzzer_path)[1]
    fuzz_language = "jvm"
    if ext.startswith('.c'):
        fuzz_language = "c++"
    
    hijacked_fuzzer_full_path = existing_fuzzers[0] # Full path to the original source, e.g., .../main_repo/libfreerdp/core/test/TestFuzzCoreServer.c
    hijacked_fuzzer_original_source_filename = os.path.basename(hijacked_fuzzer_full_path) # e.g., TestFuzzCoreServer.c
    hijacked_fuzzer_compiled_name = os.path.splitext(hijacked_fuzzer_original_source_filename)[0] # e.g., TestFuzzCoreServer

    log_message(log_file, f"Strategy: Hijacking existing fuzzer. Will overwrite '{hijacked_fuzzer_original_source_filename}' with AI-generated code.")
    log_message(log_file, f"Expected compiled name in $OUT will be: '{hijacked_fuzzer_compiled_name}'")

    # new_fuzzer_name = f"fuzzing_brain_{sanitizer}_fuzzer"
    # if fuzzer_file_name and fuzzer_file_name[0].isupper():
    #     new_fuzzer_name = f"FuzzingBrain{sanitizer}Fuzzer"
    
    new_fuzzer_name = hijacked_fuzzer_compiled_name

    new_fuzzer_path = os.path.join(out_dir, new_fuzzer_name)
    new_fuzzer_file_name_with_ext = new_fuzzer_name+ext
    new_fuzzer_src_path = os.path.join(fuzzer_src_dir, new_fuzzer_file_name_with_ext)


    log_message(log_file, f"Original fuzzer path (first): {first_existing_fuzzer_path}")
    log_message(log_file, f"Original fuzzer filename: {fuzzer_file_name}")
    log_message(log_file, f"New fuzzer source path: {new_fuzzer_src_path}")
    log_message(log_file, f"New fuzzer compiled output path: {new_fuzzer_path}")
    log_message(log_file, f"Fuzz language: {fuzz_language}")

    # ------------------------------------------------------------------
    # analyze diff for delta scan
    # ------------------------------------------------------------------
    diff_content = ""
    diff_path = os.path.join(args.task_dir, "diff", "ref.diff")
    if os.path.exists(diff_path):
        # read diff_content
        try:
            with open(diff_path, "r") as f:
                diff_content = f.read()
            log_message(log_file, f"Read diff from {diff_path}, len(diff_content): {len(diff_content)}")

            # If the diff is very large, process it to make it more manageable
            if len(diff_content) > 50000:  # More than 50KB
                log_message(log_file, "Diff is large, processing to extract relevant parts...")
                diff_content = process_large_diff(diff_content, log_file)
        except Exception as e:
            log_message(log_file, f"Error reading diff file: {str(e)}")

    # construct prompt to generate a new fuzzer
    if diff_content:
        prompt = construct_generate_new_fuzzer_prompt(existing_fuzzers, new_fuzzer_name, diff_content)
    else:
        prompt = construct_generate_new_fuzzer_prompt_full(existing_fuzzers, new_fuzzer_name, project_name)

    messages = [{"role": "system", "content": "You are a top expert in fuzzing code security vulnerabilities."}]
    messages.append({"role": "user", "content": prompt})

    # build the new fuzzer & retry logic
    build_error = ""
    MAX_ATTEMPTS_PER_MODEL = 2
    for model_name_x in MODELS:
        for attempt in range(1, MAX_ATTEMPTS_PER_MODEL + 1):
            log_message(log_file, f"Trying {model_name_x} to generate fuzzers, attempt {attempt}/{MAX_ATTEMPTS_PER_MODEL}")
            response, success = call_llm(log_file, messages, model_name_x)
            print(f"response:{response}")
            if success and response:
                source_code = extract_fuzzer_source_from_response(response) 
                with open(new_fuzzer_src_path, "w", encoding="utf-8") as f:
                    f.write(source_code)

                log_message(log_file, f"Saved new fuzzer source to {new_fuzzer_src_path}")

                # Call the refactored function
                host_temp_modified_build_sh_path = fix_build_script_if_necessary(
                    log_file, oss_fuzz_project_dir, fuzz_tooling_project_dir,
                    fuzzer_src_dir0, fuzzer_src_dir, main_repo_dir,
                    fuzzer_file_name, new_fuzzer_file_name_with_ext # Pass new name with extension
                )
                if not host_temp_modified_build_sh_path:
                    log_message(log_file, "Failed to prepare modified build.sh. Skipping build attempt with this LLM response.")
                    build_error += f"\n{model_name_x} attempt {attempt} {sanitizer} error: Failed to prepare build.sh."
                    continue # Try next LLM attempt or model

                # TODO fix build.sh if necenssary
                # oss_fuzz_build_script = os.path.join(oss_fuzz_project_dir, "build.sh")
                # if os.path.exists(oss_fuzz_build_script):
                #     #TODO replace fuzzer_file_name by new_fuzzer_file_name in oss_fuzz_build_script
                #     # copy it to fuzz_tooling_project_dir/build.sh
                # else:
                #     fuzzer_src0_build_script = os.path.join(fuzzer_src_dir0, "build.sh")
                #     if os.path.exists(fuzzer_src0_build_script):
                #         #TODO replace fuzzer_file_name by new_fuzzer_file_name in fuzzer_src0_build_script
                #         # copy it to fuzzer_src_dir/build.sh
                #     else:
                #         # TODO find build.sh under main_repo_dir, replace fuzzer_file_name by new_fuzzer_file_name,                         
                #         # and copy it to ...

                build_success = False
                
                container_build_sh_path = "/src/build.sh" # Based on Dockerfile: RUN cp ... $SRC/build.sh

                if not os.path.exists(out_dir):
                    log_message(log_file, f"CRITICAL ERROR: Docker CWD out_dir {out_dir} does NOT exist before calling docker run!")
                    # Optionally, try to create it here as a last resort, though Go should have done it.
                    # os.makedirs(out_dir, exist_ok=True)
                    # log_message(log_file, f"Attempted to create CWD {out_dir} from Python.")
                else:
                    log_message(log_file, f"Confirmed: Docker CWD out_dir {out_dir} exists.")
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
                    "-v", f"{host_temp_modified_build_sh_path}:{container_build_sh_path}",
                    f"aixcc-afc/{project_name}"
                ]
                # Convert array to string with proper escaping
                cmd_string = " ".join([arg if " " not in arg else f'"{arg}"' for arg in cmd_args])
                log_message(log_file, f"Attempting Docker build with command: {cmd_string}")
                build_start_time = time.time()
                try:
                    result = subprocess.run(
                        cmd_args,
                        shell=False,
                        env=os.environ.copy(),
                        cwd=out_dir,
                        capture_output=True,
                        text=True
                    )
                    build_end_time = time.time()
                    build_duration = build_end_time - build_start_time
                    print(f"Fuzzer build completed in {build_duration:.2f} seconds ({build_duration/60:.2f} minutes)")   
                    
                    if result.returncode != 0:
                        err_msg = f"Build failed for {sanitizer} sanitizer: {result.stderr}"
                        log_message(log_file, err_msg)
                        messages.append({"role": "assistant", "content": response})
                        messages.append({"role": "user", "content": truncate_output(err_msg, 200)})
                        build_error += f"\n{sanitizer} build error: {result.stderr}"
                    else:
                        build_success = True
                        log_message(log_file, f"Build successful for {sanitizer} sanitizer!")
                except Exception as e:
                    log_message(log_file, f"Error building with {sanitizer} sanitizer: {str(e)}")
                    build_error += f"\n{sanitizer} build error: {str(e)}" 

                if build_success:
                    if os.path.exists(new_fuzzer_path):
                        #copy to taskdir
                        task_dir_build_sh_path = os.path.join(args.task_dir, f"build-{sanitizer}.sh")
                        shutil.copy2(host_temp_modified_build_sh_path, task_dir_build_sh_path)
                        print(os.path.abspath(new_fuzzer_src_path))   # <-- stdout consumed by Go
                        print(os.path.abspath(new_fuzzer_path))   # <-- stdout consumed by Go
                        sys.exit(0)
                    else:
                        log_message(log_file, f"Build was successful but new_fuzzer_path {new_fuzzer_path} does not exist!")  
            else: # LLM call failed
                log_message(log_file, f"LLM call failed for {model_name_x} attempt {attempt}. Response: {response}")
                build_error += f"\n{model_name_x} attempt {attempt} LLM call failed."

    log_message(log_file, f"All attempts failed. Last build error: {build_error if build_error else 'No specific build error logged, LLM or other issue.'}")
    print("Failed to generate and build a valid fuzzer after all attempts.", file=sys.stderr)
    sys.exit(1)

if __name__ == "__main__":
    main()
