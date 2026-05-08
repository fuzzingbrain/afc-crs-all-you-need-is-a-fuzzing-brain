#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
TaintSan - Taint Tracking Sanitizer for Python

A sanitizer that tracks "tainted" data from untrusted sources and detects
when it reaches dangerous sinks without proper sanitization.

Usage with Atheris fuzzer:
    import taintsan_python as taintsan
    taintsan.install()

    def TestOneInput(data):
        tainted_input = taintsan.taint(data, source="fuzzer")
        # ... use tainted_input in your code ...

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

Author: AFC-CRS Security Research
"""

import sys
import os
import functools
import threading
import traceback
import json
import re
from typing import Any, Set, Dict, List, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime
import weakref


# ============================================================================
# Configuration
# ============================================================================

class TaintSanConfig:
    """Configuration for TaintSan behavior"""

    # Behavior on taint violation
    RAISE_ON_SINK = True          # Raise exception when tainted data hits sink
    LOG_VIOLATIONS = True          # Log violations to file
    LOG_FILE = "/tmp/taintsan_violations.log"

    # Taint propagation
    PROPAGATE_THROUGH_STRINGS = True
    PROPAGATE_THROUGH_CONTAINERS = True
    PROPAGATE_THROUGH_FORMATTING = True

    # Performance
    MAX_TAINT_CHAIN_LENGTH = 100   # Prevent memory explosion
    TRACK_TAINT_ORIGIN = True      # Track where taint originated

    # What to monitor
    MONITOR_SQL = True
    MONITOR_SHELL = True
    MONITOR_EVAL = True
    MONITOR_FILE = True
    MONITOR_NETWORK = True
    MONITOR_DESERIALIZE = True


# ============================================================================
# Taint Metadata
# ============================================================================

class TaintSource(Enum):
    """Sources of tainted data"""
    FUZZER = auto()        # Fuzzer-generated input
    HTTP_REQUEST = auto()  # HTTP request parameters
    FILE_INPUT = auto()    # Data read from files
    STDIN = auto()         # Standard input
    ENV_VAR = auto()       # Environment variables
    DATABASE = auto()      # Database query results
    NETWORK = auto()       # Network socket data
    USER_MARKED = auto()   # Explicitly marked by user


class SinkType(Enum):
    """Types of dangerous sinks"""
    SQL_QUERY = auto()
    SHELL_COMMAND = auto()
    EVAL_EXEC = auto()
    FILE_PATH = auto()
    FILE_WRITE = auto()
    NETWORK_REQUEST = auto()
    DESERIALIZE = auto()
    HTML_OUTPUT = auto()
    LDAP_QUERY = auto()
    XPATH_QUERY = auto()


@dataclass
class TaintInfo:
    """Metadata about tainted data"""
    source: TaintSource
    source_location: str           # File:line where taint originated
    taint_id: int                  # Unique identifier
    timestamp: float
    original_value_hash: int       # Hash of original tainted value
    propagation_chain: List[str] = field(default_factory=list)

    def add_propagation(self, operation: str, location: str):
        """Record a propagation step"""
        if len(self.propagation_chain) < TaintSanConfig.MAX_TAINT_CHAIN_LENGTH:
            self.propagation_chain.append(f"{operation}@{location}")


# Global taint ID counter
_taint_id_counter = 0
_taint_id_lock = threading.Lock()

def _next_taint_id() -> int:
    global _taint_id_counter
    with _taint_id_lock:
        _taint_id_counter += 1
        return _taint_id_counter


# ============================================================================
# Tainted Types - Wrapper classes that track taint
# ============================================================================

class TaintedMixin:
    """Mixin class providing taint tracking functionality"""

    _taint_info: Optional[TaintInfo] = None

    def _get_taint_info(self) -> Optional[TaintInfo]:
        return getattr(self, '_taint_info', None)

    def _set_taint_info(self, info: TaintInfo):
        object.__setattr__(self, '_taint_info', info)

    def is_tainted(self) -> bool:
        return self._get_taint_info() is not None

    def get_taint_source(self) -> Optional[TaintSource]:
        info = self._get_taint_info()
        return info.source if info else None


class TaintedStr(str, TaintedMixin):
    """A string that tracks taint status"""

    _taint_info: Optional[TaintInfo] = None

    def __new__(cls, value: str = "", taint_info: Optional[TaintInfo] = None):
        instance = super().__new__(cls, value)
        if taint_info:
            instance._taint_info = taint_info
        return instance

    def _propagate_taint(self, result: str, operation: str) -> 'TaintedStr':
        """Create a new TaintedStr with propagated taint"""
        if not self.is_tainted():
            return result if not isinstance(result, TaintedStr) else result

        new_info = TaintInfo(
            source=self._taint_info.source,
            source_location=self._taint_info.source_location,
            taint_id=self._taint_info.taint_id,
            timestamp=self._taint_info.timestamp,
            original_value_hash=self._taint_info.original_value_hash,
            propagation_chain=self._taint_info.propagation_chain.copy()
        )
        new_info.add_propagation(operation, _get_caller_location())

        return TaintedStr(result, new_info)

    # Override string operations to propagate taint
    def __add__(self, other) -> 'TaintedStr':
        result = super().__add__(other)
        # Propagate taint if either operand is tainted
        if self.is_tainted():
            return self._propagate_taint(result, "str.__add__")
        elif isinstance(other, TaintedMixin) and other.is_tainted():
            return TaintedStr(result, other._get_taint_info())
        return result

    def __radd__(self, other) -> 'TaintedStr':
        result = other + str(self)
        if self.is_tainted():
            return self._propagate_taint(result, "str.__radd__")
        return result

    def __mul__(self, n) -> 'TaintedStr':
        result = super().__mul__(n)
        return self._propagate_taint(result, "str.__mul__")

    def __mod__(self, args) -> 'TaintedStr':
        """String formatting with %"""
        result = super().__mod__(args)
        # Check if format string or any arg is tainted
        if self.is_tainted():
            return self._propagate_taint(result, "str.__mod__")
        if _any_tainted(args):
            taint_info = _get_any_taint_info(args)
            return TaintedStr(result, taint_info)
        return result

    def format(self, *args, **kwargs) -> 'TaintedStr':
        result = super().format(*args, **kwargs)
        if self.is_tainted():
            return self._propagate_taint(result, "str.format")
        if _any_tainted(args) or _any_tainted(kwargs.values()):
            taint_info = _get_any_taint_info(args) or _get_any_taint_info(kwargs.values())
            return TaintedStr(result, taint_info)
        return result

    def join(self, iterable) -> 'TaintedStr':
        result = super().join(iterable)
        if self.is_tainted():
            return self._propagate_taint(result, "str.join")
        if _any_tainted(iterable):
            taint_info = _get_any_taint_info(iterable)
            return TaintedStr(result, taint_info)
        return result

    def replace(self, old, new, count=-1) -> 'TaintedStr':
        result = super().replace(old, new, count)
        if self.is_tainted():
            return self._propagate_taint(result, "str.replace")
        if _is_tainted(new):
            return TaintedStr(result, new._get_taint_info())
        return result

    def lower(self) -> 'TaintedStr':
        return self._propagate_taint(super().lower(), "str.lower")

    def upper(self) -> 'TaintedStr':
        return self._propagate_taint(super().upper(), "str.upper")

    def strip(self, chars=None) -> 'TaintedStr':
        return self._propagate_taint(super().strip(chars), "str.strip")

    def lstrip(self, chars=None) -> 'TaintedStr':
        return self._propagate_taint(super().lstrip(chars), "str.lstrip")

    def rstrip(self, chars=None) -> 'TaintedStr':
        return self._propagate_taint(super().rstrip(chars), "str.rstrip")

    def split(self, sep=None, maxsplit=-1) -> List['TaintedStr']:
        results = super().split(sep, maxsplit)
        if self.is_tainted():
            return [self._propagate_taint(r, "str.split") for r in results]
        return results

    def encode(self, encoding='utf-8', errors='strict') -> 'TaintedBytes':
        result = super().encode(encoding, errors)
        if self.is_tainted():
            return TaintedBytes(result, self._taint_info)
        return result

    def __getitem__(self, key) -> 'TaintedStr':
        result = super().__getitem__(key)
        if self.is_tainted():
            return self._propagate_taint(result, "str.__getitem__")
        return result

    def __repr__(self):
        taint_marker = "[TAINTED]" if self.is_tainted() else ""
        return f"{taint_marker}{super().__repr__()}"


class TaintedBytes(bytes, TaintedMixin):
    """Bytes that track taint status"""

    _taint_info: Optional[TaintInfo] = None

    def __new__(cls, value: bytes = b"", taint_info: Optional[TaintInfo] = None):
        instance = super().__new__(cls, value)
        if taint_info:
            instance._taint_info = taint_info
        return instance

    def _propagate_taint(self, result: bytes, operation: str) -> 'TaintedBytes':
        if not self.is_tainted():
            return result

        new_info = TaintInfo(
            source=self._taint_info.source,
            source_location=self._taint_info.source_location,
            taint_id=self._taint_info.taint_id,
            timestamp=self._taint_info.timestamp,
            original_value_hash=self._taint_info.original_value_hash,
            propagation_chain=self._taint_info.propagation_chain.copy()
        )
        new_info.add_propagation(operation, _get_caller_location())

        return TaintedBytes(result, new_info)

    def __add__(self, other) -> 'TaintedBytes':
        result = super().__add__(other)
        if self.is_tainted():
            return self._propagate_taint(result, "bytes.__add__")
        elif isinstance(other, TaintedMixin) and other.is_tainted():
            return TaintedBytes(result, other._get_taint_info())
        return result

    def decode(self, encoding='utf-8', errors='strict') -> TaintedStr:
        result = super().decode(encoding, errors)
        if self.is_tainted():
            return TaintedStr(result, self._taint_info)
        return result

    def __getitem__(self, key) -> 'TaintedBytes':
        result = super().__getitem__(key)
        if self.is_tainted() and isinstance(result, bytes):
            return self._propagate_taint(result, "bytes.__getitem__")
        return result


# ============================================================================
# Helper Functions
# ============================================================================

def _get_caller_location(depth: int = 2) -> str:
    """Get the file:line of the caller"""
    try:
        frame = sys._getframe(depth)
        return f"{frame.f_code.co_filename}:{frame.f_lineno}"
    except:
        return "unknown"


def _is_tainted(value: Any) -> bool:
    """Check if a value is tainted"""
    if isinstance(value, TaintedMixin):
        return value.is_tainted()
    return False


def _any_tainted(values) -> bool:
    """Check if any value in an iterable is tainted"""
    try:
        for v in values:
            if _is_tainted(v):
                return True
            # Check nested structures
            if isinstance(v, (list, tuple, set)):
                if _any_tainted(v):
                    return True
            elif isinstance(v, dict):
                if _any_tainted(v.keys()) or _any_tainted(v.values()):
                    return True
    except TypeError:
        pass
    return False


def _get_any_taint_info(values) -> Optional[TaintInfo]:
    """Get taint info from the first tainted value"""
    try:
        for v in values:
            if isinstance(v, TaintedMixin) and v.is_tainted():
                return v._get_taint_info()
            if isinstance(v, (list, tuple, set)):
                info = _get_any_taint_info(v)
                if info:
                    return info
            elif isinstance(v, dict):
                info = _get_any_taint_info(v.values())
                if info:
                    return info
    except TypeError:
        pass
    return None


def _extract_taint_info(value: Any) -> Optional[TaintInfo]:
    """Extract taint info from any value"""
    if isinstance(value, TaintedMixin):
        return value._get_taint_info()
    if isinstance(value, (list, tuple)):
        return _get_any_taint_info(value)
    if isinstance(value, dict):
        return _get_any_taint_info(value.values())
    return None


# ============================================================================
# Taint Violation Handling
# ============================================================================

@dataclass
class TaintViolation:
    """Record of a taint violation"""
    sink_type: SinkType
    sink_function: str
    sink_location: str
    taint_info: TaintInfo
    tainted_value_preview: str
    timestamp: float
    stack_trace: str


_violations: List[TaintViolation] = []
_violations_lock = threading.Lock()


def _report_violation(
    sink_type: SinkType,
    sink_function: str,
    taint_info: TaintInfo,
    tainted_value: Any
):
    """Report a taint violation"""
    import time

    # Create violation record
    violation = TaintViolation(
        sink_type=sink_type,
        sink_function=sink_function,
        sink_location=_get_caller_location(3),
        taint_info=taint_info,
        tainted_value_preview=repr(tainted_value)[:200],
        timestamp=time.time(),
        stack_trace=traceback.format_stack()[-10:]  # Last 10 frames
    )

    with _violations_lock:
        _violations.append(violation)

    # Log to file
    if TaintSanConfig.LOG_VIOLATIONS:
        _log_violation(violation)

    # Raise exception
    if TaintSanConfig.RAISE_ON_SINK:
        raise TaintViolationError(violation)


def _log_violation(violation: TaintViolation):
    """Log violation to file"""
    try:
        with open(TaintSanConfig.LOG_FILE, 'a') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"TAINT VIOLATION DETECTED\n")
            f.write(f"Time: {datetime.fromtimestamp(violation.timestamp)}\n")
            f.write(f"Sink Type: {violation.sink_type.name}\n")
            f.write(f"Sink Function: {violation.sink_function}\n")
            f.write(f"Sink Location: {violation.sink_location}\n")
            f.write(f"Taint Source: {violation.taint_info.source.name}\n")
            f.write(f"Taint Origin: {violation.taint_info.source_location}\n")
            f.write(f"Tainted Value: {violation.tainted_value_preview}\n")
            f.write(f"Propagation Chain:\n")
            for step in violation.taint_info.propagation_chain:
                f.write(f"  -> {step}\n")
            f.write(f"Stack Trace:\n")
            for line in violation.stack_trace:
                f.write(f"  {line}")
            f.write(f"{'='*60}\n")
    except Exception as e:
        print(f"TaintSan: Failed to log violation: {e}", file=sys.stderr)


class TaintViolationError(Exception):
    """Exception raised when tainted data reaches a dangerous sink"""

    def __init__(self, violation: TaintViolation):
        self.violation = violation
        message = (
            f"TAINT VIOLATION: {violation.sink_type.name} sink '{violation.sink_function}' "
            f"received tainted data from {violation.taint_info.source.name} "
            f"(origin: {violation.taint_info.source_location})"
        )
        super().__init__(message)


# ============================================================================
# Sink Monitors - Hook dangerous functions
# ============================================================================

def _check_sink(sink_type: SinkType, sink_name: str, *args, **kwargs):
    """Check if any argument to a sink is tainted"""
    # Check positional args
    for arg in args:
        taint_info = _extract_taint_info(arg)
        if taint_info:
            _report_violation(sink_type, sink_name, taint_info, arg)

    # Check keyword args
    for key, value in kwargs.items():
        taint_info = _extract_taint_info(value)
        if taint_info:
            _report_violation(sink_type, sink_name, taint_info, value)


def _wrap_sink(original_func: Callable, sink_type: SinkType, sink_name: str) -> Callable:
    """Wrap a function to check for tainted arguments"""
    @functools.wraps(original_func)
    def wrapper(*args, **kwargs):
        _check_sink(sink_type, sink_name, *args, **kwargs)
        return original_func(*args, **kwargs)
    return wrapper


# Store original functions for restoration
_original_functions: Dict[str, Callable] = {}


def _install_sql_monitors():
    """Install monitors for SQL-related functions"""
    if not TaintSanConfig.MONITOR_SQL:
        return

    # sqlite3
    try:
        import sqlite3
        _original_functions['sqlite3.Cursor.execute'] = sqlite3.Cursor.execute
        sqlite3.Cursor.execute = _wrap_sink(
            sqlite3.Cursor.execute, SinkType.SQL_QUERY, "sqlite3.Cursor.execute"
        )
        _original_functions['sqlite3.Cursor.executemany'] = sqlite3.Cursor.executemany
        sqlite3.Cursor.executemany = _wrap_sink(
            sqlite3.Cursor.executemany, SinkType.SQL_QUERY, "sqlite3.Cursor.executemany"
        )
    except ImportError:
        pass

    # MySQL connector
    try:
        import mysql.connector
        # Hook cursor.execute
    except ImportError:
        pass

    # psycopg2 (PostgreSQL)
    try:
        import psycopg2
        # Hook cursor.execute
    except ImportError:
        pass


def _install_shell_monitors():
    """Install monitors for shell command execution"""
    if not TaintSanConfig.MONITOR_SHELL:
        return

    import subprocess
    import os

    # subprocess.run
    _original_functions['subprocess.run'] = subprocess.run
    subprocess.run = _wrap_sink(subprocess.run, SinkType.SHELL_COMMAND, "subprocess.run")

    # subprocess.Popen
    _original_functions['subprocess.Popen'] = subprocess.Popen
    subprocess.Popen = _wrap_sink(subprocess.Popen, SinkType.SHELL_COMMAND, "subprocess.Popen")

    # subprocess.call
    _original_functions['subprocess.call'] = subprocess.call
    subprocess.call = _wrap_sink(subprocess.call, SinkType.SHELL_COMMAND, "subprocess.call")

    # subprocess.check_output
    _original_functions['subprocess.check_output'] = subprocess.check_output
    subprocess.check_output = _wrap_sink(
        subprocess.check_output, SinkType.SHELL_COMMAND, "subprocess.check_output"
    )

    # os.system
    _original_functions['os.system'] = os.system
    os.system = _wrap_sink(os.system, SinkType.SHELL_COMMAND, "os.system")

    # os.popen
    _original_functions['os.popen'] = os.popen
    os.popen = _wrap_sink(os.popen, SinkType.SHELL_COMMAND, "os.popen")

    # os.execv family
    for func_name in ['execl', 'execle', 'execlp', 'execlpe', 'execv', 'execve', 'execvp', 'execvpe']:
        if hasattr(os, func_name):
            _original_functions[f'os.{func_name}'] = getattr(os, func_name)
            setattr(os, func_name, _wrap_sink(
                getattr(os, func_name), SinkType.SHELL_COMMAND, f"os.{func_name}"
            ))


def _install_eval_monitors():
    """Install monitors for eval/exec"""
    if not TaintSanConfig.MONITOR_EVAL:
        return

    import builtins

    # eval
    _original_functions['builtins.eval'] = builtins.eval
    builtins.eval = _wrap_sink(builtins.eval, SinkType.EVAL_EXEC, "eval")

    # exec
    _original_functions['builtins.exec'] = builtins.exec
    builtins.exec = _wrap_sink(builtins.exec, SinkType.EVAL_EXEC, "exec")

    # compile
    _original_functions['builtins.compile'] = builtins.compile
    builtins.compile = _wrap_sink(builtins.compile, SinkType.EVAL_EXEC, "compile")


def _install_file_monitors():
    """Install monitors for file operations"""
    if not TaintSanConfig.MONITOR_FILE:
        return

    import builtins
    import os

    # open() - check filename for path traversal
    _original_functions['builtins.open'] = builtins.open
    builtins.open = _wrap_sink(builtins.open, SinkType.FILE_PATH, "open")

    # os.path operations that could be dangerous with tainted input
    for func_name in ['remove', 'unlink', 'rmdir', 'rename', 'mkdir', 'makedirs',
                      'chmod', 'chown', 'symlink', 'link']:
        if hasattr(os, func_name):
            _original_functions[f'os.{func_name}'] = getattr(os, func_name)
            setattr(os, func_name, _wrap_sink(
                getattr(os, func_name), SinkType.FILE_PATH, f"os.{func_name}"
            ))


def _install_network_monitors():
    """Install monitors for network operations"""
    if not TaintSanConfig.MONITOR_NETWORK:
        return

    # urllib
    try:
        import urllib.request
        _original_functions['urllib.request.urlopen'] = urllib.request.urlopen
        urllib.request.urlopen = _wrap_sink(
            urllib.request.urlopen, SinkType.NETWORK_REQUEST, "urllib.request.urlopen"
        )
    except ImportError:
        pass

    # requests library
    try:
        import requests
        for method in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
            func = getattr(requests, method)
            _original_functions[f'requests.{method}'] = func
            setattr(requests, method, _wrap_sink(
                func, SinkType.NETWORK_REQUEST, f"requests.{method}"
            ))
    except ImportError:
        pass


def _install_deserialize_monitors():
    """Install monitors for deserialization"""
    if not TaintSanConfig.MONITOR_DESERIALIZE:
        return

    # pickle
    try:
        import pickle
        _original_functions['pickle.loads'] = pickle.loads
        pickle.loads = _wrap_sink(pickle.loads, SinkType.DESERIALIZE, "pickle.loads")

        _original_functions['pickle.load'] = pickle.load
        pickle.load = _wrap_sink(pickle.load, SinkType.DESERIALIZE, "pickle.load")
    except ImportError:
        pass

    # yaml
    try:
        import yaml
        if hasattr(yaml, 'unsafe_load'):
            _original_functions['yaml.unsafe_load'] = yaml.unsafe_load
            yaml.unsafe_load = _wrap_sink(yaml.unsafe_load, SinkType.DESERIALIZE, "yaml.unsafe_load")

        # yaml.load with unsafe Loader
        _original_functions['yaml.load'] = yaml.load
        def _yaml_load_wrapper(data, Loader=None, **kwargs):
            # Check if using unsafe loader
            unsafe_loaders = ['UnsafeLoader', 'FullLoader', 'Loader']
            if Loader and Loader.__name__ in unsafe_loaders:
                _check_sink(SinkType.DESERIALIZE, "yaml.load", data)
            return _original_functions['yaml.load'](data, Loader=Loader, **kwargs)
        yaml.load = _yaml_load_wrapper
    except ImportError:
        pass

    # json (generally safe, but check anyway for completeness)
    try:
        import json
        _original_functions['json.loads'] = json.loads
        # Note: json.loads is generally safe, but we monitor it for completeness
        # Don't wrap it by default as it's very common and safe
    except ImportError:
        pass


# ============================================================================
# Public API
# ============================================================================

def taint(value: Any, source: TaintSource = TaintSource.USER_MARKED) -> Any:
    """
    Mark a value as tainted.

    Args:
        value: The value to taint (str, bytes, or other)
        source: The source of the tainted data

    Returns:
        A tainted version of the value
    """
    import time

    taint_info = TaintInfo(
        source=source,
        source_location=_get_caller_location(),
        taint_id=_next_taint_id(),
        timestamp=time.time(),
        original_value_hash=hash(str(value)[:1000]) if value else 0,
        propagation_chain=[]
    )

    if isinstance(value, str):
        return TaintedStr(value, taint_info)
    elif isinstance(value, bytes):
        return TaintedBytes(value, taint_info)
    else:
        # For other types, we can't easily wrap them
        # In a full implementation, we'd have TaintedList, TaintedDict, etc.
        return value


def taint_from_fuzzer(data: bytes) -> TaintedBytes:
    """Convenience function for tainting fuzzer input"""
    return taint(data, TaintSource.FUZZER)


def is_tainted(value: Any) -> bool:
    """Check if a value is tainted"""
    return _is_tainted(value)


def get_violations() -> List[TaintViolation]:
    """Get all recorded violations"""
    with _violations_lock:
        return _violations.copy()


def clear_violations():
    """Clear recorded violations"""
    global _violations
    with _violations_lock:
        _violations = []


def install():
    """Install all TaintSan monitors"""
    print("TaintSan: Installing taint tracking monitors...", file=sys.stderr)

    _install_sql_monitors()
    _install_shell_monitors()
    _install_eval_monitors()
    _install_file_monitors()
    _install_network_monitors()
    _install_deserialize_monitors()

    print("TaintSan: Monitors installed successfully", file=sys.stderr)


def uninstall():
    """Restore original functions"""
    import builtins
    import subprocess
    import os

    for name, func in _original_functions.items():
        parts = name.split('.')
        if len(parts) == 2:
            module_name, func_name = parts
            if module_name == 'builtins':
                setattr(builtins, func_name, func)
            elif module_name == 'subprocess':
                setattr(subprocess, func_name, func)
            elif module_name == 'os':
                setattr(os, func_name, func)
            # Add other modules as needed

    _original_functions.clear()
    print("TaintSan: Monitors uninstalled", file=sys.stderr)


# ============================================================================
# Integration with Atheris
# ============================================================================

def atheris_test_one_input(test_func: Callable[[bytes], None]) -> Callable[[bytes], None]:
    """
    Decorator to wrap an Atheris test function with taint tracking.

    Usage:
        @taintsan.atheris_test_one_input
        def TestOneInput(data: bytes):
            # data is automatically tainted
            process_input(data)
    """
    @functools.wraps(test_func)
    def wrapper(data: bytes):
        tainted_data = taint_from_fuzzer(data)
        try:
            test_func(tainted_data)
        except TaintViolationError as e:
            # Re-raise as a regular exception for Atheris to catch
            raise RuntimeError(str(e)) from e

    return wrapper


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    # Demo of TaintSan
    install()

    print("\n--- TaintSan Demo ---\n")

    # Create tainted string
    user_input = taint("'; DROP TABLE users; --", TaintSource.HTTP_REQUEST)
    print(f"Tainted input: {user_input}")
    print(f"Is tainted: {is_tainted(user_input)}")

    # Taint propagates through operations
    modified = user_input.upper()
    print(f"After upper(): {modified}")
    print(f"Still tainted: {is_tainted(modified)}")

    concatenated = "SELECT * FROM users WHERE name = '" + user_input + "'"
    print(f"SQL query: {concatenated}")
    print(f"Query tainted: {is_tainted(concatenated)}")

    # This would trigger a violation (uncomment to test):
    # import subprocess
    # subprocess.run(["echo", user_input], shell=True)  # VIOLATION!

    print("\n--- Demo Complete ---")
