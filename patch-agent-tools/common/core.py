import sys
import types
from typing import TypedDict, List, Optional, Any, TypeVar, Generic
import yaml

class Ok:
    __match_args__ = ("value",)
    def __init__(self, value):
        self.value = value
    def __repr__(self):
        return f"Ok({self.value})"

class Err:
    __match_args__ = ("error",)
    def __init__(self, error):
        self.error = error
    def __repr__(self):
        return f"Err({self.error})"

def synthetic_traceback(level: int = 0):
    """Generate a synthetic traceback for error reporting."""
    frame = sys._getframe(level)
    tb = None
    while frame.f_back is not None:
        frame = frame.f_back
        tb = types.TracebackType(tb, frame, frame.f_lasti, frame.f_lineno)
    return tb

# Common exception type for all of our handled exceptions
class CRSError(Exception):
    def __init__(self, error: str, extra: Optional[dict[str, Any]] = None, include_traceback: bool = True):
        self.error = error
        self.extra = extra
        if include_traceback:
            self.__traceback__ = synthetic_traceback(level=1)

    def __repr__(self):
        return f'{self.__class__.__name__}({self.error}, extra={self.extra})'

# Simplify result based on fixed error type
type Result[T] = Ok[T] | Err[CRSError]

# Utility functions that were moved from test_patch.py
def parse_fuzzer_name(vuln_yaml_path: str) -> Optional[str]:
    """Parse fuzzer name from vuln.yaml file."""
    try:
        with open(vuln_yaml_path, 'r') as f:
            data = yaml.safe_load(f)
            return data['pov']['harness']
    except Exception as e:
        print(f"Error parsing fuzzer name from {vuln_yaml_path}: {e}")
        return None

def trim_tool_output(output: str, max_length: int = 1000) -> str:
    """Trim tool output to reasonable length."""
    if len(output) <= max_length:
        return output
    return output[:max_length] + "... (truncated)"



# 工具函数

def require(result):
    """从Result中提取值，失败时抛出异常"""
    if isinstance(result, Err):
        raise result.error
    return result.value

def requireable(func):
    """装饰器，用于标记需要验证的函数"""
    return func

class SourceContents(TypedDict): start:int; end:int; contents:str
class FileReference(TypedDict): line:int; content:str
class FileReferences(TypedDict): file_name:str; refs:List[FileReference]