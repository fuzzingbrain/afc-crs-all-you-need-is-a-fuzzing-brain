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
    frame = sys._getframe(level)
    tb = None
    while frame.f_back is not None:
        frame = frame.f_back
        tb = types.TracebackType(tb, frame, frame.f_lasti, frame.f_lineno)
    return tb

class CRSError(Exception):
    def __init__(self, error: str, extra: Optional[dict[str, Any]] = None, include_traceback: bool = True):
        self.error = error
        self.extra = extra
        if include_traceback:
            self.__traceback__ = synthetic_traceback(level=1)
    def __repr__(self):
        return f'{self.__class__.__name__}({self.error}, extra={self.extra})'

type Result[T] = Ok[T] | Err[CRSError]

def parse_fuzzer_name(vuln_yaml_path: str) -> Optional[str]:
    try:
        with open(vuln_yaml_path, 'r') as f:
            data = yaml.safe_load(f)
            return data['pov']['harness']
    except Exception as e:
        print(f"Error parsing fuzzer name from {vuln_yaml_path}: {e}")
        return None

def trim_tool_output(output: str, max_length: int = 1000) -> str:
    if len(output) <= max_length:
        return output
    return output[:max_length] + "... (truncated)"

def require(result):
    if isinstance(result, Err):
        raise result.error
    return result.value

def requireable(func):
    return func

class SourceContents(TypedDict): start:int; end:int; contents:str
class FileReference(TypedDict): line:int; content:str
class FileReferences(TypedDict): file_name:str; refs:List[FileReference]


