# SPDX-License-Identifier: Apache-2.0
"""
Adversarial tests for the tree-sitter C/C++ function extractor.

Function-name resolution walks tree-sitter declarator subtrees, which are a
minefield of nesting: pointer returns, function-pointer parameters, functions
that RETURN function pointers, C++ scope-resolved methods, K&R prototypes, and
multi-line signatures. These tests feed each shape and assert the extracted
name and (1-indexed) line span. They also pin the crucial negative: a bare
prototype (declaration, no body) must NOT be reported as a definition.
"""

from fuzzingbrain.analysis.parsers.c_parser import (
    extract_c_functions,
    parse_c_file,
)


def _names(src: str):
    return [f.name for f in extract_c_functions(src.encode(), "x.c")]


def _one(src: str):
    fns = extract_c_functions(src.encode(), "x.c")
    assert len(fns) == 1, f"expected exactly one function, got {[f.name for f in fns]}"
    return fns[0]


# --------------------------------------------------------------------------
# Return-type / declarator shapes
# --------------------------------------------------------------------------


def test_plain_function():
    assert _names("int foo(int x){ return x; }") == ["foo"]


def test_pointer_and_double_pointer_return():
    assert _names("char *foo(void){ return 0; }") == ["foo"]
    assert _names("char **bar(void){ return 0; }") == ["bar"]


def test_void_star_and_const_pointer_return():
    assert _names("void *alloc(int n){ return 0; }") == ["alloc"]
    assert _names('const char *name(void){ return "x"; }') == ["name"]


def test_qualified_and_storage_class():
    assert _names("static inline unsigned long c(void){ return 0; }") == ["c"]


def test_function_pointer_parameter_uses_function_name_not_param():
    """The parameter is a function pointer 'f'; the function name is 'cb'.

    A resolver that grabs the first identifier in the declarator subtree would
    wrongly return the parameter name.
    """
    assert _names("int cb(void (*f)(int)){ return 0; }") == ["cb"]


def test_function_returning_function_pointer():
    """Regression: 'void (*getcb(int x))(int)' returns a function pointer.

    The old fixed-depth walk returned None (function silently dropped). The
    name is 'getcb' — not the parameter 'x', not None.
    """
    assert _names("void (*getcb(int x))(int){ return 0; }") == ["getcb"]


def test_cpp_scope_resolved_method():
    """C++ 'int MyClass::method(int a)' — the simple name is 'method'."""
    assert _names("int MyClass::method(int a){ return a; }") == ["method"]


def test_kr_style_definition():
    assert _names("int old(a, b) int a; int b; { return a + b; }") == ["old"]


# --------------------------------------------------------------------------
# Line spans (1-indexed) and content
# --------------------------------------------------------------------------


def test_single_line_span():
    f = _one("int foo(void){ return 0; }")
    assert (f.start_line, f.end_line) == (1, 1)


def test_multiline_span_is_first_to_last_line():
    src = "int\nmulti(\n  int a,\n  int b\n)\n{\n  return a;\n}"
    f = _one(src)
    assert f.name == "multi"
    assert f.start_line == 1  # starts at the return type line
    assert f.end_line == 8  # closing brace line


def test_leading_comment_not_counted_in_span():
    """A doc comment above the function is not part of the definition node."""
    f = _one("/* doc */\nint g(void){ return 0; }")
    assert f.name == "g"
    assert f.start_line == 2


def test_content_is_the_exact_definition_bytes():
    src = "int foo(void){ return 42; }"
    f = _one(src)
    assert f.content == src


# --------------------------------------------------------------------------
# Negatives: what must NOT be extracted
# --------------------------------------------------------------------------


def test_bare_prototype_is_not_a_definition():
    """A declaration with no body must not be reported as a function."""
    assert _names("int justdecl(int);") == []


def test_empty_and_comment_only_sources():
    assert _names("") == []
    assert _names("// nothing\n/* here */") == []


def test_global_variable_is_not_a_function():
    assert _names("int global_counter = 0;") == []


def test_typedef_is_not_a_function():
    assert _names("typedef int (*handler_t)(int, int);") == []


# --------------------------------------------------------------------------
# Multiple functions / ordering
# --------------------------------------------------------------------------


def test_multiple_functions_in_order():
    src = "int a(void){return 1;}\nint b(void){return 2;}\nint c(void){return 3;}"
    fns = extract_c_functions(src.encode(), "x.c")
    assert [f.name for f in fns] == ["a", "b", "c"]
    assert [f.start_line for f in fns] == [1, 2, 3]


def test_nested_gnu_function_both_captured():
    """GNU nested functions: both outer and inner are definitions."""
    src = "int outer(void){ int inner(int y){ return y; } return inner(3); }"
    assert set(_names(src)) == {"outer", "inner"}


# --------------------------------------------------------------------------
# Robustness: bad bytes / bad UTF-8 must not crash
# --------------------------------------------------------------------------


def test_non_utf8_bytes_in_body_do_not_crash():
    """A stray invalid UTF-8 byte in the body must be replaced, not raise."""
    src = b"int f(void){ char c = '\xff'; return 0; }"
    fns = extract_c_functions(src, "x.c")
    assert [f.name for f in fns] == ["f"]


def test_parse_c_file_reads_and_extracts(tmp_path):
    p = tmp_path / "src.c"
    p.write_text("int fromfile(int n){ return n * 2; }")
    fns = parse_c_file(p)
    assert [f.name for f in fns] == ["fromfile"]
    assert fns[0].file_path == str(p)
