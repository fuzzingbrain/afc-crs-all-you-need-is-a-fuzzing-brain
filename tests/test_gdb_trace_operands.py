"""reach_probe operand capture: script generation and FBOPS parsing (no gdb)."""
import json
import re

from fuzzingbrain.tools.gdb_trace import _gen_script, _parse


def _python_blocks(script):
    return re.findall(r"^python\n(.*?)^end$", script, re.S | re.M)


def _commands_for(script, loc):
    m = re.search(rf"^break {re.escape(loc)}\ncommands\n(.*?)^end$", script, re.S | re.M)
    return m.group(1) if m else ""


def test_sink_that_is_also_a_target_shares_one_breakpoint():
    s = _gen_script(["dict_do", "sendf"], "dict_do", {})
    assert s.count("break dict_do\n") == 1
    body = _commands_for(s, "dict_do")
    assert 'printf "HIT:dict_do\\n"' in body
    assert 'printf "HIT-SINK:dict_do\\n"' in body
    assert body.rstrip().endswith("continue")


def test_separate_sink_gets_its_own_breakpoint():
    s = _gen_script(["dict_do"], "dict.c:230", {})
    assert "break dict.c:230\n" in s
    body = _commands_for(s, "dict.c:230")
    assert "HIT-SINK:dict.c:230" in body and "HIT:dict.c:230" not in body


def test_embedded_python_is_valid_and_carries_operand_exprs():
    s = _gen_script(["f"], None, {"len": "buf->len", "q": 'p[0] == "x"'})
    blocks = _python_blocks(s)
    assert len(blocks) == 2
    for b in blocks:
        compile(b, "<gdb-python>", "exec")
    ns = {}
    exec(blocks[0].split("\ndef ")[0], ns)   # the header needs no gdb module
    assert ns["_FB_OPS"] == {"len": "buf->len", "q": 'p[0] == "x"'}


def _out(fbops, extra=""):
    return extra + "\nFBOPS " + json.dumps(fbops) + "\n"


def test_parse_prefers_sink_then_crash_then_last():
    sink = {"at": "dict_do @ dict.c:230", "values": {"data": "0x1"}}
    crash = {"at": "formatf @ mprintf.c:894", "values": {"format": "\"user%s\""}}
    last = {"at": "sendf @ dict.c:139", "values": {"fmt": "0x2"}}
    r = _parse(_out({"sink": sink, "crash": crash, "last": last}), ["sendf"], "dict_do", {})
    assert (r["operands_source"], r["operands_at"]) == ("sink", "dict_do @ dict.c:230")
    r = _parse(_out({"sink": None, "crash": crash, "last": last}), ["sendf"], None, {})
    assert r["operands_source"] == "crash" and r["operands"] == {"format": "\"user%s\""}
    r = _parse(_out({"sink": None, "crash": None, "last": last}), ["sendf"], None, {})
    assert r["operands_source"] == "last" and r["operands_at"] == "sendf @ dict.c:139"


def test_parse_without_fbops_leaves_operands_empty():
    r = _parse("HIT:f\n[Inferior 1 (process 1) exited normally]\n", ["f"], None, {})
    assert r["reached"] == {"f": True}
    assert r["operands"] == {} and r["operands_at"] is None and r["operands_source"] is None


def test_sink_reached_needs_hit_sink_line():
    r = _parse("HIT:dict_do\nHIT-SINK:dict_do\n" + "FBOPS {}\n", ["dict_do"], "dict_do", {})
    assert r["sink_reached"] is True
