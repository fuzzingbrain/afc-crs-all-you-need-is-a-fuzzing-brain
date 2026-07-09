# SPDX-License-Identifier: Apache-2.0
"""
Adversarial tests for POVPackager's serialization / file-materialization helpers.

These target the pure, side-effecting-but-deterministic pieces that run while
packaging a verified POV: datetime serialization, conversation->markdown (which
must survive structured/dict tool content and truncate long tool output), the
POV-binary writer's decode/copy/placeholder fallbacks, the generator-script
wrapper, and the zip builder. A crash in any of these silently turns a real POV
into a None return from package_pov, so robustness here is load-bearing.
"""

import asyncio
import base64
import zipfile
from datetime import datetime

from fuzzingbrain.core.pov_packager import POVPackager


def _packager(tmp_path):
    return POVPackager(results_dir=str(tmp_path))


def _run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------
# _serialize_datetime
# --------------------------------------------------------------------------


def test_serialize_datetime_none_is_none(tmp_path):
    assert _packager(tmp_path)._serialize_datetime(None) is None


def test_serialize_datetime_roundtrips_iso(tmp_path):
    dt = datetime(2026, 7, 3, 12, 30, 45)
    assert _packager(tmp_path)._serialize_datetime(dt) == "2026-07-03T12:30:45"


def test_serialize_datetime_non_datetime_stringified(tmp_path):
    """A pre-stringified value (or ObjectId, etc.) must be coerced with str(),
    never assumed to be a datetime."""
    assert _packager(tmp_path)._serialize_datetime("2026-01-01") == "2026-01-01"
    assert _packager(tmp_path)._serialize_datetime(12345) == "12345"


# --------------------------------------------------------------------------
# _conversation_to_markdown
# --------------------------------------------------------------------------


def test_markdown_empty_conversation_has_placeholder(tmp_path):
    md = _packager(tmp_path)._conversation_to_markdown([])
    assert "No conversation history available" in md


def test_markdown_renders_each_role(tmp_path):
    conv = [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "USR"},
        {"role": "assistant", "content": "ASST"},
        {"role": "tool", "name": "grep", "content": "TOOLOUT"},
    ]
    md = _packager(tmp_path)._conversation_to_markdown(conv)
    assert "## System Prompt" in md and "SYS" in md
    assert "### User" in md and "USR" in md
    assert "### Assistant" in md and "ASST" in md
    assert "Tool: grep" in md and "TOOLOUT" in md


def test_markdown_truncates_long_tool_output(tmp_path):
    """Tool output is capped at 2000 chars; a 5000-char blob must be cut."""
    conv = [{"role": "tool", "name": "cat", "content": "X" * 5000}]
    md = _packager(tmp_path)._conversation_to_markdown(conv)
    assert "X" * 2000 in md
    assert "X" * 2001 not in md


def test_markdown_survives_dict_tool_content(tmp_path):
    """Regression: dict content hit `content[:2000]` -> TypeError('unhashable
    type: slice') and crashed the whole packaging. It must render instead."""
    conv = [{"role": "tool", "name": "x", "content": {"stdout": "boom", "rc": 1}}]
    md = _packager(tmp_path)._conversation_to_markdown(conv)
    assert "Tool: x" in md
    assert "boom" in md  # dict is serialized, content preserved


def test_markdown_survives_list_content(tmp_path):
    """Anthropic-style structured content (list of blocks) must not crash."""
    conv = [{"role": "assistant", "content": [{"type": "text", "text": "hello"}]}]
    md = _packager(tmp_path)._conversation_to_markdown(conv)
    assert "hello" in md


def test_markdown_unknown_role_is_ignored_not_fatal(tmp_path):
    conv = [{"role": "function", "content": "weird"}, {"role": "user", "content": "hi"}]
    md = _packager(tmp_path)._conversation_to_markdown(conv)
    assert "hi" in md  # known role still rendered; unknown one simply skipped


# --------------------------------------------------------------------------
# _write_pov_binary: decode / copy / placeholder fallbacks
# --------------------------------------------------------------------------


def test_write_binary_decodes_base64_blob(tmp_path):
    raw = b"\x00\x01CRASH\xff"
    pov = {"blob": base64.b64encode(raw).decode()}
    folder = tmp_path / "pov"
    folder.mkdir()
    _run(_packager(tmp_path)._write_pov_binary(folder, pov))
    assert (folder / "pov.bin").read_bytes() == raw


def test_write_binary_copies_from_blob_path_when_no_blob(tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(b"from-disk")
    folder = tmp_path / "pov"
    folder.mkdir()
    _run(_packager(tmp_path)._write_pov_binary(folder, {"blob_path": str(src)}))
    assert (folder / "pov.bin").read_bytes() == b"from-disk"


def test_write_binary_placeholder_when_nothing_available(tmp_path):
    folder = tmp_path / "pov"
    folder.mkdir()
    _run(_packager(tmp_path)._write_pov_binary(folder, {}))
    assert b"not available" in (folder / "pov.bin").read_bytes()


def test_write_binary_missing_blob_path_falls_through_to_placeholder(tmp_path):
    """blob_path pointing at a nonexistent file must not raise; placeholder."""
    folder = tmp_path / "pov"
    folder.mkdir()
    _run(
        _packager(tmp_path)._write_pov_binary(
            folder, {"blob_path": str(tmp_path / "nope.bin")}
        )
    )
    assert (folder / "pov.bin").exists()


# --------------------------------------------------------------------------
# _write_gen_blob
# --------------------------------------------------------------------------


def test_gen_blob_wraps_user_code_with_main(tmp_path):
    folder = tmp_path / "pov"
    folder.mkdir()
    _run(
        _packager(tmp_path)._write_gen_blob(
            folder, {"gen_blob": "def generate():\n    return b'x'"}
        )
    )
    text = (folder / "gen_blob.py").read_text()
    assert "def generate():" in text
    assert '__name__ == "__main__"' in text
    assert "sys.stdout.buffer.write(data)" in text


def test_gen_blob_placeholder_when_absent(tmp_path):
    folder = tmp_path / "pov"
    folder.mkdir()
    _run(_packager(tmp_path)._write_gen_blob(folder, {}))
    assert "No generator code available" in (folder / "gen_blob.py").read_text()


# --------------------------------------------------------------------------
# _write_sp_details: None SP (fuzzer-discovered crash) path
# --------------------------------------------------------------------------


def test_sp_details_handles_none_sp(tmp_path):
    """A fuzzer-discovered crash has no SP; the writer must emit a valid record,
    not dereference None."""
    import json

    folder = tmp_path / "pov"
    folder.mkdir()
    _run(_packager(tmp_path)._write_sp_details(folder, None))
    data = json.loads((folder / "sp_details.json").read_text())
    assert data["function_name"] == "fuzzer-discovered"
    assert data["suspicious_point_id"] is None


# --------------------------------------------------------------------------
# _create_zip
# --------------------------------------------------------------------------


def test_create_zip_contains_top_level_files_by_name(tmp_path):
    folder = tmp_path / "pov_abc"
    folder.mkdir()
    (folder / "report.md").write_text("r")
    (folder / "pov.bin").write_bytes(b"b")
    # a nested dir should be ignored (writer only takes top-level files)
    (folder / "sub").mkdir()
    (folder / "sub" / "ignored.txt").write_text("x")

    zpath = tmp_path / "out.zip"
    _packager(tmp_path)._create_zip(folder, zpath)

    with zipfile.ZipFile(zpath) as zf:
        names = set(zf.namelist())
    assert names == {"report.md", "pov.bin"}  # flat, no 'sub/ignored.txt'
