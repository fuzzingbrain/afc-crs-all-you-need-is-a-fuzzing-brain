#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Run Viewer - Generate a web page to view run details

Usage:
    python view_run.py <run_id>
    python view_run.py  # Interactive mode
"""

import argparse
import json
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

from pymongo import MongoClient


def find_conversations(run_id: str) -> list:
    """Find all conversation JSON files for a run."""
    conversations = []
    logs_dir = Path("logs")

    # Find run log directory
    for run_dir in logs_dir.glob(f"*_{run_id}_*"):
        agent_dir = run_dir / "agent"
        if agent_dir.exists():
            for conv_file in agent_dir.glob("*.conversation.json"):
                try:
                    with open(conv_file, "r", encoding="utf-8") as f:
                        conv_data = json.load(f)
                        conversations.append(
                            {
                                "file": str(conv_file.name),
                                "messages": conv_data
                                if isinstance(conv_data, list)
                                else conv_data.get("messages", []),
                            }
                        )
                except Exception as e:
                    print(f"Warning: Failed to read {conv_file}: {e}")

    return conversations


def extract_tool_calls(conversations: list) -> list:
    """Extract all tool calls from conversations."""
    tool_calls = []

    for conv in conversations:
        conv_file = conv.get("file", "Unknown")
        for msg in conv.get("messages", []):
            # Check for tool_calls in assistant messages
            if msg.get("tool_calls"):
                for tc in msg["tool_calls"]:
                    func = tc.get("function", {})
                    tool_calls.append(
                        {
                            "conversation": conv_file,
                            "tool_call_id": tc.get("id", ""),
                            "name": func.get("name", "unknown"),
                            "arguments": func.get("arguments", ""),
                        }
                    )

            # Check for tool role messages (responses)
            if msg.get("role") == "tool":
                tool_call_id = msg.get("tool_call_id", "")
                content = msg.get("content", "")
                # Find matching call and add response
                for tc in tool_calls:
                    if tc.get("tool_call_id") == tool_call_id and "response" not in tc:
                        tc["response"] = content
                        break

    return tool_calls


def get_run_data(run_id: str) -> dict:
    """Fetch all run-related data from MongoDB."""
    import re

    client = MongoClient("mongodb://localhost:27017")
    db = client["fuzzingbrain"]

    # Try exact match first, then partial match
    run = db.runs.find_one({"run_id": run_id})
    if not run:
        # Try partial match - run_id might be embedded in a longer ID
        run = db.runs.find_one({"run_id": re.compile(run_id)})

    # Get the actual run_id from the found run for consistent queries
    actual_run_id = run["run_id"] if run else run_id

    # Get workers for this run
    workers = list(db.workers.find({"run_id": actual_run_id}))

    # Get vulnerability hypotheses for this run
    vulnerability_hypotheses = list(db.vulnerability_hypotheses.find({"run_id": actual_run_id}))

    # Get PoCs for this run
    pocs = list(db.pocs.find({"run_id": actual_run_id}))

    # Convert ObjectId to string
    for w in workers:
        w["_id"] = str(w["_id"])
    for vh in vulnerability_hypotheses:
        vh["_id"] = str(vh["_id"])
    for poc in pocs:
        poc["_id"] = str(poc["_id"])
    if run:
        run["_id"] = str(run["_id"])

    # Get conversations - use actual_run_id for consistent matching
    conversations = find_conversations(actual_run_id)

    # Extract tool calls
    tool_calls = extract_tool_calls(conversations)

    return {
        "run": run,
        "workers": workers,
        "vulnerability_hypotheses": vulnerability_hypotheses,
        "pocs": pocs,
        "conversations": conversations,
        "tool_calls": tool_calls,
    }


def generate_html(run_id: str, data: dict) -> str:
    """Generate HTML content for the run viewer."""
    run = data["run"]
    workers = data["workers"]
    vulnerability_hypotheses = data["vulnerability_hypotheses"]
    pocs = data.get("pocs", [])
    conversations = data.get("conversations", [])
    tool_calls = data.get("tool_calls", [])

    # Sort vulnerability hypotheses by score (descending)
    vulnerability_hypotheses.sort(key=lambda x: x.get("score", 0), reverse=True)

    # Status colors
    def status_color(status):
        colors = {
            "pending": "#6c757d",
            "building": "#17a2b8",
            "running": "#007bff",
            "completed": "#28a745",
            "failed": "#dc3545",
        }
        return colors.get(status, "#6c757d")

    def vuln_color(vuln_type):
        colors = {
            "buffer-overflow": "#dc3545",
            "use-after-free": "#e83e8c",
            "out-of-bounds-read": "#fd7e14",
            "out-of-bounds-write": "#dc3545",
            "integer-overflow": "#6f42c1",
            "null-pointer-dereference": "#20c997",
            "format-string": "#17a2b8",
            "double-free": "#e83e8c",
            "uninitialized-memory": "#6c757d",
        }
        return colors.get(vuln_type, "#6c757d")

    def score_color(score):
        if score >= 0.8:
            return "#dc3545"  # Red - high confidence
        elif score >= 0.5:
            return "#fd7e14"  # Orange - medium
        else:
            return "#6c757d"  # Gray - low

    # Helper function to generate time bar HTML
    def generate_time_bar(w):
        """Generate time bar HTML for a worker."""
        # Phase definitions: (name, field, color)
        phases = [
            ("Build", "phase_build", "#4CAF50"),  # Green
            ("Reach", "phase_reachability", "#2196F3"),  # Blue
            ("Find VH", "phase_find_vh", "#FF9800"),  # Orange
            ("Verify", "phase_verify", "#9C27B0"),  # Purple
            ("POC", "phase_poc", "#E91E63"),  # Pink
            ("Save", "phase_save", "#607D8B"),  # Grey
        ]

        # Calculate total and phase durations
        phase_values = []
        for name, field, color in phases:
            duration = w.get(field, 0) or 0
            phase_values.append((name, duration, color))

        total_tracked = sum(p[1] for p in phase_values)

        # Calculate total worker time from timestamps
        started_at = w.get("started_at")
        finished_at = w.get("finished_at")
        total_time = 0
        if started_at and finished_at:
            if isinstance(started_at, str):
                try:
                    started_at = datetime.fromisoformat(
                        started_at.replace("Z", "+00:00")
                    )
                except Exception:
                    started_at = None
            if isinstance(finished_at, str):
                try:
                    finished_at = datetime.fromisoformat(
                        finished_at.replace("Z", "+00:00")
                    )
                except Exception:
                    finished_at = None
            if started_at and finished_at:
                total_time = (finished_at - started_at).total_seconds()

        # Use tracked total if no timestamps
        if total_time <= 0:
            total_time = total_tracked

        # Add "Other" time if there's untracked time
        other_time = max(0, total_time - total_tracked)
        if other_time > 1:
            phase_values.append(("Other", other_time, "#BDBDBD"))

        # Format total time string
        if total_time < 60:
            total_str = f"{total_time:.1f}s"
        elif total_time < 3600:
            total_str = f"{total_time / 60:.1f}m"
        else:
            total_str = f"{total_time / 3600:.1f}h"

        # Generate bar segments
        segments_html = ""
        legend_html = ""
        for name, duration, color in phase_values:
            if duration > 0 and total_time > 0:
                pct = (duration / total_time) * 100
                dur_str = (
                    f"{duration:.1f}s" if duration < 60 else f"{duration / 60:.1f}m"
                )
                # Only show label if segment is wide enough
                label = name if pct > 10 else ""
                segments_html += f'<div class="time-bar-segment" style="width: {pct:.1f}%; background: {color};" title="{name}: {dur_str} ({pct:.1f}%)">{label}</div>'
                legend_html += f'<div class="legend-item"><div class="legend-color" style="background: {color};"></div><span class="legend-text">{name}: {dur_str}</span></div>'

        if not segments_html:
            return ""  # No timing data

        return f"""
            <div class="time-bar-container">
                <div class="time-bar-header">
                    <span>Phase Timing</span>
                    <span>Total: {total_str}</span>
                </div>
                <div class="time-bar">{segments_html}</div>
                <div class="time-bar-legend">{legend_html}</div>
            </div>
        """

    # Generate workers HTML
    workers_html = ""
    for w in workers:
        status = w.get("status", "unknown")
        time_bar_html = generate_time_bar(w)
        workers_html += f"""
        <div class="worker-card">
            <div class="worker-header">
                <span class="worker-name">{w.get("fuzzer", "N/A")} / {w.get("sanitizer", "N/A")}</span>
                <span class="status-badge" style="background-color: {status_color(status)}">{status}</span>
            </div>
            <div class="worker-details">
                <div><strong>Worker ID:</strong> {w.get("worker_id", "N/A")}</div>
                <div><strong>Job Type:</strong> {w.get("task_type", "N/A")}</div>
                <div><strong>PoCs Generated:</strong> {w.get("poc_generated", 0)}</div>
                <div><strong>Patches Generated:</strong> {w.get("patch_generated", 0)}</div>
                {f'<div class="error-msg"><strong>Error:</strong> {w.get("error_msg", "")}</div>' if w.get("error_msg") else ""}
            </div>
            {time_bar_html}
        </div>
        """

    # Generate vulnerability hypotheses HTML
    vh_html = ""
    for i, vh in enumerate(vulnerability_hypotheses, 1):
        score = vh.get("score", 0)
        is_crash_found = vh.get("is_crash_found", False)
        is_checked_by_verifier = vh.get("is_checked_by_verifier", False)
        vuln_type = vh.get("vuln_type", "unknown")

        real_badge = ""
        if is_checked_by_verifier:
            if is_crash_found:
                real_badge = '<span class="badge badge-real">CONFIRMED</span>'
            else:
                real_badge = '<span class="badge badge-fp">FALSE POSITIVE</span>'

        controlflow_html = ""
        for cf in vh.get("important_controlflow", []):
            controlflow_html += f"""
            <div class="controlflow-item">
                <span class="cf-type">{cf.get("type", "")}</span>
                <span class="cf-name">{cf.get("name", "")}</span>
                <span class="cf-loc">{cf.get("location", "")}</span>
            </div>
            """

        vh_html += f"""
        <div class="vh-card" id="vh-{i}">
            <div class="vh-header">
                <div class="vh-title">
                    <span class="vh-num">#{i}</span>
                    <span class="vh-func">{vh.get("function_name", "N/A")}</span>
                    {real_badge}
                </div>
                <div class="vh-meta">
                    <span class="vuln-badge" style="background-color: {vuln_color(vuln_type)}">{vuln_type}</span>
                    <span class="score-badge" style="background-color: {score_color(score)}">Score: {score:.2f}</span>
                </div>
            </div>
            <div class="vh-body">
                <div class="vh-desc">{vh.get("description", "No description")}</div>
                {f'<div class="vh-notes"><strong>Verification Notes:</strong> {vh.get("verification_notes", "")}</div>' if vh.get("verification_notes") else ""}
                {f'<div class="vh-controlflow"><strong>Important Control Flow:</strong>{controlflow_html}</div>' if controlflow_html else ""}
            </div>
            <div class="vh-footer">
                <span class="vh-id">ID: {vh.get("vulnerability_hypothesis_id", "N/A")}</span>
                <span class="vh-time">Created: {vh.get("created_at", "N/A")}</span>
            </div>
        </div>
        """

    # Summary stats
    total_vh = len(vulnerability_hypotheses)
    confirmed = len([vh for vh in vulnerability_hypotheses if vh.get("is_crash_found")])
    checked = len([vh for vh in vulnerability_hypotheses if vh.get("is_checked_by_verifier")])
    high_score = len([vh for vh in vulnerability_hypotheses if vh.get("score", 0) >= 0.8])

    # PoC stats
    total_pocs = len(pocs)
    successful_pocs = [p for p in pocs if p.get("is_successful")]

    # Generate PoCs HTML - separate successful and all PoCs
    import html as html_module

    def generate_poc_card_html(poc, idx):
        """Generate HTML for a single PoC card."""
        poc_id = poc.get("poc_id", "N/A")
        vuln_type = poc.get("vuln_type", "unknown")
        harness = poc.get("harness_name", "N/A")
        sanitizer = poc.get("sanitizer", "N/A")
        is_successful = poc.get("is_successful", False)
        blob_path = poc.get("blob_path", "")
        vh_id = poc.get("vulnerability_hypothesis_id", "N/A")
        iteration = poc.get("iteration", 0)
        attempt = poc.get("attempt", 0)
        description = poc.get("description", "")
        sanitizer_output = poc.get("sanitizer_output", "")

        # Status badge
        if is_successful:
            status_badge = '<span class="badge badge-real">CRASHED</span>'
            card_border = "#28a745"
        else:
            status_badge = '<span class="badge badge-fp">NO CRASH</span>'
            card_border = "#6c757d"

        # Sanitizer output (truncated)
        sanitizer_html = ""
        if sanitizer_output:
            sanitizer_escaped = html_module.escape(str(sanitizer_output)[:2000])
            if len(str(sanitizer_output)) > 2000:
                sanitizer_escaped += "... (truncated)"
            sanitizer_html = f'<div class="poc-sanitizer"><strong>Sanitizer Output:</strong><pre>{sanitizer_escaped}</pre></div>'

        return f"""
        <div class="poc-card" style="border-left-color: {card_border}">
            <div class="poc-header">
                <div class="poc-title">
                    <span class="poc-num">#{idx}</span>
                    <span class="vuln-badge" style="background-color: {vuln_color(vuln_type)}">{vuln_type}</span>
                    {status_badge}
                </div>
                <div class="poc-meta">
                    <span class="poc-harness">{harness} ({sanitizer})</span>
                </div>
            </div>
            <div class="poc-body">
                <div class="poc-info-grid">
                    <div><strong>PoC ID:</strong> {poc_id[:16]}...</div>
                    <div><strong>VH ID:</strong> {vh_id[:16] if vh_id != "N/A" else "N/A"}...</div>
                    <div><strong>Iteration:</strong> {iteration}</div>
                    <div><strong>Attempt:</strong> {attempt}</div>
                </div>
                {f'<div class="poc-desc"><strong>Description:</strong> {html_module.escape(description)}</div>' if description else ""}
                {f'<div class="poc-blob"><strong>Blob:</strong> {blob_path}</div>' if blob_path else ""}
                {sanitizer_html}
            </div>
            <div class="poc-footer">
                <span class="poc-time">Created: {poc.get("created_at", "N/A")}</span>
            </div>
        </div>
        """

    # Generate HTML for successful PoCs
    success_pocs_html = ""
    for i, poc in enumerate(successful_pocs, 1):
        success_pocs_html += generate_poc_card_html(poc, i)

    # Generate HTML for all PoCs
    pocs_html = ""
    for i, poc in enumerate(pocs, 1):
        pocs_html += generate_poc_card_html(poc, i)

    # Generate conversations HTML
    conv_html = ""
    for idx, conv in enumerate(conversations):
        messages_html = ""
        for msg in conv.get("messages", []):
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            # Escape HTML
            content_escaped = html_module.escape(str(content) if content else "")
            # Truncate very long content
            if len(content_escaped) > 5000:
                content_escaped = content_escaped[:5000] + "\n\n... (truncated)"

            msg_class = f"msg msg-{role}"
            tool_calls_html = ""

            if msg.get("tool_calls"):
                tool_calls_html = (
                    '<div class="msg-tool-calls"><strong>Tool Calls:</strong>'
                )
                for tc in msg["tool_calls"]:
                    func_name = tc.get("function", {}).get("name", "unknown")
                    func_args = tc.get("function", {}).get("arguments", "")
                    # Truncate long args
                    if len(func_args) > 500:
                        func_args = func_args[:500] + "..."
                    tool_calls_html += f'<div class="tool-call">{func_name}({html_module.escape(func_args)})</div>'
                tool_calls_html += "</div>"

            messages_html += f'''
            <div class="{msg_class}">
                <div class="msg-role">{role}</div>
                <div class="msg-content">{content_escaped}</div>
                {tool_calls_html}
            </div>
            '''

        conv_html += f"""
        <div class="conv-file">
            <div class="conv-file-header" onclick="toggleConv({idx})">
                <span class="conv-file-name">{conv.get("file", "Unknown")}</span>
                <span class="conv-toggle" id="toggle-{idx}">▼ Click to collapse</span>
            </div>
            <div class="conv-messages" id="conv-{idx}">
                {messages_html}
            </div>
        </div>
        """

    # Generate tool calls HTML
    # Group by tool name
    tool_stats = {}
    for tc in tool_calls:
        name = tc.get("name", "unknown")
        tool_stats[name] = tool_stats.get(name, 0) + 1

    tool_stats_html = ""
    for name, count in sorted(tool_stats.items(), key=lambda x: -x[1]):
        tool_stats_html += f'<div class="tool-stat"><span class="tool-name">{name}</span><span class="tool-count">{count}</span></div>'

    tool_list_html = ""
    for idx, tc in enumerate(tool_calls):
        args_escaped = html_module.escape(tc.get("arguments", ""))
        response = tc.get("response", "")
        response_escaped = (
            html_module.escape(str(response)[:2000])
            if response
            else "<em>No response</em>"
        )
        if len(str(response)) > 2000:
            response_escaped += "... (truncated)"

        tool_list_html += f"""
        <div class="tool-item">
            <div class="tool-header" onclick="toggleTool({idx})">
                <span class="tool-badge">{tc.get("name", "unknown")}</span>
                <span class="tool-expand" id="tool-toggle-{idx}">▶</span>
            </div>
            <div class="tool-details" id="tool-{idx}">
                <div class="tool-section">
                    <div class="tool-section-title">Arguments:</div>
                    <pre class="tool-args">{args_escaped}</pre>
                </div>
                <div class="tool-section">
                    <div class="tool-section-title">Response:</div>
                    <pre class="tool-response">{response_escaped}</pre>
                </div>
            </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Run {run_id} - FuzzingBrain Viewer</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #1a1a2e;
            color: #eee;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; margin-bottom: 10px; }}
        h2 {{ color: #ff6b6b; margin: 30px 0 15px; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        .run-info {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .run-info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 15px;
        }}
        .info-item {{ }}
        .info-label {{ color: #888; font-size: 12px; text-transform: uppercase; }}
        .info-value {{ font-size: 16px; font-weight: 500; }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}
        .summary-num {{ font-size: 36px; font-weight: bold; }}
        .summary-label {{ color: #888; font-size: 14px; }}
        .workers-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
        }}
        .worker-card {{
            background: #16213e;
            border-radius: 10px;
            padding: 15px;
        }}
        .worker-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .worker-name {{ font-weight: bold; font-size: 16px; }}
        .status-badge {{
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            color: white;
            text-transform: uppercase;
        }}
        .worker-details {{ font-size: 14px; color: #aaa; }}
        .worker-details div {{ margin: 5px 0; }}
        .error-msg {{ color: #ff6b6b; }}
        .vh-card {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #00d4ff;
        }}
        .vh-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .vh-title {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
        .vh-num {{ color: #00d4ff; font-weight: bold; font-size: 18px; }}
        .vh-func {{ font-family: 'Monaco', 'Menlo', monospace; font-size: 16px; color: #ffd93d; }}
        .vh-meta {{ display: flex; gap: 10px; }}
        .vuln-badge, .score-badge {{
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            color: white;
        }}
        .badge {{ padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: bold; }}
        .badge-real {{ background: #28a745; color: white; }}
        .badge-fp {{ background: #6c757d; color: white; }}
        .vh-body {{ margin-bottom: 15px; }}
        .vh-desc {{
            background: #0f0f23;
            padding: 15px;
            border-radius: 8px;
            font-size: 14px;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .vh-notes {{
            margin-top: 10px;
            padding: 10px;
            background: #1a3a1a;
            border-radius: 8px;
            font-size: 13px;
        }}
        .vh-controlflow {{
            margin-top: 10px;
            font-size: 13px;
        }}
        .controlflow-item {{
            background: #0f0f23;
            padding: 8px 12px;
            margin: 5px 0;
            border-radius: 5px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .cf-type {{ color: #17a2b8; font-weight: bold; min-width: 60px; }}
        .cf-name {{ color: #ffd93d; font-family: monospace; }}
        .cf-loc {{ color: #888; }}
        .vh-footer {{
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: #666;
            border-top: 1px solid #333;
            padding-top: 10px;
        }}
        .refresh-btn {{
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #00d4ff;
            color: #1a1a2e;
            border: none;
            padding: 15px 25px;
            border-radius: 30px;
            font-size: 16px;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(0,212,255,0.3);
        }}
        .refresh-btn:hover {{ background: #00b8e6; }}
        .no-data {{ color: #888; font-style: italic; padding: 20px; text-align: center; }}
        .generated-time {{ color: #666; font-size: 12px; margin-top: 5px; }}

        /* Time bar styles */
        .time-bar-container {{
            margin-top: 10px;
            background: #0f0f23;
            border-radius: 8px;
            padding: 12px;
        }}
        .time-bar-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 12px;
            color: #888;
        }}
        .time-bar {{
            height: 24px;
            border-radius: 4px;
            overflow: hidden;
            display: flex;
            background: #1a1a2e;
        }}
        .time-bar-segment {{
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 10px;
            font-weight: bold;
            color: white;
            text-shadow: 0 0 2px rgba(0,0,0,0.5);
            transition: opacity 0.2s;
            min-width: 2px;
        }}
        .time-bar-segment:hover {{
            opacity: 0.8;
        }}
        .time-bar-legend {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 8px;
            font-size: 11px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 4px;
        }}
        .legend-color {{
            width: 12px;
            height: 12px;
            border-radius: 2px;
        }}
        .legend-text {{
            color: #aaa;
        }}

        /* PoC styles */
        .poc-card {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #28a745;
        }}
        .poc-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .poc-title {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
        .poc-num {{ color: #28a745; font-weight: bold; font-size: 18px; }}
        .poc-meta {{ color: #888; }}
        .poc-harness {{ font-family: monospace; }}
        .poc-body {{ margin-bottom: 15px; }}
        .poc-info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 10px;
            background: #0f0f23;
            padding: 15px;
            border-radius: 8px;
            font-size: 14px;
            margin-bottom: 10px;
        }}
        .poc-desc {{
            background: #0f0f23;
            padding: 15px;
            border-radius: 8px;
            font-size: 14px;
            margin-bottom: 10px;
        }}
        .poc-blob {{
            background: #1a3a1a;
            padding: 10px 15px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 13px;
            margin-bottom: 10px;
        }}
        .poc-sanitizer {{
            margin-top: 10px;
        }}
        .poc-sanitizer pre {{
            background: #0f0f23;
            padding: 15px;
            border-radius: 8px;
            font-size: 12px;
            overflow-x: auto;
            max-height: 300px;
            overflow-y: auto;
            color: #ff6b6b;
        }}
        .poc-footer {{
            font-size: 12px;
            color: #666;
            border-top: 1px solid #333;
            padding-top: 10px;
        }}

        /* Conversation styles */
        .conv-container {{ margin-top: 20px; }}
        .conv-file {{
            background: #16213e;
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .conv-file-header {{
            background: #0f3460;
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .conv-file-header:hover {{ background: #1a4a7a; }}
        .conv-file-name {{ font-weight: bold; color: #00d4ff; }}
        .conv-toggle {{ color: #888; }}
        .conv-messages {{
            display: block;
            padding: 20px;
            max-height: 800px;
            overflow-y: auto;
        }}
        .conv-messages.hide {{ display: none; }}
        .msg {{
            margin-bottom: 15px;
            padding: 15px;
            border-radius: 10px;
        }}
        .msg-system {{ background: #2d2d44; border-left: 4px solid #6c757d; }}
        .msg-user {{ background: #1a3a5c; border-left: 4px solid #00d4ff; }}
        .msg-assistant {{ background: #1a3a1a; border-left: 4px solid #28a745; }}
        .msg-tool {{ background: #3a2a1a; border-left: 4px solid #fd7e14; }}
        .msg-role {{
            font-size: 12px;
            text-transform: uppercase;
            font-weight: bold;
            margin-bottom: 8px;
        }}
        .msg-system .msg-role {{ color: #6c757d; }}
        .msg-user .msg-role {{ color: #00d4ff; }}
        .msg-assistant .msg-role {{ color: #28a745; }}
        .msg-tool .msg-role {{ color: #fd7e14; }}
        .msg-content {{
            font-size: 14px;
            white-space: pre-wrap;
            word-break: break-word;
            max-height: 400px;
            overflow-y: auto;
        }}
        .msg-tool-calls {{
            margin-top: 10px;
            padding: 10px;
            background: #0f0f23;
            border-radius: 5px;
            font-family: monospace;
            font-size: 12px;
        }}
        .tool-call {{ margin: 5px 0; color: #ffd93d; }}

        /* Tab styles */
        .tabs {{
            display: flex;
            gap: 5px;
            margin: 20px 0;
            border-bottom: 2px solid #333;
            padding-bottom: 0;
        }}
        .tab-btn {{
            padding: 12px 24px;
            background: #16213e;
            border: none;
            border-radius: 8px 8px 0 0;
            color: #888;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.2s;
        }}
        .tab-btn:hover {{ background: #1a3a5c; color: #fff; }}
        .tab-btn.active {{
            background: #0f3460;
            color: #00d4ff;
            border-bottom: 2px solid #00d4ff;
            margin-bottom: -2px;
        }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}

        /* Tool calls styles */
        .tool-stats {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 20px;
        }}
        .tool-stat {{
            background: #16213e;
            padding: 10px 15px;
            border-radius: 8px;
            display: flex;
            gap: 10px;
            align-items: center;
        }}
        .tool-name {{ color: #ffd93d; font-family: monospace; }}
        .tool-count {{
            background: #0f3460;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 12px;
            color: #00d4ff;
        }}
        .tool-item {{
            background: #16213e;
            border-radius: 8px;
            margin-bottom: 10px;
            overflow: hidden;
        }}
        .tool-header {{
            padding: 12px 15px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .tool-header:hover {{ background: #1a3a5c; }}
        .tool-badge {{
            background: #0f3460;
            color: #ffd93d;
            padding: 4px 12px;
            border-radius: 15px;
            font-family: monospace;
            font-size: 13px;
        }}
        .tool-expand {{ color: #888; }}
        .tool-details {{
            display: none;
            padding: 15px;
            border-top: 1px solid #333;
        }}
        .tool-details.show {{ display: block; }}
        .tool-section {{ margin-bottom: 15px; }}
        .tool-section-title {{
            font-size: 12px;
            color: #888;
            text-transform: uppercase;
            margin-bottom: 8px;
        }}
        .tool-args, .tool-response {{
            background: #0f0f23;
            padding: 12px;
            border-radius: 5px;
            font-size: 12px;
            overflow-x: auto;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .tool-args {{ color: #17a2b8; }}
        .tool-response {{ color: #28a745; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>FuzzingBrain Run Viewer</h1>
        <p class="generated-time">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

        <div class="run-info">
            <div class="run-info-grid">
                <div class="info-item">
                    <div class="info-label">Run ID</div>
                    <div class="info-value">{run_id}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Project</div>
                    <div class="info-value">{run.get("project_name", "N/A") if run else "N/A"}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Status</div>
                    <div class="info-value">{run.get("status", "N/A") if run else "N/A"}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Scan Mode</div>
                    <div class="info-value">{run.get("scan_mode", "N/A") if run else "N/A"}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Job Type</div>
                    <div class="info-value">{run.get("task_type", "N/A") if run else "N/A"}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Created</div>
                    <div class="info-value">{run.get("created_at", "N/A") if run else "N/A"}</div>
                </div>
            </div>
        </div>

        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-num" style="color: #00d4ff">{total_vh}</div>
                <div class="summary-label">Total Vulnerability Hypotheses</div>
            </div>
            <div class="summary-card">
                <div class="summary-num" style="color: #ff6b6b">{high_score}</div>
                <div class="summary-label">High Confidence (≥0.8)</div>
            </div>
            <div class="summary-card">
                <div class="summary-num" style="color: #28a745">{confirmed}</div>
                <div class="summary-label">Confirmed Bugs</div>
            </div>
            <div class="summary-card">
                <div class="summary-num" style="color: #ffd93d">{checked}/{total_vh}</div>
                <div class="summary-label">Verified</div>
            </div>
        </div>

        <!-- Tab Navigation -->
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('workers')">Workers ({len(workers)})</button>
            <button class="tab-btn" onclick="switchTab('suspicious')">Vulnerability Hypotheses ({total_vh})</button>
            <button class="tab-btn" onclick="switchTab('success-pocs')">Success PoCs ({len(successful_pocs)})</button>
            <button class="tab-btn" onclick="switchTab('all-pocs')">All PoCs ({total_pocs})</button>
            <button class="tab-btn" onclick="switchTab('conversations')">Conversations ({len(conversations)})</button>
            <button class="tab-btn" onclick="switchTab('tools')">Tool Calls ({len(tool_calls)})</button>
        </div>

        <!-- Tab: Workers -->
        <div id="tab-workers" class="tab-content active">
            <h2>Workers</h2>
            <div class="workers-grid">
                {workers_html if workers_html else '<div class="no-data">No workers found</div>'}
            </div>
        </div>

        <!-- Tab: Vulnerability Hypotheses -->
        <div id="tab-suspicious" class="tab-content">
            <h2>Vulnerability Hypotheses</h2>
            {vh_html if vh_html else '<div class="no-data">No vulnerability hypotheses found</div>'}
        </div>

        <!-- Tab: Success PoCs -->
        <div id="tab-success-pocs" class="tab-content">
            <h2>Successful PoCs ({len(successful_pocs)})</h2>
            {success_pocs_html if success_pocs_html else '<div class="no-data">No successful PoCs found</div>'}
        </div>

        <!-- Tab: All PoCs -->
        <div id="tab-all-pocs" class="tab-content">
            <h2>All PoCs ({total_pocs})</h2>
            {pocs_html if pocs_html else '<div class="no-data">No PoCs found</div>'}
        </div>

        <!-- Tab: Conversations -->
        <div id="tab-conversations" class="tab-content">
            <h2>Conversations</h2>
            <div class="conv-container">
                {conv_html if conv_html else '<div class="no-data">No conversation records found</div>'}
            </div>
        </div>

        <!-- Tab: Tool Calls -->
        <div id="tab-tools" class="tab-content">
            <h2>Tool Calls Summary</h2>
            <div class="tool-stats">
                {tool_stats_html if tool_stats_html else '<div class="no-data">No tool calls</div>'}
            </div>
            <h2>All Tool Calls ({len(tool_calls)})</h2>
            {tool_list_html if tool_list_html else '<div class="no-data">No tool calls found</div>'}
        </div>
    </div>

    <button class="refresh-btn" onclick="location.reload()">Refresh</button>

    <script>
        function switchTab(tabName) {{
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));

            // Show selected tab
            document.getElementById('tab-' + tabName).classList.add('active');
            event.target.classList.add('active');
        }}

        function toggleConv(idx) {{
            const conv = document.getElementById('conv-' + idx);
            const toggle = document.getElementById('toggle-' + idx);
            if (conv.classList.contains('hide')) {{
                conv.classList.remove('hide');
                toggle.textContent = '▼ Click to collapse';
            }} else {{
                conv.classList.add('hide');
                toggle.textContent = '▶ Click to expand';
            }}
        }}

        function toggleTool(idx) {{
            const details = document.getElementById('tool-' + idx);
            const toggle = document.getElementById('tool-toggle-' + idx);
            if (details.classList.contains('show')) {{
                details.classList.remove('show');
                toggle.textContent = '▶';
            }} else {{
                details.classList.add('show');
                toggle.textContent = '▼';
            }}
        }}
    </script>
</body>
</html>
"""
    return html


def main():
    parser = argparse.ArgumentParser(description="View run details in a web page")
    parser.add_argument("run_id", nargs="?", help="Run ID to view")
    args = parser.parse_args()

    # Get run ID
    run_id = args.run_id
    if not run_id:
        run_id = input("Enter Run ID: ").strip()
        if not run_id:
            print("Error: Run ID is required")
            sys.exit(1)

    print(f"Fetching data for run: {run_id}")

    # Fetch data
    data = get_run_data(run_id)

    if not data["run"] and not data["workers"] and not data["vulnerability_hypotheses"]:
        print(f"Warning: No data found for run {run_id}")

    # Generate HTML
    html = generate_html(run_id, data)

    # Create output directory
    output_dir = Path(f"run_view_{run_id}")
    output_dir.mkdir(exist_ok=True)

    # Write HTML file
    html_path = output_dir / "index.html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # Also save raw JSON for reference
    json_path = output_dir / "data.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str, ensure_ascii=False)

    print(f"Generated: {html_path}")
    print(f"Data saved: {json_path}")

    # Open in browser
    file_url = f"file://{html_path.absolute()}"
    print(f"Opening: {file_url}")
    webbrowser.open(file_url)


if __name__ == "__main__":
    main()
