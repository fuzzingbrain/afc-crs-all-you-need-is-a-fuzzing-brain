#!/usr/bin/env python3
"""Convert conversation JSON to readable HTML."""

import json
import html
import sys
from pathlib import Path

try:
    import tiktoken
    enc = tiktoken.encoding_for_model('gpt-4')
    def count_tokens(text):
        return len(enc.encode(str(text)))
except:
    def count_tokens(text):
        return len(str(text)) // 4  # rough estimate

def convert_to_html(json_path: str, output_path: str = None):
    with open(json_path) as f:
        data = json.load(f)

    if output_path is None:
        output_path = json_path.replace('.json', '.html')

    messages = data.get('messages', [])
    meta = {
        'agent': data.get('agent', ''),
        'task_id': data.get('task_id', ''),
        'worker_id': data.get('worker_id', ''),
        'fuzzer': data.get('fuzzer', ''),
        'sanitizer': data.get('sanitizer', ''),
        'total_iterations': data.get('total_iterations', 0),
        'total_tool_calls': data.get('total_tool_calls', 0),
    }

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>POV Conversation - {meta['worker_id']}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #1a1a2e;
            color: #eee;
        }}
        .meta {{
            background: #16213e;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .meta h1 {{
            margin: 0 0 10px 0;
            color: #00d9ff;
        }}
        .meta-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
        }}
        .meta-item {{
            background: #0f3460;
            padding: 8px 12px;
            border-radius: 4px;
        }}
        .message {{
            margin: 10px 0;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid;
        }}
        .message-header {{
            font-weight: bold;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
        }}
        .message-index {{
            color: #888;
            font-size: 0.9em;
        }}
        .system {{
            background: #2d2d44;
            border-color: #888;
        }}
        .user {{
            background: #1e3a5f;
            border-color: #00d9ff;
        }}
        .assistant {{
            background: #1e4d3a;
            border-color: #00ff88;
        }}
        .tool {{
            background: #3d2d1e;
            border-color: #ffaa00;
        }}
        .content {{
            white-space: pre-wrap;
            word-wrap: break-word;
            font-size: 14px;
            line-height: 1.5;
        }}
        .tool-call {{
            background: #0f3460;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        .tool-name {{
            color: #ffaa00;
            font-weight: bold;
        }}
        .tool-args {{
            color: #aaa;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .collapsed {{
            max-height: 300px;
            overflow: hidden;
            position: relative;
        }}
        .collapsed::after {{
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 50px;
            background: linear-gradient(transparent, #1a1a2e);
        }}
        .expand-btn {{
            background: #0f3460;
            color: #00d9ff;
            border: none;
            padding: 5px 15px;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 10px;
        }}
        .expand-btn:hover {{
            background: #1e4d6a;
        }}
        code {{
            background: #0a0a15;
            padding: 2px 6px;
            border-radius: 3px;
        }}
        pre {{
            background: #0a0a15;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
        }}
        .nav {{
            position: fixed;
            top: 20px;
            right: 20px;
            background: #16213e;
            padding: 10px;
            border-radius: 8px;
            z-index: 100;
        }}
        .nav input {{
            width: 60px;
            padding: 5px;
            border: 1px solid #0f3460;
            border-radius: 4px;
            background: #0a0a15;
            color: #eee;
        }}
        .nav button {{
            background: #0f3460;
            color: #00d9ff;
            border: none;
            padding: 5px 10px;
            border-radius: 4px;
            cursor: pointer;
            margin-left: 5px;
        }}
    </style>
</head>
<body>
    <div class="nav">
        <span>Jump to #</span>
        <input type="number" id="msgNum" min="0" max="{len(messages)-1}">
        <button onclick="jumpTo()">Go</button>
    </div>

    <div class="meta">
        <h1>POV Generation Conversation</h1>
        <div class="meta-info">
            <div class="meta-item"><strong>Agent:</strong> {meta['agent']}</div>
            <div class="meta-item"><strong>Task:</strong> {meta['task_id']}</div>
            <div class="meta-item"><strong>Worker:</strong> {meta['worker_id']}</div>
            <div class="meta-item"><strong>Fuzzer:</strong> {meta['fuzzer']}</div>
            <div class="meta-item"><strong>Sanitizer:</strong> {meta['sanitizer']}</div>
            <div class="meta-item"><strong>Iterations:</strong> {meta['total_iterations']}</div>
            <div class="meta-item"><strong>Tool Calls:</strong> {meta['total_tool_calls']}</div>
            <div class="meta-item"><strong>Messages:</strong> {len(messages)}</div>
        </div>
    </div>

    <div id="messages">
"""

    total_tokens = 0
    for i, msg in enumerate(messages):
        role = msg.get('role', 'unknown')
        content = msg.get('content', '')
        tool_calls = msg.get('tool_calls', [])
        tool_call_id = msg.get('tool_call_id', '')

        # Count tokens for this message
        msg_tokens = count_tokens(content)
        if tool_calls:
            for tc in tool_calls:
                msg_tokens += count_tokens(json.dumps(tc))
        total_tokens += msg_tokens

        # Escape HTML
        if content:
            content = html.escape(str(content))

        html_content += f"""
        <div class="message {role}" id="msg-{i}">
            <div class="message-header">
                <span class="role">{role.upper()}</span>
                <span class="message-index">#{i} | {msg_tokens} tokens | cumulative: {total_tokens}</span>
            </div>
"""

        # Tool calls (assistant calling tools)
        if tool_calls:
            for tc in tool_calls:
                func = tc.get('function', {})
                name = func.get('name', '')
                args = func.get('arguments', '{}')
                try:
                    args_formatted = json.dumps(json.loads(args), indent=2)
                except:
                    args_formatted = args
                args_formatted = html.escape(args_formatted)

                html_content += f"""
            <div class="tool-call">
                <div class="tool-name">{name}()</div>
                <div class="tool-args"><pre>{args_formatted}</pre></div>
            </div>
"""

        # Content
        if content:
            # Check if content is long
            is_long = len(content) > 1500
            collapsed_class = 'collapsed' if is_long else ''

            html_content += f"""
            <div class="content {collapsed_class}" id="content-{i}">
{content}
            </div>
"""
            if is_long:
                html_content += f"""
            <button class="expand-btn" onclick="toggleExpand({i})">Show more</button>
"""

        if tool_call_id:
            html_content += f"""
            <div style="color: #888; font-size: 0.8em;">Tool Call ID: {tool_call_id}</div>
"""

        html_content += """
        </div>
"""

    html_content += """
    </div>

    <script>
        function toggleExpand(idx) {
            const content = document.getElementById('content-' + idx);
            const btn = content.nextElementSibling;
            if (content.classList.contains('collapsed')) {
                content.classList.remove('collapsed');
                btn.textContent = 'Show less';
            } else {
                content.classList.add('collapsed');
                btn.textContent = 'Show more';
            }
        }

        function jumpTo() {
            const num = document.getElementById('msgNum').value;
            const el = document.getElementById('msg-' + num);
            if (el) {
                el.scrollIntoView({ behavior: 'smooth', block: 'start' });
                el.style.boxShadow = '0 0 20px #00d9ff';
                setTimeout(() => el.style.boxShadow = '', 2000);
            }
        }
    </script>
</body>
</html>
"""

    with open(output_path, 'w') as f:
        f.write(html_content)

    print(f"Generated: {output_path}")
    print(f"Messages: {len(messages)}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python view_conversation.py <conversation.json> [output.html]")
        sys.exit(1)

    json_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    convert_to_html(json_path, output_path)
