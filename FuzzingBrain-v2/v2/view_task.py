#!/usr/bin/env python3
"""
Task Viewer - Generate a web page to view task details

Usage:
    python view_task.py <task_id>
    python view_task.py  # Interactive mode
"""

import argparse
import json
import os
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

from pymongo import MongoClient


def get_task_data(task_id: str) -> dict:
    """Fetch all task-related data from MongoDB."""
    client = MongoClient('mongodb://localhost:27017')
    db = client['fuzzingbrain']

    # Get task
    task = db.tasks.find_one({'task_id': task_id})

    # Get workers for this task
    workers = list(db.workers.find({'task_id': task_id}))

    # Get suspicious points for this task
    suspicious_points = list(db.suspicious_points.find({'task_id': task_id}))

    # Convert ObjectId to string
    for w in workers:
        w['_id'] = str(w['_id'])
    for sp in suspicious_points:
        sp['_id'] = str(sp['_id'])
    if task:
        task['_id'] = str(task['_id'])

    return {
        'task': task,
        'workers': workers,
        'suspicious_points': suspicious_points,
    }


def generate_html(task_id: str, data: dict) -> str:
    """Generate HTML content for the task viewer."""
    task = data['task']
    workers = data['workers']
    suspicious_points = data['suspicious_points']

    # Sort suspicious points by score (descending)
    suspicious_points.sort(key=lambda x: x.get('score', 0), reverse=True)

    # Status colors
    def status_color(status):
        colors = {
            'pending': '#6c757d',
            'building': '#17a2b8',
            'running': '#007bff',
            'completed': '#28a745',
            'failed': '#dc3545',
        }
        return colors.get(status, '#6c757d')

    def vuln_color(vuln_type):
        colors = {
            'buffer-overflow': '#dc3545',
            'use-after-free': '#e83e8c',
            'out-of-bounds-read': '#fd7e14',
            'out-of-bounds-write': '#dc3545',
            'integer-overflow': '#6f42c1',
            'null-pointer-dereference': '#20c997',
            'format-string': '#17a2b8',
            'double-free': '#e83e8c',
            'uninitialized-memory': '#6c757d',
        }
        return colors.get(vuln_type, '#6c757d')

    def score_color(score):
        if score >= 0.8:
            return '#dc3545'  # Red - high confidence
        elif score >= 0.5:
            return '#fd7e14'  # Orange - medium
        else:
            return '#6c757d'  # Gray - low

    # Generate workers HTML
    workers_html = ""
    for w in workers:
        status = w.get('status', 'unknown')
        workers_html += f'''
        <div class="worker-card">
            <div class="worker-header">
                <span class="worker-name">{w.get('fuzzer', 'N/A')} / {w.get('sanitizer', 'N/A')}</span>
                <span class="status-badge" style="background-color: {status_color(status)}">{status}</span>
            </div>
            <div class="worker-details">
                <div><strong>Worker ID:</strong> {w.get('worker_id', 'N/A')}</div>
                <div><strong>Job Type:</strong> {w.get('job_type', 'N/A')}</div>
                <div><strong>POVs Found:</strong> {w.get('povs_found', 0)}</div>
                <div><strong>Patches Found:</strong> {w.get('patches_found', 0)}</div>
                {f'<div class="error-msg"><strong>Error:</strong> {w.get("error_msg", "")}</div>' if w.get('error_msg') else ''}
            </div>
        </div>
        '''

    # Generate suspicious points HTML
    sp_html = ""
    for i, sp in enumerate(suspicious_points, 1):
        score = sp.get('score', 0)
        is_real = sp.get('is_real', False)
        is_checked = sp.get('is_checked', False)
        vuln_type = sp.get('vuln_type', 'unknown')

        real_badge = ''
        if is_checked:
            if is_real:
                real_badge = '<span class="badge badge-real">CONFIRMED</span>'
            else:
                real_badge = '<span class="badge badge-fp">FALSE POSITIVE</span>'

        controlflow_html = ""
        for cf in sp.get('important_controlflow', []):
            controlflow_html += f'''
            <div class="controlflow-item">
                <span class="cf-type">{cf.get('type', '')}</span>
                <span class="cf-name">{cf.get('name', '')}</span>
                <span class="cf-loc">{cf.get('location', '')}</span>
            </div>
            '''

        sp_html += f'''
        <div class="sp-card" id="sp-{i}">
            <div class="sp-header">
                <div class="sp-title">
                    <span class="sp-num">#{i}</span>
                    <span class="sp-func">{sp.get('function_name', 'N/A')}</span>
                    {real_badge}
                </div>
                <div class="sp-meta">
                    <span class="vuln-badge" style="background-color: {vuln_color(vuln_type)}">{vuln_type}</span>
                    <span class="score-badge" style="background-color: {score_color(score)}">Score: {score:.2f}</span>
                </div>
            </div>
            <div class="sp-body">
                <div class="sp-desc">{sp.get('description', 'No description')}</div>
                {f'<div class="sp-notes"><strong>Verification Notes:</strong> {sp.get("verification_notes", "")}</div>' if sp.get('verification_notes') else ''}
                {f'<div class="sp-controlflow"><strong>Important Control Flow:</strong>{controlflow_html}</div>' if controlflow_html else ''}
            </div>
            <div class="sp-footer">
                <span class="sp-id">ID: {sp.get('suspicious_point_id', 'N/A')}</span>
                <span class="sp-time">Created: {sp.get('created_at', 'N/A')}</span>
            </div>
        </div>
        '''

    # Summary stats
    total_sp = len(suspicious_points)
    confirmed = len([sp for sp in suspicious_points if sp.get('is_real')])
    checked = len([sp for sp in suspicious_points if sp.get('is_checked')])
    high_score = len([sp for sp in suspicious_points if sp.get('score', 0) >= 0.8])

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Task {task_id} - FuzzingBrain Viewer</title>
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
        .task-info {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .task-info-grid {{
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
        .sp-card {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #00d4ff;
        }}
        .sp-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .sp-title {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
        .sp-num {{ color: #00d4ff; font-weight: bold; font-size: 18px; }}
        .sp-func {{ font-family: 'Monaco', 'Menlo', monospace; font-size: 16px; color: #ffd93d; }}
        .sp-meta {{ display: flex; gap: 10px; }}
        .vuln-badge, .score-badge {{
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            color: white;
        }}
        .badge {{ padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: bold; }}
        .badge-real {{ background: #28a745; color: white; }}
        .badge-fp {{ background: #6c757d; color: white; }}
        .sp-body {{ margin-bottom: 15px; }}
        .sp-desc {{
            background: #0f0f23;
            padding: 15px;
            border-radius: 8px;
            font-size: 14px;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .sp-notes {{
            margin-top: 10px;
            padding: 10px;
            background: #1a3a1a;
            border-radius: 8px;
            font-size: 13px;
        }}
        .sp-controlflow {{
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
        .sp-footer {{
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
    </style>
</head>
<body>
    <div class="container">
        <h1>FuzzingBrain Task Viewer</h1>
        <p class="generated-time">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <div class="task-info">
            <div class="task-info-grid">
                <div class="info-item">
                    <div class="info-label">Task ID</div>
                    <div class="info-value">{task_id}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Project</div>
                    <div class="info-value">{task.get('project_name', 'N/A') if task else 'N/A'}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Status</div>
                    <div class="info-value">{task.get('status', 'N/A') if task else 'N/A'}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Scan Mode</div>
                    <div class="info-value">{task.get('scan_mode', 'N/A') if task else 'N/A'}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Job Type</div>
                    <div class="info-value">{task.get('job_type', 'N/A') if task else 'N/A'}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Created</div>
                    <div class="info-value">{task.get('created_at', 'N/A') if task else 'N/A'}</div>
                </div>
            </div>
        </div>

        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-num" style="color: #00d4ff">{total_sp}</div>
                <div class="summary-label">Total Suspicious Points</div>
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
                <div class="summary-num" style="color: #ffd93d">{checked}/{total_sp}</div>
                <div class="summary-label">Verified</div>
            </div>
        </div>

        <h2>Workers ({len(workers)})</h2>
        <div class="workers-grid">
            {workers_html if workers_html else '<div class="no-data">No workers found</div>'}
        </div>

        <h2>Suspicious Points ({total_sp})</h2>
        {sp_html if sp_html else '<div class="no-data">No suspicious points found</div>'}
    </div>

    <button class="refresh-btn" onclick="location.reload()">Refresh</button>
</body>
</html>
'''
    return html


def main():
    parser = argparse.ArgumentParser(description='View task details in a web page')
    parser.add_argument('task_id', nargs='?', help='Task ID to view')
    args = parser.parse_args()

    # Get task ID
    task_id = args.task_id
    if not task_id:
        task_id = input('Enter Task ID: ').strip()
        if not task_id:
            print('Error: Task ID is required')
            sys.exit(1)

    print(f'Fetching data for task: {task_id}')

    # Fetch data
    data = get_task_data(task_id)

    if not data['task'] and not data['workers'] and not data['suspicious_points']:
        print(f'Warning: No data found for task {task_id}')

    # Generate HTML
    html = generate_html(task_id, data)

    # Create output directory
    output_dir = Path(f'task_view_{task_id}')
    output_dir.mkdir(exist_ok=True)

    # Write HTML file
    html_path = output_dir / 'index.html'
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)

    # Also save raw JSON for reference
    json_path = output_dir / 'data.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str, ensure_ascii=False)

    print(f'Generated: {html_path}')
    print(f'Data saved: {json_path}')

    # Open in browser
    file_url = f'file://{html_path.absolute()}'
    print(f'Opening: {file_url}')
    webbrowser.open(file_url)


if __name__ == '__main__':
    main()
