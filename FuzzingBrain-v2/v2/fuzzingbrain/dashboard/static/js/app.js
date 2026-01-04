// FuzzingBrain Dashboard Application

const API_BASE = window.location.origin;

// State
let currentTaskId = null;
let currentTaskData = null;

// DOM Elements
const connectionStatus = document.getElementById('connection-status');
const totalCost = document.getElementById('total-cost');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    updateConnectionStatus('connected');
    refreshAll();

    // Auto-refresh every 5 seconds (including task detail if open)
    setInterval(() => {
        refreshAll();
        if (currentTaskId) {
            refreshTaskDetail();
        }
    }, 5000);
});

function updateConnectionStatus(status) {
    connectionStatus.className = `status-indicator ${status}`;
    connectionStatus.querySelector('.text').textContent =
        status === 'connected' ? 'Connected' :
        status === 'disconnected' ? 'Disconnected' : 'Connecting...';
}

// API Calls
async function fetchAPI(endpoint) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error(`API error (${endpoint}):`, error);
        return null;
    }
}

// ========== Tasks List View ==========

async function refreshAll() {
    await Promise.all([
        refreshTasks(),
        refreshSummary(),
    ]);
}

async function refreshSummary() {
    const summary = await fetchAPI('/api/v1/costs/summary');
    const instances = await fetchAPI('/api/v1/instances/');

    if (summary) {
        totalCost.textContent = `$${summary.total_cost?.toFixed(4) || '0.00'}`;
        document.getElementById('stat-total-cost').textContent = `$${summary.total_cost?.toFixed(2) || '0.00'}`;
        document.getElementById('stat-llm-calls').textContent = summary.total_llm_calls || 0;
    }

    if (instances) {
        document.getElementById('stat-instances').textContent = instances.length;
    }
}

async function refreshTasks() {
    const tasks = await fetchAPI('/api/v1/tasks/');
    if (!tasks) return;

    const tbody = document.getElementById('tasks-tbody');

    // Update stats
    const running = tasks.filter(t => t.status === 'running').length;
    const completed = tasks.filter(t => t.status === 'completed').length;
    const totalCost = tasks.reduce((sum, t) => sum + (t.cost_total || 0), 0);

    document.getElementById('stat-total-tasks').textContent = tasks.length;
    document.getElementById('stat-running-tasks').textContent = running;
    document.getElementById('stat-completed-tasks').textContent = completed;

    if (tasks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty">No tasks found</td></tr>';
        return;
    }

    tbody.innerHTML = tasks.map(task => {
        const startedAt = task.started_at ? new Date(task.started_at).toLocaleString() : '-';
        const statusClass = task.status === 'running' ? 'status-running' :
                           task.status === 'completed' ? 'status-completed' : 'status-error';

        return `
            <tr>
                <td class="task-id">${task.task_id.slice(0, 8)}...</td>
                <td>${task.project_name || '-'}</td>
                <td><span class="status-badge ${statusClass}">${task.status}</span></td>
                <td class="cost">$${task.cost_total?.toFixed(4) || '0.00'}</td>
                <td>${task.llm_calls || 0}</td>
                <td>${startedAt}</td>
                <td>
                    <button class="view-btn" onclick="showTaskDetail('${task.task_id}')">View</button>
                </td>
            </tr>
        `;
    }).join('');
}

// ========== Task Detail View ==========

function showTasksList() {
    document.getElementById('view-tasks-list').classList.add('active');
    document.getElementById('view-task-detail').classList.remove('active');
    currentTaskId = null;
    currentTaskData = null;
}

async function showTaskDetail(taskId) {
    currentTaskId = taskId;

    document.getElementById('view-tasks-list').classList.remove('active');
    document.getElementById('view-task-detail').classList.add('active');

    await refreshTaskDetail();
}

async function refreshTaskDetail() {
    if (!currentTaskId) return;

    const data = await fetchAPI(`/api/v1/tasks/${currentTaskId}`);
    if (!data) {
        document.getElementById('task-detail-title').textContent = 'Task Not Found';
        return;
    }

    currentTaskData = data;
    const task = data.task;

    // Update title
    document.getElementById('task-detail-title').textContent =
        `Task: ${task.project_name || task.task_id.slice(0, 8)}`;

    // Update info grid
    const infoGrid = document.getElementById('task-info-grid');
    const startedAt = task.started_at ? new Date(task.started_at).toLocaleString() : '-';
    const endedAt = task.ended_at ? new Date(task.ended_at).toLocaleString() : '-';

    infoGrid.innerHTML = `
        <div class="info-card">
            <div class="info-label">Task ID</div>
            <div class="info-value">${task.task_id}</div>
        </div>
        <div class="info-card">
            <div class="info-label">Project</div>
            <div class="info-value">${task.project_name || '-'}</div>
        </div>
        <div class="info-card">
            <div class="info-label">Status</div>
            <div class="info-value status-${task.status}">${task.status}</div>
        </div>
        <div class="info-card">
            <div class="info-label">Started</div>
            <div class="info-value">${startedAt}</div>
        </div>
        <div class="info-card">
            <div class="info-label">Ended</div>
            <div class="info-value">${endedAt}</div>
        </div>
        <div class="info-card highlight">
            <div class="info-label">Total Cost</div>
            <div class="info-value cost">$${data.costs.total_cost?.toFixed(6) || '0.00'}</div>
        </div>
    `;

    // Update overview tab
    renderOverviewTab(data);

    // Update workers tab
    renderWorkersTab(data.workers);

    // Update agents tab
    renderAgentsTab(data.agents);

    // Update costs tab
    renderCostsTab(data.costs);

    // Update LLM calls tab
    renderLLMCallsTab(data.llm_calls);

    // Update tools tab
    renderToolsTab(data.tools);

    // Update logs tab
    renderLogsTab(data.logs);

    // Fetch and render SP, POV, Report, and Directions data
    fetchAndRenderSPTab();
    fetchAndRenderPOVTab();
    fetchAndRenderReportTab();
    fetchAndRenderDirectionsTab();
}

function renderOverviewTab(data) {
    // Update stats
    document.getElementById('task-worker-count').textContent = (data.workers || []).length;
    document.getElementById('task-agent-count').textContent = (data.agents || []).length;
    document.getElementById('task-llm-count').textContent = data.costs?.total_llm_calls || 0;
    document.getElementById('task-total-cost').textContent = `$${data.costs?.total_cost?.toFixed(4) || '0.00'}`;

    // Render workflow timeline
    const workflow = data.workflow || {};
    const sp = workflow.sp || {};
    const direction = workflow.direction || {};
    const pov = workflow.pov || {};

    const timelineEl = document.getElementById('task-timeline');
    timelineEl.innerHTML = `
        <div class="workflow-section">
            <h4>SP Workflow</h4>
            <div class="workflow-stats">
                <div class="workflow-stat">
                    <span class="workflow-label">Created</span>
                    <span class="workflow-value">${sp.created || 0}</span>
                </div>
                <div class="workflow-stat">
                    <span class="workflow-label">Verified</span>
                    <span class="workflow-value">${sp.verified || 0}</span>
                </div>
                <div class="workflow-stat">
                    <span class="workflow-label">Real Bugs</span>
                    <span class="workflow-value cost">${sp.marked_real || 0}</span>
                </div>
                <div class="workflow-stat">
                    <span class="workflow-label">False Positives</span>
                    <span class="workflow-value">${sp.marked_fp || 0}</span>
                </div>
            </div>
        </div>
        <div class="workflow-section">
            <h4>Direction Workflow</h4>
            <div class="workflow-stats">
                <div class="workflow-stat">
                    <span class="workflow-label">Created</span>
                    <span class="workflow-value">${direction.created || 0}</span>
                </div>
                <div class="workflow-stat">
                    <span class="workflow-label">Completed</span>
                    <span class="workflow-value">${direction.completed || 0}</span>
                </div>
            </div>
        </div>
        <div class="workflow-section">
            <h4>POV Generation</h4>
            <div class="workflow-stats">
                <div class="workflow-stat">
                    <span class="workflow-label">Attempts</span>
                    <span class="workflow-value">${pov.attempts || 0}</span>
                </div>
                <div class="workflow-stat">
                    <span class="workflow-label">Created</span>
                    <span class="workflow-value cost">${pov.created || 0}</span>
                </div>
                <div class="workflow-stat">
                    <span class="workflow-label">Crashed</span>
                    <span class="workflow-value cost">${pov.crashed || 0}</span>
                </div>
            </div>
        </div>
    `;
}

function renderWorkersTab(workers) {
    const tbody = document.getElementById('workers-tbody');

    if (!workers || workers.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty">No workers</td></tr>';
        return;
    }

    tbody.innerHTML = workers.map(w => {
        const startedAt = w.started_at ? new Date(w.started_at).toLocaleTimeString() : '-';
        const statusClass = w.status === 'running' ? 'status-running' :
                           w.status === 'completed' ? 'status-completed' : 'status-error';
        const cpu = w.cpu_percent !== null ? `${w.cpu_percent?.toFixed(1)}%` : '-';
        const mem = w.memory_mb !== null ? `${w.memory_mb?.toFixed(0)}MB` : '-';

        return `
            <tr>
                <td class="task-id">${w.worker_id.slice(0, 20)}...</td>
                <td>${w.fuzzer || '-'}</td>
                <td>${w.sanitizer || '-'}</td>
                <td><span class="status-badge ${statusClass}">${w.status}</span></td>
                <td>${cpu}</td>
                <td>${mem}</td>
                <td>${startedAt}</td>
            </tr>
        `;
    }).join('');
}

function renderAgentsTab(agents) {
    const tbody = document.getElementById('agents-tbody');

    if (!agents || agents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty">No agents</td></tr>';
        return;
    }

    tbody.innerHTML = agents.map(a => {
        const startedAt = a.started_at ? new Date(a.started_at).toLocaleTimeString() : '-';
        const statusClass = a.status === 'running' ? 'status-running' :
                           a.status === 'completed' ? 'status-completed' : 'status-error';

        // Extract operation from agent_id (format: AgentType_operation_num_id)
        const parts = a.agent_id.split('_');
        const operation = parts.length > 1 ? parts[1] : '-';

        // Use max_iteration if available, otherwise iteration
        const iterCount = a.max_iteration || a.iteration || 0;

        return `
            <tr>
                <td class="task-id">${a.agent_id.slice(0, 20)}...</td>
                <td>${a.agent_type || '-'}</td>
                <td>${operation}</td>
                <td>${a.worker_id ? a.worker_id.slice(0, 12) + '...' : '-'}</td>
                <td><span class="status-badge ${statusClass}">${a.status}</span></td>
                <td>${iterCount}</td>
                <td>${startedAt}</td>
            </tr>
        `;
    }).join('');
}

function switchTab(tabName) {
    // Update buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });

    // Update content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === `tab-${tabName}`);
    });
}

function renderCostsTab(costs) {
    // Cost summary
    const summaryEl = document.getElementById('task-cost-summary');
    summaryEl.innerHTML = `
        <div class="cost-row">
            <span class="cost-label">Total Cost</span>
            <span class="cost-value">$${costs.total_cost?.toFixed(6) || '0.00'}</span>
        </div>
        <div class="cost-row">
            <span class="cost-label">LLM Calls</span>
            <span class="cost-value">${costs.total_llm_calls || 0}</span>
        </div>
        <div class="cost-row">
            <span class="cost-label">Input Tokens</span>
            <span class="cost-value">${(costs.total_input_tokens || 0).toLocaleString()}</span>
        </div>
        <div class="cost-row">
            <span class="cost-label">Output Tokens</span>
            <span class="cost-value">${(costs.total_output_tokens || 0).toLocaleString()}</span>
        </div>
    `;

    // Cost by model
    const byModelEl = document.getElementById('task-cost-by-model');
    if (!costs.by_model || costs.by_model.length === 0) {
        byModelEl.innerHTML = '<div class="empty">No data</div>';
    } else {
        byModelEl.innerHTML = costs.by_model.map(m => `
            <div class="model-row">
                <span class="model-name">${m.model || 'unknown'}</span>
                <div class="model-stats">
                    <div class="model-cost">$${m.cost?.toFixed(4) || '0.00'}</div>
                    <div class="model-calls">${m.calls || 0} calls</div>
                </div>
            </div>
        `).join('');
    }
}

function renderLLMCallsTab(llmCalls) {
    const tbody = document.getElementById('llm-calls-tbody');

    if (!llmCalls || llmCalls.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No LLM calls</td></tr>';
        return;
    }

    tbody.innerHTML = llmCalls.map(call => {
        const time = call.timestamp ? new Date(call.timestamp).toLocaleTimeString() : '-';
        const operation = call.operation || '-';
        return `
            <tr>
                <td>${time}</td>
                <td>${operation}</td>
                <td>${call.model || '-'}</td>
                <td>${call.tokens?.toLocaleString() || 0}</td>
                <td class="cost">$${call.cost?.toFixed(6) || '0.00'}</td>
                <td>${call.latency_ms || 0}ms</td>
            </tr>
        `;
    }).join('');
}

function renderToolsTab(tools) {
    const container = document.getElementById('task-tools');

    if (!tools || tools.length === 0) {
        container.innerHTML = '<div class="empty">No tool usage data</div>';
        return;
    }

    container.innerHTML = tools.map(t => `
        <div class="tool-row">
            <span class="tool-name">${t.name || 'unknown'}</span>
            <div class="tool-stats">
                <span class="tool-calls">${t.calls || 0} calls</span>
                <span class="tool-success">${t.success || 0} ok</span>
                <span class="tool-failure">${t.failure || 0} fail</span>
            </div>
        </div>
    `).join('');
}

function renderLogsTab(logs) {
    const container = document.getElementById('task-logs-container');

    if (!logs || logs.length === 0) {
        container.innerHTML = '<div class="empty">No logs available</div>';
        return;
    }

    container.innerHTML = logs.map(log => {
        const time = log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '';
        const role = log.role || 'unknown';

        return `
            <div class="log-entry ${role}">
                <div class="log-header">
                    <span class="log-role ${role}">${role}</span>
                    <span class="log-time">${time}</span>
                </div>
                <div class="log-content">${escapeHtml(log.content || '')}</div>
            </div>
        `;
    }).join('');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ========== Suspicious Points Tab ==========

async function fetchAndRenderSPTab() {
    if (!currentTaskId) return;

    // Fetch stats for this task
    const stats = await fetchAPI(`/api/v1/suspicious-points/stats?task_id=${currentTaskId}`);
    if (stats) {
        document.getElementById('sp-total').textContent = stats.total || 0;
        document.getElementById('sp-checked').textContent = stats.checked || 0;
        document.getElementById('sp-real').textContent = stats.real_bugs || 0;
        document.getElementById('sp-fp').textContent = stats.false_positives || 0;
    }

    // Fetch list for this task
    const sps = await fetchAPI(`/api/v1/suspicious-points?task_id=${currentTaskId}&limit=50`);
    renderSPList(sps || []);
}

function renderSPList(sps) {
    const tbody = document.getElementById('sp-tbody');

    if (!sps || sps.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty">No suspicious points</td></tr>';
        document.getElementById('sp-detail-content').innerHTML = '<div class="empty">No suspicious points</div>';
        return;
    }

    tbody.innerHTML = sps.map((sp, index) => {
        let statusBadge = '<span class="status-badge status-running">Pending</span>';
        if (sp.is_important) {
            statusBadge = '<span class="status-badge status-completed">Real Bug</span>';
        } else if (sp.is_checked) {
            statusBadge = '<span class="status-badge status-error">FP</span>';
        }

        return `
            <tr class="clickable" onclick="showSPDetail('${sp.id}', this)">
                <td>${sp.function_name || '-'}</td>
                <td>${sp.vuln_type || '-'}</td>
                <td>${(sp.score || 0).toFixed(2)}</td>
                <td>${statusBadge}</td>
            </tr>
        `;
    }).join('');

    // Auto-select first item
    if (sps.length > 0) {
        const firstRow = tbody.querySelector('tr');
        if (firstRow) {
            showSPDetail(sps[0].id, firstRow);
        }
    }
}

async function showSPDetail(spId, rowElement) {
    // Update selected row
    document.querySelectorAll('#sp-tbody tr').forEach(tr => tr.classList.remove('selected'));
    if (rowElement) rowElement.classList.add('selected');

    const sp = await fetchAPI(`/api/v1/suspicious-points/${spId}`);
    if (!sp) return;

    const container = document.getElementById('sp-detail-content');
    const statusBadge = sp.is_important
        ? '<span class="detail-badge real">Real Bug</span>'
        : (sp.is_checked ? '<span class="detail-badge fp">False Positive</span>' : '<span class="detail-badge">Pending</span>');

    container.innerHTML = `
        <div class="detail-header">
            <h3>${sp.function_name}</h3>
            ${statusBadge}
        </div>
        <div class="detail-card">
            <h4>Basic Info</h4>
            <div class="detail-card-content short">
Type: ${sp.vuln_type}
Score: ${sp.score}
Harness: ${sp.harness_name || 'N/A'}
Sanitizer: ${sp.sanitizer || 'N/A'}
            </div>
        </div>
        <div class="detail-card">
            <h4>Description</h4>
            <div class="detail-card-content">${escapeHtml(sp.description || 'No description')}</div>
        </div>
        <div class="detail-card">
            <h4>Verification Notes</h4>
            <div class="detail-card-content">${escapeHtml(sp.verification_notes || 'Not verified yet')}</div>
        </div>
        <div class="detail-card">
            <h4>POV Guidance</h4>
            <div class="detail-card-content">${escapeHtml(sp.pov_guidance || 'No guidance')}</div>
        </div>
    `;
}

// ========== POVs Tab ==========

async function fetchAndRenderPOVTab() {
    if (!currentTaskId) return;

    // Fetch stats for this task
    const stats = await fetchAPI(`/api/v1/povs/stats?task_id=${currentTaskId}`);
    if (stats) {
        document.getElementById('pov-total').textContent = stats.total || 0;
        document.getElementById('pov-crashed').textContent = stats.crashed || 0;
        document.getElementById('pov-not-crashed').textContent = stats.not_crashed || 0;
        document.getElementById('pov-pending').textContent = stats.pending || 0;
    }

    // Fetch list for this task
    const povs = await fetchAPI(`/api/v1/povs?task_id=${currentTaskId}&limit=50`);
    renderPOVList(povs || []);
}

function renderPOVList(povs) {
    const tbody = document.getElementById('pov-tbody');

    if (!povs || povs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty">No POVs</td></tr>';
        document.getElementById('pov-detail-content').innerHTML = '<div class="empty">No POVs</div>';
        return;
    }

    tbody.innerHTML = povs.map(pov => {
        let crashedBadge = '<span class="status-badge status-running">Pending</span>';
        if (pov.crashed === true) {
            crashedBadge = '<span class="status-badge status-completed">Crashed</span>';
        } else if (pov.crashed === false) {
            crashedBadge = '<span class="status-badge status-error">No Crash</span>';
        }

        return `
            <tr class="clickable" onclick="showPOVDetail('${pov.id}', this)">
                <td>${pov.function_name || '-'}</td>
                <td>${pov.vuln_type || '-'}</td>
                <td>${crashedBadge}</td>
                <td>${pov.crash_type || '-'}</td>
            </tr>
        `;
    }).join('');

    // Auto-select first item
    if (povs.length > 0) {
        const firstRow = tbody.querySelector('tr');
        if (firstRow) {
            showPOVDetail(povs[0].id, firstRow);
        }
    }
}

async function showPOVDetail(povId, rowElement) {
    // Update selected row
    document.querySelectorAll('#pov-tbody tr').forEach(tr => tr.classList.remove('selected'));
    if (rowElement) rowElement.classList.add('selected');

    const pov = await fetchAPI(`/api/v1/povs/${povId}`);
    if (!pov) return;

    const container = document.getElementById('pov-detail-content');
    const crashedBadge = pov.crashed === true
        ? '<span class="detail-badge crashed">Crashed</span>'
        : (pov.crashed === false ? '<span class="detail-badge not-crashed">No Crash</span>' : '<span class="detail-badge">Pending</span>');

    container.innerHTML = `
        <div class="detail-header">
            <h3>${pov.function_name}</h3>
            ${crashedBadge}
        </div>
        <div class="detail-card">
            <h4>Basic Info</h4>
            <div class="detail-card-content short">
Type: ${pov.vuln_type}
Crash Type: ${pov.crash_type || 'N/A'}
Harness: ${pov.harness_name || 'N/A'}
Sanitizer: ${pov.sanitizer || 'N/A'}
Attempt: ${pov.attempt || 0}
Path: ${pov.pov_path || 'N/A'}
            </div>
        </div>
        <div class="detail-card">
            <h4>Crash Output (Sanitizer)</h4>
            <div class="detail-card-content">${escapeHtml(pov.crash_output || 'No crash output')}</div>
        </div>
        <div class="detail-card">
            <h4>POV Generator Code</h4>
            <div class="detail-card-content">${escapeHtml(pov.gen_code || 'No generator code')}</div>
        </div>
        <div class="detail-card">
            <h4>POV Input (Base64)</h4>
            <div class="detail-card-content">${escapeHtml(pov.pov_input || 'No input data')}</div>
        </div>
    `;
}

// ========== Report Tab ==========

async function fetchAndRenderReportTab() {
    if (!currentTaskId) return;

    const container = document.getElementById('report-container');
    container.innerHTML = '<div class="empty">Loading reports...</div>';

    // Fetch reports for this task
    const reports = await fetchAPI(`/api/v1/reports?task_id=${currentTaskId}&limit=20`);

    if (!reports || reports.length === 0) {
        container.innerHTML = '<div class="empty">No reports generated yet</div>';
        return;
    }

    container.innerHTML = reports.map(report => `
        <div class="report-card">
            <div class="report-card-header">
                <h4>${report.function_name || 'Unknown Function'}</h4>
                <span class="detail-badge ${report.crashed ? 'crashed' : 'not-crashed'}">
                    ${report.crashed ? 'Crash Confirmed' : 'No Crash'}
                </span>
            </div>
            <div class="report-card-body">
                <div class="report-meta">
                    <div class="report-meta-item">
                        <span class="report-meta-label">Vuln Type:</span>
                        <span class="report-meta-value">${report.vuln_type || 'N/A'}</span>
                    </div>
                    <div class="report-meta-item">
                        <span class="report-meta-label">Crash Type:</span>
                        <span class="report-meta-value">${report.crash_type || 'N/A'}</span>
                    </div>
                    <div class="report-meta-item">
                        <span class="report-meta-label">Harness:</span>
                        <span class="report-meta-value">${report.harness_name || 'N/A'}</span>
                    </div>
                    <div class="report-meta-item">
                        <span class="report-meta-label">Sanitizer:</span>
                        <span class="report-meta-value">${report.sanitizer || 'N/A'}</span>
                    </div>
                </div>
                <div class="report-section">
                    <h5>Vulnerability Description</h5>
                    <div class="report-section-content">${escapeHtml(report.description || 'No description')}</div>
                </div>
                <div class="report-section">
                    <h5>Crash Output (Sanitizer)</h5>
                    <div class="report-section-content">${escapeHtml(report.crash_output || 'No crash output')}</div>
                </div>
                <div class="report-section">
                    <h5>POV Generator Code</h5>
                    <div class="report-section-content">${escapeHtml(report.gen_code || 'No generator code')}</div>
                </div>
                <div class="report-section">
                    <h5>POV Input (Base64)</h5>
                    <div class="report-section-content">${escapeHtml(report.pov_input || 'No POV input')}</div>
                </div>
            </div>
        </div>
    `).join('');
}

// ========== Directions Tab ==========

async function fetchAndRenderDirectionsTab() {
    if (!currentTaskId) return;

    // Fetch stats for this task
    const stats = await fetchAPI(`/api/v1/directions/stats?task_id=${currentTaskId}`);
    if (stats) {
        document.getElementById('dir-total').textContent = stats.total || 0;
        document.getElementById('dir-completed').textContent = stats.completed || 0;
        document.getElementById('dir-pending').textContent = stats.pending || 0;
        document.getElementById('dir-processing').textContent = stats.processing || 0;
    }

    // Fetch list for this task
    const dirs = await fetchAPI(`/api/v1/directions?task_id=${currentTaskId}&limit=50`);
    renderDirectionList(dirs || []);
}

function renderDirectionList(dirs) {
    const tbody = document.getElementById('dir-tbody');

    if (!dirs || dirs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty">No directions</td></tr>';
        document.getElementById('dir-detail-content').innerHTML = '<div class="empty">No directions</div>';
        return;
    }

    tbody.innerHTML = dirs.map(dir => {
        let statusBadge = '<span class="status-badge status-running">Pending</span>';
        if (dir.status === 'completed') {
            statusBadge = '<span class="status-badge status-completed">Completed</span>';
        } else if (dir.status === 'processing') {
            statusBadge = '<span class="status-badge status-running">Processing</span>';
        }

        let riskClass = '';
        if (dir.risk_level === 'high') riskClass = 'status-error';
        else if (dir.risk_level === 'medium') riskClass = 'status-running';
        else if (dir.risk_level === 'low') riskClass = 'status-completed';

        return `
            <tr class="clickable" onclick="showDirectionDetail('${dir.id}', this)">
                <td>${dir.name || '-'}</td>
                <td><span class="status-badge ${riskClass}">${dir.risk_level || '-'}</span></td>
                <td>${statusBadge}</td>
                <td>${dir.sp_count || 0}</td>
            </tr>
        `;
    }).join('');

    // Auto-select first item
    if (dirs.length > 0) {
        const firstRow = tbody.querySelector('tr');
        if (firstRow) {
            showDirectionDetail(dirs[0].id, firstRow);
        }
    }
}

async function showDirectionDetail(dirId, rowElement) {
    // Update selected row
    document.querySelectorAll('#dir-tbody tr').forEach(tr => tr.classList.remove('selected'));
    if (rowElement) rowElement.classList.add('selected');

    const dir = await fetchAPI(`/api/v1/directions/${dirId}`);
    if (!dir) return;

    const container = document.getElementById('dir-detail-content');

    let riskClass = '';
    if (dir.risk_level === 'high') riskClass = 'crashed';
    else if (dir.risk_level === 'medium') riskClass = 'not-crashed';

    let statusBadge = '<span class="detail-badge">Pending</span>';
    if (dir.status === 'completed') {
        statusBadge = '<span class="detail-badge real">Completed</span>';
    } else if (dir.status === 'processing') {
        statusBadge = '<span class="detail-badge not-crashed">Processing</span>';
    }

    const coreFuncs = (dir.core_functions || []).join(', ') || 'N/A';
    const entryFuncs = (dir.entry_functions || []).join(', ') || 'N/A';

    container.innerHTML = `
        <div class="detail-header">
            <h3>${dir.name}</h3>
            ${statusBadge}
        </div>
        <div class="detail-card">
            <h4>Basic Info</h4>
            <div class="detail-card-content short">
Fuzzer: ${dir.fuzzer || 'N/A'}
Risk Level: ${dir.risk_level || 'N/A'}
SPs Generated: ${dir.sp_count || 0}
Functions Analyzed: ${dir.functions_analyzed || 0}
Created: ${dir.created_at || 'N/A'}
Completed: ${dir.completed_at || 'N/A'}
            </div>
        </div>
        <div class="detail-card">
            <h4>Risk Reason</h4>
            <div class="detail-card-content">${escapeHtml(dir.risk_reason || 'No risk reason provided')}</div>
        </div>
        <div class="detail-card">
            <h4>Core Functions</h4>
            <div class="detail-card-content">${escapeHtml(coreFuncs)}</div>
        </div>
        <div class="detail-card">
            <h4>Entry Functions</h4>
            <div class="detail-card-content">${escapeHtml(entryFuncs)}</div>
        </div>
        <div class="detail-card">
            <h4>Call Chain Summary</h4>
            <div class="detail-card-content">${escapeHtml(dir.call_chain_summary || 'No call chain summary')}</div>
        </div>
        <div class="detail-card">
            <h4>Code Summary</h4>
            <div class="detail-card-content">${escapeHtml(dir.code_summary || 'No code summary')}</div>
        </div>
    `;
}

// Expose functions globally
window.refreshTasks = refreshTasks;
window.showTaskDetail = showTaskDetail;
window.showTasksList = showTasksList;
window.refreshTaskDetail = refreshTaskDetail;
window.switchTab = switchTab;
window.showSPDetail = showSPDetail;
window.showPOVDetail = showPOVDetail;
window.fetchAndRenderReportTab = fetchAndRenderReportTab;
window.showDirectionDetail = showDirectionDetail;
window.fetchAndRenderDirectionsTab = fetchAndRenderDirectionsTab;
