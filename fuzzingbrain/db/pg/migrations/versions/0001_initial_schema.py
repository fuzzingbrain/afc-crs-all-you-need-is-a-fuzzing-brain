# SPDX-License-Identifier: Apache-2.0
"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-10-12 17:14:10.919626
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None

_CYCLE_FKS = (
    ("crashes", "first_attempt_id", "poc_attempts"),
    ("agents", "crash_id", "crashes"),
    ("agents", "lg_id", "logic_groups"),
    ("agents", "vh_id", "vulnerability_hypotheses"),
)


def upgrade() -> None:
    op.create_table('runs',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('project_name', sa.Text(), nullable=False),
    sa.Column('task_type', sa.Text(), nullable=False),
    sa.Column('scan_mode', sa.Text(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('end_reason', sa.Text(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('heartbeat_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('config', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('config_given', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('workspace_path', sa.Text(), nullable=False),
    sa.Column('code_version', sa.Text(), nullable=True),
    sa.Column('label', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('dispatched_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("(end_reason IS NOT NULL) = (status = 'completed')", name=op.f('ck_runs_end_reason_iff_completed')),
    sa.CheckConstraint("(error IS NOT NULL) = (status = 'error')", name=op.f('ck_runs_error_iff_error')),
    sa.CheckConstraint("end_reason IN ('poc_target', 'timeout', 'budget')", name=op.f('ck_runs_end_reason')),
    sa.CheckConstraint("scan_mode IN ('full', 'delta')", name=op.f('ck_runs_scan_mode')),
    sa.CheckConstraint("status IN ('preparing', 'running', 'completed', 'cancelled', 'error', 'lost')", name=op.f('ck_runs_status')),
    sa.CheckConstraint("task_type = 'poc'", name=op.f('ck_runs_task_type')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_runs'))
    )
    op.create_index(op.f('ix_runs_created_at'), 'runs', ['created_at'], unique=False)
    op.create_index(op.f('ix_runs_label'), 'runs', ['label'], unique=False)
    op.create_index(op.f('ix_runs_status'), 'runs', ['status'], unique=False)
    op.create_table('crashes',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('run_id', sa.UUID(), nullable=False),
    sa.Column('signature', sa.Text(), nullable=False),
    sa.Column('vuln_type', sa.Text(), nullable=False),
    sa.Column('first_attempt_id', sa.UUID(), nullable=False),
    sa.Column('package_path', sa.Text(), nullable=True),
    sa.Column('report', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['run_id'], ['runs.id'], name=op.f('fk_crashes_run_id_runs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_crashes')),
    sa.UniqueConstraint('run_id', 'signature', name=op.f('uq_crashes_run_id_signature'))
    )
    op.create_index(op.f('ix_crashes_run_id'), 'crashes', ['run_id'], unique=False)
    op.create_table('graphs',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('run_id', sa.UUID(), nullable=False),
    sa.Column('commit', sa.Text(), nullable=False),
    sa.Column('path', sa.Text(), nullable=False),
    sa.Column('content_sha256', sa.Text(), nullable=False),
    sa.Column('n_functions', sa.Integer(), nullable=False),
    sa.Column('n_edges', sa.Integer(), nullable=False),
    sa.Column('n_indirect_edges', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('n_functions >= 0 AND n_edges >= 0 AND n_indirect_edges >= 0', name=op.f('ck_graphs_counts')),
    sa.ForeignKeyConstraint(['run_id'], ['runs.id'], name=op.f('fk_graphs_run_id_runs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_graphs')),
    sa.UniqueConstraint('run_id', 'commit', name=op.f('uq_graphs_run_id_commit'))
    )
    op.create_index(op.f('ix_graphs_run_id'), 'graphs', ['run_id'], unique=False)
    op.create_table('harnesses',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('run_id', sa.UUID(), nullable=False),
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('source_path', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['run_id'], ['runs.id'], name=op.f('fk_harnesses_run_id_runs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_harnesses')),
    sa.UniqueConstraint('run_id', 'name', name=op.f('uq_harnesses_run_id_name'))
    )
    op.create_index(op.f('ix_harnesses_run_id'), 'harnesses', ['run_id'], unique=False)
    op.create_table('llm_messages',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=False), nullable=False),
    sa.Column('run_id', sa.UUID(), nullable=False),
    sa.Column('sha256', sa.Text(), nullable=False),
    sa.Column('role', sa.Text(), nullable=False),
    sa.Column('content', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("role IN ('system', 'user', 'assistant', 'tool')", name=op.f('ck_llm_messages_role')),
    sa.ForeignKeyConstraint(['run_id'], ['runs.id'], name=op.f('fk_llm_messages_run_id_runs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_llm_messages')),
    sa.UniqueConstraint('run_id', 'sha256', name=op.f('uq_llm_messages_run_id_sha256'))
    )
    op.create_table('graph_harnesses',
    sa.Column('graph_id', sa.UUID(), nullable=False),
    sa.Column('harness_id', sa.UUID(), nullable=False),
    sa.Column('n_reachable', sa.Integer(), nullable=False),
    sa.Column('max_depth', sa.Integer(), nullable=False),
    sa.CheckConstraint('n_reachable >= 0 AND max_depth >= 0', name=op.f('ck_graph_harnesses_counts')),
    sa.ForeignKeyConstraint(['graph_id'], ['graphs.id'], name=op.f('fk_graph_harnesses_graph_id_graphs'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['harness_id'], ['harnesses.id'], name=op.f('fk_graph_harnesses_harness_id_harnesses'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('graph_id', 'harness_id', name=op.f('pk_graph_harnesses'))
    )
    op.create_table('harness_binaries',
    sa.Column('harness_id', sa.UUID(), nullable=False),
    sa.Column('sanitizer', sa.Text(), nullable=False),
    sa.Column('binary_path', sa.Text(), nullable=False),
    sa.CheckConstraint("sanitizer IN ('address', 'memory', 'undefined')", name=op.f('ck_harness_binaries_sanitizer')),
    sa.ForeignKeyConstraint(['harness_id'], ['harnesses.id'], name=op.f('fk_harness_binaries_harness_id_harnesses'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('harness_id', 'sanitizer', name=op.f('pk_harness_binaries'))
    )
    op.create_table('workers',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('run_id', sa.UUID(), nullable=False),
    sa.Column('harness_id', sa.UUID(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('end_reason', sa.Text(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('heartbeat_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('celery_job_id', sa.Text(), nullable=True),
    sa.Column('workspace_path', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("(end_reason IS NOT NULL) = (status = 'completed')", name=op.f('ck_workers_end_reason_iff_completed')),
    sa.CheckConstraint("(error IS NOT NULL) = (status = 'error')", name=op.f('ck_workers_error_iff_error')),
    sa.CheckConstraint("end_reason IN ('work_done', 'poc_target', 'timeout', 'budget')", name=op.f('ck_workers_end_reason')),
    sa.CheckConstraint("status IN ('queued', 'running', 'completed', 'cancelled', 'error', 'lost')", name=op.f('ck_workers_status')),
    sa.ForeignKeyConstraint(['harness_id'], ['harnesses.id'], name=op.f('fk_workers_harness_id_harnesses'), initially='DEFERRED', deferrable=True),
    sa.ForeignKeyConstraint(['run_id'], ['runs.id'], name=op.f('fk_workers_run_id_runs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_workers')),
    sa.UniqueConstraint('run_id', 'harness_id', name=op.f('uq_workers_run_id_harness_id'))
    )
    op.create_index(op.f('ix_workers_run_id'), 'workers', ['run_id'], unique=False)
    op.create_table('agents',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('run_id', sa.UUID(), nullable=False),
    sa.Column('worker_id', sa.UUID(), nullable=True),
    sa.Column('agent_type', sa.Text(), nullable=False),
    sa.Column('crash_id', sa.UUID(), nullable=True),
    sa.Column('function_file', sa.Text(), nullable=True),
    sa.Column('function_name', sa.Text(), nullable=True),
    sa.Column('function_start_line', sa.Integer(), nullable=True),
    sa.Column('vh_id', sa.UUID(), nullable=True),
    sa.Column('lg_id', sa.UUID(), nullable=True),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('end_reason', sa.Text(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('iterations', sa.Integer(), server_default='0', nullable=False),
    sa.Column('seeds_generated', sa.Integer(), nullable=True),
    sa.Column('log_path', sa.Text(), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("(agent_type IN ('FullVHGenerator', 'LargeFullVHGenerator')) = (function_name IS NOT NULL)", name=op.f('ck_agents_function_iff_full_finder')),
    sa.CheckConstraint("(crash_id IS NOT NULL) = (agent_type = 'POCReportAgent')", name=op.f('ck_agents_crash_iff_report')),
    sa.CheckConstraint("(end_reason IS NOT NULL) = (status = 'completed')", name=op.f('ck_agents_end_reason_iff_completed')),
    sa.CheckConstraint("(error IS NOT NULL) = (status = 'error')", name=op.f('ck_agents_error_iff_error')),
    sa.CheckConstraint("(vh_id IS NOT NULL) = (agent_type IN ('VHVerifier', 'POCAgent'))", name=op.f('ck_agents_vh_iff_verifier_or_poc')),
    sa.CheckConstraint("agent_type IN ('LGPlanningAgent', 'FullVHGenerator', 'LargeFullVHGenerator', 'DeltaVHGenerator', 'VHVerifier', 'POCAgent', 'POCReportAgent', 'SeedAgent')", name=op.f('ck_agents_agent_type')),
    sa.CheckConstraint("end_reason IN ('work_done', 'max_iterations', 'poc_target', 'timeout', 'budget')", name=op.f('ck_agents_end_reason')),
    sa.CheckConstraint("lg_id IS NOT NULL OR NOT (agent_type IN ('FullVHGenerator', 'LargeFullVHGenerator'))", name=op.f('ck_agents_full_finder_has_lg')),
    sa.CheckConstraint("lg_id IS NULL OR agent_type IN ('FullVHGenerator', 'LargeFullVHGenerator', 'SeedAgent')", name=op.f('ck_agents_lg_only_finder_or_seed')),
    sa.CheckConstraint("seeds_generated IS NULL OR agent_type = 'SeedAgent'", name=op.f('ck_agents_seeds_only_seed')),
    sa.CheckConstraint("status IN ('running', 'completed', 'cancelled', 'error', 'lost')", name=op.f('ck_agents_status')),
    sa.CheckConstraint("worker_id IS NOT NULL OR agent_type = 'POCReportAgent'", name=op.f('ck_agents_worker_unless_report')),
    sa.CheckConstraint('(function_file IS NULL) = (function_name IS NULL) AND (function_name IS NULL) = (function_start_line IS NULL)', name=op.f('ck_agents_function_all_or_none')),
    sa.CheckConstraint('iterations >= 0', name=op.f('ck_agents_iterations')),
    sa.ForeignKeyConstraint(['run_id'], ['runs.id'], name=op.f('fk_agents_run_id_runs'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['worker_id'], ['workers.id'], name=op.f('fk_agents_worker_id_workers'), initially='DEFERRED', deferrable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_agents'))
    )
    op.create_index(op.f('ix_agents_run_id'), 'agents', ['run_id'], unique=False)
    op.create_index(op.f('ix_agents_vh_id'), 'agents', ['vh_id'], unique=False)
    op.create_index(op.f('ix_agents_worker_id'), 'agents', ['worker_id'], unique=False)
    op.create_table('llm_calls',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=False), nullable=False),
    sa.Column('run_id', sa.UUID(), nullable=False),
    sa.Column('worker_id', sa.UUID(), nullable=True),
    sa.Column('agent_id', sa.UUID(), nullable=True),
    sa.Column('role', sa.Text(), nullable=False),
    sa.Column('model', sa.Text(), nullable=False),
    sa.Column('requested_model', sa.Text(), nullable=True),
    sa.Column('params', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('provider', sa.Text(), nullable=False),
    sa.Column('input_tokens', sa.Integer(), nullable=False),
    sa.Column('output_tokens', sa.Integer(), nullable=False),
    sa.Column('cache_read_tokens', sa.Integer(), nullable=True),
    sa.Column('cache_creation_tokens', sa.Integer(), nullable=True),
    sa.Column('reasoning_tokens', sa.Integer(), nullable=True),
    sa.Column('cost', sa.Numeric(precision=12, scale=6), nullable=True),
    sa.Column('latency_ms', sa.Integer(), nullable=False),
    sa.Column('success', sa.Boolean(), nullable=False),
    sa.Column('error_msg', sa.Text(), nullable=True),
    sa.Column('input_message_ids', postgresql.ARRAY(sa.BigInteger()), nullable=False),
    sa.Column('output_message_id', sa.BigInteger(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("role IN ('lg_planner', 'finder', 'verifier', 'poc', 'seed', 'utility')", name=op.f('ck_llm_calls_role')),
    sa.CheckConstraint('(output_message_id IS NOT NULL) = success', name=op.f('ck_llm_calls_output_iff_success')),
    sa.CheckConstraint('error_msg IS NULL OR NOT success', name=op.f('ck_llm_calls_error_only_failed')),
    sa.CheckConstraint('input_tokens >= 0 AND output_tokens >= 0 AND cache_read_tokens >= 0 AND cache_creation_tokens >= 0 AND reasoning_tokens >= 0 AND cost >= 0 AND latency_ms >= 0', name=op.f('ck_llm_calls_non_negative')),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], name=op.f('fk_llm_calls_agent_id_agents'), initially='DEFERRED', deferrable=True),
    sa.ForeignKeyConstraint(['output_message_id'], ['llm_messages.id'], name=op.f('fk_llm_calls_output_message_id_llm_messages'), initially='DEFERRED', deferrable=True),
    sa.ForeignKeyConstraint(['run_id'], ['runs.id'], name=op.f('fk_llm_calls_run_id_runs'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['worker_id'], ['workers.id'], name=op.f('fk_llm_calls_worker_id_workers'), initially='DEFERRED', deferrable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_llm_calls'))
    )
    op.create_index(op.f('ix_llm_calls_agent_id'), 'llm_calls', ['agent_id'], unique=False)
    op.create_index(op.f('ix_llm_calls_run_id'), 'llm_calls', ['run_id'], unique=False)
    op.create_index(op.f('ix_llm_calls_worker_id'), 'llm_calls', ['worker_id'], unique=False)
    op.create_table('logic_groups',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('run_id', sa.UUID(), nullable=False),
    sa.Column('worker_id', sa.UUID(), nullable=False),
    sa.Column('created_by_agent_id', sa.UUID(), nullable=False),
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('risk_level', sa.Text(), nullable=False),
    sa.Column('core_functions', postgresql.ARRAY(sa.Text()), nullable=False),
    sa.Column('entry_functions', postgresql.ARRAY(sa.Text()), nullable=False),
    sa.Column('summary', sa.Text(), nullable=True),
    sa.Column('planned_functions', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("risk_level IN ('high', 'medium', 'low')", name=op.f('ck_logic_groups_risk_level')),
    sa.CheckConstraint('planned_functions >= 0', name=op.f('ck_logic_groups_planned_functions')),
    sa.ForeignKeyConstraint(['created_by_agent_id'], ['agents.id'], name=op.f('fk_logic_groups_created_by_agent_id_agents'), initially='DEFERRED', deferrable=True),
    sa.ForeignKeyConstraint(['run_id'], ['runs.id'], name=op.f('fk_logic_groups_run_id_runs'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['worker_id'], ['workers.id'], name=op.f('fk_logic_groups_worker_id_workers'), initially='DEFERRED', deferrable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_logic_groups'))
    )
    op.create_index(op.f('ix_logic_groups_run_id'), 'logic_groups', ['run_id'], unique=False)
    op.create_index(op.f('ix_logic_groups_worker_id'), 'logic_groups', ['worker_id'], unique=False)
    op.create_table('function_analysis',
    sa.Column('lg_id', sa.UUID(), nullable=False),
    sa.Column('function_file', sa.Text(), nullable=False),
    sa.Column('function_name', sa.Text(), nullable=False),
    sa.Column('function_start_line', sa.Integer(), nullable=False),
    sa.Column('function_end_line', sa.Integer(), nullable=False),
    sa.Column('agent_id', sa.UUID(), nullable=False),
    sa.Column('analyzed_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('function_start_line > 0 AND function_end_line >= function_start_line', name=op.f('ck_function_analysis_lines')),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], name=op.f('fk_function_analysis_agent_id_agents'), initially='DEFERRED', deferrable=True),
    sa.ForeignKeyConstraint(['lg_id'], ['logic_groups.id'], name=op.f('fk_function_analysis_lg_id_logic_groups'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('lg_id', 'function_file', 'function_name', 'function_start_line', name=op.f('pk_function_analysis'))
    )
    op.create_table('tool_calls',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=False), nullable=False),
    sa.Column('run_id', sa.UUID(), nullable=False),
    sa.Column('llm_call_id', sa.BigInteger(), nullable=False),
    sa.Column('result_message_id', sa.BigInteger(), nullable=True),
    sa.Column('tool_name', sa.Text(), nullable=False),
    sa.Column('success', sa.Boolean(), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('latency_ms', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('error IS NULL OR NOT success', name=op.f('ck_tool_calls_error_only_failed')),
    sa.CheckConstraint('latency_ms >= 0', name=op.f('ck_tool_calls_latency')),
    sa.ForeignKeyConstraint(['llm_call_id'], ['llm_calls.id'], name=op.f('fk_tool_calls_llm_call_id_llm_calls'), initially='DEFERRED', deferrable=True),
    sa.ForeignKeyConstraint(['result_message_id'], ['llm_messages.id'], name=op.f('fk_tool_calls_result_message_id_llm_messages'), initially='DEFERRED', deferrable=True),
    sa.ForeignKeyConstraint(['run_id'], ['runs.id'], name=op.f('fk_tool_calls_run_id_runs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_tool_calls'))
    )
    op.create_index(op.f('ix_tool_calls_llm_call_id'), 'tool_calls', ['llm_call_id'], unique=False)
    op.create_index(op.f('ix_tool_calls_run_id'), 'tool_calls', ['run_id'], unique=False)
    op.create_table('vulnerability_hypotheses',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('run_id', sa.UUID(), nullable=False),
    sa.Column('worker_id', sa.UUID(), nullable=False),
    sa.Column('function_file', sa.Text(), nullable=False),
    sa.Column('function_name', sa.Text(), nullable=False),
    sa.Column('sink_code', sa.Text(), nullable=True),
    sa.Column('sink_line', sa.Integer(), nullable=True),
    sa.Column('lg_id', sa.UUID(), nullable=True),
    sa.Column('sanitizer', sa.Text(), nullable=True),
    sa.Column('created_by_agent_id', sa.UUID(), nullable=True),
    sa.Column('finder_description', sa.Text(), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('finder_score', sa.REAL(), nullable=False),
    sa.Column('score', sa.REAL(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('verifier_reproduced', sa.Boolean(), nullable=True),
    sa.Column('evidence', sa.Text(), nullable=True),
    sa.Column('important_controlflow', sa.Text(), nullable=True),
    sa.Column('verification_notes', sa.Text(), nullable=True),
    sa.Column('poc_guidance', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("sanitizer IN ('address', 'memory', 'undefined')", name=op.f('ck_vulnerability_hypotheses_sanitizer')),
    sa.CheckConstraint("status IN ('pending_verify', 'verifying', 'rejected', 'pending_poc', 'generating_poc', 'poc_generated', 'poc_failed')", name=op.f('ck_vulnerability_hypotheses_status')),
    sa.CheckConstraint('finder_score BETWEEN 0 AND 1', name=op.f('ck_vulnerability_hypotheses_finder_score')),
    sa.CheckConstraint('score BETWEEN 0 AND 1', name=op.f('ck_vulnerability_hypotheses_score')),
    sa.CheckConstraint('sink_line IS NULL OR sink_code IS NOT NULL', name=op.f('ck_vulnerability_hypotheses_sink_line_needs_code')),
    sa.ForeignKeyConstraint(['created_by_agent_id'], ['agents.id'], name=op.f('fk_vulnerability_hypotheses_created_by_agent_id_agents'), initially='DEFERRED', deferrable=True),
    sa.ForeignKeyConstraint(['lg_id'], ['logic_groups.id'], name=op.f('fk_vulnerability_hypotheses_lg_id_logic_groups'), initially='DEFERRED', deferrable=True),
    sa.ForeignKeyConstraint(['run_id'], ['runs.id'], name=op.f('fk_vulnerability_hypotheses_run_id_runs'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['worker_id'], ['workers.id'], name=op.f('fk_vulnerability_hypotheses_worker_id_workers'), initially='DEFERRED', deferrable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_vulnerability_hypotheses'))
    )
    op.create_index('ix_vh_worker_status_score', 'vulnerability_hypotheses', ['worker_id', 'status', 'score'], unique=False)
    op.create_index(op.f('ix_vulnerability_hypotheses_run_id'), 'vulnerability_hypotheses', ['run_id'], unique=False)
    op.create_table('poc_attempts',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('run_id', sa.UUID(), nullable=False),
    sa.Column('vh_id', sa.UUID(), nullable=True),
    sa.Column('worker_id', sa.UUID(), nullable=True),
    sa.Column('agent_id', sa.UUID(), nullable=True),
    sa.Column('source', sa.Text(), nullable=False),
    sa.Column('harness_id', sa.UUID(), nullable=False),
    sa.Column('sanitizer', sa.Text(), nullable=False),
    sa.Column('attempt', sa.Integer(), nullable=True),
    sa.Column('variant', sa.Integer(), nullable=True),
    sa.Column('blob', sa.LargeBinary(), nullable=False),
    sa.Column('blob_sha256', sa.Text(), nullable=False),
    sa.Column('generator_code', sa.Text(), nullable=True),
    sa.Column('status', sa.Text(), nullable=False),
    sa.Column('sanitizer_output', sa.Text(), nullable=True),
    sa.Column('crash_id', sa.UUID(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(crash_id IS NOT NULL) = (status = 'crashed')", name=op.f('ck_poc_attempts_crash_iff_crashed')),
    sa.CheckConstraint("(sanitizer_output IS NOT NULL) = (status = 'crashed')", name=op.f('ck_poc_attempts_output_iff_crashed')),
    sa.CheckConstraint("sanitizer IN ('address', 'memory', 'undefined')", name=op.f('ck_poc_attempts_sanitizer')),
    sa.CheckConstraint("source <> 'global_fuzzer' OR (vh_id IS NULL AND agent_id IS NULL AND worker_id IS NULL AND attempt IS NULL AND variant IS NULL AND generator_code IS NULL)", name=op.f('ck_poc_attempts_global_fuzzer_columns')),
    sa.CheckConstraint("source <> 'vh_agent' OR (vh_id IS NOT NULL AND agent_id IS NOT NULL AND worker_id IS NOT NULL AND attempt IS NOT NULL AND variant IS NOT NULL AND generator_code IS NOT NULL)", name=op.f('ck_poc_attempts_vh_agent_columns')),
    sa.CheckConstraint("source <> 'vh_fuzzer' OR (vh_id IS NOT NULL AND agent_id IS NULL AND worker_id IS NOT NULL AND attempt IS NULL AND variant IS NULL AND generator_code IS NULL)", name=op.f('ck_poc_attempts_vh_fuzzer_columns')),
    sa.CheckConstraint("source IN ('vh_agent', 'global_fuzzer', 'vh_fuzzer')", name=op.f('ck_poc_attempts_source')),
    sa.CheckConstraint("status IN ('pending', 'crashed', 'no_crash', 'error')", name=op.f('ck_poc_attempts_status')),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], name=op.f('fk_poc_attempts_agent_id_agents'), initially='DEFERRED', deferrable=True),
    sa.ForeignKeyConstraint(['crash_id'], ['crashes.id'], name=op.f('fk_poc_attempts_crash_id_crashes'), initially='DEFERRED', deferrable=True),
    sa.ForeignKeyConstraint(['harness_id', 'sanitizer'], ['harness_binaries.harness_id', 'harness_binaries.sanitizer'], name=op.f('fk_poc_attempts_harness_id_sanitizer_harness_binaries'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['run_id'], ['runs.id'], name=op.f('fk_poc_attempts_run_id_runs'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['vh_id'], ['vulnerability_hypotheses.id'], name=op.f('fk_poc_attempts_vh_id_vulnerability_hypotheses'), initially='DEFERRED', deferrable=True),
    sa.ForeignKeyConstraint(['worker_id'], ['workers.id'], name=op.f('fk_poc_attempts_worker_id_workers'), initially='DEFERRED', deferrable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_poc_attempts'))
    )
    op.create_index(op.f('ix_poc_attempts_agent_id'), 'poc_attempts', ['agent_id'], unique=False)
    op.create_index(op.f('ix_poc_attempts_crash_id'), 'poc_attempts', ['crash_id'], unique=False)
    op.create_index(op.f('ix_poc_attempts_run_id'), 'poc_attempts', ['run_id'], unique=False)
    op.create_index(op.f('ix_poc_attempts_vh_id'), 'poc_attempts', ['vh_id'], unique=False)
    op.create_table('vh_merges',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=False), nullable=False),
    sa.Column('vh_id', sa.UUID(), nullable=False),
    sa.Column('agent_id', sa.UUID(), nullable=True),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('finder_score', sa.REAL(), nullable=False),
    sa.Column('merged_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('finder_score BETWEEN 0 AND 1', name=op.f('ck_vh_merges_finder_score')),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.id'], name=op.f('fk_vh_merges_agent_id_agents'), initially='DEFERRED', deferrable=True),
    sa.ForeignKeyConstraint(['vh_id'], ['vulnerability_hypotheses.id'], name=op.f('fk_vh_merges_vh_id_vulnerability_hypotheses'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_vh_merges'))
    )
    op.create_index(op.f('ix_vh_merges_vh_id'), 'vh_merges', ['vh_id'], unique=False)

    # agents, VHs, logic groups, crashes and PoC attempts point at one another,
    # so these references can only be added once every table exists.
    # (create_table silently drops a use_alter constraint.)
    for table, column, target in _CYCLE_FKS:
        op.create_foreign_key(
            op.f(f"fk_{table}_{column}_{target}"), table, target, [column], ["id"],
            deferrable=True, initially="DEFERRED",
        )


def downgrade() -> None:
    for table, column, target in _CYCLE_FKS:
        op.drop_constraint(
            op.f(f"fk_{table}_{column}_{target}"), table, type_="foreignkey"
        )
    op.drop_index(op.f('ix_vh_merges_vh_id'), table_name='vh_merges')
    op.drop_table('vh_merges')
    op.drop_index(op.f('ix_poc_attempts_vh_id'), table_name='poc_attempts')
    op.drop_index(op.f('ix_poc_attempts_run_id'), table_name='poc_attempts')
    op.drop_index(op.f('ix_poc_attempts_crash_id'), table_name='poc_attempts')
    op.drop_index(op.f('ix_poc_attempts_agent_id'), table_name='poc_attempts')
    op.drop_table('poc_attempts')
    op.drop_index(op.f('ix_vulnerability_hypotheses_run_id'), table_name='vulnerability_hypotheses')
    op.drop_index('ix_vh_worker_status_score', table_name='vulnerability_hypotheses')
    op.drop_table('vulnerability_hypotheses')
    op.drop_index(op.f('ix_tool_calls_run_id'), table_name='tool_calls')
    op.drop_index(op.f('ix_tool_calls_llm_call_id'), table_name='tool_calls')
    op.drop_table('tool_calls')
    op.drop_table('function_analysis')
    op.drop_index(op.f('ix_logic_groups_worker_id'), table_name='logic_groups')
    op.drop_index(op.f('ix_logic_groups_run_id'), table_name='logic_groups')
    op.drop_table('logic_groups')
    op.drop_index(op.f('ix_llm_calls_worker_id'), table_name='llm_calls')
    op.drop_index(op.f('ix_llm_calls_run_id'), table_name='llm_calls')
    op.drop_index(op.f('ix_llm_calls_agent_id'), table_name='llm_calls')
    op.drop_table('llm_calls')
    op.drop_index(op.f('ix_agents_worker_id'), table_name='agents')
    op.drop_index(op.f('ix_agents_vh_id'), table_name='agents')
    op.drop_index(op.f('ix_agents_run_id'), table_name='agents')
    op.drop_table('agents')
    op.drop_index(op.f('ix_workers_run_id'), table_name='workers')
    op.drop_table('workers')
    op.drop_table('harness_binaries')
    op.drop_table('graph_harnesses')
    op.drop_table('llm_messages')
    op.drop_index(op.f('ix_harnesses_run_id'), table_name='harnesses')
    op.drop_table('harnesses')
    op.drop_index(op.f('ix_graphs_run_id'), table_name='graphs')
    op.drop_table('graphs')
    op.drop_index(op.f('ix_crashes_run_id'), table_name='crashes')
    op.drop_table('crashes')
    op.drop_index(op.f('ix_runs_status'), table_name='runs')
    op.drop_index(op.f('ix_runs_label'), table_name='runs')
    op.drop_index(op.f('ix_runs_created_at'), table_name='runs')
    op.drop_table('runs')
