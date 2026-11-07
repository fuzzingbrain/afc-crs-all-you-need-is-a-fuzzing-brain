# SPDX-License-Identifier: Apache-2.0
"""
The worker: one per harness, run as a Celery task (tasks.py).

    executor.py   picks the strategy and owns the harness's fuzzers
    pipeline.py   the VH verify and PoC agent pools
    scope.py      which run / worker / harness this process works for
    context.py    the worker row's lifecycle and the LLM buffer

Nothing is imported here, so the tools can import worker.scope cheaply.
"""
