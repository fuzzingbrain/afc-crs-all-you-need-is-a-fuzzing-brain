"""
Entry point for FuzzingBrain Dashboard.

Usage:
    python -m fuzzingbrain.dashboard
    python -m fuzzingbrain.dashboard --port 18081 --eval-server http://localhost:18080
"""

import argparse

from .app import run_dashboard


def main():
    parser = argparse.ArgumentParser(
        description="FuzzingBrain Dashboard - Web UI for monitoring"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=18081,
        help="Port to listen on (default: 18081)",
    )
    parser.add_argument(
        "--eval-server",
        default="http://localhost:8765",
        help="Eval server URL (default: http://localhost:8765)",
    )

    args = parser.parse_args()

    run_dashboard(
        host=args.host,
        port=args.port,
        eval_server_url=args.eval_server,
    )


if __name__ == "__main__":
    main()
