"""
Entry point for running the Evaluation Server.

Usage:
    python -m fuzzingbrain.eval_server [OPTIONS]

Options:
    --host TEXT     Host to bind to (default: 0.0.0.0)
    --port INT      Port to bind to (default: 8081)
    --reload        Enable auto-reload for development
"""

import argparse
import sys


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="FuzzingBrain Evaluation Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8081,
        help="Port to bind to (default: 8081)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )
    parser.add_argument(
        "--mongodb-uri",
        default=None,
        help="MongoDB URI (default: mongodb://localhost:27017)",
    )
    parser.add_argument(
        "--redis-url",
        default=None,
        help="Redis URL (default: redis://localhost:6379)",
    )

    args = parser.parse_args()

    # Configure server
    from .config import ServerConfig, set_config

    config = ServerConfig(
        host=args.host,
        port=args.port,
    )
    if args.mongodb_uri:
        config.mongodb_uri = args.mongodb_uri
    if args.redis_url:
        config.redis_url = args.redis_url

    set_config(config)

    # Run server
    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn not installed. Install with: pip install uvicorn")
        sys.exit(1)

    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║         FuzzingBrain Evaluation Server                        ║
╠═══════════════════════════════════════════════════════════════╣
║  Host:      {args.host:<50} ║
║  Port:      {args.port:<50} ║
║  MongoDB:   {config.mongodb_uri:<50} ║
║  Redis:     {config.redis_url:<50} ║
║                                                               ║
║  API Docs:  http://{args.host}:{args.port}/docs{" " * 30} ║
╚═══════════════════════════════════════════════════════════════╝
    """)

    uvicorn.run(
        "fuzzingbrain.eval_server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
