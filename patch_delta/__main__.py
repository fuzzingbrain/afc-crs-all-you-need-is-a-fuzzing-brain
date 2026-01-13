from __future__ import annotations

import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Patch Delta Strategy (separate system)")
    parser.add_argument("--project", required=True)
    parser.add_argument("--benchmark-path", required=True)
    parser.add_argument("--model", required=False)
    parser.add_argument("--log-file", required=False)
    args, _ = parser.parse_known_args()

    # Defer to local strategy's unified entry
    from .patch0_delta import unified_main  # type: ignore
    # Rebuild argv minimally; unified_main parses again from sys.argv
    sys.argv = [
        sys.argv[0],
        "--project", args.project,
        "--benchmark-path", args.benchmark_path,
        *( ["--model", args.model] if args.model else [] ),
        *( ["--log-file", args.log_file] if args.log_file else [] ),
    ]
    raise SystemExit(unified_main())


if __name__ == "__main__":
    main()


