"""`python -m elastik` — quick info + REPL helpers.

  python -m elastik                  # show binary info
  python -m elastik run               # spawn the bundled core, block
  python -m elastik run --port 3105  # custom port + env
"""
from __future__ import annotations

import argparse
import sys

from elastik._spawn import binary_info, start, stop


def main() -> int:
    parser = argparse.ArgumentParser(prog="elastik")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("info", help="show bundled-binary info")

    p_run = sub.add_parser("run", help="launch bundled elastik-core (foreground)")
    p_run.add_argument("--host", default=None)
    p_run.add_argument("--port", type=int, default=None)
    p_run.add_argument("--key", default=None)
    p_run.add_argument("--read-token", dest="read_token", default=None)
    p_run.add_argument("--token", default=None)
    p_run.add_argument("--approve-token", dest="approve_token", default=None)
    p_run.add_argument("--data-dir", dest="data_dir", default=None)

    args = parser.parse_args()

    if args.cmd in (None, "info"):
        info = binary_info()
        for k, v in info.items():
            print(f"  {k}: {v}")
        return 0

    if args.cmd == "run":
        try:
            client = start(
                host=args.host,
                port=args.port,
                key=args.key,
                read_token=args.read_token,
                token=args.token,
                approve_token=args.approve_token,
                data_dir=args.data_dir,
                quiet=False,
            )
            print(f"elastik running at {client.url}", flush=True)
            print("  Ctrl-C to stop", flush=True)
            try:
                while True:
                    import time
                    time.sleep(3600)
            except KeyboardInterrupt:
                pass
        finally:
            stop()
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
