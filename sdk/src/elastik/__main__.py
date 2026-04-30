"""`python -m elastik`: quick info + REPL helpers.

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

    p_run = sub.add_parser(
        "run",
        help="launch bundled elastik-core (foreground)",
        description=(
            "Launch bundled elastik-core. --key is required unless ELASTIK_KEY "
            "or .env supplies it. Token flags are optional gates: missing "
            "--read-token leaves reads public, missing --token disables ordinary "
            "PUT/POST, and missing --approve-token disables DELETE/system writes."
        ),
    )
    p_run.add_argument("--host", default=None, help="bind host (default: ELASTIK_HOST or 127.0.0.1)")
    p_run.add_argument("--port", type=int, default=None, help="bind port (default: ELASTIK_PORT or 3105)")
    p_run.add_argument("--key", default=None, help="audit-chain HMAC key; required unless ELASTIK_KEY/.env is set")
    p_run.add_argument("--read-token", dest="read_token", default=None, help="optional read gate; omit to keep reads public")
    p_run.add_argument("--token", default=None, help="optional write token for ordinary PUT/POST; omit to disable writes")
    p_run.add_argument("--approve-token", dest="approve_token", default=None, help="optional approve token for DELETE and system writes")
    p_run.add_argument("--data-dir", dest="data_dir", default=None, help="storage root (default: ELASTIK_DATA or ./data)")

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
