"""`python -m elastik`: quick info + REPL helpers.

  python -m elastik                  # show binary info
  python -m elastik run               # spawn the bundled core, block
  python -m elastik run --port 3105  # custom port + env
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from elastik._spawn import binary_info, start, stop
from elastik._coap_client import coap_code_text, get as coap_get, put as coap_put
from elastik.sdk import Elastik
from elastik.tools import decode_disk_name


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(prog="elastik")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("info", help="show bundled-binary info")
    p_decode = sub.add_parser("decode-path", help="decode a data/ disk directory name")
    p_decode.add_argument("disk_name", help="for example: home%2Fnote%2Etxt")

    p_ls_data = sub.add_parser("ls-data", help="list decoded durable worlds in a data directory")
    p_ls_data.add_argument("data_dir", nargs="?", default="./data", help="storage root (default: ./data)")

    p_ls = sub.add_parser("ls", help="list virtual children from a running core")
    p_ls.add_argument("prefix", nargs="?", default="")
    p_ls.add_argument("--all", action="store_true", help="show all descendants")

    p_tree = sub.add_parser("tree", help="show a virtual tree from a running core")
    p_tree.add_argument("prefix", nargs="?", default="")

    p_rm = sub.add_parser("rm", help="delete a path from a running core")
    p_rm.add_argument("path")
    p_rm.add_argument("-r", "--recursive", action="store_true")
    p_rm.add_argument("--force", action="store_true", help="confirm recursive deletion of namespace roots or all paths")

    p_mv = sub.add_parser("mv", help="move/rename paths from a running core")
    p_mv.add_argument("src")
    p_mv.add_argument("dst")
    p_mv.add_argument("-r", "--recursive", action="store_true")
    p_mv.add_argument("--overwrite", action="store_true", help="allow replacing existing destination paths")

    p_du = sub.add_parser("du", help="show Content-Length usage from a running core")
    p_du.add_argument("prefix", nargs="?", default="")
    p_du.add_argument("--max-workers", type=_positive_int, default=4, help="parallel HEAD requests to use (default: 4)")

    p_coap = sub.add_parser("coap", help="send one UDP-curl shaped CoAP request")
    coap_sub = p_coap.add_subparsers(dest="coap_cmd")
    p_coap_get = coap_sub.add_parser("get", help="CoAP GET HOST PORT PATH")
    p_coap_get.add_argument("host")
    p_coap_get.add_argument("port", type=int)
    p_coap_get.add_argument("path")
    p_coap_get.add_argument("--token", default=None, help="elastik auth token carried in CoAP option 65001")
    p_coap_get.add_argument("--timeout", type=float, default=2.0)

    p_coap_put = coap_sub.add_parser("put", help="CoAP PUT HOST PORT PATH [PAYLOAD]")
    p_coap_put.add_argument("host")
    p_coap_put.add_argument("port", type=int)
    p_coap_put.add_argument("path")
    p_coap_put.add_argument("payload", nargs="?", default=None, help="UTF-8 payload; omit or use '-' to read stdin bytes")
    p_coap_put.add_argument("--token", default=None, help="elastik auth token carried in CoAP option 65001")
    p_coap_put.add_argument("--content-type", default=None, help="text/plain or application/octet-stream")
    p_coap_put.add_argument("--timeout", type=float, default=2.0)
    p_coap_put.add_argument("--verbose", action="store_true", help="print CoAP status to stderr")

    p_run = sub.add_parser(
        "run",
        help="launch bundled elastik-core (foreground)",
        description=(
            "Launch bundled elastik-core. --key is required unless ELASTIK_KEY "
            "or .env supplies it. Token flags are optional gates: missing "
            "--read-token leaves reads public, missing --write-token disables ordinary "
            "PUT/POST, and missing --approve-token disables DELETE/system writes."
        ),
    )
    p_run.add_argument("--host", default=None, help="bind host (default: ELASTIK_HOST or 127.0.0.1)")
    p_run.add_argument("--port", type=int, default=None, help="bind port (default: ELASTIK_PORT or 3105)")
    p_run.add_argument(
        "--key",
        default=None,
        help=(
            "audit-chain HMAC key, at least 32 UTF-8 bytes and not all "
            "whitespace; required unless ELASTIK_KEY/.env is set"
        ),
    )
    p_run.add_argument("--read-token", dest="read_token", default=None, help="optional read gate; omit to keep reads public")
    p_run.add_argument("--write-token", default=None, help="optional write token for ordinary PUT/POST; omit to disable writes")
    p_run.add_argument("--approve-token", dest="approve_token", default=None, help="optional approve token for DELETE and system writes")
    p_run.add_argument("--data-dir", dest="data_dir", default=None, help="storage root (default: ELASTIK_DATA or ./data)")

    args = parser.parse_args()

    if args.cmd in (None, "info"):
        info = binary_info()
        for k, v in info.items():
            print(f"  {k}: {v}")
        return 0

    if args.cmd == "decode-path":
        print(decode_disk_name(args.disk_name))
        return 0

    if args.cmd == "ls-data":
        data_root = Path(args.data_dir)
        if not data_root.exists():
            return 0
        for child in sorted(data_root.iterdir()):
            if child.is_dir() and child.joinpath("universe.db").exists():
                print(f"{decode_disk_name(child.name)}\t(disk: {child.name}/)")
        return 0

    if args.cmd == "ls":
        e = Elastik()
        for path in e.ls(args.prefix, depth=-1 if args.all else 1):
            print(path)
        return 0

    if args.cmd == "tree":
        print(Elastik().tree(args.prefix))
        return 0

    if args.cmd == "rm":
        print(Elastik().rm(args.path, recursive=args.recursive, force=args.force))
        return 0

    if args.cmd == "mv":
        print(Elastik().mv(args.src, args.dst, recursive=args.recursive, overwrite=args.overwrite))
        return 0

    if args.cmd == "du":
        for path, size in Elastik().du(args.prefix, max_workers=args.max_workers).items():
            print(f"{size}\t{path}")
        return 0

    if args.cmd == "coap":
        if args.coap_cmd == "get":
            try:
                response = coap_get(
                    args.host,
                    args.port,
                    args.path,
                    token=args.token,
                    timeout=args.timeout,
                )
            except TimeoutError:
                print("coap: timeout", file=sys.stderr)
                return 1
            except ValueError as exc:
                print(f"coap: {exc}", file=sys.stderr)
                return 1
            if not response.ok:
                print(f"coap: {response.status}", file=sys.stderr)
                if response.payload:
                    sys.stderr.buffer.write(response.payload)
                return 1
            sys.stdout.buffer.write(response.payload)
            return 0
        if args.coap_cmd == "put":
            payload = (
                sys.stdin.buffer.read()
                if args.payload is None or args.payload == "-"
                else args.payload
            )
            try:
                response = coap_put(
                    args.host,
                    args.port,
                    args.path,
                    payload,
                    token=args.token,
                    content_type=args.content_type,
                    timeout=args.timeout,
                )
            except TimeoutError:
                print("coap: timeout", file=sys.stderr)
                return 1
            except ValueError as exc:
                print(f"coap: {exc}", file=sys.stderr)
                return 1
            if not response.ok:
                print(f"coap: {response.status}", file=sys.stderr)
                if response.payload:
                    sys.stderr.buffer.write(response.payload)
                return 1
            if args.verbose:
                print(coap_code_text(response.code), file=sys.stderr)
            if response.payload:
                sys.stdout.buffer.write(response.payload)
            return 0
        p_coap.print_help()
        return 2

    if args.cmd == "run":
        try:
            try:
                client = start(
                    host=args.host,
                    port=args.port,
                    key=args.key,
                    read_token=args.read_token,
                    write_token=args.write_token,
                    approve_token=args.approve_token,
                    data_dir=args.data_dir,
                    quiet=False,
                    _key_source="--key" if args.key is not None else None,
                )
                print(f"elastik running at {client.url}", flush=True)
                print("  Ctrl-C to stop", flush=True)
                try:
                    while True:
                        import time
                        time.sleep(3600)
                except KeyboardInterrupt:
                    pass
            except RuntimeError as exc:
                print(f"elastik: {exc}", file=sys.stderr)
                return 1
        finally:
            stop()
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
