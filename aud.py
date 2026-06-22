#!/usr/bin/env python3
"""aud — transparent audit daemon. inotify IS the engine.

Write files however you want. This daemon handles integrity.

    echo "hello" > $STORE/greeting       ← you just write files
    aud sees CLOSE_WRITE             ← inotify (ctypes, no subprocess)
    → HMAC chain appended                ← hmac+hashlib (in-process, no fork)
    → hooks notified                     ← persistent subprocess, hot-reload

Zero pip dependencies. One process. Any language for hooks.

Usage:
    aud [store_dir]                  watch and audit
    aud verify [store_dir]           verify all chains
    aud verify [store_dir] <key>     verify one chain

Hooks ($STORE/hooks/ — any executable, hot-reload):
    chmod +x → persistent subprocess started, stdin=JSON lines
    edit     → old killed, new started
    rm       → killed

    daemon → stdin:  {"event":"write","path":"doc","sha256":"a948...","size":12}
    hook → stdout:   {"skip":true}     (optional, skip default audit)
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import hmac as hmac_mod
import json
import os
import signal
import struct
import subprocess
import sys
import time
import fcntl

# ═══════════════════════════════════════════
# INOTIFY VIA CTYPES — zero dependency
# ═══════════════════════════════════════════

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_libc.inotify_init.restype = ctypes.c_int
_libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
_libc.inotify_add_watch.restype = ctypes.c_int

IN_CLOSE_WRITE = 0x00000008
IN_ATTRIB      = 0x00000004
IN_DELETE      = 0x00000200
IN_MOVED_TO    = 0x00000080
IN_CREATE      = 0x00000100
IN_ISDIR       = 0x40000000
IN_MASK = IN_CLOSE_WRITE | IN_DELETE | IN_MOVED_TO | IN_CREATE

_EVENT_STRUCT = struct.Struct("iIII")

class Inotify:
    """Minimal inotify wrapper. ctypes only. No pip. No subprocess."""

    def __init__(self) -> None:
        self._fd = _libc.inotify_init()
        if self._fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init failed")
        self._wd_to_path: dict[int, str] = {}

    def add(self, path: str, mask: int = IN_MASK) -> int:
        wd = _libc.inotify_add_watch(self._fd, path.encode(), mask)
        if wd < 0:
            raise OSError(ctypes.get_errno(), f"inotify_add_watch failed: {path}")
        self._wd_to_path[wd] = path
        return wd

    def add_recursive(self, root: str, mask: int = IN_MASK) -> int:
        count = 0
        self.add(root, mask | IN_CREATE); count += 1
        for dirpath, dirnames, _ in os.walk(root):
            for d in dirnames:
                if d.startswith("."):
                    continue
                try:
                    self.add(os.path.join(dirpath, d), mask | IN_CREATE)
                    count += 1
                except OSError:
                    pass
        return count

    def read(self) -> list[tuple[str, int, str]]:
        buf = os.read(self._fd, 8192)
        events = []
        offset = 0
        while offset < len(buf):
            wd, mask, _, name_len = _EVENT_STRUCT.unpack_from(buf, offset)
            offset += _EVENT_STRUCT.size
            name = buf[offset:offset + name_len].rstrip(b"\0").decode(errors="replace")
            offset += name_len
            dir_path = self._wd_to_path.get(wd, "?")
            if mask & IN_ISDIR and mask & IN_CREATE and name and not name.startswith("."):
                full = os.path.join(dir_path, name)
                if not any(p == full for p in self._wd_to_path.values()):
                    try: self.add(full, IN_MASK | IN_CREATE)
                    except OSError: pass
            events.append((dir_path, mask, name))
        return events

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

def check_inotify_limit(watch_count: int) -> None:
    try:
        limit = int(open("/proc/sys/fs/inotify/max_user_watches").read().strip())
        used_pct = watch_count / limit * 100
        if used_pct > 80:
            log(f"WARNING: inotify watches {watch_count}/{limit} ({used_pct:.0f}%) — "
                f"raise with: sysctl fs.inotify.max_user_watches=65536")
    except (OSError, ValueError):
        pass

# ═══════════════════════════════════════════
# HMAC — pure Unix, no MIME, no HTTP legacy
#
# Fields: prev, type, target, body_sha256, size
# That's it. content-type is a browser concept.
# ═══════════════════════════════════════════

def _hmac_field(mac: hmac_mod.HMAC, label: bytes, value: str) -> None:
    mac.update(label + b"\0")
    mac.update(str(len(value)).encode() + b"\0")
    mac.update(value.encode() + b"\0")

def compute_hmac(key: bytes, prev: str, event_type: str,
                 target: str, body_sha256: str, size: int) -> str:
    mac = hmac_mod.new(key, digestmod=hashlib.sha256)
    _hmac_field(mac, b"prev", prev)
    _hmac_field(mac, b"type", event_type)
    _hmac_field(mac, b"target", target)
    _hmac_field(mac, b"body-sha256", body_sha256)
    _hmac_field(mac, b"size", str(size))
    return mac.hexdigest()

def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

# ═══════════════════════════════════════════
# CHAIN — append-only HMAC ledger
#
# Format: id \t ts \t type \t target \t sha256 \t size \t hmac \t prev
# 8 fields. No content-type. No meta_sha256. Pure.
# ═══════════════════════════════════════════

class ChainWriter:
    """In-memory prev cache. No re-read per event."""

    def __init__(self, key: bytes) -> None:
        self._key = key
        self._prev: dict[str, str] = {}
        self._counts: dict[str, int] = {}

    def append(self, chain_file: str, event_type: str, target: str,
               body_sha256: str, size: int) -> str:
        if chain_file not in self._prev:
            self._load(chain_file)

        prev = self._prev.get(chain_file, "")
        count = self._counts.get(chain_file, 0) + 1

        h = compute_hmac(self._key, prev, event_type, target, body_sha256, size)
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        line = f"{count}\t{ts}\t{event_type}\t{target}\t{body_sha256}\t{size}\t{h}\t{prev}\n"

        os.makedirs(os.path.dirname(chain_file), exist_ok=True)
        lock_path = chain_file + ".lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with open(chain_file, "a") as f:
                f.write(line)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

        self._prev[chain_file] = h
        self._counts[chain_file] = count
        return h

    def _load(self, chain_file: str) -> None:
        """Bug #1 fix: try/except for corrupted chain files."""
        try:
            if os.path.isfile(chain_file) and os.path.getsize(chain_file) > 0:
                with open(chain_file) as f:
                    lines = f.read().splitlines()
                if lines:
                    self._counts[chain_file] = len(lines)
                    parts = lines[-1].split("\t")
                    self._prev[chain_file] = parts[6] if len(parts) > 6 else ""
                    return
        except (OSError, IndexError, ValueError) as e:
            log(f"chain load failed {chain_file}: {e}")
        self._prev[chain_file] = ""
        self._counts[chain_file] = 0

# ═══════════════════════════════════════════
# VERIFY
# ═══════════════════════════════════════════

def verify_chain(chain_file: str, key: bytes) -> tuple[bool, int, str]:
    """Verify a chain file. Returns (ok, event_count, detail)."""
    if not os.path.isfile(chain_file) or os.path.getsize(chain_file) == 0:
        return True, 0, "empty"
    prev = ""
    count = 0
    try:
        with open(chain_file) as f:
            for lineno, line in enumerate(f):
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 8:
                    return False, count, f"line {lineno}: malformed ({len(parts)} fields, need 8)"
                _, _, etype, target, bsha, sz, hmac_val, row_prev = parts[:8]
                if row_prev != prev:
                    return False, count, f"line {lineno}: prev mismatch expected={prev!r} got={row_prev!r}"
                expected = compute_hmac(key, prev, etype, target, bsha, int(sz))
                if not hmac_mod.compare_digest(expected, hmac_val):
                    return False, count, f"line {lineno}: hmac mismatch"
                prev = hmac_val
                count += 1
    except (OSError, ValueError) as e:
        return False, count, f"read error: {e}"
    return True, count, f"ok, latest=hmac-{prev}"

# ═══════════════════════════════════════════
# HOOKS — any executable, persistent, hot-reload
# ═══════════════════════════════════════════

class _LiveHook:
    __slots__ = ("name", "proc")

    def __init__(self, path: str) -> None:
        self.name = os.path.basename(path)
        self.proc = subprocess.Popen(
            [path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, bufsize=1,
        )

    def send(self, event: dict) -> bool:
        """Bug #2 fix: non-blocking. Write event, don't wait for response.
        Response is drained opportunistically on next call."""
        if self.proc.poll() is not None:
            return False
        try:
            assert self.proc.stdin is not None
            assert self.proc.stdout is not None
            # drain any pending response from previous event (non-blocking)
            self._drain()
            # send new event
            self.proc.stdin.write(json.dumps(event) + "\n")
            self.proc.stdin.flush()
            # try to read response immediately (non-blocking via O_NONBLOCK)
            return self._try_read_skip()
        except (BrokenPipeError, OSError):
            pass
        return False

    def _drain(self) -> None:
        """Drain pending stdout without blocking."""
        fd = self.proc.stdout.fileno()  # type: ignore
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        try:
            while True:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
        except BlockingIOError:
            pass
        finally:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags)

    def _try_read_skip(self) -> bool:
        """Non-blocking attempt to read skip response."""
        fd = self.proc.stdout.fileno()  # type: ignore
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        try:
            data = os.read(fd, 4096).decode()
            for line in data.splitlines():
                line = line.strip()
                if line:
                    try:
                        return json.loads(line).get("skip", False)
                    except (json.JSONDecodeError, AttributeError):
                        pass
        except BlockingIOError:
            pass
        finally:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags)
        return False

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try: self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired: self.proc.kill()


class HookRegistry:
    def __init__(self, hooks_dir: str, ino: Inotify) -> None:
        self._dir = hooks_dir
        self._hooks: dict[str, _LiveHook] = {}
        os.makedirs(hooks_dir, exist_ok=True)
        ino.add(hooks_dir, IN_CLOSE_WRITE | IN_DELETE | IN_MOVED_TO | IN_ATTRIB)
        for f in os.listdir(hooks_dir):
            self._start(f)

    def handle_hook_event(self, mask: int, name: str) -> None:
        if mask & (IN_CLOSE_WRITE | IN_MOVED_TO | IN_ATTRIB):
            self._start(name)
        elif mask & IN_DELETE:
            self._stop(name)

    def _start(self, name: str) -> None:
        path = os.path.join(self._dir, name)
        if not os.path.isfile(path):
            return
        self._stop(name)
        try:
            self._hooks[name] = _LiveHook(path)
            log(f"hook started: {name}")
        except (OSError, PermissionError):
            pass  # not executable yet — ATTRIB will retry

    def _stop(self, name: str) -> None:
        hook = self._hooks.pop(name, None)
        if hook is not None:
            hook.kill()
            log(f"hook stopped: {name}")

    def fire(self, event_name: str, event: dict) -> bool:
        skip = False
        dead: list[str] = []
        for name, hook in self._hooks.items():
            if hook.proc.poll() is not None:
                dead.append(name)
                continue
            if hook.send(event):
                skip = True
        for name in dead:
            self._hooks.pop(name, None)
            log(f"hook died: {name}")
        return skip

    def shutdown(self) -> None:
        for hook in self._hooks.values():
            hook.kill()
        self._hooks.clear()

# ═══════════════════════════════════════════
# DAEMON
# ═══════════════════════════════════════════

SKIP_NAMES = frozenset({".audit", ".hmac_key", ".ledger", ".lock", "hooks"})

def should_audit(name: str) -> bool:
    if not name or name.startswith("."):
        return False
    if name in SKIP_NAMES:
        return False
    if name.endswith(".chain") or name.endswith(".lock"):
        return False
    return True

def log(msg: str) -> None:
    ts = time.strftime("%H:%M:%S", time.gmtime())
    print(f"aud: {ts} {msg}", file=sys.stderr, flush=True)

EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def cmd_watch(store: str) -> int:
    os.makedirs(store, exist_ok=True)

    # PID file
    pid_file = os.path.join(store, ".pid")
    if os.path.exists(pid_file):
        old_pid = int(open(pid_file).read().strip())
        try:
            os.kill(old_pid, 0)  # check if alive
            log(f"already running (pid={old_pid}), exiting")
            return 1
        except ProcessLookupError:
            pass  # stale pid file
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))

    # SIGTERM/SIGHUP handler — raise SystemExit to break ino.read() (PEP 475 auto-retries EINTR)
    def _handle_term(signum: int, _: object) -> None:
        log(f"received signal {signal.Signals(signum).name}, shutting down")
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, _handle_term)
    signal.signal(signal.SIGHUP, _handle_term)

    # key
    key_file = os.path.join(store, ".hmac_key")
    if not os.path.exists(key_file):
        key_hex = os.urandom(32).hex()
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, key_hex.encode())
        os.close(fd)
        log(f"generated key: {key_file}")
    else:
        key_hex = open(key_file).read().strip()

    key = bytes.fromhex(key_hex)
    chain = ChainWriter(key)
    audit_dir = os.path.join(store, ".audit")
    ledger_file = os.path.join(store, ".ledger", "deletes.chain")
    hooks_dir = os.path.join(store, "hooks")
    status_file = os.path.join(store, ".status")
    os.makedirs(audit_dir, exist_ok=True)
    os.makedirs(os.path.dirname(ledger_file), exist_ok=True)

    ino = Inotify()
    watch_count = ino.add_recursive(store)
    check_inotify_limit(watch_count)
    check_privilege_separation(store)
    check_disk_space(store)

    registry = HookRegistry(hooks_dir, ino)

    # event counters
    stats = {"writes": 0, "deletes": 0, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    _write_status(status_file, stats, watch_count)

    log(f"watching {store} ({watch_count} watches) pid={os.getpid()}")
    log(f"hooks: {hooks_dir}")

    try:
        while True:
            for dir_path, mask, name in ino.read():
                if dir_path == hooks_dir:
                    registry.handle_hook_event(mask, name)
                    continue

                if not should_audit(name):
                    continue

                filepath = os.path.join(dir_path, name)
                target = os.path.relpath(filepath, store)
                chain_file = os.path.join(audit_dir, target + ".chain")

                if mask & (IN_CLOSE_WRITE | IN_MOVED_TO):
                    if not os.path.isfile(filepath):
                        continue
                    bsha = file_sha256(filepath)
                    sz = os.path.getsize(filepath)
                    event = {"event": "write", "path": target, "sha256": bsha, "size": sz}
                    skip = registry.fire("write", event)
                    if not skip:
                        chain.append(chain_file, "put", target, bsha, sz)
                        stats["writes"] += 1
                        log(f"WRITE {target} sha256={bsha[:16]}…")

                elif mask & IN_DELETE:
                    event = {"event": "delete", "path": target}
                    skip = registry.fire("delete", event)
                    if not skip:
                        chain.append(ledger_file, "delete_commit", target, EMPTY_SHA, 0)
                        stats["deletes"] += 1
                        log(f"DELETE {target}")

                _write_status(status_file, stats, watch_count)

    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        log(f"stopped (writes={stats['writes']} deletes={stats['deletes']})")
        registry.shutdown()
        ino.close()
        for f in [pid_file, status_file]:
            try: os.unlink(f)
            except OSError: pass
    return 0

def _write_status(path: str, stats: dict, watches: int) -> None:
    """Write machine-readable status for `aud status`."""
    try:
        with open(path, "w") as f:
            json.dump({
                "pid": os.getpid(),
                "started": stats["started"],
                "writes": stats["writes"],
                "deletes": stats["deletes"],
                "watches": watches,
                "last_update": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }, f)
    except OSError:
        pass

def check_disk_space(store: str) -> None:
    """Warn if disk is >90% full."""
    try:
        st = os.statvfs(store)
        used_pct = (1 - st.f_bavail / st.f_blocks) * 100
        if used_pct > 90:
            log(f"WARNING: disk {used_pct:.0f}% full — chain writes may fail")
        elif used_pct > 80:
            log(f"NOTICE: disk {used_pct:.0f}% full")
    except OSError:
        pass

def cmd_verify(store: str, key_name: str | None = None) -> int:
    key_file = os.path.join(store, ".hmac_key")
    if not os.path.exists(key_file):
        print(f"ERR store not initialized: {store}", file=sys.stderr)
        return 1
    key = bytes.fromhex(open(key_file).read().strip())
    audit_dir = os.path.join(store, ".audit")
    ledger_file = os.path.join(store, ".ledger", "deletes.chain")

    if key_name:
        chain_file = os.path.join(audit_dir, key_name + ".chain")
        ok, count, detail = verify_chain(chain_file, key)
        status = "OK" if ok else "FAIL"
        print(f"{status} {key_name}: {count} events, {detail}")
        return 0 if ok else 1

    # verify all
    all_ok = True
    if os.path.isdir(audit_dir):
        for f in sorted(os.listdir(audit_dir)):
            if not f.endswith(".chain"):
                continue
            name = f[:-6]  # strip .chain
            ok, count, detail = verify_chain(os.path.join(audit_dir, f), key)
            status = "OK" if ok else "FAIL"
            print(f"{status}   {name}: {count} events, {detail}")
            if not ok:
                all_ok = False

    if os.path.isfile(ledger_file):
        ok, count, detail = verify_chain(ledger_file, key)
        status = "OK" if ok else "FAIL"
        print(f"{status}   (ledger): {count} events, {detail}")
        if not ok:
            all_ok = False

    return 0 if all_ok else 1

# ═══════════════════════════════════════════
# WATCH-AUDIT — real-time chain monitor
#
# The auditor AI runs this. Read-only.
# inotify on .audit/ — verify every chain change.
# Raises alarm on tamper. No write access needed.
#
#   sudo -u <auditor> aud watch-audit /var/lib/aud
#
# Three processes, three users, three roles:
#   aud          → aud watch      → writes chains
#   agent        → echo > data/file   → writes data
#   auditor      → aud watch-audit → reads + verifies chains
# ═══════════════════════════════════════════

def cmd_watch_audit(store: str) -> int:
    """Real-time chain verifier. Read-only. For auditor AI."""
    key_file = os.path.join(store, ".hmac_key")
    if not os.path.exists(key_file):
        print(f"ERR store not initialized: {store}", file=sys.stderr)
        return 1

    try:
        key = bytes.fromhex(open(key_file).read().strip())
    except PermissionError:
        print(f"ERR cannot read {key_file} — add this user to {AUDITOR_GROUP}: "
              f"usermod -aG {AUDITOR_GROUP} $(whoami)", file=sys.stderr)
        return 1

    audit_dir = os.path.join(store, ".audit")
    ledger_file = os.path.join(store, ".ledger", "deletes.chain")

    if not os.path.isdir(audit_dir):
        print(f"ERR audit dir not found: {audit_dir}", file=sys.stderr)
        return 1

    # initial verify of all chains
    log("initial verification...")
    ok_count, fail_count = 0, 0
    for f in sorted(os.listdir(audit_dir)):
        if not f.endswith(".chain"):
            continue
        ok, count, detail = verify_chain(os.path.join(audit_dir, f), key)
        if ok:
            ok_count += 1
        else:
            fail_count += 1
            log(f"ALERT chain FAIL: {f[:-6]}: {detail}")
    if os.path.isfile(ledger_file):
        ok, count, detail = verify_chain(ledger_file, key)
        if not ok:
            fail_count += 1
            log(f"ALERT ledger FAIL: {detail}")
    log(f"initial: {ok_count} ok, {fail_count} failures")

    # watch .audit/ and .ledger/ for changes
    ino = Inotify()
    ino.add(audit_dir, IN_CLOSE_WRITE | IN_MOVED_TO)
    ledger_dir = os.path.join(store, ".ledger")
    if os.path.isdir(ledger_dir):
        ino.add(ledger_dir, IN_CLOSE_WRITE | IN_MOVED_TO)
    log(f"watching {audit_dir} (read-only, verify on every change)")

    # track last-known event count per chain
    counts: dict[str, int] = {}

    try:
        while True:
            for dir_path, mask, name in ino.read():
                if not name.endswith(".chain"):
                    continue

                chain_file = os.path.join(dir_path, name)
                ok, count, detail = verify_chain(chain_file, key)
                prev_count = counts.get(chain_file, 0)
                counts[chain_file] = count

                if ok:
                    if count > prev_count:
                        new_events = count - prev_count
                        label = name[:-6] if name != "deletes.chain" else "(ledger)"
                        log(f"VERIFIED {label}: +{new_events} events (total={count})")
                else:
                    log(f"═══ ALERT ═══ CHAIN INTEGRITY FAILURE: {name}")
                    log(f"  detail: {detail}")
                    log(f"  action: investigate immediately")

    except KeyboardInterrupt:
        log("auditor stopped")
    finally:
        ino.close()
    return 0

# ═══════════════════════════════════════════
# PRIVILEGE SEPARATION
#
# 审计员和被审计人不能是同一个人。
# Unix 50 年前就知道这个。
#
# Layout after `aud install`:
#   $STORE/                  750 aud:aud        daemon owns root
#     .hmac_key              600 aud:aud        key — only daemon reads
#     .audit/                700 aud:aud        chains — only daemon writes
#     .ledger/               700 aud:aud        delete log — only daemon writes
#     hooks/                 700 aud:aud        hooks — only daemon manages
#     data/                 1773 aud:agents     agent writes here (sticky bit)
#
# Agent can:   echo "hello" > $STORE/data/greeting   ✓
# Agent can't: cat $STORE/.hmac_key                  ✗ (600)
# Agent can't: echo fake >> $STORE/.audit/x.chain    ✗ (700)
# Agent can't: kill <daemon-pid>                     ✗ (different user)
# Agent can't: rm $STORE/data/other_agent_file       ✗ (sticky bit)
#
# Like auditd: auditd runs root → users can't touch audit logs.
# ═══════════════════════════════════════════

import grp
import pwd
import shutil

AUD_USER = "aud"
AUD_GROUP = "aud"
AGENTS_GROUP = "aud-agents"
AUDITOR_GROUP = "aud-auditor"

def cmd_install(store: str) -> int:
    """Set up privilege separation. Must run as root."""
    if os.geteuid() != 0:
        print("ERR aud install must run as root (sets up user + permissions)", file=sys.stderr)
        return 1

    # create system user
    if not _user_exists(AUD_USER):
        subprocess.run(["useradd", "--system", "--shell", "/usr/sbin/nologin",
                        "--home-dir", "/nonexistent", AUD_USER], check=True)
        log(f"created user: {AUD_USER}")
    else:
        log(f"user exists: {AUD_USER}")

    # create groups
    for g in (AGENTS_GROUP, AUDITOR_GROUP):
        if not _group_exists(g):
            subprocess.run(["groupadd", "--system", g], check=True)
            log(f"created group: {g}")
        else:
            log(f"group exists: {g}")

    uid = pwd.getpwnam(AUD_USER).pw_uid
    gid = pwd.getpwnam(AUD_USER).pw_gid
    agents_gid = grp.getgrnam(AGENTS_GROUP).gr_gid
    auditor_gid = grp.getgrnam(AUDITOR_GROUP).gr_gid

    # directory structure
    os.makedirs(store, exist_ok=True)
    data_dir = os.path.join(store, "data")

    # daemon-only dirs (hooks, ledger)
    for d in [store, os.path.join(store, "hooks")]:
        os.makedirs(d, exist_ok=True)
        os.chown(d, uid, gid)
        os.chmod(d, 0o700)

    # auditor-readable dirs (audit chain, ledger)
    for d in [os.path.join(store, ".audit"),
              os.path.join(store, ".ledger")]:
        os.makedirs(d, exist_ok=True)
        os.chown(d, uid, auditor_gid)
        os.chmod(d, 0o750)  # daemon rwx, auditor r-x

    # data dir: agents write, sticky
    os.makedirs(data_dir, exist_ok=True)
    os.chown(data_dir, uid, agents_gid)
    os.chmod(data_dir, 0o1773)

    # store root
    os.chown(store, uid, gid)
    os.chmod(store, 0o750)

    # key: daemon rw, auditor read-only (needs key to verify)
    key_file = os.path.join(store, ".hmac_key")
    if not os.path.exists(key_file):
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        os.write(fd, os.urandom(32).hex().encode())
        os.close(fd)
    os.chown(key_file, uid, auditor_gid)
    os.chmod(key_file, 0o640)  # daemon rw, auditor r

    log(f"installed: {store}")
    log(f"  daemon user:    {AUD_USER} (uid={uid})")
    log(f"  agents group:   {AGENTS_GROUP} (gid={agents_gid})")
    log(f"  auditor group:  {AUDITOR_GROUP} (gid={auditor_gid})")
    log(f"  .hmac_key:      640 {AUD_USER}:{AUDITOR_GROUP}  (auditor can read, not write)")
    log(f"  .audit/:        750 {AUD_USER}:{AUDITOR_GROUP}  (auditor can read, not write)")
    log(f"  data/:         1773 {AUD_USER}:{AGENTS_GROUP}   (agents write, sticky)")
    log(f"")
    log(f"  run daemon:     sudo -u {AUD_USER} aud watch {store}/data")
    log(f"  add agent:      usermod -aG {AGENTS_GROUP} <agent_user>")
    log(f"  add auditor AI: usermod -aG {AUDITOR_GROUP} <auditor_user>")
    log(f"  live audit:     sudo -u <auditor> aud watch-audit {store}")

    # kernel-level identity tracking via auditd
    if shutil.which("auditctl"):
        data_dir_abs = os.path.abspath(data_dir)
        subprocess.run(["auditctl", "-w", data_dir_abs, "-p", "wa", "-k", "aud"],
                       check=False)
        log(f"  auditctl: -w {data_dir_abs} -p wa -k aud")
        log(f"  query:    ausearch -k aud")
    else:
        log(f"  auditctl: not found (install auditd for kernel-level uid tracking)")

    # generate systemd unit
    store_abs = os.path.abspath(store)
    unit = f"""[Unit]
Description=aud — transparent HMAC audit daemon
After=local-fs.target

[Service]
Type=simple
User={AUD_USER}
ExecStart={os.path.abspath(__file__)} watch {store_abs}/data
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aud

[Install]
WantedBy=multi-user.target
"""
    unit_path = "/etc/systemd/system/aud.service"
    try:
        with open(unit_path, "w") as f:
            f.write(unit)
        log(f"  systemd: {unit_path}")
        log(f"  enable:  systemctl enable --now aud")
    except OSError:
        log(f"  systemd: could not write {unit_path}")
        log(f"  unit content printed to stderr for manual install:")
        print(unit, file=sys.stderr)

    # generate logrotate config
    logrotate_conf = f"""{store_abs}/.audit/*.chain {{
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}}

{store_abs}/.ledger/*.chain {{
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}}
"""
    logrotate_path = "/etc/logrotate.d/aud"
    try:
        with open(logrotate_path, "w") as f:
            f.write(logrotate_conf)
        log(f"  logrotate: {logrotate_path}")
    except OSError:
        log(f"  logrotate: could not write {logrotate_path}")

    return 0

def _user_exists(name: str) -> bool:
    try: pwd.getpwnam(name); return True
    except KeyError: return False

def _group_exists(name: str) -> bool:
    try: grp.getgrnam(name); return True
    except KeyError: return False

def check_privilege_separation(store: str) -> None:
    """Warn on startup if permissions are weak."""
    key_file = os.path.join(store, ".hmac_key")
    audit_dir = os.path.join(store, ".audit")
    warnings = []

    if os.path.exists(key_file):
        st = os.stat(key_file)
        if st.st_mode & 0o077:
            warnings.append(f".hmac_key is world/group-readable (mode={oct(st.st_mode)[-3:]})")
            warnings.append(f"  fix: chmod 600 {key_file}")

    if os.path.isdir(audit_dir):
        st = os.stat(audit_dir)
        if st.st_mode & 0o077:
            warnings.append(f".audit/ is world/group-accessible (mode={oct(st.st_mode)[-3:]})")
            warnings.append(f"  fix: chmod 700 {audit_dir}")

    if os.geteuid() == 0:
        warnings.append("running as root — consider: aud install + sudo -u aud")

    # check if current user == file owner (same-user = no separation)
    if os.path.exists(key_file):
        key_owner = os.stat(key_file).st_uid
        if key_owner == os.geteuid() and os.geteuid() != 0:
            data_parent = os.path.dirname(store)
            warnings.append(f"daemon and data owned by same user (uid={key_owner}) — no privilege separation")
            warnings.append(f"  fix: aud install {os.path.dirname(store)}")

    for w in warnings:
        log(f"SECURITY: {w}")

# ═══════════════════════════════════════════
# STATUS
# ═══════════════════════════════════════════

def cmd_status(store: str) -> int:
    pid_file = os.path.join(store, ".pid")
    status_file = os.path.join(store, ".status")

    running = False
    pid = None
    if os.path.exists(pid_file):
        try:
            pid = int(open(pid_file).read().strip())
            os.kill(pid, 0)
            running = True
        except (ProcessLookupError, ValueError, OSError):
            pass

    if running:
        print(f"● aud is running (pid={pid})")
    else:
        print(f"○ aud is not running")

    if os.path.exists(status_file):
        try:
            st = json.load(open(status_file))
            print(f"  started:     {st.get('started', '?')}")
            print(f"  last update: {st.get('last_update', '?')}")
            print(f"  writes:      {st.get('writes', '?')}")
            print(f"  deletes:     {st.get('deletes', '?')}")
            print(f"  watches:     {st.get('watches', '?')}")
        except (json.JSONDecodeError, OSError):
            pass

    audit_dir = os.path.join(store, ".audit")
    if os.path.isdir(audit_dir):
        chains = [f for f in os.listdir(audit_dir) if f.endswith(".chain")]
        total_events = 0
        total_bytes = 0
        for c in chains:
            p = os.path.join(audit_dir, c)
            total_bytes += os.path.getsize(p)
            with open(p) as f:
                total_events += sum(1 for _ in f)
        print(f"  chains:      {len(chains)}")
        print(f"  events:      {total_events}")
        print(f"  chain size:  {_human_bytes(total_bytes)}")

    try:
        sv = os.statvfs(store)
        used_pct = (1 - sv.f_bavail / sv.f_blocks) * 100
        free = sv.f_bavail * sv.f_frsize
        print(f"  disk:        {used_pct:.0f}% used ({_human_bytes(free)} free)")
    except OSError:
        pass

    return 0 if running else 1

def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="aud",
        description="Transparent audit daemon. inotify IS the engine.",
    )
    sub = parser.add_subparsers(dest="command")

    w = sub.add_parser("watch", help="watch and audit (default)")
    w.add_argument("store", nargs="?",
                   default=os.environ.get("AUDITED_STORE", os.path.expanduser("~/.localstore/data")))

    v = sub.add_parser("verify", help="verify HMAC chains")
    v.add_argument("store", nargs="?",
                   default=os.environ.get("AUDITED_STORE", os.path.expanduser("~/.localstore/data")))
    v.add_argument("key", nargs="?", default=None, help="specific key to verify")

    i = sub.add_parser("install", help="set up privilege separation (run as root)")
    i.add_argument("store", nargs="?",
                   default=os.environ.get("AUDITED_STORE", os.path.expanduser("~/.localstore/data")))

    a = sub.add_parser("watch-audit", help="real-time chain monitor (run as auditor)")
    a.add_argument("store", nargs="?",
                   default=os.environ.get("AUDITED_STORE", os.path.expanduser("~/.localstore/data")))

    s = sub.add_parser("status", help="show daemon status")
    s.add_argument("store", nargs="?",
                   default=os.environ.get("AUDITED_STORE", os.path.expanduser("~/.localstore/data")))

    args = parser.parse_args()

    if args.command == "install":
        return cmd_install(args.store)
    elif args.command == "verify":
        return cmd_verify(args.store, args.key)
    elif args.command == "watch-audit":
        return cmd_watch_audit(args.store)
    elif args.command == "status":
        return cmd_status(args.store)
    else:
        store = getattr(args, "store",
                        os.environ.get("AUDITED_STORE", os.path.expanduser("~/.localstore/data")))
        return cmd_watch(store)

if __name__ == "__main__":
    sys.exit(main())
