"""CLI: run in foreground, let systemd manage service lifecycle."""
import argparse
import fcntl
import getpass
import json
import os
from pathlib import Path
import signal
import sys
import threading

from .config import load, private_read
from .runtime import State, Supervisor, dependencies, health


def status(directory):
    path = Path(directory)
    if not path.exists():
        return {"state": "stopped", "running": False}
    info = path.lstat()
    if path.is_symlink() or not path.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("unsafe state directory")
    try:
        fd = os.open(path / "lock", os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {"state": "stopped", "running": False}
    with os.fdopen(fd) as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            try:
                data = json.loads(private_read(str(path / "status.json")))
            except FileNotFoundError:
                data = {"state": "starting"}
            return dict(data, running=True)
        return {"state": "stopped", "running": False}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="vpn-keeper", description="VPN Keeper: single-password Linux OpenConnect supervisor")
    parser.add_argument("--config", default="/etc/vpn-keeper/config.toml")
    parser.add_argument("--state-dir", default="/run/vpn-keeper")
    parser.add_argument("action", choices=["validate", "doctor", "connect", "run", "health", "status"])
    args = parser.parse_args(argv)
    try:
        if args.action == "status":
            data = status(args.state_dir)
            print(json.dumps(data))
            return 0 if data["running"] else 1
        cfg = load(args.config)
        if args.action == "validate":
            print("Configuration valid (no credentials read, no network access).")
            return 0
        bins = dependencies(cfg)
        if args.action == "doctor":
            print("Configuration and executable dependencies found. VPN connectivity not tested.")
            return 0
        if args.action == "health":
            ok = health(cfg, bins)
            print("healthy" if ok else "unhealthy")
            return 0 if ok else 1
        if os.geteuid() != 0:
            raise ValueError("connect/run require root for tunnel and route setup")
        if Path("/sys/class/net", cfg.interface).exists():
            raise ValueError("configured interface already exists; choose an unused interface")
        if args.action == "run" and not cfg.password_file:
            raise ValueError("run requires password_file for unattended reauthentication")
        secret = None
        if not cfg.password_file:
            if not sys.stdin.isatty():
                raise ValueError("connect needs a terminal or password_file")
            secret = getpass.getpass("VPN password: ")
        stop = threading.Event()
        old = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
        state = State(args.state_dir)
        state.acquire()
        try:
            for sig in old:
                signal.signal(sig, lambda *_: stop.set())
            return Supervisor(cfg, bins, state, stop, once=args.action == "connect", password=secret).run()
        except Exception:
            state.write("failed")
            raise
        finally:
            state.close()
            for sig, handler in old.items():
                signal.signal(sig, handler)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        # Never render subprocess output or file contents, which may contain secrets.
        print("Error: " + (str(exc) if isinstance(exc, ValueError) else type(exc).__name__), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
