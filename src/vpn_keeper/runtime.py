"""Foreground process ownership, bounded retries and interface-scoped health."""
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import stat
import subprocess
import threading
import time

from .config import read_password

# Do not pass inherited proxy settings, credentials or shell startup variables.
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}


def dependencies(cfg):
    result = {}
    for name in ["openconnect", "ip"] + (["ping"] if cfg.health_target else []) + (["vpn-slice"] if cfg.routes else []):
        path = shutil.which(name, path=SAFE_ENV["PATH"])
        if path is None:
            raise ValueError(f"missing dependency: {name}")
        result[name] = path
    if not cfg.routes and not (Path(cfg.vpnc_script).is_file() and os.access(cfg.vpnc_script, os.X_OK)):
        raise ValueError("vpnc_script must exist and be executable")
    return result


def command(cfg, bins):
    script = shlex.join([bins["vpn-slice"], *cfg.routes]) if cfg.routes else shlex.quote(cfg.vpnc_script)
    args = [bins["openconnect"], "--protocol=anyconnect", "--non-inter", "--passwd-on-stdin",
            "--user=" + cfg.username, "--interface=" + cfg.interface, "--script=" + script,
            "--reconnect-timeout=30"]
    if cfg.group:
        args.append("--authgroup=" + cfg.group)
    return args + [cfg.server]


def probe(args, stop, *, timeout=5):
    """Bound each direct health command and interrupt it on service stop."""
    if stop.is_set():
        raise subprocess.TimeoutExpired(args, timeout)
    proc = subprocess.Popen(args, env=SAFE_ENV, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + timeout
    try:
        while not stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                output, _ = proc.communicate(timeout=min(0.1, remaining))
                if proc.returncode:
                    raise subprocess.CalledProcessError(proc.returncode, args)
                return output
            except subprocess.TimeoutExpired:
                continue
        raise subprocess.TimeoutExpired(args, timeout)
    finally:
        # Popen owns this direct child; kill() checks its state before signalling.
        if proc.returncode is None:
            proc.kill()
        proc.communicate()


def health(cfg, bins, stop=None):
    stop = stop if stop is not None else threading.Event()
    try:
        def query(args):
            if stop.is_set():
                raise subprocess.TimeoutExpired(args, 5)
            return json.loads(probe([bins["ip"], "-j", *args], stop))
        links = query(["address", "show", "dev", cfg.interface])
        if not any("UP" in item.get("flags", []) and any(a.get("family") in ("inet", "inet6") and a.get("scope") == "global" for a in item.get("addr_info", [])) for item in links):
            return False
        for family in (4, 6):
            wanted = {ipaddress.ip_network(r) for r in cfg.routes if ipaddress.ip_network(r).version == family}
            if wanted:
                rows = query([f"-{family}", "route", "show", "dev", cfg.interface])
                found = {ipaddress.ip_network(r["dst"]) for r in rows if r.get("dst") not in (None, "default")}
                if ("default" in [r.get("dst") for r in rows]):
                    found.add(ipaddress.ip_network("0.0.0.0/0" if family == 4 else "::/0"))
                if not wanted <= found:
                    return False
        if cfg.health_target:
            probe([bins["ping"], "-n", "-I", cfg.interface, "-c", "1", "-W", "3", cfg.health_target], stop)
        return not stop.is_set()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return False


class State:
    """Lock ownership is authoritative; a stale JSON status is never treated as live."""
    def __init__(self, directory):
        self.directory = Path(directory)
        self.lock = None

    def acquire(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("state directory must be owner-only (0700), owned by current user, not a symlink")
        fd = os.open(self.directory / "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self.lock = os.fdopen(fd, "r+")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self.lock.close()
            raise ValueError("another supervisor already owns this state directory") from exc

    def write(self, state, attempt=0):
        temporary = self.directory / "status.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"state": state, "pid": os.getpid(), "attempt": attempt, "updated": time.time()}, stream)
        os.replace(temporary, self.directory / "status.json")

    def close(self):
        if self.lock:
            self.lock.close()


def child_exited(proc):
    """Observe without reaping: reserve the leader PID until group cleanup ends.

    This child must have exactly one waiter (this supervisor). Never call poll(),
    wait() or communicate() before terminate(), even after a natural exit.
    """
    if proc.returncode is not None:
        raise RuntimeError("owned process was reaped before group cleanup")
    return os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def terminate(proc, *, grace=10):
    # Validate ownership first, without reaping. An unreaped child reserves its
    # PID/PGID, so neither signal can target a recycled process group.
    child_exited(proc)
    try:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        # The leader may exit before a script does. Keep it unreaped for the
        # whole grace period, then kill remaining group members before wait().
        time.sleep(grace)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    finally:
        proc.wait()


class Supervisor:
    def __init__(self, cfg, bins, state, stop, *, once=False, password=None):
        self.cfg, self.bins, self.state, self.stop = cfg, bins, state, stop
        self.once, self.password = once, password

    def session(self):
        secret = read_password(self.cfg.password_file) if self.cfg.password_file else self.password
        if not secret or "\n" in secret or "\r" in secret or "\x00" in secret or len(secret.encode()) > 4096:
            raise ValueError("a valid password file or interactive password is required")
        proc = subprocess.Popen(command(self.cfg, self.bins), stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env=SAFE_ENV, start_new_session=True)
        start, ready, failures = time.monotonic(), False, 0
        healthy_since = None
        stable = False
        try:
            try:
                proc.stdin.write((secret + "\n").encode())
                proc.stdin.close()
            except BrokenPipeError:
                pass
            del secret
            while not self.stop.is_set():
                if child_exited(proc):
                    return stable
                healthy = health(self.cfg, self.bins, self.stop)
                if self.stop.is_set():
                    return stable
                now = time.monotonic()
                if healthy:
                    ready, failures = True, 0
                    if healthy_since is None:
                        healthy_since = now
                    stable = stable or now - healthy_since >= self.cfg.stable_after
                    self.state.write("connected")
                elif not ready:
                    if now - start >= self.cfg.startup_timeout:
                        return stable
                else:
                    healthy_since = None
                    failures += 1
                    self.state.write("degraded")
                    if failures >= self.cfg.failure_threshold:
                        return stable
                self.stop.wait(self.cfg.interval)
            return stable
        finally:
            terminate(proc)

    def run(self):
        failures = 0
        while not self.stop.is_set():
            self.state.write("connecting", failures + 1)
            stable = self.session()
            if self.stop.is_set():
                break
            if self.once:
                return 1
            failures = 1 if stable else failures + 1
            if failures >= self.cfg.max_failures:
                self.state.write("failed", failures)
                return 1
            delay = min(self.cfg.retry_max, self.cfg.retry_initial * 2 ** min(failures - 1, 30))
            self.state.write("backoff", failures)
            self.stop.wait(delay)
        self.state.write("stopped")
        return 0
