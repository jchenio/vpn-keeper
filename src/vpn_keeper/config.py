"""Strict, non-executable TOML configuration and private credential loading."""
from dataclasses import dataclass, field
import ipaddress
import math
import os
from pathlib import Path
import re
import stat
import tomllib
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Config:
    server: str
    username: str
    group: str = ""
    interface: str = "vpnk0"
    password_file: str = ""
    vpnc_script: str = "/usr/share/vpnc-scripts/vpnc-script"
    routes: list[str] = field(default_factory=list)
    health_target: str = ""
    interval: float = 15
    startup_timeout: float = 60
    failure_threshold: int = 3
    retry_initial: float = 5
    retry_max: float = 120
    max_failures: int = 5
    stable_after: float = 300


def private_read(path: str, *, secret: bool = False) -> str:
    """Open once without following symlinks; validate the descriptor, not the path."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r", encoding="utf-8", newline="") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError("file must be a regular file owned by the current user")
        forbidden = 0o077 if secret else 0o022
        if info.st_mode & forbidden:
            raise ValueError("unsafe file permissions (use 0600 for credentials; no group/other write for config)")
        data = stream.read(65537)
        if len(data) > 65536:
            raise ValueError("file too large")
        return data


def load(path: str) -> Config:
    raw = tomllib.loads(private_read(path))
    if set(raw) - {"vpn"} or not isinstance(raw.get("vpn"), dict):
        raise ValueError("configuration must contain only a [vpn] table")
    values = raw["vpn"]
    if set(values) - set(Config.__dataclass_fields__):
        raise ValueError("unknown configuration key")
    try:
        cfg = Config(**values)
    except TypeError as exc:
        raise ValueError("server and username are required") from exc
    for key in ("server", "username", "group", "interface", "password_file", "vpnc_script", "health_target"):
        value = getattr(cfg, key)
        if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError(f"invalid {key}")
    url = urlsplit(cfg.server)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("server must be an https URL without userinfo, query or fragment")
    try:
        url.port
    except ValueError as exc:
        raise ValueError("invalid server port") from exc
    if not cfg.username or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,14}", cfg.interface):
        raise ValueError("username required and interface must be a safe Linux interface name")
    for key in ("vpnc_script", "password_file"):
        value = getattr(cfg, key)
        if value and not Path(value).is_absolute():
            raise ValueError(f"{key} must be absolute")
    if not cfg.vpnc_script:
        raise ValueError("vpnc_script is required")
    if not isinstance(cfg.routes, list) or not all(isinstance(x, str) for x in cfg.routes):
        raise ValueError("routes must be a list of CIDRs")
    for route in cfg.routes:
        ipaddress.ip_network(route, strict=True)
    if cfg.health_target:
        ipaddress.ip_address(cfg.health_target)
    for key in ("interval", "startup_timeout", "retry_initial", "retry_max", "stable_after"):
        value = getattr(cfg, key)
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"{key} must be finite and positive")
    for key in ("failure_threshold", "max_failures"):
        if type(getattr(cfg, key)) is not int or getattr(cfg, key) < 1:
            raise ValueError(f"{key} must be a positive integer")
    if cfg.retry_max < cfg.retry_initial:
        raise ValueError("retry_max must be >= retry_initial")
    return cfg


def read_password(path: str) -> str:
    value = private_read(path, secret=True).removesuffix("\n")
    if not value or "\n" in value or "\r" in value or "\x00" in value or len(value.encode()) > 4096:
        raise ValueError("password must be one nonempty line, at most 4096 bytes")
    return value
