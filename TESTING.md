# Verification and development testing

## Offline checks (2026-11-11 UTC)

VPN Keeper is tested with synthetic credentials, mock network responses and local subprocesses. On Python 3.12.14, all 34 offline tests passed following the rename and lifecycle fixes. The checks cover:

- Configuration types, unsafe URLs, permissions, symlink/FIFO rejection and password newline handling.
- Argument isolation, exact IPv4/IPv6 routes and interface-bound health probe arguments.
- Startup timeout, failure thresholds, bounded backoff, retry reset and single-session behavior.
- Duplicate locks, stale state, natural process exit and TERM-resistant descendants.
- Ownership checks before group signals, cancelled/timed-out probes and skipped queries after stop.
- A synthetic local child receiving a test password only through stdin.

Commands from the project root:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
PYTHONPATH=src python3 -m vpn_keeper.cli --config examples/config.toml validate
python3 -m build
```

The local package verification uses the installed setuptools PEP 517 backend to build an sdist and wheel offline. The wheel is installed in a fresh temporary venv with `--no-index --no-deps`; CLI help and example validation are checked outside the source tree. MIT license text and metadata are checked in the distributions.

CI is configured for Python 3.11–3.13 and includes build/install smoke checks. Local verification uses Python 3.12; remote CI results should be checked for the exact published commit.

## Deployment checklist

Use an authorized staging account and Linux host. Verify the server accepts one password, system CA trust, correct auth group, route inclusion/exclusion, DNS and IPv6 behavior, interface-bound health, network loss and reconnect, bad-password retry limits, SIGTERM/systemd stop, stale interface recovery, sleep/wake and route/DNS restoration. Do not test repeated failures against an account with an unknown lockout policy.

Real-server, privileged network and systemd integration require a separately authorized isolated host with compatible OpenConnect packages, a TUN device and network-administration capabilities. Confirm supported versions and host behavior before making production compatibility claims. Offline tests verify isolated behavior, not end-to-end VPN compatibility.
