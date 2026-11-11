# Contributing

This is an unreleased Linux/Python 3.11+ prototype. This implementation uses the MIT license in LICENSE. Rights/provenance review remains a pre-release requirement; see LICENSE-REVIEW.md. Do not submit third-party code without confirming its provenance and compatible permissions. No contributor license agreement is currently defined.

Use synthetic credentials and reserved example addresses in fixtures. Keep changes focused and include regression tests. Do not commit secrets, real corporate configuration, authentication traces or local runtime files. Follow SECURITY.md for vulnerability reporting.

Run from the repository root:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
PYTHONPATH=src python3 -m vpn_keeper.cli --config examples/config.toml validate
python3 -m build
```

The build command requires the standard PyPA `build` package and setuptools. CI builds both sdist and wheel, installs the wheel into an isolated venv, and checks the CLI outside the source tree. Offline runtime tests need no VPN, root, real credentials, or network changes. Linux process-cleanup fixtures run in an isolated subreaper so orphan test processes are reaped.

For process lifecycle changes, preserve single-waiter ownership: do not poll, wait, or communicate with the OpenConnect child before group cleanup. Cover natural leader exit, TERM-triggered leader exit, and TERM-resistant descendants. Probe changes must preserve cancellation and bounded timeouts.

Real-server, privileged network, and systemd integration require a separately authorized isolated host. Record what actually ran and any unverified stages in TESTING.md. Do not describe offline tests as end-to-end VPN verification.
