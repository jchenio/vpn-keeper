# Changelog

## Unreleased

- Preserve OpenConnect leader identity until process-group cleanup finishes, including natural leader exit and TERM-resistant descendants.
- Cancel health commands on stop, skip subsequent health queries, and leave 30 seconds for systemd stop handling.
- Add offline process-lifecycle, cancellation, and timeout regressions.
- Add package README/classifiers and CI sdist/wheel build plus isolated installed-CLI smoke checks.
- Document contribution steps, private security reporting prerequisites, and process cleanup limits.
- Apply the user-selected MIT license with copyright attribution “2026 xchen-zhao”; pre-release ownership/provenance review remains required.
- Rename the project to VPN Keeper, with `vpn-keeper` CLI/service, `vpn_keeper` Python package, and `vpnk0` default interface.

## 0.1.0 prototype

- Initial single-password OpenConnect supervisor, strict configuration, private credentials, health checks, bounded reconnects, and offline synthetic tests.
