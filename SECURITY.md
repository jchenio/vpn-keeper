# Security

Only use on VPNs you are authorized to access. No MFA bypass is supported. Config, code, executable dependencies and their parent directories must be administrator-controlled when running as root. vpnc-script and vpn-slice run with network privileges; replacing them is equivalent to executing privileged code.

Passwords pass through a pipe to OpenConnect, never argv, inherited environment, a cookie file, status JSON or project logs. They necessarily exist in process memory and the private credential file; Python cannot guarantee memory erasure. Root and privileged debuggers can inspect them.

All subprocess output is discarded. A private state directory contains non-secret status and a lock. Runtime paths must be on trusted local filesystems; hostile ancestors, shared/network filesystems and malicious root users are outside the threat model. Do not use the same interface for another VPN. TLS verification uses the system trust store.

Not a kill switch, anonymity tool or guarantee against DNS/IPv6 leakage. A SIGKILL/power failure can interrupt routing cleanup. Stop through systemd or SIGINT/SIGTERM and test routing recovery in staging. Do not publish passwords, cookies, tokens or unredacted diagnostic traces in issues.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting channel in the repository's [Security advisories](https://github.com/xchen-zhao/vpn-keeper/security/advisories) page. Private vulnerability reporting is enabled. Do not open a public issue containing exploit details or confidential material. No response-time commitment is made.

A private report should include the affected version, operating system and Python version, impact, and minimal reproduction using synthetic credentials and redacted configuration. Never include real passwords, cookies, tokens, private server names, account details or raw authentication traces. Coordinate disclosure with the maintainer; no fix or support SLA is currently promised for this prototype.

## Process cleanup limits

The supervisor keeps its direct OpenConnect child unreaped until TERM, the 10-second grace period, and final group KILL have completed. This reserves the leader PID and avoids signalling a recycled PGID even when the leader exits before its scripts. No other thread or signal handler may reap that child. Already-reaped children fail closed rather than signalling an unverified group.

Cleanup covers descendants remaining in that process group. A descendant that deliberately starts another session/process group is outside this mechanism; the systemd unit provides a cgroup-wide final cleanup boundary. Uninterruptible kernel waits can exceed application timeouts. Forced KILL can interrupt route/DNS restoration, which still requires real-host testing.
