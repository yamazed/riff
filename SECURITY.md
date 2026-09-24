# Security policy

riff is an interception proxy. It decrypts HTTPS, installs a certificate authority
into your trust store, and — if you ask it to — sends attack payloads at hosts you
name. Those are its features, not its bugs. This document is about the bugs.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting instead:
[**Report a vulnerability**](https://github.com/yamazed/riff/security/advisories/new).
It is private between you and the maintainer until an advisory is published.

riff is maintained by one person in their own time, so please be realistic about
response times. I will acknowledge a report when I see it and tell you honestly
whether and when I expect to fix it.

## What I am most interested in

In rough order of how much they would worry me:

1. **Anything that exposes the CA private key**, or lets a leaf certificate be
   minted for a host the operator did not authorise. The key lives at
   `%USERPROFILE%\.riff\riff-ca.key`, owner-ACLed, and the root is marked
   `pathlen:0` so it cannot sign a sub-CA. Holes in any of that matter most.
   A CA created with `riff ca regenerate --constrain-to ...` additionally
   carries a critical RFC 5280 `NameConstraints` extension; **a way to get a
   validator to accept a leaf outside those subtrees is the single most
   valuable thing you could report.**
2. **Anything that lets the active scanner send a probe to a host outside the
   configured scope.** Scope is re-checked before every probe opens a socket;
   a bypass is a serious bug, because it means riff attacked something it was
   not pointed at.
3. **Anything that reaches the local web UI from a web page.** It is loopback-only
   with a per-run token, a double-submit header on mutating calls, Host-header
   validation against DNS rebinding, and a strict CSP. A way around any of those
   gives a hostile page access to every byte riff has captured.
4. **Anything that escapes the rule language** into arbitrary code or file access.
   It is a deliberately small interpreter with no shell, no `import`, and no
   filesystem primitives beyond `save`.
5. **Remote code execution, or a crash that is exploitable**, anywhere in the
   HTTP/1.x parsing or TLS handling.

## What is out of scope

- **That riff can decrypt HTTPS.** That is the entire purpose. It requires a CA
  you chose to trust, which `riff ca uninstall` removes.
- **That a trusted riff CA could be abused by malware already running as you.**
  True, and documented. An attacker at that privilege level has already won;
  they can read the key, your cookies and your session tokens regardless.
- **That the active scanner sends attack traffic.** It does, on purpose, only to
  hosts you put in scope.
- **That `demo/app.py` is full of holes.** Deliberate — it is the scanner's
  target practice. It binds `127.0.0.1` and refuses anything else without
  `--unsafe-host`.
- **That `--insecure` disables upstream certificate verification.** That is what
  the flag is for, and riff prints a warning when you use it.

## Supported versions

The latest release only. riff is pre-1.0 and there are no maintenance branches.
