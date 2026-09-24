"""Command line entry point."""

from __future__ import annotations

import argparse
import os
import re
import subprocess  # nosec B404 - only certutil/explorer with fixed arguments, never a shell
import sys
import threading
import webbrowser

from . import __version__
from .access import AccessError, AccessPolicy
from .ca import CaError, CertAuthority, default_home, expires_at, system_tool
from .console import ConsoleObserver, MultiObserver, enable_ansi, human_size
from .hub import Hub
from .listen import AddressInUse
from .proxy import Options, Proxy
from .script import Engine
from .script.errors import RiffSyntaxError
from .webui import UiOptions, UiServer
from . import winproxy
from .workspace import Workspace

SIZE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?\s*$", re.I)
UNITS = {"b": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3}


def parse_size(text: str) -> int:
    match = SIZE.match(text)
    if not match:
        raise argparse.ArgumentTypeError(f"{text!r} is not a size like 512kb or 8mb")
    return int(float(match.group(1)) * UNITS[(match.group(2) or "b").lower()])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="riff",
        description="A scriptable HTTP(S) interception proxy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  riff run -s rules.riff\n"
            "  riff run -p 8080 --no-ui --dump\n"
            "  riff check rules.riff\n"
            "  riff ca install\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"riff {__version__}")
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="start the proxy (default)")
    run.add_argument("-p", "--port", type=int, default=8888, help="proxy port (default 8888)")
    run.add_argument(
        "--host",
        default="127.0.0.1",
        help="proxy bind address (default 127.0.0.1; anything else exposes an open relay)",
    )
    run.add_argument("-s", "--script", default="", help="path to a .riff rule script")
    run.add_argument("--no-ui", action="store_true", help="do not start the web UI")
    run.add_argument("--ui-port", type=int, default=8899, help="web UI port (default 8899)")
    run.add_argument(
        "--workspace",
        default="",
        help="folder for saved requests and environments (default: next to the rules file)",
    )
    run.add_argument("--ui-host", default="127.0.0.1", help="web UI bind address (default 127.0.0.1)")
    run.add_argument("--open", action="store_true", help="open the UI in a browser on start")
    run.add_argument("--dump", action="store_true", help="print full headers and bodies to the console")
    run.add_argument("--quiet", action="store_true", help="no per-flow console output")
    run.add_argument("--no-scan", action="store_true", help="turn off the passive security scanner")
    run.add_argument("--jsonl", default="", help="append every flow to this JSONL file (plaintext!)")
    run.add_argument(
        "--no-proxy-watch",
        action="store_true",
        help="do not re-apply the Windows proxy when another program (e.g. Zscaler) switches it off",
    )
    run.add_argument("--max-body", type=parse_size, default="8mb", help="buffer limit per body (default 8mb)")
    run.add_argument("--upstream-proxy", default="", help="send outbound traffic via this proxy")
    run.add_argument(
        "--insecure",
        action="store_true",
        help="do not verify upstream TLS certificates (you become the only check that is left)",
    )
    run.add_argument("--ca-home", default="", help=f"where the CA lives (default {default_home()})")
    run.add_argument("--ca-cert", default="", help="use this CA certificate (PEM) instead of generating one")
    run.add_argument("--ca-key", default="", help="unencrypted PEM private key matching --ca-cert")
    run.add_argument(
        "--auth",
        default="",
        help="require proxy credentials, as user:password (strongly advised when --host is not loopback)",
    )
    run.add_argument(
        "--allow-from",
        default="",
        help="only accept clients in these addresses/CIDR blocks, comma separated",
    )
    run.add_argument("--no-colour", action="store_true", help="disable ANSI colour")

    check = sub.add_parser("check", help="parse a script and report problems")
    check.add_argument("script")

    scan = sub.add_parser("scan", help="run the active vulnerability scanner over captured flows")
    scan.add_argument("source", help="a riff export or HAR file of the traffic to scan")
    scan.add_argument(
        "--host", action="append", default=[], metavar="HOST",
        help="in-scope host(s) you are authorised to test; repeat or comma-separate. Globs allowed (*.example.com). Required.",
    )
    scan.add_argument("--checks", default="", help="comma-separated check names to run (default: the fast, high-confidence set)")
    scan.add_argument("--time-based", action="store_true", help="also run the slow time-based SQLi check")
    scan.add_argument("--time-delay", type=float, default=3.0, help="target delay in seconds for the time-based check")
    scan.add_argument("--oob", action="store_true",
                      help="enable out-of-band checks with a local collaborator (blind SSRF/injection). Loopback by default")
    scan.add_argument("--collaborator-host", default="",
                      help="address a remote target can reach the collaborator on (implies --oob); e.g. 10.0.0.5 or host:port")
    scan.add_argument("--delay-ms", type=int, default=0, help="pause between probes, per worker (rate limit)")
    scan.add_argument("--max-points", type=int, default=40, help="most insertion points to probe per flow (default 40)")
    scan.add_argument("--workers", type=int, default=6, help="concurrent probe workers (default 6)")
    scan.add_argument("--out", default="", help="write the report here (.md or .json by extension)")
    scan.add_argument("--insecure", action="store_true", help="do not verify upstream TLS certificates")
    scan.add_argument("--upstream-proxy", default="", help="send probes via this proxy")
    scan.add_argument("--ca-home", default="", help=f"where the CA lives (default {default_home()})")

    ca = sub.add_parser("ca", help="manage the root certificate authority")
    ca.add_argument(
        "action",
        choices=["path", "show", "install", "uninstall", "regenerate"],
        help="path/show print details; install/uninstall touch your USER trust store",
    )
    ca.add_argument("--ca-home", default="", help="where the CA lives")
    ca.add_argument("--ca-cert", default="", help="inspect this CA certificate instead")
    ca.add_argument("--ca-key", default="", help="private key matching --ca-cert")
    ca.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    setup = sub.add_parser(
        "setup", help="one-time per-user bootstrap: make a CA, trust it, point Windows at riff"
    )
    setup.add_argument("-p", "--port", type=int, default=8888, help="proxy port riff will use")
    setup.add_argument("--host", default="127.0.0.1", help="proxy host clients should use")
    setup.add_argument("--ca-home", default="", help="where the CA lives")
    setup.add_argument("--no-proxy", action="store_true", help="do not offer to change the Windows proxy")
    setup.add_argument("--yes", action="store_true", help="skip the confirmation prompts")

    ui_cmd = sub.add_parser("ui", help="print (or open) the web UI address of a running riff")
    ui_cmd.add_argument("--open", action="store_true", help="open it in your browser")
    ui_cmd.add_argument("--ca-home", default="", help="where riff keeps its state")

    winproxy_cmd = sub.add_parser("proxy", help="point the Windows proxy at riff, or put it back")
    winproxy_cmd.add_argument("action", choices=["on", "off", "status"])
    winproxy_cmd.add_argument("-p", "--port", type=int, default=8888)
    winproxy_cmd.add_argument("--host", default="127.0.0.1")
    winproxy_cmd.add_argument("--ca-home", default="", help="where riff keeps its state")
    winproxy_cmd.add_argument(
        "--bypass",
        default=winproxy.DEFAULT_BYPASS,
        help=f"addresses that skip the proxy (default {winproxy.DEFAULT_BYPASS!r})",
    )

    return parser


# ---------------------------------------------------------------- commands


def cmd_check(args) -> int:
    try:
        with open(args.script, "r", encoding="utf-8") as fh:
            source = fh.read()
    except OSError as exc:
        print(f"riff: cannot read {args.script}: {exc}", file=sys.stderr)
        return 2
    try:
        engine = Engine.from_source(source, args.script)
    except RiffSyntaxError as exc:
        print(exc.render(), file=sys.stderr)
        return 1
    print(f"{args.script}: OK — {engine.rule_count} rule(s)")
    print()
    print(f"  TLS scope ({len(engine.tls_rules)} directive(s)):")
    for mode, pattern in engine.tls_rules:
        print(f"    {mode:<8} {pattern}")
    if not engine.tls_rules:
        print("    (none — every CONNECT will be decrypted)")
    else:
        print("    everything else is tunnelled opaquely")

    print()
    print(f"  Capture scope ({len(engine.capture_rules)} directive(s)):")
    for mode, pattern in engine.capture_rules:
        print(f"    {mode:<8} {pattern}")
    if not engine.capture_rules:
        print("    (none — every flow is recorded)")
    elif any(mode == "capture" for mode, _ in engine.capture_rules):
        print("    everything else is proxied but not recorded")
    return 0


def _split_hosts(values: list[str]) -> tuple[str, ...]:
    out: list[str] = []
    for value in values:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return tuple(out)


def cmd_scan(args) -> int:
    import json as _json
    import time as _time

    from .scan import ScanConfig, Scanner, ScopeError, host_in_scope
    from .scan.engine import targets_from_flows
    from .scan import report as _report
    from .transfer import TransferError, import_flows

    hosts = _split_hosts(args.host)
    if not hosts:
        print("riff scan: name at least one in-scope host with --host. Scan only what you are authorised to test.",
              file=sys.stderr)
        return 2

    try:
        with open(args.source, "r", encoding="utf-8") as fh:
            payload = _json.load(fh)
    except OSError as exc:
        print(f"riff scan: cannot read {args.source}: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"riff scan: {args.source} is not valid JSON: {exc}", file=sys.stderr)
        return 2
    try:
        flows = import_flows(payload)
    except TransferError as exc:
        print(f"riff scan: {exc}", file=sys.stderr)
        return 2
    for i, flow in enumerate(flows, 1):  # imported flows arrive unnumbered
        flow.id = i

    targets = targets_from_flows(flows)
    in_scope = [t for t in targets if host_in_scope(t.request.host, hosts)]
    if not in_scope:
        print(f"riff scan: none of the {len(targets)} flow(s) are in scope for {', '.join(hosts)}.", file=sys.stderr)
        return 1

    check_names = None
    if args.checks:
        check_names = tuple(c.strip() for c in args.checks.split(",") if c.strip())
    elif args.time_based:
        from .scan import DEFAULT_CHECK_NAMES
        check_names = DEFAULT_CHECK_NAMES + ("sqli-time",)

    ca = CertAuthority(args.ca_home or None)
    options = Options(verify_upstream=not args.insecure, upstream_proxy=args.upstream_proxy)
    hub = Hub(scan=False)  # we drive the active scanner ourselves; no passive pass here
    proxy = Proxy(options, engine=Engine.empty(), ca=ca, observer=hub)
    scanner = Scanner(proxy, hub)

    collaborator = None
    if args.oob or args.collaborator_host:
        from .scan import Collaborator
        advertise = args.collaborator_host or ""
        host, _, port = advertise.partition(":")
        collaborator = Collaborator(host="0.0.0.0" if advertise else "127.0.0.1",
                                    port=int(port) if port else 0,
                                    advertise_host=host or "127.0.0.1").start()
        print(f"Collaborator listening; targets call back to {collaborator.base_url}", file=sys.stderr)

    config = ScanConfig(
        allowed_hosts=hosts, check_names=check_names,
        max_points_per_flow=args.max_points, max_workers=args.workers,
        delay_ms=args.delay_ms, time_delay_s=args.time_delay, collaborator=collaborator,
    )
    print(f"Scanning {len(in_scope)} in-scope flow(s) across {', '.join(hosts)} "
          f"with {len(config.checks)} check(s)…", file=sys.stderr)
    try:
        job = scanner.start(in_scope, config)
    except ScopeError as exc:
        if collaborator:
            collaborator.stop()
        print(f"riff scan: {exc}", file=sys.stderr)
        return 2
    while job.status == "running":
        _time.sleep(0.2)
    if collaborator:
        collaborator.stop()

    rows = hub.finding_rows()
    counts = hub.finding_counts()
    meta = {"hosts": list(hosts), "source": args.source, "probes": job.probes_sent, "flows": len(in_scope)}

    if args.out:
        text = _report.to_json(rows, meta) if args.out.lower().endswith(".json") else _report.to_markdown(rows, meta)
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            print(f"riff scan: cannot write {args.out}: {exc}", file=sys.stderr)
            return 2
        print(f"Report written to {args.out}", file=sys.stderr)

    print(f"\n{counts['total']} finding(s): {counts['high']} high, {counts['medium']} medium, "
          f"{counts['low']} low, {counts['info']} info  ({job.probes_sent} probes sent)")
    for r in rows:
        print(f"  [{r['severity']:6}] {r['check']:16} #{r['flow_id']:<4} {r.get('title', '')}")
    return 1 if counts["high"] or counts["medium"] else 0


def cmd_ca(args) -> int:
    ca = CertAuthority(args.ca_home or None, cert_path=args.ca_cert, key_path=args.ca_key)

    if args.action == "path":
        print(ca.ca_cert_path)
        return 0

    if args.action == "show":
        cert, _ = ca.load_or_create()
        print(f"certificate  {ca.ca_cert_path}")
        print(f"private key  {ca.ca_key_path}")
        print(f"fingerprint  SHA-256 {ca.fingerprint()}")
        print(f"expires      {expires_at(cert).date().isoformat()}")
        print(f"leaf cache   {ca.certs_dir}")
        return 0

    if args.action == "regenerate":
        if not args.yes and not _confirm("Delete the existing CA and create a new one?"):
            return 1
        for path in (ca.ca_cert_path, ca.ca_key_path, ca.leaf_key_path):
            if os.path.exists(path):
                os.remove(path)
        if os.path.isdir(ca.certs_dir):
            for name in os.listdir(ca.certs_dir):
                os.remove(os.path.join(ca.certs_dir, name))
        ca.load_or_create()
        print(f"New CA written to {ca.ca_cert_path}")
        print("Any previously trusted riff CA is now stale — uninstall it from your trust store.")
        return 0

    if os.name != "nt":
        print(
            "riff: automatic trust-store changes are only wired up for Windows.\n"
            f"      Trust this file by hand: {ca.ca_cert_path}",
            file=sys.stderr,
        )
        return 2

    if args.action == "install":
        ca.load_or_create()
        print("This adds the riff root CA to your CURRENT USER trust store.")
        print(f"  certificate  {ca.ca_cert_path}")
        print(f"  fingerprint  SHA-256 {ca.fingerprint()}")
        print()
        print("Anything able to read the matching private key can then impersonate any")
        print("HTTPS site to your account. Remove it with `riff ca uninstall` when done.")
        if not args.yes and not _confirm("Install it now?"):
            return 1
        result = subprocess.run(  # nosec B603 - fixed arguments, absolute path
            [system_tool("certutil"), "-addstore", "-user", "Root", ca.ca_cert_path],
            capture_output=True,
            text=True,
        )
        sys.stdout.write(result.stdout)
        if result.returncode != 0:
            sys.stderr.write(result.stderr)
            return result.returncode
        print("Installed.")
        return 0

    # uninstall
    if not args.yes and not _confirm("Remove 'riff Root CA' from your user trust store?"):
        return 1
    result = subprocess.run(  # nosec B603 - fixed arguments, absolute path
        [system_tool("certutil"), "-delstore", "-user", "Root", "riff Root CA"], capture_output=True, text=True
    )
    sys.stdout.write(result.stdout)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return result.returncode
    print("Removed.")
    return 0


def cmd_ui(args) -> int:
    """Recover the UI address after the startup banner has scrolled away."""
    path = os.path.join(args.ca_home or default_home(), "ui-url.txt")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            url = fh.read().strip()
    except OSError:
        print(
            "riff: no running instance found.\n"
            "      Start one with `riff run`, which prints the UI address.",
            file=sys.stderr,
        )
        return 1
    if not url:
        print(f"riff: {path} is empty", file=sys.stderr)
        return 1

    # A hard kill (closing the console window) leaves the file behind, so check
    # something is actually listening rather than handing back a dead link.
    if not _is_listening(url):
        try:
            os.remove(path)
        except OSError:
            pass
        print(
            "riff: found a leftover address from an instance that is no longer running.\n"
            "      Start one with `riff run`.",
            file=sys.stderr,
        )
        return 1

    print(url)
    if args.open:
        webbrowser.open(url)
    return 0


def _is_listening(url: str, timeout: float = 1.0) -> bool:
    import socket
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    try:
        with socket.create_connection((parts.hostname or "127.0.0.1", parts.port or 80), timeout=timeout):
            return True
    except OSError:
        return False


def cmd_proxy(args) -> int:
    home = args.ca_home or default_home()
    try:
        if args.action == "status":
            print(winproxy.read_state().describe())
            return 0
        if args.action == "on":
            state = winproxy.turn_on(args.host, args.port, home, args.bypass)
            print(f"Windows proxy is now {state.describe()}")
            if winproxy.reverted_within(args.host, args.port):
                print(
                    "riff: ...and something switched it off again within two seconds.",
                    "      An endpoint agent (Zscaler Client Connector) is enforcing its own proxy settings;",
                    "      while it is on, no change to the Windows proxy will hold — riff's or your own.",
                    "      Use riff-browser.cmd instead: its browser window is told the proxy directly,",
                    "      which the agent cannot change.",
                    sep="\n",
                    file=sys.stderr,
                )
                return 3
            print("Undo with: riff proxy off")
            return 0
        state = winproxy.turn_off(home)
        print(f"Windows proxy restored to {state.describe()}")
        return 0
    except winproxy.ProxyError as exc:
        print(f"riff: {exc}", file=sys.stderr)
        return 2


def cmd_setup(args) -> int:
    """Everything a new user needs, in one command."""
    ca = CertAuthority(args.ca_home or None)
    home = args.ca_home or default_home()

    print("riff setup")
    print()
    try:
        ca.load_or_create()
    except CaError as exc:
        print(f"riff: {exc}", file=sys.stderr)
        return 2
    print(f"  1. Certificate authority (yours alone, on this machine)")
    print(f"     {ca.ca_cert_path}")
    print(f"     SHA-256 {ca.fingerprint()}")
    print()

    if os.name != "nt":
        print("  2. Trust it using your platform's certificate tooling, then point")
        print(f"     your client at http://{args.host}:{args.port}")
        return 0

    print("  2. Trusting this CA lets whoever can read the matching private key")
    print("     impersonate any HTTPS site to your Windows account. It goes into")
    print("     your USER store only, and `riff ca uninstall` removes it.")
    if args.yes or _confirm("     Trust it now?"):
        result = subprocess.run(  # nosec B603 - fixed arguments, absolute path
            [system_tool("certutil"), "-addstore", "-user", "Root", ca.ca_cert_path], capture_output=True, text=True
        )
        if result.returncode != 0:
            sys.stderr.write(result.stderr)
            print("     could not install the certificate", file=sys.stderr)
        else:
            print("     trusted.")
    else:
        print("     skipped — HTTPS bodies will not be readable until you do.")
    print()

    if args.no_proxy:
        print(f"  3. Point your client at http://{args.host}:{args.port} when you want to capture.")
        return 0

    current = winproxy.read_state()
    print(f"  3. Windows proxy is currently {current.describe()}")
    if args.yes or _confirm(f"     Point it at {args.host}:{args.port} now?"):
        try:
            state = winproxy.turn_on(args.host, args.port, home)
            print(f"     done — {state.describe()}")
            print("     put it back with: riff proxy off")
        except winproxy.ProxyError as exc:
            print(f"     could not change it: {exc}", file=sys.stderr)
    else:
        print("     skipped — turn it on later with: riff proxy on")
    print()
    print("Now start capturing:  riff run")
    return 0


def _confirm(question: str) -> bool:
    try:
        answer = input(f"{question} [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("y", "yes")


def cmd_run(args) -> int:
    colour = enable_ansi() and not args.no_colour

    try:
        if args.script:
            engine = Engine.from_file(args.script, on_log=lambda flow, text: None)
        else:
            engine = Engine.empty()
    except RiffSyntaxError as exc:
        print(exc.render(), file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"riff: cannot read {args.script}: {exc}", file=sys.stderr)
        return 2

    options = Options(
        listen_host=args.host,
        listen_port=args.port,
        max_body=args.max_body if isinstance(args.max_body, int) else parse_size(str(args.max_body)),
        verify_upstream=not args.insecure,
        upstream_proxy=args.upstream_proxy,
    )
    try:
        access = AccessPolicy.build(auth=args.auth, allow_from=args.allow_from)
    except AccessError as exc:
        print(f"riff: {exc}", file=sys.stderr)
        return 2

    ca = CertAuthority(args.ca_home or None, cert_path=args.ca_cert, key_path=args.ca_key)
    console = ConsoleObserver(colour=colour, dump=args.dump, quiet=args.quiet, jsonl_path=args.jsonl)
    hub = Hub(scan=not getattr(args, "no_scan", False))
    observer = MultiObserver(console, hub) if not args.no_ui else console

    proxy = Proxy(options, engine=engine, ca=ca, observer=observer, access=access)

    try:
        proxy.bind()
    except CaError as exc:
        print(f"riff: {exc}", file=sys.stderr)
        return 2
    except AddressInUse as exc:
        # Already says which port and what to do; do not wrap it in more prose.
        print(f"riff: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"riff: cannot listen on {args.host}:{args.port} — {exc}", file=sys.stderr)
        return 2

    ui: UiServer | None = None
    if not args.no_ui:
        workspace = Workspace(args.workspace, ca.home) if args.workspace else None
        ui = UiServer(UiOptions(host=args.ui_host, port=args.ui_port), proxy, hub, args.script, workspace)
        try:
            ui.start()
        except OSError as exc:
            print(f"riff: cannot start the web UI on {args.ui_host}:{args.ui_port} — {exc}", file=sys.stderr)
            ui = None

    _warn_about_exposure(args, console, access)
    watcher = _start_proxy_watcher(args, ca.home, observer)

    try:
        thread = threading.Thread(target=proxy.serve_forever, daemon=True, name="riff-accept")
        thread.start()
        if ui is not None:
            console.on_log(None, f"UI          {ui.url}")
            if args.open:
                webbrowser.open(ui.url)
        console.on_log(None, "Ctrl-C to stop")
        while thread.is_alive():
            thread.join(0.4)
    except KeyboardInterrupt:
        print()
    finally:
        if watcher is not None:
            watcher.stop()
        proxy.shutdown()
        if ui is not None:
            ui.stop()
        _print_summary(engine, hub, console)
        console.close()
    return 0


def _start_proxy_watcher(args, home: str, observer) -> "winproxy.ProxyWatcher | None":
    """Keep the Windows proxy pointed at riff while it runs.

    Zscaler and similar agents switch the per-user proxy off whenever they
    restart, which silently ends capture. Only acts while the user has asked
    riff to be the proxy (`riff proxy on`) and not yet asked for it back.
    """
    if os.name != "nt" or args.no_proxy_watch:
        return None
    target = f"{args.host}:{args.port}"

    def reapplied(previous) -> None:
        observer.on_error(
            f"the Windows proxy had been switched off by another program (Zscaler does this when it "
            f"restarts) — pointed it back at {target}. Reload the page."
        )

    def gave_up(previous) -> None:
        observer.on_error(
            "an endpoint agent (Zscaler) is actively enforcing its own proxy settings — it reverted riff's "
            "change five times in a row, so riff stopped trying. Use riff-browser.cmd: its browser window is "
            "told the proxy directly, which the agent cannot change. `riff proxy on` will try again."
        )

    watcher = winproxy.ProxyWatcher(args.host, args.port, home, on_reapplied=reapplied, on_gave_up=gave_up)
    watcher.start()
    return watcher


def _warn_about_exposure(args, console: ConsoleObserver, access) -> None:
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        if access.requires_auth or access.restricts_addresses:
            console.on_log(None, f"shared      {args.host}:{args.port} ({access.describe()})")
        else:
            console.on_error(
                f"proxy is bound to {args.host} with NO --auth and NO --allow-from. Anyone who can "
                f"reach this port can relay traffic through your machine and read what they send."
            )
    if not args.no_ui and args.ui_host not in ("127.0.0.1", "localhost", "::1"):
        console.on_error(f"web UI is bound to {args.ui_host} — it exposes every captured request body.")
    if args.insecure:
        console.on_error("--insecure: upstream certificates are NOT verified. Do not use this on real traffic.")
    if args.jsonl:
        console.on_error(f"recording every flow in plaintext to {args.jsonl} — tokens and cookies included.")


def _print_summary(engine: Engine, hub: Hub, console: ConsoleObserver) -> None:
    stats = hub.stats()
    lines = [f"{stats['flows']} flow(s), {human_size(stats['bytes'])} of bodies"]
    if stats["tunnels"]:
        lines.append(f"{stats['tunnels']} opaque tunnel(s), {human_size(stats['tunnel_bytes'])}")
    if engine.counters:
        lines.append("counters: " + ", ".join(f"{k}={v}" for k, v in sorted(engine.counters.items())))
    for line in lines:
        console.on_log(None, line)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        # The Windows console defaults to cp1252, which mangles the box drawing
        # and dashes riff prints.
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    argv = list(sys.argv[1:] if argv is None else argv)
    # `riff` on its own, or `riff -p 9000`, means `riff run`.
    if not argv or (argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "run")
    args = build_parser().parse_args(argv)
    if args.command == "check":
        return cmd_check(args)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "ca":
        return cmd_ca(args)
    if args.command == "setup":
        return cmd_setup(args)
    if args.command == "proxy":
        return cmd_proxy(args)
    if args.command == "ui":
        return cmd_ui(args)
    if args.command == "run" or args.command is None:
        return cmd_run(args)
    build_parser().print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
