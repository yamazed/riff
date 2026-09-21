"""Read and set the per-user Windows (WinINET) proxy.

Windows stores this configuration twice: as the legacy `ProxyEnable` /
`ProxyServer` values, and as a binary blob under `Connections`. The blob is
the one Windows actually believes — set only the legacy values and they get
re-synced away from underneath you, which looks exactly like "the setting did
not stick". Both are written here, and `turn_off` restores the original blob
byte for byte.

Everything lives in HKEY_CURRENT_USER, so this affects only the signed-in user
and needs no admin rights.
"""

from __future__ import annotations

import base64
import json
import os
import struct
import threading
from dataclasses import dataclass

KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
CONNECTIONS_PATH = KEY_PATH + r"\Connections"
BACKUP_NAME = "proxy-backup.json"

# WinINET has to be told, or running apps keep the old settings until reboot.
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37

# Flag bits inside the connection blob.
FLAG_DIRECT = 0x01
FLAG_PROXY = 0x02
FLAG_PAC = 0x04
FLAG_AUTODETECT = 0x08

BLOB_VERSION = 0x46
DEFAULT_BYPASS = "<local>"


class ProxyError(Exception):
    """The Windows proxy settings could not be read or changed."""


@dataclass(slots=True)
class ProxyState:
    enabled: bool = False
    server: str = ""
    bypass: str = ""
    pac: str = ""
    autodetect: bool = False

    def describe(self) -> str:
        parts = []
        if self.enabled:
            parts.append(f"on — {self.server}")
            if self.bypass:
                parts.append(f"bypassing {self.bypass}")
        else:
            parts.append("off (direct connection)")
        if self.pac:
            parts.append(f"PAC {'active' if not self.enabled else 'configured but inactive'}: {self.pac}")
        if self.autodetect:
            parts.append("auto-detect on")
        return ", ".join(parts)


def _require_windows() -> None:
    if os.name != "nt":
        raise ProxyError("changing the system proxy is only implemented on Windows")


# ------------------------------------------------------------- the blob


def decode_blob(blob: bytes) -> tuple[int, int, ProxyState]:
    """Unpack DefaultConnectionSettings into (version, counter, state)."""
    if len(blob) < 12:
        raise ProxyError("the Windows connection settings blob is too short to parse")
    version, counter, flags = struct.unpack_from("<III", blob, 0)
    offset = 12
    fields = []
    for _ in range(3):
        if offset + 4 > len(blob):
            fields.append("")
            continue
        (length,) = struct.unpack_from("<I", blob, offset)
        offset += 4
        fields.append(blob[offset : offset + length].decode("latin-1"))
        offset += length
    server, bypass, pac = fields
    state = ProxyState(
        enabled=bool(flags & FLAG_PROXY),
        server=server,
        bypass=bypass,
        pac=pac if flags & FLAG_PAC else "",
        autodetect=bool(flags & FLAG_AUTODETECT),
    )
    return version, counter, state


def encode_blob(version: int, counter: int, state: ProxyState, pac_raw: str = "") -> bytes:
    flags = FLAG_DIRECT
    if state.enabled:
        flags |= FLAG_PROXY
    if state.pac:
        flags |= FLAG_PAC
    if state.autodetect:
        flags |= FLAG_AUTODETECT

    out = bytearray()
    out += struct.pack("<III", version or BLOB_VERSION, counter, flags)
    for text in (state.server, state.bypass, state.pac or pac_raw):
        encoded = text.encode("latin-1", "replace")
        out += struct.pack("<I", len(encoded))
        out += encoded
    out += b"\x00" * 32  # trailing padding Windows expects
    return bytes(out)


# ------------------------------------------------------------- registry


def _read_blob() -> tuple[bytes, int, int, ProxyState]:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, CONNECTIONS_PATH) as key:
            blob, _ = winreg.QueryValueEx(key, "DefaultConnectionSettings")
    except FileNotFoundError:
        blob = encode_blob(BLOB_VERSION, 1, ProxyState())
    except OSError as exc:
        raise ProxyError(f"cannot read the connection settings: {exc}") from None
    version, counter, state = decode_blob(bytes(blob))
    return bytes(blob), version, counter, state


def read_state() -> ProxyState:
    _require_windows()
    _, _, _, state = _read_blob()
    return state


def _write(state: ProxyState, blob: bytes) -> None:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY_PATH, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if state.enabled else 0)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, state.server)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, state.bypass)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, CONNECTIONS_PATH) as key:
            # Both names must agree; Windows copies between them.
            winreg.SetValueEx(key, "DefaultConnectionSettings", 0, winreg.REG_BINARY, blob)
            winreg.SetValueEx(key, "SavedLegacySettings", 0, winreg.REG_BINARY, blob)
    except OSError as exc:
        raise ProxyError(f"cannot change the proxy settings: {exc}") from None
    _notify()


def _notify() -> None:
    try:
        import ctypes

        wininet = ctypes.WinDLL("wininet.dll")
        for option in (INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH):
            wininet.InternetSetOptionW(0, option, 0, 0)
    except Exception:  # noqa: BLE001
        # Worst case the user opens a new browser window and it picks up.
        return


# -------------------------------------------------------------- actions


def _backup_path(home: str) -> str:
    return os.path.join(home, BACKUP_NAME)


def turn_on(host: str, port: int, home: str, bypass: str = DEFAULT_BYPASS) -> ProxyState:
    """Point the user's proxy at riff, remembering exactly what was there."""
    _require_windows()
    raw, version, counter, previous = _read_blob()
    target = f"{host}:{port}"

    os.makedirs(home, exist_ok=True)
    # Only take a backup if riff is not already the configured proxy, so
    # running this twice cannot overwrite the real original with our own value.
    if not (previous.enabled and previous.server == target):
        with open(_backup_path(home), "w", encoding="utf-8") as fh:
            json.dump({"blob": base64.b64encode(raw).decode("ascii")}, fh)

    state = ProxyState(
        enabled=True,
        server=target,
        bypass=bypass or previous.bypass,
        pac="",  # a PAC script would otherwise take precedence over our proxy
        autodetect=False,
    )
    _write(state, encode_blob(version, counter + 1, state))
    return state


def turn_off(home: str) -> ProxyState:
    """Restore the settings exactly as they were before riff touched them."""
    _require_windows()
    raw, version, counter, _ = _read_blob()
    path = _backup_path(home)

    restored_blob = None
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                saved = json.load(fh)
            restored_blob = base64.b64decode(saved["blob"])
        except (OSError, ValueError, TypeError, KeyError):
            restored_blob = None  # a damaged backup just means "turn it off"

    if restored_blob is None:
        state = ProxyState(enabled=False, server="", bypass="", pac="", autodetect=False)
        restored_blob = encode_blob(version, counter + 1, state)
    else:
        # Put the original bytes back verbatim — re-encoding could drop a PAC
        # URL that was present but inactive. Only the counter moves forward,
        # so that Windows notices the change.
        restored_blob = restored_blob[:4] + struct.pack("<I", counter + 1) + restored_blob[8:]
        _, _, state = decode_blob(restored_blob)

    _write(state, restored_blob)
    try:
        os.remove(path)
    except OSError:
        pass
    return state


# -------------------------------------------------------------- watching


def owns_proxy(home: str) -> bool:
    """True while riff's backup of the original settings exists.

    `turn_on` writes it and `turn_off` removes it, so its presence means the
    user asked riff to be the proxy and has not asked for it back yet.
    """
    return os.path.exists(_backup_path(home))


def ownership_stamp(home: str) -> float | None:
    """When the backup was last written, or None if riff does not own the proxy.

    A fresh `riff proxy on` rewrites the backup, so a changed stamp is how the
    watcher knows the user asked again after it had given up.
    """
    try:
        return os.path.getmtime(_backup_path(home))
    except OSError:
        return None


def reverted_within(host: str, port: int, seconds: float = 2.0, poll: float = 0.25) -> bool:
    """After `turn_on`, watch briefly: did something switch the setting away again?

    Zscaler Client Connector, while enabled, watches the registry key and puts
    its own settings back within a second. Catching that here lets `riff proxy
    on` say so instead of claiming success.
    """
    import time

    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        time.sleep(poll)
        try:
            if not points_at(read_state(), host, port):
                return True
        except ProxyError:
            return False
    return False


def points_at(state: ProxyState, host: str, port: int) -> bool:
    return state.enabled and state.server.strip().lower() == f"{host}:{port}".lower()


def reapply(host: str, port: int, bypass: str = DEFAULT_BYPASS) -> ProxyState:
    """Put riff back as the proxy WITHOUT touching the backup.

    Used when another program cleared the setting behind our back. The backup
    still holds the user's real original, so it must not be overwritten with
    the cleared state we are looking at now.
    """
    _require_windows()
    _, version, counter, _ = _read_blob()
    state = ProxyState(enabled=True, server=f"{host}:{port}", bypass=bypass, pac="", autodetect=False)
    _write(state, encode_blob(version, counter + 1, state))
    return state


class ProxyWatcher:
    """Re-apply riff's proxy setting when something else switches it off.

    Endpoint agents such as Zscaler Client Connector disable the per-user
    WinINET proxy whenever they (re)start, which silently ends capture. This
    watches the setting and puts it back, automatically, while riff is running.

    It only acts while `owns_proxy(home)` is true, so a deliberate
    `riff proxy off` from another console is respected. If the setting keeps
    being cleared, it gives up after `max_reapplies` consecutive attempts
    rather than fighting forever, and says so once.
    """

    def __init__(
        self,
        host: str,
        port: int,
        home: str,
        bypass: str = DEFAULT_BYPASS,
        interval: float = 3.0,
        max_reapplies: int = 5,
        on_reapplied=None,
        on_gave_up=None,
        *,
        read=None,
        apply=None,
        owns=None,
    ):
        self.host = host
        self.port = port
        self.home = home
        self.bypass = bypass
        self.interval = interval
        self.max_reapplies = max_reapplies
        self.on_reapplied = on_reapplied
        self.on_gave_up = on_gave_up
        self._read = read or read_state
        self._apply = apply or (lambda: reapply(self.host, self.port, self.bypass))
        # Any truthy value means "riff owns the proxy"; a *changed* truthy
        # value means the user ran `riff proxy on` again, which earns a retry.
        self._owns = owns or (lambda: ownership_stamp(self.home))
        self._stamp = None
        self._consecutive = 0
        self._gave_up = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.reapplied = 0

    # One poll. Returns what happened, which is what the tests look at.
    def tick(self) -> str:
        try:
            stamp = self._owns()
            if not stamp:
                self._stamp = None
                self._consecutive = 0
                self._gave_up = False
                return "not-owned"
            if self._stamp is not None and stamp != self._stamp:
                self._consecutive = 0
                self._gave_up = False
            self._stamp = stamp
            state = self._read()
        except ProxyError:
            return "unreadable"

        if points_at(state, self.host, self.port):
            self._consecutive = 0
            self._gave_up = False
            return "ok"

        if self._gave_up:
            return "gave-up"
        if self._consecutive >= self.max_reapplies:
            self._gave_up = True
            if self.on_gave_up:
                self.on_gave_up(state)
            return "gave-up"

        try:
            self._apply()
        except ProxyError:
            return "unreadable"
        self._consecutive += 1
        self.reapplied += 1
        if self.on_reapplied:
            self.on_reapplied(state)
        return "reapplied"

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self.tick()

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, daemon=True, name="riff-proxy-watch")
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
