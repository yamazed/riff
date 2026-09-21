"""The Windows connection-settings blob, which is the part Windows believes."""

from __future__ import annotations

import struct

import pytest

from riff import winproxy
from riff.winproxy import ProxyState, decode_blob, encode_blob

# A real blob captured from a machine: direct connection, with a proxy address
# and a PAC URL both recorded but inactive.
REAL = bytes.fromhex(
    "46000000ab000000010000000e0000003132372e302e302e313a38383838070000003c6c6f63616c3e2e000000"
    "687474703a2f2f3132372e302e302e313a393030302f73797374656d70726f78792d66343332643666342e7061"
    "630000000000000000000000000000000000000000000000000000000000000000"
)


def test_decodes_a_real_blob():
    version, counter, state = decode_blob(REAL)
    assert version == 0x46
    assert counter == 171
    assert state.enabled is False  # flags say DIRECT, whatever ProxyEnable claims
    assert state.server == "127.0.0.1:8888"
    assert state.bypass == "<local>"
    assert state.pac == ""  # the PAC flag is not set, so it is inactive
    assert state.autodetect is False


def test_round_trip():
    state = ProxyState(enabled=True, server="127.0.0.1:8888", bypass="<local>")
    _, counter, decoded = decode_blob(encode_blob(0x46, 5, state))
    assert counter == 5
    assert decoded.enabled is True
    assert decoded.server == "127.0.0.1:8888"
    assert decoded.bypass == "<local>"


def test_enabling_sets_the_proxy_flag():
    blob = encode_blob(0x46, 1, ProxyState(enabled=True, server="h:1", bypass=""))
    (flags,) = struct.unpack_from("<I", blob, 8)
    assert flags & winproxy.FLAG_PROXY
    assert not flags & winproxy.FLAG_PAC


def test_disabling_clears_the_proxy_flag():
    blob = encode_blob(0x46, 1, ProxyState(enabled=False))
    (flags,) = struct.unpack_from("<I", blob, 8)
    assert not flags & winproxy.FLAG_PROXY
    assert flags & winproxy.FLAG_DIRECT


def test_a_pac_url_sets_its_flag():
    blob = encode_blob(0x46, 1, ProxyState(enabled=False, pac="http://x/y.pac"))
    (flags,) = struct.unpack_from("<I", blob, 8)
    assert flags & winproxy.FLAG_PAC
    assert decode_blob(blob)[2].pac == "http://x/y.pac"


def test_counter_can_be_bumped_in_place_without_touching_anything_else():
    """This is how turn_off restores a backup byte-for-byte."""
    bumped = REAL[:4] + struct.pack("<I", 999) + REAL[8:]
    assert len(bumped) == len(REAL)
    assert bumped[12:] == REAL[12:]
    version, counter, state = decode_blob(bumped)
    assert counter == 999
    assert version == 0x46
    assert state.server == "127.0.0.1:8888"


def test_describe_is_readable():
    assert "off" in ProxyState().describe()
    on = ProxyState(enabled=True, server="127.0.0.1:8888", bypass="<local>").describe()
    assert "127.0.0.1:8888" in on and "<local>" in on


def test_a_truncated_blob_is_reported_not_guessed():
    with pytest.raises(winproxy.ProxyError):
        decode_blob(b"\x46\x00")


# ---------------------------------------------------------------- watcher


class _FakeRegistry:
    """Stand-in for the Windows setting: what is stored, and whether riff owns it."""

    def __init__(self, state: ProxyState, owns: bool = True):
        self.state = state
        self.owns = owns
        self.applied = 0

    def read(self) -> ProxyState:
        return self.state

    def apply(self) -> None:
        self.applied += 1
        self.state = ProxyState(enabled=True, server="127.0.0.1:8888", bypass="<local>")


def _watcher(reg: _FakeRegistry, **kwargs) -> winproxy.ProxyWatcher:
    return winproxy.ProxyWatcher(
        "127.0.0.1", 8888, home="unused", read=reg.read, apply=reg.apply, owns=lambda: reg.owns, **kwargs
    )


def test_watcher_leaves_a_correct_setting_alone():
    reg = _FakeRegistry(ProxyState(enabled=True, server="127.0.0.1:8888", bypass="<local>"))
    assert _watcher(reg).tick() == "ok"
    assert reg.applied == 0


def test_watcher_reapplies_when_something_switches_the_proxy_off():
    # Exactly what Zscaler leaves behind: riff's address still stored, flag cleared.
    reg = _FakeRegistry(ProxyState(enabled=False, server="127.0.0.1:8888", bypass="<local>"))
    seen = []
    w = _watcher(reg, on_reapplied=seen.append)
    assert w.tick() == "reapplied"
    assert reg.applied == 1
    assert seen and seen[0].enabled is False
    assert w.tick() == "ok"


def test_watcher_reapplies_when_the_proxy_is_pointed_elsewhere():
    reg = _FakeRegistry(ProxyState(enabled=True, server="gateway.example:3128"))
    assert _watcher(reg).tick() == "reapplied"
    assert reg.state.server == "127.0.0.1:8888"


def test_watcher_respects_a_deliberate_proxy_off():
    # `riff proxy off` removes the backup, so riff no longer owns the setting.
    reg = _FakeRegistry(ProxyState(enabled=False), owns=False)
    assert _watcher(reg).tick() == "not-owned"
    assert reg.applied == 0


def test_watcher_gives_up_instead_of_fighting_forever():
    class Stubborn(_FakeRegistry):
        def apply(self) -> None:  # the other side wins every time
            self.applied += 1

    reg = Stubborn(ProxyState(enabled=False, server="127.0.0.1:8888"))
    gave_up = []
    w = _watcher(reg, max_reapplies=3, on_gave_up=gave_up.append)
    assert [w.tick() for _ in range(3)] == ["reapplied"] * 3
    assert w.tick() == "gave-up"
    assert w.tick() == "gave-up"
    assert reg.applied == 3
    assert len(gave_up) == 1, "says so once, not every poll"


def test_watcher_recovers_after_giving_up_once_the_setting_is_right_again():
    class Stubborn(_FakeRegistry):
        def apply(self) -> None:
            self.applied += 1

    reg = Stubborn(ProxyState(enabled=False, server="127.0.0.1:8888"))
    w = _watcher(reg, max_reapplies=1)
    assert w.tick() == "reapplied"
    assert w.tick() == "gave-up"
    reg.state = ProxyState(enabled=True, server="127.0.0.1:8888")  # user ran `riff proxy on`
    assert w.tick() == "ok"
    reg.state = ProxyState(enabled=False, server="127.0.0.1:8888")
    assert w.tick() == "reapplied", "a fresh outage gets a fresh chance"


def test_watcher_does_not_touch_the_registry_on_a_read_error():
    def boom():
        raise winproxy.ProxyError("no registry here")

    reg = _FakeRegistry(ProxyState())
    w = winproxy.ProxyWatcher("127.0.0.1", 8888, home="unused", read=boom, apply=reg.apply, owns=lambda: True)
    assert w.tick() == "unreadable"
    assert reg.applied == 0


def test_points_at_ignores_case_and_whitespace():
    assert winproxy.points_at(ProxyState(enabled=True, server=" 127.0.0.1:8888 "), "127.0.0.1", 8888)
    assert not winproxy.points_at(ProxyState(enabled=False, server="127.0.0.1:8888"), "127.0.0.1", 8888)
    assert not winproxy.points_at(ProxyState(enabled=True, server="127.0.0.1:8080"), "127.0.0.1", 8888)


def test_watcher_tries_again_after_the_user_reruns_proxy_on():
    class Stubborn(_FakeRegistry):
        def apply(self) -> None:
            self.applied += 1

    reg = Stubborn(ProxyState(enabled=False, server="127.0.0.1:8888"))
    stamp = [100.0]  # mtime of proxy-backup.json
    w = winproxy.ProxyWatcher(
        "127.0.0.1", 8888, home="unused", max_reapplies=1, read=reg.read, apply=reg.apply, owns=lambda: stamp[0]
    )
    assert w.tick() == "reapplied"
    assert w.tick() == "gave-up"
    assert w.tick() == "gave-up"
    stamp[0] = 200.0  # `riff proxy on` rewrote the backup
    assert w.tick() == "reapplied", "a fresh request from the user earns a fresh attempt"
    assert w.tick() == "gave-up"
