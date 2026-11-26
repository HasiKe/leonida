"""runtime/test/check_pe_tls_callbacks.py on two PE32+ images built in memory (no MSVC, no game data).

    python -I tests/test_check_pe_tls_callbacks.py

Standard library only.
"""
import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "runtime" / "test"))
import check_pe_tls_callbacks as chk  # noqa: E402

BASE = 0x140000000


def make_pe(callbacks, tls=True):
    """One .rdata section (RVA 0x1000, file offset 0x200): TLS directory at +0, callback list at +0x40."""
    data = bytearray(0x200 + 0x200)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    pe = 0x80
    data[pe:pe + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, pe + 4, 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = pe + 24
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<Q", data, opt + 24, BASE)
    struct.pack_into("<I", data, opt + 108, 16)
    if tls:
        struct.pack_into("<II", data, opt + 112 + 8 * 9, 0x1000, 40)
    sec = opt + 240
    data[sec:sec + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, sec + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<Q", data, 0x200 + 24, BASE + 0x1040)  # AddressOfCallBacks
    for i, rva in enumerate(list(callbacks) + [0]):
        struct.pack_into("<Q", data, 0x240 + 8 * i, BASE + rva if rva else 0)
    return bytes(data)


def test_two_callbacks_are_listed():
    assert chk.tls_callbacks(make_pe([0x1100, 0x1200])) == [0x1100, 0x1200]


def test_empty_list_and_no_directory_are_clean():
    assert chk.tls_callbacks(make_pe([])) == []
    assert chk.tls_callbacks(make_pe([], tls=False)) == []


def test_main_exit_codes():
    with tempfile.TemporaryDirectory() as d:
        tmp_path = Path(d)
        bad, good, junk = tmp_path / "bad.exe", tmp_path / "good.exe", tmp_path / "junk.exe"
        bad.write_bytes(make_pe([0x1100]))
        good.write_bytes(make_pe([]))
        junk.write_bytes(b"not a pe")
        assert chk.main(["x", str(bad)]) == 1
        assert chk.main(["x", str(good)]) == 0
        assert chk.main(["x", str(junk)]) == 1
        assert chk.main(["x", str(tmp_path / "missing.exe")]) == 1


if __name__ == "__main__":
    test_two_callbacks_are_listed()
    test_empty_list_and_no_directory_are_clean()
    test_main_exit_codes()
    print("ok")
