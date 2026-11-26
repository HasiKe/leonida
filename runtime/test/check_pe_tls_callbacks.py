"""gta6rt.exe must have no TLS callbacks (TEST-GTA6RT-NO-TLS-CALLBACKS).

A thread_local with a destructor in gta6rt makes the linker emit two callbacks (__dyn_tls_init, __dyn_tls_dtor). The
UCRT then accepts only one _register_thread_local_exe_atexit_callback per process, the title registers its own, and
the game fast-fails at startup with 0xC0000409 (RT-XMEM-STARTUP-FASTFAIL). Trivially destructible thread_local data is
fine: it adds no callback.

    python -I check_pe_tls_callbacks.py <gta6rt.exe>

Exit 0 when the PE has no TLS directory or an empty AddressOfCallBacks list, 1 when the list has an entry or the file
is not a readable PE32+. Standard library only; reads the file, so it also runs where gta6rt cannot.
"""
import struct
import sys

TLS_DIR_INDEX = 9


def tls_callbacks(data):
    """RVAs (not VAs) of the TLS callbacks of a PE32+ image, in list order. [] when there is no TLS directory."""
    if data[:2] != b"MZ" or len(data) < 0x40:
        raise ValueError("not a PE (no MZ header)")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE (no PE signature)")
    nsec, = struct.unpack_from("<H", data, pe + 6)
    opt_size, = struct.unpack_from("<H", data, pe + 20)
    opt = pe + 24
    if struct.unpack_from("<H", data, opt)[0] != 0x20B:
        raise ValueError("not a PE32+ image")
    image_base, = struct.unpack_from("<Q", data, opt + 24)
    ndirs, = struct.unpack_from("<I", data, opt + 108)
    if ndirs <= TLS_DIR_INDEX:
        return []
    tls_rva, tls_size = struct.unpack_from("<II", data, opt + 112 + 8 * TLS_DIR_INDEX)
    if not tls_rva or not tls_size:
        return []
    sections = []
    sec = opt + opt_size
    for i in range(nsec):
        vsize, va, rawsize, raw = struct.unpack_from("<IIII", data, sec + 40 * i + 8)
        sections.append((va, max(vsize, rawsize), raw))

    def off(rva):
        for va, size, raw in sections:
            if va <= rva < va + size:
                return raw + rva - va
        raise ValueError("RVA 0x%x is in no section" % rva)

    # IMAGE_TLS_DIRECTORY64: StartRaw, EndRaw, AddressOfIndex, AddressOfCallBacks (VAs).
    cb_va, = struct.unpack_from("<Q", data, off(tls_rva) + 24)
    if not cb_va:
        return []
    out = []
    pos = off(cb_va - image_base)
    while True:
        entry, = struct.unpack_from("<Q", data, pos)
        if not entry:
            return out
        out.append(entry - image_base)
        pos += 8


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 1
    try:
        with open(argv[1], "rb") as f:
            cbs = tls_callbacks(f.read())
    except (OSError, ValueError, struct.error) as e:
        print("check_pe_tls_callbacks: cannot read %s: %s" % (argv[1], e))
        return 1
    if cbs:
        print("FAIL: %s has %d TLS callback(s) (RVAs %s). A thread_local with a destructor was linked in; the "
              "game's own _register_thread_local_exe_atexit_callback then fast-fails (0xC0000409)."
              % (argv[1], len(cbs), ", ".join("0x%x" % c for c in cbs)))
        return 1
    print("ok: %s has no TLS callbacks" % argv[1])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
