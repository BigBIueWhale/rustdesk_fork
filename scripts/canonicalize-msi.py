#!/usr/bin/env python3
# canonicalize-msi.py -- make a WiX .msi byte-reproducible (R-B2) by overwriting the
# non-deterministic SummaryInformation fields in place. A .msi is an OLE2 compound file whose
# \x05SummaryInformation stream is an OLE property set; three of its properties change build to
# build and would defeat the same-host recorded-SHA bar:
#   PID_REVNUMBER  (9)  -- the MSI *package code* GUID, regenerated on every build
#   PID_CREATE_DTM (12) -- the create  FILETIME
#   PID_LASTSAVE_DTM(13)-- the last-save FILETIME
# We rewrite the package code to a deterministic uuid5(version) (same length -> in-place) and zero
# the two FILETIMEs, then write the stream back (olefile write_stream needs the SAME byte length,
# which an in-place patch preserves). The analog of canonicalize-pe.py, but for OLE2 not PE.
#
# Usage: canonicalize-msi.py <file.msi> [version]   (version defaults to "" -> a fixed package code)
import sys, struct, uuid, olefile

PID_REVNUMBER, PID_CREATE_DTM, PID_LASTSAVE_DTM = 9, 12, 13
VT_LPSTR, VT_FILETIME = 0x1E, 0x40
SUMINFO = "\x05SummaryInformation"


def _section_props(data):
    # property-set header: byteOrder(2) version(2) sysId(4) CLSID(16) numSections(4) = 28 bytes,
    # then per section: FMTID(16) + offset(4). We canonicalize the FIRST (only) section.
    num_sections = struct.unpack_from("<I", data, 24)[0]
    if num_sections < 1:
        return None, {}
    sec_off = struct.unpack_from("<I", data, 28 + 16)[0]      # offset of section 1
    num_props = struct.unpack_from("<I", data, sec_off + 4)[0]
    props = {}
    for i in range(num_props):
        pid, poff = struct.unpack_from("<II", data, sec_off + 8 + i * 8)
        props[pid] = sec_off + poff                            # absolute offset of the value
    return sec_off, props


def canonicalize(path, version=""):
    ole = olefile.OleFileIO(path, write_mode=True)
    try:
        if not ole.exists(SUMINFO):
            ole.close()
            return False
        data = bytearray(ole.openstream(SUMINFO).read())
        _, props = _section_props(data)
        changed = False

        # package code (VT_LPSTR): type(4) len(4) bytes(len, NUL-terminated). Keep the byte length.
        if PID_REVNUMBER in props:
            o = props[PID_REVNUMBER]
            if struct.unpack_from("<I", data, o)[0] == VT_LPSTR:
                slen = struct.unpack_from("<I", data, o + 4)[0]
                guid = uuid.uuid5(uuid.NAMESPACE_OID, "msi-package-code-" + version)
                det = ("{%s}" % str(guid).upper()).encode("ascii") + b"\x00"
                det = det[:slen].ljust(slen, b"\x00")          # preserve the exact length
                data[o + 8 : o + 8 + slen] = det
                changed = True

        # create / last-save FILETIMEs (VT_FILETIME): type(4) + 8-byte FILETIME -> zero them.
        for pid in (PID_CREATE_DTM, PID_LASTSAVE_DTM):
            if pid in props:
                o = props[pid]
                if struct.unpack_from("<I", data, o)[0] == VT_FILETIME:
                    struct.pack_into("<Q", data, o + 4, 0)
                    changed = True

        if changed:
            ole.write_stream(SUMINFO, bytes(data))
        ole.close()
        return changed
    except Exception:
        ole.close()
        raise


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: canonicalize-msi.py <file.msi> [version]", file=sys.stderr)
        sys.exit(2)
    ver = sys.argv[2] if len(sys.argv) > 2 else ""
    ok = canonicalize(sys.argv[1], ver)
    print(f"canonicalize-msi: {sys.argv[1]} -> {'patched' if ok else 'no SummaryInformation changes'}")
