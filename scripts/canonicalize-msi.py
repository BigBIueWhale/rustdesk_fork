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


def _zero_cab_filetimes(ole):
    # WiX stamps EVERY CFFILE in the embedded cabinet with the build WALL-CLOCK date+time (DOS format),
    # so two builds differ in the time (and the date across midnight) -- a R-B2 break the SummaryInfo
    # canon does not touch. The cabinet is the .msi's largest OLE stream. CFHEADER@0: "MSCF",
    # coffFiles(u32@16), cFiles(u16@28). Each CFFILE @coffFiles: cbFile(4) uoffFolderStart(4) iFolder(2)
    # date(u16@+10) time(u16@+12) attribs(2) szName(NUL-terminated). Pin every date+time to a fixed DOS
    # value (1980-01-01 00:00:00) so the cabinet bytes are build-stable. (The CFFILE date/time are NOT
    # covered by the per-CFDATA checksums, and the .msi File table keys on name, so this stays valid.)
    cab_path = max(ole.listdir(), key=lambda p: ole.get_size(p))
    cab = bytearray(ole.openstream(cab_path).read())
    if cab[:4] != b"MSCF":
        return False
    coff = struct.unpack_from("<I", cab, 16)[0]
    nfiles = struct.unpack_from("<H", cab, 28)[0]
    p = coff
    for _ in range(nfiles):
        if p + 16 > len(cab):
            break
        struct.pack_into("<HH", cab, p + 10, 0x0021, 0)        # date=1980-01-01, time=00:00:00
        k = p + 16
        while k < len(cab) and cab[k] != 0:                    # skip the NUL-terminated szName
            k += 1
        p = k + 1
    ole.write_stream(cab_path, bytes(cab))
    return True


def _zero_root_filetime(path):
    # The OLE2 Root Entry's modify FILETIME is the build wall-clock too (canonicalize-msi zeroes the
    # SummaryInfo FILETIMEs but not this OLE2-directory one). Zero the Root Entry's create+modify times
    # in the first directory sector. OLE header: sector_shift(u16@30)->sector_size=1<<shift,
    # first_dir_sector(u32@48). Root Entry = directory entry 0; createTime@+100, modifyTime@+108.
    with open(path, "rb") as f:
        head = f.read(64)
    sector_size = 1 << struct.unpack_from("<H", head, 30)[0]
    first_dir = struct.unpack_from("<I", head, 48)[0]
    dir_off = (first_dir + 1) * sector_size
    with open(path, "r+b") as f:                               # targeted 16-byte patch (not a full rewrite)
        f.seek(dir_off + 108)
        if f.read(8) == b"\x00" * 8:                           # modifyTime already zero -> nothing to do
            return False
        f.seek(dir_off + 100)
        f.write(b"\x00" * 16)                                  # createTime + modifyTime -> 0
    return True


def canonicalize(path, version=""):
    ole = olefile.OleFileIO(path, write_mode=True)
    try:
        changed = False
        if ole.exists(SUMINFO):
            data = bytearray(ole.openstream(SUMINFO).read())
            _, props = _section_props(data)
            si = False

            # package code (VT_LPSTR): type(4) len(4) bytes(len, NUL-terminated). Keep the byte length.
            if PID_REVNUMBER in props:
                o = props[PID_REVNUMBER]
                if struct.unpack_from("<I", data, o)[0] == VT_LPSTR:
                    slen = struct.unpack_from("<I", data, o + 4)[0]
                    guid = uuid.uuid5(uuid.NAMESPACE_OID, "msi-package-code-" + version)
                    det = ("{%s}" % str(guid).upper()).encode("ascii") + b"\x00"
                    det = det[:slen].ljust(slen, b"\x00")          # preserve the exact length
                    data[o + 8 : o + 8 + slen] = det
                    si = True

            # create / last-save FILETIMEs (VT_FILETIME): type(4) + 8-byte FILETIME -> zero them.
            for pid in (PID_CREATE_DTM, PID_LASTSAVE_DTM):
                if pid in props:
                    o = props[pid]
                    if struct.unpack_from("<I", data, o)[0] == VT_FILETIME:
                        struct.pack_into("<Q", data, o + 4, 0)
                        si = True

            if si:
                ole.write_stream(SUMINFO, bytes(data))
                changed = True

        # R-B2 residuals beyond the SummaryInfo: the cabinet's per-file DOS date/time + the OLE2 Root
        # Entry modify FILETIME, both build wall-clock (localized via olefile stream + direntry diff).
        if _zero_cab_filetimes(ole):
            changed = True
        ole.close()
    except Exception:
        ole.close()
        raise
    if _zero_root_filetime(path):
        changed = True
    return changed


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: canonicalize-msi.py <file.msi> [version]", file=sys.stderr)
        sys.exit(2)
    ver = sys.argv[2] if len(sys.argv) > 2 else ""
    ok = canonicalize(sys.argv[1], ver)
    print(f"canonicalize-msi: {sys.argv[1]} -> {'patched' if ok else 'no SummaryInformation changes'}")
