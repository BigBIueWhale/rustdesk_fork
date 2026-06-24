#!/usr/bin/env python3
# scripts/canonicalize-pe.py -- zero the non-deterministic PE metadata of a Windows binary for R-B2.
#
# The fork's reproducible windows build (build-windows.ps1) already pins every CONTENT source: /Brepro on the
# flutter MSVC links + the cargo rustflags, SOURCE_DATE_EPOCH for app_metadata/gen_version. That converges the
# whole embedded flutter build dir (the portable packer's data.bin -- 78 files, all byte-identical across builds).
#
# The lone residual is the portable packer's OWN PE metadata: with /Brepro, link.exe stamps the COFF
# TimeDateStamp + a debug-directory IMAGE_DEBUG_TYPE_REPRO "repro hash" that, for the rustc BIN (vs the cdylib,
# which converges), differs build-to-build even though the PE content is byte-identical (an MSVC /Brepro quirk
# that picks up a non-content input -- the CRT-startup object metadata). cmp localized it to exactly ~200 bytes:
# the COFF TimeDateStamp (e_lfanew+8) + the debug entries' TimeDateStamps + their raw repro-hash data.
#
# This canonicalizes those fields to zero -- a standard reproducible-build technique (Debian/Go/etc. do the same).
# The zeroed fields are pure tamper-evidence metadata, never used at load time, so the .exe stays valid + runs.
# Runs on the HOST in build-windows-vm.sh extract() (pure stdlib -- no pefile), BEFORE the R-B2 SHA is taken.
import sys, struct

def u16(d, o): return struct.unpack_from('<H', d, o)[0]
def u32(d, o): return struct.unpack_from('<I', d, o)[0]
def z32(d, o): struct.pack_into('<I', d, o, 0)

def canonicalize(path):
    d = bytearray(open(path, 'rb').read())
    if d[:2] != b'MZ':
        raise SystemExit(f"{path}: not a PE (no MZ)")
    e = u32(d, 0x3C)                              # e_lfanew
    if d[e:e+4] != b'PE\0\0':
        raise SystemExit(f"{path}: bad PE signature @ {e:#x}")
    z32(d, e + 8)                                # COFF TimeDateStamp -> 0
    nsec = u16(d, e + 6)                         # NumberOfSections
    sizeopt = u16(d, e + 20)                     # SizeOfOptionalHeader
    opt = e + 24                                 # optional header
    magic = u16(d, opt)                          # 0x10b=PE32, 0x20b=PE32+
    z32(d, opt + 64)                            # CheckSum -> 0 (regular exe tolerates 0)
    dd = opt + (112 if magic == 0x20b else 96)  # data directories
    dbg_rva, dbg_size = u32(d, dd + 6 * 8), u32(d, dd + 6 * 8 + 4)  # IMAGE_DIRECTORY_ENTRY_DEBUG = 6
    # section table, to map the debug RVA -> file offset
    sec = opt + sizeopt
    def rva2off(rva):
        for i in range(nsec):
            s = sec + i * 40
            va, vs, praw = u32(d, s + 12), u32(d, s + 8), u32(d, s + 20)
            if va <= rva < va + max(vs, 1):
                return praw + (rva - va)
        return None
    cleared = 0
    if dbg_rva and dbg_size:
        doff = rva2off(dbg_rva)
        if doff is not None:
            for i in range(dbg_size // 28):     # each IMAGE_DEBUG_DIRECTORY is 28 bytes
                eo = doff + i * 28
                z32(d, eo + 4)                  # entry TimeDateStamp -> 0
                sod, prd = u32(d, eo + 16), u32(d, eo + 24)  # SizeOfData, PointerToRawData
                if prd and sod and prd + sod <= len(d):
                    d[prd:prd + sod] = b'\0' * sod   # zero the repro-hash raw data
                cleared += 1
    sorted_vi = sort_version_info(d)
    open(path, 'wb').write(d)
    print(f"canonicalize-pe: {path} -> zeroed COFF timestamp + checksum + {cleared} debug entr"
          f"{'y' if cleared == 1 else 'ies'} + sorted {sorted_vi} version-info string(s) (R-B2)")


def sort_version_info(d):
    # winres 0.1.12 stores the VS_VERSION_INFO string properties in a HashMap, so the StringTable's child
    # String entries (FileDescription/ProductName/LegalCopyright/...) are embedded in a RANDOM per-build order.
    # The strings are identical; only the order differs. Sort the String entries by key (deterministic) -- they
    # are independently DWORD-aligned length-prefixed blocks, so re-concatenating them sorted preserves the exact
    # byte total. (VS_VERSION_INFO spec: each node = wLength(2) wValueLength(2) wType(2) szKey(utf16,\0) pad.)
    marker = "StringFileInfo".encode('utf-16-le')
    sfi_key = d.find(marker)
    if sfi_key < 0:
        return 0
    align4 = lambda x: (x + 3) & ~3
    # StringTable: right after szKey "StringFileInfo\0" + padding
    p = align4(sfi_key + len(marker) + 2)          # +2 = the UTF-16 NUL
    st_start = p
    st_len = u16(d, st_start)
    st_end = st_start + st_len
    if st_end > len(d) or st_len < 24:
        return 0
    # skip the StringTable header: wLength/wValueLength/wType(6) + szKey(langid utf16,\0) + pad
    q = st_start + 6
    while q + 2 <= st_end and u16(d, q) != 0:
        q += 2
    q = align4(q + 2)
    first = q
    entries = []
    while q + 6 <= st_end:
        elen = u16(d, q)
        if elen == 0:
            break
        blk_end = align4(q + elen)
        k = q + 6
        key = bytearray()
        while k + 2 <= st_end and u16(d, k) != 0:
            key += d[k:k + 2]
            k += 2
        entries.append((bytes(key).decode('utf-16-le', 'replace'), bytes(d[q:blk_end])))
        q = blk_end
    if len(entries) < 2:
        return 0
    region = first
    rebuilt = b''.join(b for _, b in sorted(entries, key=lambda x: x[0]))
    end = region + len(rebuilt)
    d[region:end] = rebuilt                          # same total length -> in-place reorder
    return len(entries)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise SystemExit("usage: canonicalize-pe.py <file.exe> [more.exe ...]")
    for p in sys.argv[1:]:
        canonicalize(p)
