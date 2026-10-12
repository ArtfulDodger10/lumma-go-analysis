"""Minimal PE reader shared by the tools. No dependencies.

Works on files on disk ("file" layout) and on images dumped from memory
("mapped" layout, e.g. a Volatility VAD dump), where data sits at its RVA
instead of its raw offset.
"""
import struct

MACHINE_I386 = 0x14C
MACHINE_AMD64 = 0x8664


class PEError(Exception):
    pass


class Section:
    def __init__(self, name, va, vsize, raw, rsize):
        self.name, self.va, self.vsize, self.raw, self.rsize = name, va, vsize, raw, rsize


class PE:
    def __init__(self, data, layout="file", base=None):
        if data[:2] != b"MZ":
            raise PEError("not a PE file")
        e = struct.unpack_from("<I", data, 0x3C)[0]
        if e + 0x18 > len(data) or data[e:e + 4] != b"PE\0\0":
            raise PEError("not a PE file")
        self.data, self.layout = data, layout
        self.machine, count = struct.unpack_from("<HH", data, e + 4)
        opt_size = struct.unpack_from("<H", data, e + 20)[0]
        opt = e + 24
        self.pe32 = struct.unpack_from("<H", data, opt)[0] == 0x10B
        header_base = struct.unpack_from("<I" if self.pe32 else "<Q", data, opt + (28 if self.pe32 else 24))[0]
        self.header_base = header_base
        self.base = header_base if base is None else base
        dd = opt + (96 if self.pe32 else 112)
        self.dirs = [struct.unpack_from("<II", data, dd + 8 * i) for i in range(16)
                     if dd + 8 * i + 8 <= opt + opt_size]
        self.sections, off = [], opt + opt_size
        for _ in range(count):
            name, vsize, va, rsize, raw = struct.unpack_from("<8sIIII", data, off)
            self.sections.append(Section(name.rstrip(b"\0"), va, vsize, raw, rsize))
            off += 40

    def section(self, name):
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def section_data(self, name):
        s = self.section(name)
        if s is None:
            raise PEError(f"section {name!r} not found")
        if self.layout == "mapped":
            return self.data[s.va:s.va + max(s.vsize, s.rsize)]
        return self.data[s.raw:s.raw + s.rsize]

    def rva_to_off(self, rva):
        if self.layout == "mapped":
            if 0 <= rva < len(self.data):
                return rva
            raise PEError(f"RVA 0x{rva:x} outside the dump")
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.rsize) and rva - s.va < s.rsize:
                return s.raw + rva - s.va
        raise PEError(f"RVA 0x{rva:x} not in the file")

    def off_to_rva(self, off):
        if self.layout == "mapped":
            return off
        for s in self.sections:
            if s.raw <= off < s.raw + s.rsize:
                return s.va + off - s.raw
        raise PEError(f"offset 0x{off:x} not in a section")

    def read_va(self, va, n):
        o = self.rva_to_off(va - self.base)
        out = self.data[o:o + n]
        if len(out) != n:
            raise PEError(f"short read at VA 0x{va:x}")
        return out

    def va_of(self, off):
        return self.base + self.off_to_rva(off)

    def file_end(self):
        """End of the last section's raw data (drops padding after the image)."""
        return max((s.raw + s.rsize for s in self.sections), default=len(self.data))

    @property
    def is_dotnet(self):
        return len(self.dirs) > 14 and self.dirs[14][0] != 0
