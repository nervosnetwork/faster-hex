#!/usr/bin/env python3
"""Relink one downstream program while changing only padding after functions."""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys


def rows(blob):
    if blob[:6] != b"\x7fELF\x02\x01":
        return {}
    table, = struct.unpack_from("<Q", blob, 40)
    step, count, names = struct.unpack_from("<HHH", blob, 58)
    strings, length = struct.unpack_from("<QQ", blob, table + step * names + 24)
    strings = blob[strings:strings + length]
    result = {}
    for i in range(count):
        header = table + step * i
        name, = struct.unpack_from("<I", blob, header)
        name = strings[name:strings.index(0, name)].decode()
        result[name] = header
    return result


def pad_after_sections(original, changes):
    data = bytearray(original)
    sections = rows(data)
    for name, count in changes:
        if not count:
            continue
        hdr = sections[name]
        offset, size = struct.unpack_from("<QQ", original, hdr + 24)
        alignment, = struct.unpack_from("<Q", original, hdr + 48)
        data.extend(bytes(-len(data) % max(alignment, 1)))
        new_offset = len(data)
        data.extend(original[offset:offset + size])
        data.extend(b"\x90" * count)
        struct.pack_into("<QQ", data, hdr + 24, new_offset, size + count)
    return data


def main():
    cc = os.environ['LAYOUT_REAL_CC']
    args = sys.argv[1:]
    flat = []
    for arg in args:
        flat.extend(shlex.split(Path(arg[1:]).read_text()) if arg.startswith('@') else [arg])
    if '-o' not in flat or not Path(flat[flat.index('-o') + 1]).name.startswith('decode-'):
        os.execv(cc, [cc, *args])
    target = Path(flat[flat.index('-o') + 1]).resolve()
    out = Path(os.environ['LAYOUT_IMAGES'])
    out.mkdir(parents=True, exist_ok=True)
    map_file = out/'link.map'
    cmd = [cc, *args, '-Wl,-Map,' + str(map_file)]
    subprocess.run(cmd, check=True)
    shutil.copy2(target, out/'native')
    # Rust's LLD map names the input object and section for each contribution.
    entry = re.compile(r"^\s*([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+\d+\s+(.+?):\((\.text[^)]*)\)\s*$")
    parts = []
    for line in map_file.read_text().splitlines():
        m = entry.match(line)
        if m and int(m[2], 16):
            parts.append((int(m[1], 16), m[3].strip(), m[4]))
    kernel = next(i for i, (_, _, name) in enumerate(parts) if 'hex_decode_avx2_checked' in name)
    caller = next(i for i, (_, _, name) in enumerate(parts) if name == '.text.run_sample')
    assert 0 < kernel < caller, (kernel, caller)

    def available(i):
        return Path(parts[i][1]).is_file() and Path(parts[i][1]).suffix == '.o'

    def before(i, limit):
        while i > limit:
            i -= 1
            if available(i):
                return i
        raise ValueError(f'no plain relocatable object before {parts[i]}')

    locations = [parts[before(kernel, 0)], parts[before(caller, kernel)], parts[caller]]
    assert available(caller)
    (out/'anchors.json').write_text(json.dumps({'locations': locations, 'kernel': parts[kernel], 'caller': parts[caller]}, indent=2))
    original = {Path(obj): Path(obj).read_bytes() for _, obj, name in locations}
    try:
        for k in range(0, 64, 16):
            for c in range(0, 64, 16):
                changes = {path: [] for path in original}
                for (_, obj, name), length in zip(locations, [k, 64 + c - k, 64 - c]):
                    changes[Path(obj)].append((name, length))
                for obj, contents in original.items():
                    obj.write_bytes(pad_after_sections(contents, changes[obj]))
                subprocess.run([cc, *args], check=True)
                shutil.copy2(target, out/f'k{k}-c{c}')
    finally:
        for obj, contents in original.items():
            obj.write_bytes(contents)
    subprocess.run([cc, *args], check=True)
    assert target.read_bytes() == (out/'native').read_bytes(), 'unedited inputs did not reproduce the original executable'


if __name__ == '__main__':
    main()
