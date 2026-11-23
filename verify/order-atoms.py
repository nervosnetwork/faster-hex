#!/usr/bin/env python3
"""Link twice from exactly the same object files, relocating only the sampled atoms."""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

def symbols(link_map):
    rows = link_map.split('# Dead Stripped Symbols:', 1)[0].splitlines()
    objects = {}
    syms = []
    for line in rows:
        obj = re.match(r'^\[\s*(\d+)\]\s+(.+)$', line)
        if obj:
            objects[int(obj[1])] = obj[2]
        hit = re.match(r'^(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+\[\s*(\d+)\]\s+(\S+)', line)
        if hit:
            syms.append((int(hit[1], 16), int(hit[2], 16), objects[int(hit[3])], hit[4]))
    return syms

def name_for_linker(obj):
    return Path(obj.rsplit('(', 1)[-1].rstrip(')')).name

def image(args, cc, output, map_path, extra=()):
    proc = subprocess.run([cc, *args, '-Wl,-map,' + str(map_path), *extra], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode:
        sys.stderr.write(proc.stdout)
        proc.check_returncode()
    return symbols(map_path.read_text()), proc.stdout

def main():
    cc = os.environ['HEX_REAL_CC']
    args = sys.argv[1:]
    expanded = [value for a in args for value in (shlex.split(Path(a[1:]).read_text()) if a.startswith('@') else [a])]
    if '-o' not in expanded:
        os.execv(cc, [cc,*args])
    target = Path(expanded[expanded.index('-o') + 1])
    if not target.name.startswith('hex-'):
        os.execv(cc, [cc,*args])
    dest = Path(os.environ['HEX_ORDER_OUTPUT'])
    dest.mkdir()
    active = json.loads(os.environ['HEX_SAMPLED_ADDRS'])
    native, warnings_original = image(args, cc, target, dest/'native.map')
    shutil.copy2(target, dest/'native')
    picks = []
    for name, addr in active.items():
        id_hash = name.rsplit('::', 1)[1]
        hits = [row for row in native if row[0] == addr and id_hash in row[3]]
        if len(hits) != 1:
            raise RuntimeError(f'Previously sampled code no longer matches {name} at {addr:#x}: {hits}')
        begin, length, obj, symbol = hits[0]
        spec = name_for_linker(obj) + ':' + symbol
        assert sum((name_for_linker(o) + ':' + sym) == spec for _, _, o, sym in native) == 1, spec
        picks.append((name, begin, length, obj, symbol, spec))
    order = dest/'order'
    order.write_text(''.join(row[-1]+'\n' for row in picks))
    moved, warnings_placed = image(args, cc, target, dest/'moved.map', ['-Wl,-order_file,' + str(order)])
    shutil.copy2(target, dest/'placed')
    result = {}
    for name, original, size, obj, symbol, spec in picks:
        hits = [(addr,n) for addr,n,o,s in moved if o == obj and s == symbol]
        assert len(hits)==1,(name,hits)
        result[name] = {'native':original,'placed':hits[0][0],'size_native':size,'size_placed':hits[0][1],'atom':spec}
    (dest/'selection.json').write_text(json.dumps({'symbols':result,'warnings':[warnings_original,warnings_placed]},indent=2))
    # Original image goes back to rustc, as usual.
    shutil.copy2(dest/'native',target)

if __name__=='__main__':
    main()
