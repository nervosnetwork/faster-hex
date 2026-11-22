"""Compare ordinary downstream builds and links made from their same object files."""
from pathlib import Path
import hashlib
import json
import os
import random
import re
import statistics
import subprocess
from cause_common import ROOT, compare, measure, pin, save, section

work = ROOT / 'real'
profile = os.environ.get('CARGO_PROFILE_RELEASE_LTO', 'default')
base = work / 'qualification' / profile
report = work / 'short-json-sites'
report.mkdir()
roles = ('release', 'version', 'scoped', 'direct', 'owned', 'call', 'cold')
variants = ('native','shift64','shift128','after64')
kinds = ('.text','.rodata','.plt','.got','.data.rel.ro','.rela.dyn')
images, sites, sections, tables = {}, {}, {}, {}

def symbols(image):
    lines = subprocess.check_output(['nm','-anS','-C','--defined-only',image],text=True)
    entries = []
    for line in lines.splitlines():
        row = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) ([a-zA-Z]) (.+)',line)
        if row:
            entries.append((int(row[1],16), int(row[2],16), row[3], row[4]))
    return entries

for role in roles:
    loc = work/'round-layout'/role
    assert (base/(role+'-vec_round_slice')).read_bytes() == (loc/'native').read_bytes()
    for variant in variants:
        label = role+'/'+variant
        img = loc/variant
        images[label] = img
        sec = sections[label] = {s: section(img,s) for s in kinds}
        syms = symbols(img)
        sites[label] = {name:[addr,size] for addr,size,typ,name in syms if typ in 'tT'
                        and (name in ('core::str::converts::from_utf8','serde_json::ser::format_escaped_str','vec_round_slice::measure')
                             or name.startswith('faster_hex::'))}
        assert 'vec_round_slice::measure' in sites[label]
        if variant == 'native':
            table = [(addr,size,typ,name) for addr,size,typ,name in syms if name in
                     ('faster_hex::decode::UNHEX4','faster_hex::decode::UNHEX','faster_hex::decode::UNHEX_UPPER','faster_hex::decode::UNHEX_LOWER')]
            names = {x[0]:x[3] for x in table}
            start, length, _ = sec['.got']
            relocs = subprocess.check_output(['readelf','-Wr',img],text=True)
            slots = []
            for line in relocs.splitlines():
                cols=line.split()
                if len(cols)>=4 and re.fullmatch('[0-9a-fA-F]+',cols[0]) and cols[2].endswith('_RELATIVE') and start<=int(cols[0],16)<start+length:
                    address=int(cols[-1],16)
                    if address in names:
                        slots.append([int(cols[0],16)-start,names[address]])
            tables[role] = {'symbols':table,'got_slots':slots}
    native, before, further, after = [sections[role+'/'+v] for v in variants]
    assert before['.text'][0] - native['.text'][0] == 64
    assert further['.text'][0] - native['.text'][0] == 128
    assert after['.text'][:2] == native['.text'][:2]
    assert before['.text'][1] == after['.text'][1]
    assert all(before[k][:2] == after[k][:2] for k in kinds if k != '.text'),role
save(report/'sections.json',sections)
save(report/'functions.json',sites)
save(report/'tables.json',tables)

# Paired measurements use the exact ordinary executable and its alternative links.
# Keep A/A, whole-image matching and code-vs-read-only-data movement in the same run.
selected=[r+'/native' for r in roles]+['scoped/shift64','scoped/shift128','scoped/after64',
                                       'direct/shift64','direct/after64','aa']
pairs=[('scoped/native','aa'),('release/native','version/native'),('release/native','scoped/native'),
       ('scoped/native','direct/native'),('scoped/native','owned/native'),('scoped/native','call/native'),
       ('scoped/native','cold/native'),('direct/native','call/native'),('direct/native','cold/native'),
       ('scoped/shift64','direct/native'),('scoped/shift64','owned/native'),('scoped/shift128','direct/shift64')]
for role in ('scoped','direct'):
    pairs += [(role+'/native',role+'/shift64'),(role+'/native',role+'/after64'),(role+'/after64',role+'/shift64')]
pin()
rng = random.Random(361071)
for length in (32,4096):
    def one(label, count):
        return measure(work/'same-short-program',images['scoped/native' if label=='aa' else label],[length,count,'plain'],work/'caller')
    count=max(1000,min(1_000_000,round(25_000_000/one('scoped/native',5000))))
    rows=[]
    for _ in range(32):
        order = list(selected)
        rng.shuffle(order)
        results = {k:[] for k in order}
        for label in order+order[::-1]:
            results[label].append(one(label,count))
        rows.append({k:statistics.mean(v) for k,v in results.items()})
    save(report/(str(length)+'-samples.json'),rows)
    metrics={a+' vs '+b:compare(rows,a,b) for a,b in pairs}
    save(report/(str(length)+'-times.json'),metrics)
    print(length,{k:round(100*(v['ratio']-1),2) for k,v in metrics.items()}, flush=True)
