import re, subprocess as sp
from cause_common import section
def record(binary):
    symbols=sp.check_output(['nm','-anS','--demangle',binary],text=True)
    table=[line for line in symbols.splitlines() if line.strip().endswith('faster_hex::decode::UNHEX4')]
    assert len(table)==1,table
    parts=table[0].split()
    address=int(parts[0],16)
    rows=sp.check_output(['readelf','-Wr',binary],text=True)
    got=section(binary,'.got')
    reloc=[]
    for line in rows.splitlines():
        fields=line.split()
        if len(fields)>=4 and re.fullmatch(r'[a-fA-F0-9]+',fields[0]) and got[0]<=int(fields[0],16)<got[0]+got[1]:
            if fields[2].endswith('_RELATIVE') and int(fields[-1],16)==address:reloc.append(line.strip())
    return {'high_nibble_table':table[0].strip(),'table_relocations_in_got':reloc,'text':section(binary),'got':got,'rela_dyn':section(binary,'.rela.dyn')}
