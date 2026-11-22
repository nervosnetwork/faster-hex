import os
from pathlib import Path

SCOPE=os.environ['ISOLATE']
RELEASE='6d84260fe321669e7f93ecfb8aecb4db0f582f14'
SAME_VERSION='f83d1075a7945c2dfe56ee7b94d9b6b1783cdf93'
SCOPE_BASE='976abc9503a22c1b24beb54182add19af097f098'
APPEND='c2858276c1485881c1da8854c5fe1741d9df7cd9'
RECOVERY='cc708c2c0bf91275ad2685b71b5d4ee254b78d49'
VISITOR='851cb3a1cf892b01542e34b1485d85358cc84284'
if SCOPE=='visitor':
    revisions={'release': RELEASE,'scoped':SCOPE_BASE,'visitor':VISITOR}
    pairs=[('scoped','aa'),('scoped','visitor'),('release','scoped'),('release','visitor')]
    cases=[]
    for target in ('array','vec'):
        for n in (32,4096):
            for phase,kind in [('read_slice','plain'),('read_slice','escaped'),('read_reader','reader'),('write','plain'),('round_slice','plain'),('round_slice','escaped'),('round_reader','reader')]:
                cases.append((target+'_'+phase,n,kind))
elif SCOPE=='recovery':
    revisions={'release':RELEASE,'version':SAME_VERSION,'scoped':SCOPE_BASE,'append':APPEND,'fixed':RECOVERY}
    pairs=[('scoped','aa'),('release','version'),('version','scoped'),('scoped','append'),('append','fixed'),('scoped','fixed'),('release','fixed')]
    cases=[(target,n,'plain') for target in ('array_round_slice','vec_round_slice','vec_read_slice') for n in (32,4096)]

elif SCOPE=='owned':
    revisions={'release':RELEASE,'scoped':SCOPE_BASE,'owned':'b6967d9c519b1a0c3e47ea435f678b2b2d601058'}
    pairs=[('scoped','aa'),('release','scoped'),('scoped','owned'),('release','owned')]
    cases=[(target,n,kind) for target,kind in [('vec_read_slice','plain'),('vec_round_slice','plain'),('vec_read_slice','escaped'),('vec_round_reader','reader'),('optvec_read_slice','plain'),('array_read_slice','plain'),('array_round_slice','plain')] for n in (32,4096)]
else:
    assert SCOPE=='surface'
    revisions={'release':RELEASE,'version':SAME_VERSION,'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4','scoped':SCOPE_BASE,'fixed':RECOVERY}
    pairs=[('scoped','aa'),('release','version'),('version','scoped'),('release','scoped'),('pr','scoped'),('scoped','fixed'),('pr','fixed'),('release','fixed')]
    cases=[('full_format',n,k) for n in (0,32,513,4096) for k in ('display','alternate','padded')]
    cases += [('append_call',n,k) for n in (32,4096) for k in ('valid','first','middle','rollback')]
    cases += [('prefix_format',n,'display') for n in (7,12,255,1023)]
    cases += [('prefix_buffer',n,'buffer') for n in (0,1,4,7,8,12,40,64)]
