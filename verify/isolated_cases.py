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
else:
    assert SCOPE=='recovery'
    revisions={'release':RELEASE,'version':SAME_VERSION,'scoped':SCOPE_BASE,'append':APPEND,'fixed':RECOVERY}
    pairs=[('scoped','aa'),('release','version'),('version','scoped'),('scoped','append'),('append','fixed'),('scoped','fixed'),('release','fixed')]
    cases=[(target,n,'plain') for target in ('array_round_slice','vec_round_slice','vec_read_slice') for n in (32,4096)]
