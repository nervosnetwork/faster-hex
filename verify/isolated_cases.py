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
elif SCOPE=='surface':
    revisions={'release':RELEASE,'version':SAME_VERSION,'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4','scoped':SCOPE_BASE,'fixed':RECOVERY}
    pairs=[('scoped','aa'),('release','version'),('version','scoped'),('release','scoped'),('pr','scoped'),('scoped','fixed'),('pr','fixed'),('release','fixed')]
    cases=[('full_format',n,k) for n in (0,32,513,4096) for k in ('display','alternate','padded')]
    cases += [('append_call',n,k) for n in (32,4096) for k in ('valid','first','middle','rollback')]
    cases += [('prefix_format',n,'display') for n in (7,12,255,1023)]
    cases += [('prefix_buffer',n,'buffer') for n in (0,1,4,7,8,12,40,64)]

elif SCOPE in ('buffer','format'):
    revisions={'release':RELEASE,'version':SAME_VERSION,'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4','scoped':SCOPE_BASE}
    pairs=[('scoped','aa'),('release','version'),('version','scoped'),('release','scoped'),('pr','scoped'),('scoped','candidate'),('pr','candidate'),('release','candidate')]
    if SCOPE=='buffer':
        revisions['candidate']='55d8e79081f72de85e2285c39957950d0597d632'
        cases=[('prefix_buffer',n,'buffer') for n in (0,1,4,7,8,12,16,40,64)]
        cases += [('full_buffer',n,'buffer') for n in (16,32,33,4096)]
    else:
        revisions['single']='bb8a8f67944831913dcd28ffa21b0a66846d44a7'
        revisions['candidate']='e69043ffff7b529cc8a39059b05bab2175450f28'
        pairs+= [('scoped','single'),('single','candidate')]
        cases=[('full_format',n,k) for n in (0,32,513,4096) for k in ('display','alternate','padded')]
        cases += [('prefix_format',n,'display') for n in (7,12,255,1023)]

elif SCOPE=='append':
    revisions={'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4','scoped':SCOPE_BASE,'fixed':RECOVERY,'single':'e03caf6f060d9475f2a79d5994fecf7571eaf4a9','candidate':'1156b979818b562b1f295788e5e0d9ba396b1caf'}
    pairs=[('scoped','aa'),('pr','scoped'),('pr','fixed'),('pr','single'),('pr','candidate'),('single','candidate'),('fixed','candidate')]
    cases=[('append_call',n,k) for n in (32,4096) for k in ('valid','first','middle','rollback')]

elif SCOPE=='validation':
    revisions={'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4','scoped':SCOPE_BASE,'first':'e4d3e5b6088332d72c6a48409dc001902d212cea','group':'c52eb78fee9cb552da89f15dbe21b1adc679a169'}
    pairs=[('scoped','aa'),('pr','scoped'),('scoped','first'),('first','group'),('pr','first'),('pr','group'),('scoped','group')]
    cases=[('validate_call',n,k) for n in (32,4096) for k in ('valid','odd','first','middle','last')]
    cases += [(b,n,k) for b,k in [('legacy_check','valid'),('qualified_decode','valid'),('vec_round_slice','plain')] for n in (32,4096)]
