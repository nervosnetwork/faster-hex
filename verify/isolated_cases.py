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

elif SCOPE=='prefix-length':
    revisions={'release':RELEASE,'version':SAME_VERSION,'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4','scoped':'42c484112239d78a943735d97125e356f123224a','candidate':'cceed1b3fae514e93807c65e5b26d2007e46fc7e'}
    pairs=[('scoped','aa'),('release','version'),('release','scoped'),('release','candidate'),('pr','scoped'),('scoped','candidate'),('pr','candidate')]
    cases=[('prefix_buffer',n,'buffer') for n in (0,1,4,7,8,16,31,32,40,63,64)]
    cases+=[('prefix_format',n,'display') for n in (7,32,1023)]
    cases+=[('gix_prefix',n,kind+'-adopt') for kind,digits in (('sha1',(0,4,7,8,40)),('sha256',(0,7,32,63,64))) for n in digits]
    cases+=[('gix_prefix',n,kind+'-legacy') for kind,n in (('sha1',7),('sha256',64))]
    cases+=[('full_buffer',n,'buffer') for n in (16,32,4096)]
    cases+=[('full_format',n,'display') for n in (32,513,4096)]
    cases+=[('full_format',32,k) for k in ('alternate','padded')]
    cases+=[(b,n,'plain') for n in (32,4096) for b in ('vec_round_slice','array_round_slice','ckb_caller')]

elif SCOPE=='range-check':
    revisions={'release':RELEASE,'version':SAME_VERSION,'scoped':'42c484112239d78a943735d97125e356f123224a','width':'00b8d795a02cb1812ad740d0871a297b056f6e49','range':'0b3f0f0467b0bccc3224ef12b7b590b9199ee70c'}
    pairs=[('scoped','aa'),('release','version'),('release','scoped')]+[(base,variant) for base in ('scoped','release') for variant in ('width','range')]
    cases=[('ascii_check',n,'mixed-valid') for n in (15,16,17,31,32,63,64,65,128,256,8192,8193)]
    cases+=[('ascii_check',n,how) for n in (64,8192) for how in ('mixed-first','mixed-middle','mixed-last','upper-valid','lower-valid','upper-last','lower-last')]
    cases+=[('qualified_decode',n,'valid') for n in (32,256,4096)]
    cases+=[(target+'_'+phase,n,'plain') for target in ('vec','array') for phase in ('read_slice','write','round_slice') for n in (32,4096)]
    cases+=[('ckb_caller',n,'plain') for n in (32,4096)]+[('gix_caller',n,'parse') for n in (20,32)]

elif SCOPE=='arm-store':
    revisions={'release':RELEASE,'version':SAME_VERSION,'scoped':'42c484112239d78a943735d97125e356f123224a','candidate':'3408ecdfb47ce20435ed9a6860ec47d5dd0e65ad'}
    pairs=[('scoped','aa'),('release','version'),('release','scoped'),('scoped','candidate'),('release','candidate')]
    cases=[('full_buffer',n,'buffer') for n in (8,15,16,20,32,33,64,65,256,4096,4097)]
    cases+=[(target+'_'+phase,n,'plain') for target in ('vec','array') for phase in ('read_slice','write','round_slice') for n in (32,4096)]
    cases+=[('ckb_caller',n,kind) for n in (32,4096) for kind in ('plain','escaped')]
    cases+=[('gix_caller',n,'parse') for n in (20,32)]

elif SCOPE=='short-json':
    revisions={'release':RELEASE,'version':SAME_VERSION,'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4','scoped':'42c484112239d78a943735d97125e356f123224a','direct':'8ccdbc0428d5f20ad8e8383d69eea001549f754d','owned':'7dfaa3ae35b6ee7376c2247f3d3cbbd4ef5912d6','call':'fc834c71026b6d7f81738b53bd73237f408474ff','cold':'3ab653f0ba171618dd175d70331c556d11a9cc08'}
    if os.environ.get('SHORT_JSON_LIGHT')=='1':
        revisions={k:v for k,v in revisions.items() if k not in ('version','owned')}
    pairs=[('scoped','aa'),('release','version'),('release','scoped'),('release','direct'),('release','owned'),('release','call'),('release','cold'),('version','direct'),('version','call'),('version','cold'),('scoped','direct'),('scoped','owned'),('scoped','call'),('scoped','cold'),('direct','call'),('direct','cold'),('pr','direct'),('pr','call'),('pr','cold')]
    cases=[(b,n,'plain') for b in ('vec_read_slice','vec_write','vec_round_slice','array_read_slice','array_round_slice') for n in (32,4096)]
    cases += [(b,n,'escaped') for b in ('vec_read_slice','vec_round_slice','array_read_slice') for n in (32,4096)]
    cases += [('append_call',n,k) for n in (32,256,1025,4096) for k in ('valid','middle','rollback')]
    cases += [('ckb_caller',n,'plain') for n in (32,4096)]+[('gix_caller',20,'parse')]
elif SCOPE=='append-recovery':
    revisions={'release':RELEASE,'version':SAME_VERSION,'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4','scoped':'8ccdbc0428d5f20ad8e8383d69eea001549f754d','candidate':'7dfaa3ae35b6ee7376c2247f3d3cbbd4ef5912d6'}
    pairs=[('scoped','aa'),('release','version'),('release','scoped'),('release','candidate'),('pr','scoped'),('pr','candidate'),('scoped','candidate')]
    cases=[('append_call',n,'valid') for n in (0,16,32,33,64,256,1024,1025,4096,4097)]
    cases += [('append_call',n,k) for n in (32,256,1025,4096) for k in ('first','middle','rollback')]
    cases += [('owned_blocks',n,k) for n in (32,4096) for k in ('array-late','vec-late','array-valid','vec-valid')]
    cases += [('validate_call',n,k) for n in (32,4096) for k in ('first','middle','last','valid')]
    cases += [(b,n,'plain') for b in ('array_round_slice','vec_round_slice','ckb_caller') for n in (32,4096)]
    cases += [('gix_caller',n,'parse') for n in (20,32)]
elif SCOPE=='append-report':
    revisions={'release':RELEASE,'version':SAME_VERSION,'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4','scoped':'073a9f0b089d1354afb3773b3e93616a18fa8cfd','report':'163e41047af2938797b1e7d3f11488837cd22069'}
    pairs=[('scoped','aa'),('release','version'),('release','scoped'),('release','report'),('pr','scoped'),('pr','report'),('scoped','report')]
    cases=[('append_call',n,'valid') for n in (0,1,16,32,33,64,256,1024,1025,4096,4097)]
    cases+=[('append_call',n,k) for n in (32,256,4096) for k in ('first','middle','rollback')]
    cases+=[('owned_blocks',n,k) for n in (32,4096) for k in ('array-valid','vec-valid','array-late','vec-late')]
    cases+=[(b,n,'plain') for b in ('vec_round_slice','array_round_slice') for n in (32,4096)]

elif SCOPE=='append':
    revisions={'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4','scoped':'42c484112239d78a943735d97125e356f123224a','blocks':'9a14e514d93332ef67964742aca12a4730beafb2','plain':'073a9f0b089d1354afb3773b3e93616a18fa8cfd','outline':'3eb357d81f919095b12f72723dfdfd5a3ad1de5d'}
    pairs=[('scoped','aa'),('pr','scoped')] + [(base,role) for base in ('pr','scoped') for role in ('blocks','plain','outline')]+[('blocks','plain'),('blocks','outline')]
    cases=[('append_call',n,'valid') for n in (1,16,32,33,64,256,1024,1025,4096,4097)]
    cases+= [('append_call',n,k) for n in (32,256,4096) for k in ('first','middle','rollback')]
    cases+= [('qualified_decode',n,'valid') for n in (32,4096)]
    cases+= [('vec_round_slice',n,'plain') for n in (32,4096)]

elif SCOPE=='validation':
    revisions={'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4','scoped':SCOPE_BASE,'policy':'286e072562e67ff47cab33b1816cd6e02135e90d','review':'c1c7a8fa74489546e1c9623d0dbb7aec2d25470c','integrated':'256e5df62ca1d457557e7083d73f78b1120a4615','shared':'b7bc8baef3c902c230351dc489a648f575eed559'}
    pairs=[('scoped','aa'),('pr','scoped'),('scoped','policy'),('pr','policy'),('pr','review'),('review','integrated'),('pr','integrated'),('policy','integrated'),('integrated','shared'),('review','shared'),('pr','shared')]
    cases=[('validate_call',n,k) for n in (32,4096) for k in ('valid','odd','first','middle','last')]
    cases += [(b,n,k) for b,k in [('legacy_check','valid'),('qualified_decode','valid'),('vec_round_slice','plain')] for n in (32,4096)]
    cases += [('append_call',n,k) for n in (32,4096) for k in ('valid','first','middle','rollback')]

elif SCOPE=='release-audit':
    revisions={'release':RELEASE, 'version':SAME_VERSION, 'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4', 'scoped':os.environ['AUDIT_SHA']}
    pairs=[('scoped','aa'),('release','version'),('version','scoped'),('release','scoped'),('pr','scoped')]
    if os.environ.get('INTEGRATED_RELEASE') == '1':
        revisions['narrow']=SCOPE_BASE
        revisions.update({'diagnosis': '629412c03a45984dba610b62535e89658b793145', 'owned': '88eccb90f29402f8e2a0b00d1d5d0a72b05f91bd', 'formatter': '30a07ceb94ae075b2fef34cbb53aa2c9dcc99d56', 'combined': '518128a32856beed0436b53e450ad7a34652eb4b', 'view': '52211f708ad51eb3ee48292ca863ea7c0d00deb1'})
        pairs += [('release','pr'),('release','narrow'),('narrow','scoped'),('view','view_control'),('combined','combined_control')]
        pairs += [(base,candidate) for base in ('release','version','pr','narrow','scoped') for candidate in ('diagnosis','owned','formatter','combined','view')]
        pairs += [('diagnosis','owned'),('owned','combined'),('formatter','combined'),('combined','view'),('diagnosis','combined')]
    if os.environ.get('INTEGRATED_CONFIRM')=='1':
        revisions['narrow']=SCOPE_BASE
        revisions.update({'owned': '88eccb90f29402f8e2a0b00d1d5d0a72b05f91bd', 'combined': '518128a32856beed0436b53e450ad7a34652eb4b', 'selected': 'f644d94914f90127dfe2f3eb697fd5575eea8e85', 'pairs': 'ceed2f88ba940dfea800cd9dfccea1174cdbdc6b', 'windows': '1009af415033f1348184846c5dd2defe73d3b794'})
        pairs=[('combined','aa'),('windows','windows_control'),('release','version'),('release','narrow'),('release','pr')]
        pairs += [(a,b) for a in ('release','version','pr','narrow','scoped') for b in ('owned','combined','selected','pairs','windows')]
        pairs += [('owned','combined'),('combined','selected'),('combined','pairs'),('pairs','windows'),('combined','windows')]
    cases=[('full_buffer',n,'buffer') for n in (8,16,32,65,4096)]
    cases += [('qualified_decode',n,'valid') for n in (16,32,4096)]
    cases += [('legacy_check',n,'valid') for n in (32,4096)]
    cases += [('owned_blocks',n,k) for n in (32,4096) for k in ('array-valid','vec-valid','array-late','vec-late')]
    cases += [('full_format',n,k) for n,k in ((32,'display'),(32,'alternate'),(513,'padded'),(4096,'display'))]
    cases += [('validate_call',n,k) for n in (32,4096) for k in ('valid','odd','first','middle','last')]
    cases += [('append_call',n,'valid') for n in (0,16,32,33,64,256,1024,1025,4096,4097)]
    cases += [('append_call',n,k) for n in (32,256,4096) for k in ('first','middle','rollback')]
    cases += [('prefix_buffer',n,'buffer') for n in (0,4,7,8,12,40,64)]
    cases += [('prefix_format',n,'display') for n in (7,12,1023)]
    cases += [('gix_prefix',n,k+'-adopt') for k,ns in (('sha1',(0,7,40)),('sha256',(0,7,64))) for n in ns]
    cases += [('gix_caller',n,'parse') for n in (20,32)]
    cases += [('ckb_caller',n,k) for n in (32,4096) for k in ('plain','escaped')]
    for target in ('array','vec'):
        for n in (32,4096):
            for phase,kind in (('read_slice','plain'),('read_slice','escaped'),('read_reader','reader'),('write','plain'),('round_slice','plain'),('round_slice','escaped'),('round_reader','reader')):
                cases.append((target+'_'+phase,n,kind))
    assert len(cases)==len(set(cases))==101
    if os.environ.get('DIAGNOSTIC_ROUTE')=='1':
        revisions.update({'narrow': '976abc9503a22c1b24beb54182add19af097f098', 'lanes': '6781415032ba193c1bf0032a220ed1be4efc5c14', 'cold': '3c163709927c1c2eb9bcff6ef037690d57046003', 'local': '014fc8ca8d3e10887ef2350c098027547ce5d292'})
        pairs=[('scoped','aa'),('local','local_control'),('cold','cold_control'),('release','version'),('release','pr'),('release','narrow'),('version','narrow')]
        pairs += [(a,b) for a in ('release','version','pr','narrow') for b in ('scoped','lanes','cold','local')]
        pairs += [('scoped','lanes'),('scoped','cold'),('scoped','local'),('lanes','cold'),('lanes','local'),('cold','local')]
        cases=[('owned_blocks',n,kind) for n in (32,4096) for kind in ('array-valid','array-late','vec-valid','vec-late')]
        cases+=[('owned_failure',n,kind) for n in (32,4096) for kind in ('array-first','array-middle','vec-first','vec-middle')]
        cases+=[(op,n,kind) for op in ('vec_read_slice','array_read_slice','vec_round_slice','array_round_slice') for n,kind in ((32,'escaped'),(4096,'plain'))]
        cases += [('qualified_decode',n,'valid') for n in (16,32,4096)]
        cases += [('vec_write',4096,'plain'),('vec_read_slice',32,'plain'),('vec_round_slice',4096,'escaped'),('ckb_caller',32,'plain'),('ckb_caller',4096,'plain'),('gix_caller',20,'parse'),('append_call',32,'first'),('append_call',256,'first'),('gix_prefix',7,'sha1-adopt')]
        cases += [('mask_slice',n,kind) for n in (31,32,33) for kind in ('mixed-valid','upper-last','lower-first')]
        cases += [('mask_slice',32,'mixed-both')]
    if os.environ.get('DIAGNOSTIC_STEPS')=='1':
        revisions.update({'plain': '10346c96e8b2ea41558211936a975de94a440163', 'first': 'a3d45d8deaff30834d8d330f3401d629f031c246', 'groups': '075ab5a3bb18542a634f2a3af5d73bd283a47c83'})
        pairs=[('scoped','aa'),('groups','groups_control'),('release','version'),('release','pr'),('release','scoped'),('pr','scoped')]
        pairs += [(a,b) for a in ('release','version','pr') for b in ('plain','first','groups')]
        pairs += [('plain','first'),('plain','groups'),('plain','scoped'),('groups','scoped'),('first','scoped'),('first','groups')]
        include={('vec_read_slice',32,'escaped'),('array_read_slice',32,'escaped'),('vec_round_slice',32,'escaped'),
                 ('vec_read_slice',32,'plain'),('array_read_slice',32,'plain'),
                 ('vec_round_slice',4096,'plain'),('array_round_slice',4096,'plain'),
                 ('vec_read_slice',4096,'plain'),('vec_write',4096,'plain'),
                 ('gix_prefix',7,'sha1-adopt'),('gix_caller',20,'parse'),('ckb_caller',32,'escaped'),('ckb_caller',4096,'plain'),
                 ('append_call',32,'first'),('append_call',32,'rollback'),('append_call',256,'middle'),('append_call',4096,'rollback'),
                 ('append_call',32,'valid'),('append_call',4097,'valid'),('append_call',1025,'valid')}
        cases=[(b,n,k) for b,n,k in cases if b in ('qualified_decode','owned_blocks') or (b=='validate_call' and k in ('valid','first','last')) or (b,n,k) in include]
        assert len(cases)==len(set(cases))==37

    if os.environ.get('PREFIX_ENTRY')=='1':
        revisions.update({'donor': '09a50778d4d210a27fcaba7cc993a18e918ca4f6', 'bounded': 'd1ffe8ee992bd5267eced3c3e4b7e34340beb664'})
        pairs=[('scoped','aa'),('bounded','bounded_control'),('release','version'),('release','pr'),('release','scoped'),('pr','scoped')]
        pairs += [(a,b) for a in ('release','version','pr','scoped') for b in ('donor','bounded')]
        pairs += [('donor','bounded')]
        controls={('qualified_decode',4096,'valid'),('array_read_slice',32,'escaped'),('vec_read_slice',32,'escaped'),
                  ('vec_round_slice',32,'escaped'),('array_read_slice',32,'plain'),('vec_read_slice',32,'plain'),
                  ('vec_round_slice',4096,'plain'),('array_round_slice',4096,'plain'),
                  ('ckb_caller',32,'plain'),('gix_caller',20,'parse'),('full_format',32,'alternate'),
                  ('append_call',32,'valid'),('validate_call',32,'last')}
        cases=[(b,n,k) for b,n,k in cases if b in ('prefix_buffer','prefix_format','gix_prefix','full_buffer') or (b,n,k) in controls]
        cases += [('prefix_extent',n,k) for n in (7,30,31,32,33,62,63,64,65,66,127,8192) for k in ('exact','spare')]
        assert len(set(cases))==len(cases)==58

    if os.environ.get('DIAGNOSTIC_BOUNDARY')=='1':
        revisions.update({'direct': '407cf594016b39c7bd338e5cdf375af69b40de73', 'split': 'a0b6d03c6a695968ed8de260cdb1085c3d02b0f6'})
        pairs=[('scoped','aa'),('split','split_control'),('release','version'),('release','pr'),('release','scoped'),('pr','scoped')]
        pairs += [(a,b) for a in ('release','version','pr','scoped') for b in ('direct','split')]
        pairs += [('direct','split')]
        selected={
            ('qualified_decode',32,'valid'),('qualified_decode',4096,'valid'),
            ('gix_caller',20,'parse'),('gix_prefix',7,'sha1-adopt'),('full_format',32,'alternate'),
            ('validate_call',32,'valid'),('validate_call',32,'first'),('validate_call',32,'last'),('validate_call',4096,'last'),
            ('append_call',32,'valid'),('append_call',1025,'valid'),('append_call',4097,'valid'),
            ('append_call',32,'first'),('append_call',256,'middle'),('append_call',4096,'rollback')}
        cases=[(op,n,k) for op,n,k in cases if op.startswith(('array_','vec_')) or op in ('owned_blocks','ckb_caller') or (op,n,k) in selected]
        assert len(set(cases))==55


elif SCOPE in ('legacy-errors','bounded-errors'):
    revisions={'release':RELEASE,'version':SAME_VERSION,'narrow':SCOPE_BASE,'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4','scoped':'fc834c71026b6d7f81738b53bd73237f408474ff','group':'8800debd7a36c84ba8a0ec455b9d1c4705cad6ba','one':'5ea9c7a3bb98706a5dcfa7eb36b0b37920109f4d'}
    if os.environ.get('LEGACY_LIGHT')=='1':
        revisions.pop('narrow')
    pairs=[('scoped','aa'),('release','version'),('release','narrow'),('narrow','scoped'),('release','scoped'),('release','group'),('release','one'),('version','group'),('version','one'),('scoped','group'),('group','one'),('scoped','one'),('pr','scoped'),('pr','group'),('pr','one')]
    cases=[('owned_blocks',n,k) for n in (32,4096) for k in ('array-valid','array-late','vec-valid','vec-late')]
    cases += [('legacy_error_positions',32,k) for k in ('mixed-first','mixed-second','mixed-middle','mixed-last','lower-last','upper-last')]
    cases += [('legacy_error_positions',4096,k) for k in ('mixed-first','mixed-boundary','lower-middle','upper-last')]
    cases += [('qualified_decode',n,'valid') for n in (16,32,4096)]
    cases += [('append_call',n,k) for n,k in ((32,'valid'),(256,'valid'),(256,'middle'),(256,'rollback'),(1025,'valid'),(4096,'valid'),(4096,'rollback'))]
    cases += [('validate_call',32,k) for k in ('valid','first','last')]
    cases += [(b,n,k) for n in (32,4096) for b,k in (('vec_round_slice','plain'),('vec_round_slice','escaped'),('vec_read_slice','plain'),('array_read_slice','plain'),('array_round_slice','plain'))]
    cases += [('ckb_caller',n,'plain') for n in (32,4096)]+[('gix_caller',20,'parse')]
    assert len(cases)==len(set(cases))==44

    if SCOPE == 'bounded-errors':
        revisions.pop('narrow',None)
        revisions.pop('one')
        revisions['bounded']='54ef1bbac826a9e43dc2cb42456addf0ab23032c'
        pairs=[p for p in pairs if 'one' not in p and 'narrow' not in p]
        pairs += [(r,'bounded') for r in ('release','version','pr','scoped','group')]
        cases += [('legacy_error_positions',n,k) for n in (31,33,64,65) for k in ('mixed-first','mixed-middle','mixed-last')]
        assert len(cases)==len(set(cases))==56

elif SCOPE == 'append-storage':
    revisions = {
        'release': RELEASE,
        'version': SAME_VERSION,
        'pr': '25cfd8eb6a4cd8257a96fabaf73771cabcced4b4',
        'scoped': 'fc834c71026b6d7f81738b53bd73237f408474ff',
        'staged': '1ef4f422595bbe5021d7d6afc714dddbd036e493',
    }
    pairs = [('scoped', 'aa'), ('release', 'version'), ('release', 'pr'),
             ('release', 'scoped'), ('release', 'staged'), ('version', 'staged'),
             ('pr', 'scoped'), ('pr', 'staged'), ('scoped', 'staged')]
    cases = [('append_call',n,'valid') for n in (0,16,32,33,64,256,1024,1025,4096,4097)]
    cases += [('append_call',n,k) for n in (32,256,1025,4096) for k in ('first','middle','rollback')]
    storage = ('reuse-0-0-valid','reuse-0-3-valid','reuse-0-31-valid','reuse-0-63-valid',
               'reuse-1-3-valid','reuse-0-3-late','grow-0-0-valid','grow-0-0-late',
               'slice-0-3-valid','zero-0-3-valid')
    cases += [('append_storage',n,k) for n in (256,1025,4096) for k in storage]
    cases += [('owned_blocks',32,k) for k in ('array-late','vec-late','array-valid','vec-valid')]
    cases += [('qualified_decode',n,'valid') for n in (32,4096)]
    cases += [('vec_round_slice',n,k) for n in (32,4096) for k in ('plain','escaped')]
    cases += [('array_round_slice',n,'plain') for n in (32,4096)]
    cases += [('ckb_caller',n,'plain') for n in (32,4096)] + [('gix_caller',20,'parse')]
    assert len(cases)==len(set(cases))==67

elif SCOPE in ('append-callsite', 'append-suffix'):
    revisions = {
        'release': RELEASE, 'version': SAME_VERSION,
        'pr': '25cfd8eb6a4cd8257a96fabaf73771cabcced4b4',
        'scoped': 'fc834c71026b6d7f81738b53bd73237f408474ff',
        'ordinary': '458fb61c74dcbcc99549d296b158656acbc5505c',
    }
    pairs = [('scoped','aa'),('release','version'),('release','pr'),
             ('release','scoped'),('release','ordinary'),('version','ordinary'),
             ('pr','scoped'),('pr','ordinary'),('scoped','ordinary')]
    cases = [('append_call',n,'valid') for n in (0,16,32,33,64,256,1024,1025,4096,4097)]
    cases += [('append_call',n,k) for n in (32,256,4096) for k in ('first','middle','rollback')]
    cases += [('append_callsite',n,k+'-valid') for n in (32,256,1025,4096)
              for k in ('direct','api','wrapper')]
    cases += [('append_callsite',256,k+'-rollback') for k in ('direct','api','wrapper')]
    cases += [('owned_blocks',n,k) for n in (32,4096)
              for k in ('array-valid','vec-valid','array-late','vec-late')]
    cases += [(b,n,k) for n in (32,4096) for b,k in
              (('vec_round_slice','plain'),('vec_round_slice','escaped'),('array_round_slice','plain'),
               ('array_read_slice','plain'),('vec_read_slice','plain'))]
    cases += [('qualified_decode',n,'valid') for n in (32,4096)]
    cases += [('ckb_caller',n,'plain') for n in (32,4096)] + [('gix_caller',20,'parse')]
    assert len(cases)==len(set(cases))==57

    if SCOPE == 'append-suffix':
        revisions['suffix']='bb1eecaff85fd359f2c717cffcae0d9f99d6f2c3'
        pairs.extend((r,'suffix') for r in ('release','version','pr','scoped','ordinary'))
        cases += [('append_result',n,how) for n in (32,256,1025,4096) for how in ('opaque','suffix','status')]
        assert len(cases)==len(set(cases))==69

elif SCOPE in ('prefix-kernel-exchange','prefix-operation'):
    revisions = {
        'release': RELEASE, 'version': SAME_VERSION, 'narrow': SCOPE_BASE,
        'pr': '25cfd8eb6a4cd8257a96fabaf73771cabcced4b4',
        'scoped': 'fc834c71026b6d7f81738b53bd73237f408474ff',
        'pr_native': '2680b238f7c5c211aed329a70c8a30c669570ec9',
        'scoped_native': '6a3053149201aa89a8d76e32754c2fa1ffd9b598',
        'window': '2cb6384a8206ff598b3c811c15dbe28ddee7ba4d',
    }
    pairs=[('scoped','aa'),('release','version'),('release','narrow'),('release','pr'),
           ('release','scoped'),('pr','scoped'),('narrow','scoped')]
    pairs += [(left,right) for right in ('pr_native','scoped_native','window')
              for left in ('release','version','pr','scoped')]
    pairs += [('pr_native','scoped'),('pr','scoped_native'),('scoped_native','window')]
    pairs=list(dict.fromkeys(pairs))
    cases=[('full_buffer',n,'buffer') for n in (4,7,8,15,16,17,20,31,32,33,63,64,65,66,128,4096,65536)]
    cases += [('prefix_buffer',n,'buffer') for n in (0,1,3,4,6,7,8,12,15,16,31,40,63,64)]
    cases += [('gix_prefix',n,k+'-adopt') for k,ns in (('sha1',(0,7,40)),('sha256',(0,7,64))) for n in ns]
    cases += [('prefix_format',n,'display') for n in (7,12,1023)]
    cases += [('full_format',n,k) for n,k in ((32,'display'),(32,'alternate'),(513,'padded'),(4096,'display'))]
    cases += [(k,n,'plain') for k in ('vec_round_slice','array_round_slice','ckb_caller') for n in (32,4096)]
    cases += [('vec_round_slice',4096,'escaped'),('gix_caller',20,'parse'),('gix_caller',32,'parse')]
    cases += [('append_call',n,'valid') for n in (256,1025)]
    assert len(cases)==len(set(cases))==55

    if SCOPE == 'prefix-operation':
        for role in ('pr_native','scoped_native','window'):
            del revisions[role]
        revisions.update({'earlier': '4edae506b3b7145958c8b2356189473f5c49cd44', 'policy': '24b99b7a5e532edc8ea9a421e2d23c5e0c687aca'})
        pairs=[(a,b) for a,b in pairs if a in revisions and (b in revisions or b=='aa')]
        pairs += [(a,b) for a in ('pr','scoped','release','version') for b in ('earlier','policy')]
        pairs += [('earlier','policy')]
        cases += [('prefix_extent',n,view) for n in (7,63,64,65,127,1023,8191,8192) for view in ('exact','spare')]
        assert len(cases)==len(set(cases))==71

elif SCOPE == 'append-fill':
    revisions={'release':RELEASE,'version':SAME_VERSION,'narrow':SCOPE_BASE,
           'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4',
           'scoped':'fc834c71026b6d7f81738b53bd73237f408474ff'}
    revisions.update({'initialized': 'd5d53be1e11a718e9326a675e4cc7fc40e3aa216', 'extend': '6c068d01dd224f4cd6343a530105c10c77c3a5ad', 'native': '7c8a78d50e68d3aa9782576d9d7a5e5c7ec40887'})
    pairs=[('scoped','aa'),('release','version'),('release','pr'),('release','narrow'),
           ('release','scoped'),('pr','scoped'),('narrow','scoped')]
    pairs += [(left,right) for left in ('release','version','pr','scoped') for right in ('initialized','extend','native')]
    pairs += [('initialized','extend'),('native','extend'),('native','initialized')]
    cases=[('append_call',n,'valid') for n in (0,1,16,32,33,64,256,1024,1025,4096,4097,65536)]
    cases += [('append_call',n,k) for n in (32,256,1025,4096) for k in ('first','middle','rollback')]
    cases += [('append_storage',n,k) for n in (256,1025,4096) for k in
             ('reuse-0-3-valid','reuse-0-31-valid','reuse-1-3-valid','grow-0-0-valid','reuse-0-3-late','zero-0-3-valid','slice-0-3-valid')]
    cases += [('validate_call',n,'valid') for n in (32,256,4096)]
    cases += [('owned_blocks',n,k) for n in (32,4096) for k in ('array-valid','array-late','vec-valid','vec-late')]
    cases += [('qualified_decode',n,'valid') for n in (32,4096)]
    cases += [(b,n,k) for n in (32,4096) for b,k in [('vec_round_slice','plain'),('vec_round_slice','escaped'),('array_round_slice','plain'),('ckb_caller','plain')]]
    cases += [('gix_caller',20,'parse')]
    assert len(cases)==len(set(cases))==67

elif SCOPE == 'append-shape':
    revisions={'release':RELEASE,'version':SAME_VERSION,'narrow':SCOPE_BASE,
               'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4',
               'scoped':'fc834c71026b6d7f81738b53bd73237f408474ff',
               'ordinary':'458fb61c74dcbcc99549d296b158656acbc5505c',
               'extend':'6c068d01dd224f4cd6343a530105c10c77c3a5ad',
               'staged':'1ef4f422595bbe5021d7d6afc714dddbd036e493'}
    revisions.update({'pr_inline': 'e24615c55ab943fdc2d8b3173c6ff60d4713d3af', 'grouped': 'c80ecfa97e0ee3a444d3bc5044594a3f73dfa7ec', 'array': 'eb8257c9a923db04550108e1703842999f1b3a8f'})
    pairs=[('scoped','aa'),('release','version'),('release','narrow'),('narrow','scoped'),('release','pr'),('release','scoped'),('pr','scoped')]
    pairs += [(left,right) for left in ('release','pr','scoped') for right in ('pr_inline','ordinary','extend','grouped','staged','array')]
    pairs += [('pr_inline','scoped'),('pr_inline','ordinary'),('extend','grouped'),('staged','array'),('grouped','array')]
    pairs=list(dict.fromkeys(pairs))
    cases=[('append_call',n,'valid') for n in (0,1,16,31,32,33,63,64,65,256,1024,1025,4096,4097,65536)]
    cases += [('append_call',n,k) for n in (32,256,4096) for k in ('first','middle','rollback')]
    cases += [('append_callsite',n,k+'-valid') for n in (256,4096) for k in ('direct','api','wrapper')]
    cases += [('append_storage',n,k) for n in (256,4096) for k in ('reuse-0-3-valid','reuse-0-3-late','grow-0-0-valid')]
    cases += [('vec_round_slice',4096,k) for k in ('plain','escaped')]
    cases += [(b,n,k) for n in (32,4096) for b,k in (('array_round_slice','plain'),('ckb_caller','plain'),('owned_blocks','vec-late'),('qualified_decode','valid'))]
    cases += [('gix_caller',20,'parse')]
    assert len(cases)==len(set(cases))==47

elif SCOPE == 'fmt-field':
    revisions={'release':RELEASE,'version':SAME_VERSION,'narrow':SCOPE_BASE,
      'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4','scoped':'fc834c71026b6d7f81738b53bd73237f408474ff'}
    revisions.update({'coalesced': '283da6a91a455190fd1de9cf17dd8d3d12063276', 'separate': 'fe7d49d673b66c6c519369e78f87842a19faf5e4', 'plain': '6440b73e3bb5f68fd335af4adec1bc000586a8ce', 'typed': '315a34ee891d1ab290a1e5e6db842b428a2bb546'})
    pairs=[('scoped','aa'),('release','version'),('release','narrow'),('release','pr'),('release','scoped'),('pr','scoped'),('version','scoped')]
    pairs += [(a,b) for a in ('release','version','pr','scoped') for b in ('coalesced','separate','plain','typed')]
    pairs += [('coalesced','plain'),('coalesced','typed'),('plain','typed')]
    cases=[('full_format',n,k) for n,k in ((0,'display'),(7,'display'),(32,'display'),(32,'alternate'),(32,'padded'),(128,'display'),(129,'display'),(512,'display'),(513,'padded'),(4096,'display'))]
    cases += [('fmt_sink',32,k) for k in ('display','upper','alternate','both','small-width','zero','unicode')]
    cases += [('fmt_sink',n,k) for n,k in ((0,'both'),(20,'both'),(128,'upper'),(129,'upper'),(513,'unicode'),(4096,'upper'))]
    cases += [('prefix_format',n,'display') for n in (7,12,255,256,257,1023,1024)]
    cases += [('gix_prefix',n,k+'-adopt') for k,ns in (('sha1',(0,7,40)),('sha256',(0,7,64))) for n in ns]
    cases += [('prefix_buffer',n,'buffer') for n in (4,7,64)]
    cases += [('ckb_caller',n,'plain') for n in (32,4096)]
    cases += [(b,4096,k) for b in ('vec_round_slice','array_round_slice') for k in ('plain','escaped')]
    cases += [('owned_blocks',n,k) for n,k in ((32,'array-late'),(32,'vec-late'),(4096,'vec-late'))]
    cases += [('full_buffer',65,'buffer'),('append_call',256,'valid'),('append_call',1025,'valid'),('gix_caller',20,'parse')]
    assert len(cases)==len(set(cases))==52

elif SCOPE == 'fmt-join':
    revisions={'release':RELEASE,'version':SAME_VERSION,'narrow':SCOPE_BASE,
      'pr':'25cfd8eb6a4cd8257a96fabaf73771cabcced4b4','scoped':'fc834c71026b6d7f81738b53bd73237f408474ff',
      'coalesced':'283da6a91a455190fd1de9cf17dd8d3d12063276'}
    revisions.update({'header': '58dd3686dfa8f0a7e92a87d5eb656d72a67945f1', 'joined': 'f3fb72cb2e941f4f821eec6dd21ab49d62aefc28', 'safe': 'c2b79d9b53fb41d981db5359b30884eff34b2e0e'})
    pairs=[('scoped','aa'),('release','version'),('release','narrow'),('release','pr'),('release','scoped'),('release','coalesced'),('pr','scoped'),('pr','coalesced'),('scoped','coalesced')]
    pairs += [(a,b) for a in ('release','version','pr','scoped','coalesced') for b in ('header','joined','safe')]
    pairs += [('header','joined'),('safe','joined')]
    cases=[('full_format',n,k) for n,k in ((32,'display'),(32,'alternate'),(32,'padded'),(513,'padded'),(4096,'display'))]
    cases += [('fmt_sink',32,k) for k in ('display','upper','alternate','both','zero','unicode')]
    cases += [('fmt_sink',n,'both') for n in (0,20,65,128,129,4096)]
    cases += [('fmt_reject',n,'both') for n in (32,128,129)]
    cases += [('serde_tag',n,k) for n in (32,65,66,67,4096) for k in ('tag-lower','bare-upper')]
    cases += [('serde_tag',32,k) for k in ('tag-upper','bare-lower')]
    cases += [(b,n,'plain') for b in ('array_write','vec_write','array_round_slice','vec_round_slice','ckb_caller') for n in (32,4096)]
    cases += [(b,4096,'escaped') for b in ('array_round_slice','vec_round_slice')]
    cases += [('prefix_format',n,'display') for n in (7,12,1023)]
    cases += [('gix_prefix',7,'sha1-adopt'),('full_buffer',65,'buffer'),('append_call',256,'valid')]
    assert len(cases)==len(set(cases))==50

if os.environ.get("PR_BULK_REMAINDER") == "1":
    from pr_encode_residual_cases import revisions, cases, pairs
