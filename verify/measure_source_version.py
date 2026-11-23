from pathlib import Path
import hashlib
import json
import os
import shutil
import sys

v=Path(__file__).resolve().parent;sys.path.insert(0,str(v))
import isolated_cases as scope
from cause_common import pin,save,section
from cross_file_copies import crossover
spec=json.loads((v/"source_version_inputs.json").read_text())
refs=spec["refs"];scope.revisions=refs
scope.cases=[("vec_round_slice",4096,"plain")];scope.pairs=[("version/native","candidate/native"), ("release/native","candidate/before-core"),
       ("release/native","candidate/native"), ("release/native","version/native"), ("version/native","pr/native")]
for a,b in pairs:
    x,y=(work/"object-order"/name for name in (a,b));pair=out/(a.replace("/","_")+"-vs-"+b.replace("/","_"))
    if x.read_bytes()==y.read_bytes():
        save(pair/"same.json",{"sha256":hashlib.sha256(x.read_bytes()).hexdigest()})
    else:
        crossover([x,y],out/"fixed-program",work/"caller",pair,[(4096,"plain")])
