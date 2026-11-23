"""Repeat the two unclassified old entry points on their original processor models."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

v = Path(__file__).resolve().parent
sys.path.insert(0, str(v))
import isolated_cases as scope
from cause_common import pin, save, section
from cross_file_copies import crossover

inputs = json.loads((v / "remaining_existing_inputs.json").read_text())
scope.revisions = inputs["refs"]
arm = os.environ["PROFILE"] == "default"
op, case = ("vec_round_slice", (4096, "escaped")) if arm else ("qualified_decode", (4096, "valid"))
scope.cases = [(op, *case)]
scope.pairs = []
driver = v / "isolate_callers.py"
source, stop, _ = driver.read_text().partition("\npin();rng=")
assert stop
guard = "    if SCOPE in ('fmt-join','fmt-field','prefix-length','release-audit','prefix-kernel-exchange','prefix-operation') and role in ('release','version'):"
assert source.count(guard) == 1
source = source.replace(guard, guard[:-1] + " and 'gix_prefix' in bins:")
context = {"__name__":"__main__", "__file__":str(driver)}
exec(compile(source,str(driver),"exec"),context)
out, work = context["out"], context["work"]
host = json.loads((out / "host.json").read_text())
model, = re.findall(r"^Model name:\s*(.*?)\s*$", host["cpu"], re.M)
assert model == ("Neoverse-N2" if arm else "AMD EPYC 7763 64-Core Processor"), model
archives = json.loads((out.parent / "archives.json").read_text())
assert {a["role"]:a["sha"] for a in archives} == scope.revisions
assert next(a["checksum"] for a in archives if a["role"]=="release") == context["PUBLISHED"]
assert subprocess.check_output(["git","diff","--name-only",scope.revisions["release"],scope.revisions["version"]],cwd=v.parent,text=True).strip()=="Cargo.toml"
images = {s:out/(s+"-"+op) for s in scope.revisions}
sections = {s:{label:section(file,label) for label in (".text",".rodata")} for s,file in images.items()}
save(out/"fingerprints.json",sections)
for role, expected in inputs["anchors"][op].items():
    assert all(sections[role][label]==value for label,value in expected.items()), (role,op,expected,sections[role])
pin()
for a,b in [("version","candidate"),("release","candidate"),("release","pr"),("release","version")]:
    sample = out/(a+"-vs-"+b)
    if images[a].read_bytes() == images[b].read_bytes():
        save(sample/"same.json",{"sha256":hashlib.sha256(images[a].read_bytes()).hexdigest()})
    else:
        crossover([images[a],images[b]],out/"fixed-program",work/"caller",sample,[case])
