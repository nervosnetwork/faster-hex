"""Measure where the released and version-only downstream programs spend CPU time."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys

v = Path(__file__).resolve().parent
sys.path.insert(0, str(v))
from cause_common import pin, save

source = v / "pr_components.py"
build, sep, _ = source.read_text().partition("\npin()\n")
assert sep
build = build.replace("v/'pr_component_inputs.json'", "v/'n2_paired_profile_inputs.json'")
start = build.index("fixed=[('qualified_decode'")
end = build.index("scope.revisions=", start)
build = build[:start] + "fixed=[('vec_round_slice',4096,'plain')]\n" + build[end:]
scope = {"__name__": "__main__", "__file__": str(source)}
exec(compile(build, str(source), "exec"), scope)
out, work = scope["out"], scope["work"]
assert all(scope["checks"].values())
assert "Neoverse-N2" in json.loads((out / "host.json").read_text())["cpu"]
pin()

profile = out / "profile"
profile.mkdir()
profiler = shutil.which("gprofng") or shutil.which("aarch64-linux-gnu-gprofng")
assert profiler
env = dict(os.environ, LC_ALL="C")
rows = []
for role in ("release", "version", "combined_paths"):
    exe = out / (role + "-vec_round_slice")
    shutil.copyfile(exe, profile / (role + ".elf"))
    symbols = subprocess.check_output(["nm", "-nS", "-C", "--defined-only", exe], text=True)
    (profile / (role + "-symbols.txt")).write_text(symbols)

# Use equal iteration counts and alternate which program goes first. Timing
# without the sampler distinguishes a profile-induced change from the original loss.
for pair in range(10):
    roles = ["release", "version"] if pair < 8 else ["version", "combined_paths"]
    if pair % 2:
        roles.reverse()
    for role in roles:
        name = f"p{pair:02d}-{role}"
        exe = out / (role + "-vec_round_slice")
        argv = ["4096", "1000000", "plain"]
        normal = subprocess.check_output([exe, "4096", "220000", "plain"], cwd=work/"caller", text=True)
        experiment = work / (name + ".er")
        cmd = [profiler, "collect", "app", "-p", "hi", "-o", str(experiment), str(exe), *argv]
        result = subprocess.run(cmd, cwd=work/"caller", env=env, text=True, capture_output=True)
        (profile / (name + "-collect.txt")).write_text(result.stdout + "\n" + result.stderr)
        result.check_returncode()
        metrics = [profiler, "display", "text", "-metrics", "e.totalcpu:name", "-functions", str(experiment)]
        report = subprocess.check_output(metrics, env=env, text=True, stderr=subprocess.STDOUT)
        (profile / (name + "-functions.txt")).write_text(report)
        assert "<Total>" in report, report[:500]
        if pair < 2:
            header = subprocess.check_output([profiler, "display", "text", "-header", str(experiment)], env=env, text=True)
            (profile / (name + "-header.txt")).write_text(header)
        rows.append(dict(pair=pair, role=role, normal_ns=float(normal), profiled_output=result.stdout.strip()))
        save(profile / "runs.json", rows)
        print(name, normal.strip(), flush=True)
