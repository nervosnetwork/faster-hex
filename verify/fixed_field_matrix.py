import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FILTER = r"^serde_json/(array|option_array)/(plain|escaped)/(32|4096)$"
CASES = {f"serde_json/{field}/{text}/{size}" for field in ("array", "option_array")
         for text in ("plain", "escaped") for size in (32, 4096)}


def build(work):
    crate = work / "codec"
    crate.mkdir()
    dep_lock = None
    bins = {}
    for name, ref in (("release", "6d84260fe321669e7f93ecfb8aecb4db0f582f14"),
                      ("pr", "25cfd8eb6a4cd8257a96fabaf73771cabcced4b4"),
                      ("visitor", "HEAD")):
        tar = work / "codec.tar"
        subprocess.run(["git", "archive", "-o", tar, ref], cwd=ROOT, check=True)
        subprocess.run(["tar", "-xf", tar], cwd=crate, check=True)
        for filename in ("benches/serde.rs", ".cargo/config.toml"):
            shutil.copyfile(ROOT / filename, crate / filename)
        v = re.search(r'^version = "([^"]+)"', (crate / "Cargo.toml").read_text(), re.M)[1]
        if dep_lock is None:
            subprocess.run(["cargo", "generate-lockfile"], cwd=crate, check=True)
            lock = (crate / "Cargo.lock").read_text()
            marker = f'name = "faster-hex"\nversion = "{v}"'
            assert lock.count(marker) == 1
            dep_lock = lock.replace(marker, 'name = "faster-hex"\nversion = "VERSION"')
        (crate / "Cargo.lock").write_text(dep_lock.replace('"VERSION"', f'"{v}"'))
        subprocess.run(["cargo", "clean", "-p", "faster-hex", "--release"], cwd=crate, check=True)
        messages = subprocess.check_output(["cargo", "bench", "--locked", "--bench", "serde", "--no-run",
                                             "--message-format=json"], cwd=crate, text=True)
        exe, = [Path(m["executable"]) for line in messages.splitlines()
                if (m := json.loads(line)).get("target", {}).get("name") == "serde" and m.get("executable")]
        bins[name] = work / name
        shutil.copy2(exe, bins[name])
    return bins


def measure(work, bins, destination):
    exe = work / "field-bench"
    data = work / "criterion"
    env = dict(os.environ, CRITERION_HOME=str(data))
    results = []
    for name in ("release", "pr", "visitor", "visitor", "pr", "release"):
        exe.unlink(missing_ok=True)
        os.link(bins[name], exe)
        listed = subprocess.check_output([exe, FILTER, "--list", "--bench"], cwd=work, env=env, text=True)
        assert {l.removesuffix(": benchmark") for l in listed.splitlines() if l.endswith(": benchmark")} == CASES
        subprocess.run([exe, FILTER, "--bench", "--warm-up-time", "0.25", "--measurement-time", "0.7",
                        "--sample-size", "30", "--nresamples", "5000", "--noplot", "--save-baseline", "current"],
                       cwd=work, env=env, check=True, stdout=subprocess.DEVNULL)
        cases = {}
        for info in data.glob("**/new/benchmark.json"):
            name_id = json.loads(info.read_text())["full_id"]
            cases[name_id] = json.loads(info.with_name("estimates.json").read_text())["median"]
        assert set(cases) == CASES, (cases.keys(), CASES)
        results.append({"revision": name, "cases": cases})
        print(name, len(cases), "measured", flush=True)
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as location:
        work = Path(location)
        os.environ["CARGO_TARGET_DIR"] = str(work / "target")
        measure(work, build(work), ROOT / "results" / "fixed-fields.json")
