from pathlib import Path
import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
out = Path(os.environ.get("RESULTS", root / "results")).resolve()
out.mkdir(exist_ok=True, parents=True)
base = "25cfd8eb6a4cd8257a96fabaf73771cabcced4b4"
head = "dec48432d8ac3df9d6a15a265fbac66fb850b292"
smoke = bool(os.environ.get("STAGE_SMOKE"))
cpu = ["lscpu"] if platform.system() == "Linux" else ["sysctl", "-n", "machdep.cpu.brand_string"]
host = platform.machine() if smoke else subprocess.check_output(cpu, text=True)
(out / "host.txt").write_text(host + "\n" + subprocess.check_output(["rustc", "-vV"], text=True))

checks = [
    ("full", 0, 1), ("duplicate", 6, 7), ("control A", 0, 6), ("control B", 1, 7),
    ("read, writer A", 2, 3), ("read, writer B", 4, 5),
    ("write, reader A", 2, 4), ("write, reader B", 3, 5),
    ("read alone", 8, 9), ("write alone", 10, 11),
]
def extract(dest, revision):
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir()
    archive = dest.parent / "source.tar"
    subprocess.run(["git", "archive", "-o", archive, revision], cwd=root, check=True)
    subprocess.run(["tar", "-xf", archive, "-C", dest], check=True)

with tempfile.TemporaryDirectory() as tmp:
    app = Path(tmp)
    (app / "src").mkdir()
    shutil.copyfile(root / "verify/stages.rs", app / "src/main.rs")
    (app / "Cargo.toml").write_text('''[package]
name = "hex-field-stages"
version = "0.1.0"
edition = "2021"
[dependencies]
baseline = { package = "faster-hex-reference", path = "reference" }
candidate = { package = "faster-hex", path = "candidate" }
serde = { version = "=1.0.229", features = ["derive"] }
serde_json = "=1.0.154"
[workspace]
members = ["."]
exclude = ["reference", "candidate"]
''')
    target = app / "target"
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    profile = os.environ.get("CARGO_PROFILE_RELEASE_LTO", "false")
    rng = random.Random(458121)
    scores = {}
    inputs = [(32, "plain"), (32, "escaped"), (4096, "plain"), (4096, "escaped")]
    for order, a, b in [("forward", base, head), ("reverse", head, base)]:
        extract(app / "reference", a)
        extract(app / "candidate", b)
        manifest = app / "reference/Cargo.toml"
        source = manifest.read_text()
        assert source.count('name = "faster-hex"') == 1
        manifest.write_text(source.replace('name = "faster-hex"', 'name = "faster-hex-reference"'))
        if (app / "Cargo.lock").exists():
            subprocess.run(["cargo", "clean", "--release", "-p", "hex-field-stages", "-p", "faster-hex", "-p", "faster-hex-reference"], cwd=app, env=env, check=True)
        else:
            subprocess.run(["cargo", "generate-lockfile"], cwd=app, env=env, check=True)
        subprocess.run(["cargo", "build", "--release", "--locked"], cwd=app, env=env, check=True)
        shutil.copyfile(app / "Cargo.lock", out / "Cargo.lock")
        for n, kind in inputs:
            amount = (65000 if n == 32 else 2100) if not smoke else 20
            cycles = 20 if not smoke else 2
            data = subprocess.check_output([target / "release/hex-field-stages", str(n), str(amount), str(cycles), kind], text=True)
            rows = [list(map(float, line.split())) for line in data.splitlines()]
            assert len(rows) == cycles and all(len(row) == 12 for row in rows)
            (out / f"{order}-{n}-{kind}.txt").write_text(data)
            scores[f"{order}/{n}/{kind}"] = {}
            for label, i, j in checks:
                if order == "reverse":
                    i, j = j, i
                ratios = [r[j] / r[i] for r in rows]
                boot = sorted(statistics.median(rng.choices(ratios, k=len(rows))) for _ in range(2000))
                values = [statistics.median(ratios), boot[49], boot[-50]]
                scores[f"{order}/{n}/{kind}"][label] = values
                print(profile, order, n, kind, label, *(f"{100*(x-1):+.2f}%" for x in values), flush=True)
    (out / "stage-summary.json").write_text(json.dumps(scores, indent=2))
