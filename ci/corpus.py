"""Content-addressed fuzz seeds shared by libFuzzer and AFL runners."""
import hashlib
from pathlib import Path
import tempfile


def contents(directory):
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError(f"corpus must not be a symlink: {directory}")
    entries = {}
    if directory.exists():
        for path in sorted(directory.iterdir()):
            # AFL keeps bookkeeping in a .state subdirectory.
            if path.name.startswith("."):
                continue
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"unexpected corpus entry: {path}")
            data = path.read_bytes()
            entries[hashlib.sha256(data).hexdigest()] = data
    return entries


def merge(sources, destination):
    entries = {}
    for source in sources:
        entries.update(contents(source))
    destination.mkdir(parents=True, exist_ok=True)
    for name, data in entries.items():
        (destination / name).write_bytes(data)
    return {"files": len(entries), "bytes": sum(map(len, entries.values()))}


def replace(source, destination):
    """Publish only a successful, nonempty minimization; keep the old set on failure."""
    entries = contents(source)
    if not entries:
        raise ValueError("refusing to replace a corpus with an empty minimization")
    contents(destination)  # Check the old corpus before moving it.
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".corpus-", dir=destination.parent) as temporary:
        stage = Path(temporary)
        ready = stage / "ready"
        ready.mkdir()
        for name, data in entries.items():
            (ready / name).write_bytes(data)
        previous = stage / "previous"
        if destination.exists():
            destination.rename(previous)
        try:
            ready.rename(destination)
        except OSError:
            if previous.exists():
                previous.rename(destination)
            raise
    return {"files": len(entries), "bytes": sum(map(len, entries.values()))}
