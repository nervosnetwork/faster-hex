#!/usr/bin/env python3
"""Generate deterministic boundary seeds; libFuzzer grows these ignored corpora."""
from pathlib import Path
import argparse
import json

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "corpus")
root = parser.parse_args().out
core = root / "faster-hex"
serde = root / "serde"
core.mkdir(parents=True, exist_ok=True)
serde.mkdir(parents=True, exist_ok=True)
for length in [0, 1, 2, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 4096]:
    raw = bytes((i * 37 + length) % 256 for i in range(length))
    for kind, data in [("binary", raw), ("lower", raw.hex().encode()),
                       ("upper", raw.hex().upper().encode())]:
        # Deliberately independent alignment and capacity controls.
        header = bytes([length % 32, (length * 7) % 32]) + length.to_bytes(2, "little")
        (core / f"{kind}-{length}").write_bytes(header + data)
    for position in {0, max(0, length - 1), length // 2}:
        data = bytearray(b"aB" * length)
        if data:
            data[position] = 255
        (core / f"invalid-{length}-{position}").write_bytes(bytes([1, 31]) + length.to_bytes(2, "little") + data)
for name, data in {
    "empty": b'"0x"', "mixed": b'"0x0123aBcDeF"', "null": b"null",
    "escaped": b'"\\u0030x\\u00303"', "odd": b'"0xa"',
    "wrong-prefix": b'"0X01"', "unicode": '"0x你"'.encode(),
}.items():
    (serde / name).write_bytes(data)

# The Serde target expects records. Keep scalar seeds as wrong-type inputs,
# and provide valid records so mutations can reach each field's hex decoder.
for name, payload in {
    "record-empty": {"bytes": "0x", "optional": ""},
    "record-mixed": {"bytes": "0x0123aBcDeF", "optional": "abcd"},
    "record-none": {"bytes": "0x00", "optional": None},
    "record-odd": {"bytes": "0xa", "optional": None},
    "record-prefix": {"bytes": "0X01", "optional": None},
    "record-case": {"bytes": "0x01", "optional": "AB"},
    "record-unicode": {"bytes": "0x你", "optional": None},
    "record-array": {"bytes": "0x" + "aB" * 32, "optional": "AB" * 32},
    "record-at-limit": {"bytes": "0x" + "ab" * 64, "optional": "ab" * 64},
    "record-over-limit": {"bytes": "0x" + "ab" * 65, "optional": None},
}.items():
    (serde / name).write_text(json.dumps(payload, ensure_ascii=False))
(serde / "record-escaped").write_bytes(b'{"bytes":"\\u0030x\\u0061b","optional":null}')

fragment = (Path(__file__).resolve().parents[1] / "afl/in/case4").read_bytes()
header = bytes([1, 7]) + len(fragment).to_bytes(2, "little")
for name, data in [("today-binary", fragment), ("today-hex", fragment.hex().encode())]:
    (core / name).write_bytes(header + data)
(serde / "today").write_text(json.dumps({"bytes": "0x" + fragment.hex(), "optional": None}))
