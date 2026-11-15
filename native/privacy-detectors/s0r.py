#!/usr/bin/env python3
"""Serve S0R model findings over Magpie's pf-serve pipe protocol."""

import argparse
import json
import struct
import sys
import time
from contextlib import redirect_stdout

PII_LABELS = {
    "identity.person_name": "private_person",
    "contact.address": "private_address",
    "contact.phone": "private_phone",
    "contact.email": "private_email",
    "financial.bank_account": "account_number",
}


def read_exact(pipe, size):
    data = pipe.read(size)
    if len(data) != size:
        raise EOFError
    return data


def read_batch(pipe):
    size = pipe.read(4)
    if not size:
        return None
    count, = struct.unpack("<I", size)
    if count > 1024:
        raise ValueError("too many texts")
    texts = []
    for _ in range(count):
        length, = struct.unpack("<I", read_exact(pipe, 4))
        if length > 1 << 20:
            raise ValueError("text too large")
        texts.append(read_exact(pipe, length).decode("utf-8"))
    return texts


def encode_spans(detector, text):
    _, rows = detector.spans(text)
    offsets = [0]
    for char in text:
        offsets.append(offsets[-1] + len(char.encode("utf-8")))
    output = bytearray()
    count = 0
    for row in rows:
        label = "secret" if row["kind"] == "secret" else PII_LABELS.get(row["type"])
        if label is None:
            continue
        kind = label.encode("ascii")
        output += struct.pack(
            "<IIfB",
            offsets[row["start"]],
            offsets[row["end"]],
            row["score"],
            len(kind),
        )
        output += kind
        count += 1
    return struct.pack("<I", count) + output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, help="S0R's local model directory")
    parser.add_argument("--device", default="auto")
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()
    out = sys.stdout.buffer
    start = time.monotonic()
    try:
        with redirect_stdout(sys.stderr):
            from s0r_router import Redactor

            detector = Redactor(
                args.model, rules=False, pii_rules=False, device=args.device,
                threads=args.threads,
            )
            detector.spans("warm")
        hello = {
            "device": detector.device,
            "gpu": detector.device != "cpu",
            "ms": round((time.monotonic() - start) * 1000),
        }
    except Exception as exc:
        hello = {"error": f"S0R could not load the local model ({type(exc).__name__})"}
    out.write(json.dumps(hello).encode() + b"\n")
    out.flush()
    if "error" in hello:
        return 1

    while True:
        try:
            texts = read_batch(sys.stdin.buffer)
            if texts is None:
                return 0
            with redirect_stdout(sys.stderr):
                result = b"".join(encode_spans(detector, text) for text in texts)
            out.write(struct.pack("<I", 0) + result)
            out.flush()
        except (EOFError, BrokenPipeError):
            return 0
        except Exception:
            message = b"S0R could not detect sensitive spans"
            out.write(struct.pack("<II", 1, len(message)) + message)
            out.flush()
            return 1


if __name__ == "__main__":
    sys.exit(main())
