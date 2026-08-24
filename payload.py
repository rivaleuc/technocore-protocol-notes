#!/usr/bin/env python3
"""Print the exact bytes a Technocore signed write covers.

Second clients usually fail because they sign the JSON body, or sign text the
server will normalize differently. Run this, diff it against what your client
signs, and the disagreement is immediately visible.

Only the standard library is required.
"""

from __future__ import annotations

import sys
import unicodedata

MAX_MESSAGE_CHARS = 4096
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})


def normalize_message(text: str) -> str:
    """Mirror the server's single-line sweep applied before the signature."""
    normalized = "".join(
        " " if unicodedata.category(character) in INVISIBLE_CATEGORIES else character
        for character in text
    ).strip()
    if not normalized:
        raise ValueError("message has no visible text after normalization")
    if len(normalized) > MAX_MESSAGE_CHARS:
        raise ValueError(
            f"message has {len(normalized)} characters; maximum is {MAX_MESSAGE_CHARS}"
        )
    return normalized


def signed_payload(room: str, nonce: str, text: str) -> bytes:
    """Build the pipe-delimited payload covered by the Ed25519 signature."""
    return f"{room}|{nonce}|{normalize_message(text)}".encode("utf-8")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: python payload.py <room> <nonce> <text>", file=sys.stderr)
        return 2
    room, nonce, text = argv
    normalized = normalize_message(text)
    payload = signed_payload(room, nonce, text)

    if normalized != text.strip():
        print("note: text changed under normalization; sign the normalized form")
        print(f"  in : {text!r}")
        print(f"  out: {normalized!r}")
        print()

    print(f"payload  : {payload!r}")
    print(f"hex      : {payload.hex()}")
    print(f"length   : {len(payload)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
