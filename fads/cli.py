from __future__ import annotations

import argparse
import os
from pathlib import Path

from .ledger import EvidenceLedger


def main() -> None:
    parser = argparse.ArgumentParser(prog="fads")
    subcommands = parser.add_subparsers(dest="command", required=True)
    verify = subcommands.add_parser("verify-ledger", help="verify a FADS evidence ledger")
    verify.add_argument("path", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "verify-ledger":
        key_hex = os.environ.get("FADS_LEDGER_KEY")
        if key_hex is None:
            parser.error("FADS_LEDGER_KEY must contain a hex-encoded key")
        count = EvidenceLedger(arguments.path, bytes.fromhex(key_hex)).verify()
        print(f"verified {count} records")
