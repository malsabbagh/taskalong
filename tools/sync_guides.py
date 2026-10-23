#!/usr/bin/env python3
"""Keep wheel-only guides byte-bound to their canonical repository documents."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUIDES = {"fixture": "docs/fixture-walkthrough.md", "operations": "docs/operations.md",
          "contracts": "docs/contracts.md", "qualification": "docs/qualification.md"}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    payload = {name: (ROOT / path).read_text(encoding="utf-8") for name, path in GUIDES.items()}
    data = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    target = ROOT / "src/taskalong/resources/docs/guides.json"
    if args.check:
        if not target.is_file() or target.read_bytes() != data:
            parser.exit(1, "Packaged guides are stale; run python tools/sync_guides.py.\n")
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    print("Packaged guides match four canonical documents.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
