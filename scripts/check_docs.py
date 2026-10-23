#!/usr/bin/env python3
"""Check that relative Markdown link targets exist within this repository."""

from pathlib import Path
import re
import json
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"!?\[[^\]\n]*\]\((<[^>]+>|[^\s)]+)(?:\s+\"[^\"]*\")?\)")


def main() -> int:
    errors = []
    checked = 0
    documents = sorted(
        path for path in ROOT.rglob("*.md") if ".git" not in path.relative_to(ROOT).parts
    )
    for document in documents:
        fenced = False
        for number, line in enumerate(document.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith(("```", "~~~")):
                fenced = not fenced
                continue
            if fenced:
                continue
            for match in LINK.finditer(line):
                url = urlsplit(match.group(1).strip("<>"))
                if url.scheme or url.netloc or not url.path:
                    continue
                checked += 1
                target = (document.parent / unquote(url.path)).resolve()
                location = f"{document.relative_to(ROOT)}:{number}"
                try:
                    target.relative_to(ROOT)
                except ValueError:
                    errors.append(f"{location}: link leaves repository: {url.path}")
                    continue
                if not target.exists():
                    errors.append(f"{location}: missing link target: {url.path}")
    guides = {"fixture": "docs/fixture-walkthrough.md", "operations": "docs/operations.md",
              "contracts": "docs/contracts.md", "qualification": "docs/qualification.md"}
    bundled = json.loads((ROOT / "src/taskalong/resources/docs/guides.json").read_text())
    if set(bundled) != set(guides) or any(bundled[name] != (ROOT / source).read_text() for name, source in guides.items()):
        errors.append("Packaged guides are stale; run python tools/sync_guides.py.")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Checked {checked} local links in {len(documents)} Markdown files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
