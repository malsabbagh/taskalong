#!/usr/bin/env python3
"""Synthetic gh process boundary. Only a qualification wrapper selects its state.

Wrapper sets TASKALONG_FAKE_GH_STATE before runpy.run_path. This program is test
material, never a distributed publisher or production executable.
"""
import json
import os
from pathlib import Path
import sys
from urllib.parse import parse_qs, unquote, urlsplit


def main():
    path = Path(os.environ["TASKALONG_FAKE_GH_STATE"])
    state = json.loads(path.read_text())
    argv = sys.argv[1:]
    if argv[:3] != ["api", "--hostname", "github.com"]:
        return 2
    args = argv[3:]
    endpoint = next((x for x in args if x.startswith("repos/")), "")
    url = urlsplit(endpoint)
    parts = url.path.split("/")
    repository = state.get("repository_full_name", "fixture/repository")
    repository_id = state.get("repository_id", 4242)
    if "/".join(parts[:3]) != f"repos/{repository}":
        return 2
    repo = {"id": repository_id, "full_name": repository, "private": state.get("private", True),
            "permissions": {"push": state.get("push", True)}}
    if len(parts) == 3:
        output = repo
    elif parts[3] == "branches":
        output = {"name": unquote("/".join(parts[4:])), "commit": {"sha": state["base_commit"]}}
    elif parts[3] == "pulls":
        state.setdefault("prs", [])
        if "--method" in args and args[args.index("--method") + 1] == "POST":
            request = json.loads(Path(args[args.index("--input") + 1]).read_text())
            number = state.get("next_number", 1)
            commit = (Path(state["git_remote"]) / "refs" / "heads" / request["head"]).read_text().strip()
            output = {"number": number, "state": "open", "draft": request["draft"], "merged_at": None,
                      "title": request["title"], "body": request["body"],
                      "head": {"sha": commit, "ref": request["head"], "repo": repo},
                      "base": {"sha": state["base_commit"], "ref": request["base"], "repo": repo},
                      "html_url": f"https://github.com/{repository}/pull/{number}"}
            state["prs"].append(output)
            state["next_number"] = number + 1
            state["create_calls"] = state.get("create_calls", 0) + 1
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(state))
            os.replace(temporary, path)
            if state.get("lose_create_response"):
                return 1
        elif len(parts) == 5:
            output = next((pr for pr in state["prs"] if pr["number"] == int(parts[4])), None)
            if output is None:
                return 1
        else:
            query = parse_qs(url.query)
            head = query.get("head", [""])[0].split(":", 1)[-1]
            base = query.get("base", [""])[0]
            output = [pr for pr in state["prs"] if (not head or pr["head"]["ref"] == head) and (not base or pr["base"]["ref"] == base)]
            if "--slurp" in args:
                output = [output]
    else:
        return 2
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
