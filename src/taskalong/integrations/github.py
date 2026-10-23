"""Create-only, exact-intent draft publication through Git and gh.

The caller owns durable effect records. A prior prepared/sending/unknown effect
permits observation only; a negative lookup never authorizes another POST.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import shutil
from typing import Any, Callable
from urllib.parse import quote

from ..errors import TaskAlongError
from ..process import fingerprint, minimal_environment, run_bounded
from ..validation import canonical_bytes, loads, validate, digest

HEX40 = re.compile(r"^[0-9a-f]{40}$")
SAFE_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SAFE_BRANCH = re.compile(r"^taskalong/[a-zA-Z0-9_-]{1,128}$")


def _error(code: str, message: str, *, uncertain: bool = False) -> TaskAlongError:
    return TaskAlongError(code, message, exit_code=5 if uncertain else 3,
                         effect_outcome="uncertain" if uncertain else "not_sent")


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes({k: v for k, v in value.items() if k != "digest"})).hexdigest()


def build_publish_intent(run: dict, spec: dict, acceptance: dict, *, body_template: str | None = None) -> dict:
    """Make the complete reviewable payload; this function grants no authority."""
    publication = spec.get("publication")
    candidate = run.get("candidate")
    if not publication or not candidate or run.get("state") not in {"accepted", "publishing", "blocked", "draft_published"}:
        raise _error("publication_not_ready", "Publication requires an accepted exact candidate and configured target.")
    try:
        validate("acceptance", acceptance)
    except TaskAlongError:
        raise _error("acceptance_stale", "Publication acceptance violates its immutable contract.") from None
    if (acceptance["decision"] != "accepted" or acceptance["candidate"] != candidate
        or acceptance["run_id"] != run["run_id"] or acceptance["spec_digest"] != spec["digest"]
        or acceptance["qualification"] != run["qualification"] or acceptance["digest"] != _digest(acceptance)
        or acceptance["acceptance_id"] != run.get("acceptance_id")
        or acceptance["policy_digest"] != digest(spec["review"])
        or acceptance["evidence_set_digest"] != digest(sorted(acceptance["evidence_ids"]))
        or candidate["base_commit"] != spec["repository"]["base_commit"]):
        raise _error("acceptance_stale", "Publication acceptance does not match the candidate, specification and qualification.")
    if body_template is None:
        body_template = "TaskAlong independently accepted this bounded candidate."
    if not isinstance(body_template, str) or not body_template or len(body_template.encode()) > 32768:
        raise _error("publication_payload_invalid", "The publication body exceeds its bounded contract.")
    expected_template = publication.get("body_template_digest")
    actual_template = hashlib.sha256(body_template.encode("utf-8")).hexdigest()
    if expected_template != actual_template:
        raise _error("publication_body_changed", "The publication body template differs from the submitted specification.")
    acceptance_digest = acceptance.get("digest") or _digest(acceptance)
    body = (body_template + "\n\n" + f"<!-- taskalong:run:{run['run_id']} -->\n"
            + f"<!-- taskalong:acceptance:{acceptance_digest} -->\n")
    intent = {"kind": "publication_intent", "schema_version": "1.0", "run_id": run["run_id"],
              "qualification": run["qualification"], "repository_id": publication["repository_id"],
              "repository_full_name": publication["repository_full_name"], "host": publication["host"],
              "base_branch": publication["base_branch"], "base_commit": candidate["base_commit"],
              "candidate_commit": candidate["commit"], "candidate_tree": candidate["tree"],
              "spec_digest": spec["digest"], "acceptance_digest": acceptance_digest,
              "body_template_digest": actual_template, "branch": f"taskalong/{run['run_id']}",
              "title": publication["title"], "body": body, "draft": True}
    intent["digest"] = _digest(intent)
    validate_intent(intent)
    return intent


def validate_intent(intent: dict) -> None:
    required = {"kind", "schema_version", "run_id", "qualification", "repository_id", "repository_full_name", "host",
                "base_branch", "base_commit", "candidate_commit", "candidate_tree", "spec_digest", "acceptance_digest",
                "body_template_digest", "branch", "title", "body", "draft", "digest"}
    if not isinstance(intent, dict) or set(intent) != required:
        raise _error("publication_intent_invalid", "Publication requires the exact supported intent document.")
    if intent["kind"] != "publication_intent" or intent["schema_version"] != "1.0" or intent["host"] != "github.com":
        raise _error("publication_intent_invalid", "The publication target or intent version is unsupported.")
    if intent["qualification"] not in {"synthetic", "production"} or type(intent["repository_id"]) is not int or intent["repository_id"] < 1:
        raise _error("publication_intent_invalid", "The publication qualification or repository identity is invalid.")
    if not isinstance(intent["repository_full_name"], str) or not SAFE_REPO.fullmatch(intent["repository_full_name"]):
        raise _error("publication_intent_invalid", "The publication repository identity is invalid.")
    for key in ("base_commit", "candidate_commit", "candidate_tree"):
        if not isinstance(intent[key], str) or not HEX40.fullmatch(intent[key]):
            raise _error("publication_intent_invalid", "Publication requires exact SHA-1 object identities.")
    for key in ("spec_digest", "acceptance_digest", "body_template_digest", "digest"):
        if not isinstance(intent[key], str) or not re.fullmatch(r"[a-f0-9]{64}", intent[key]):
            raise _error("publication_intent_invalid", "Publication requires exact content digests.")
    if not isinstance(intent["branch"], str) or not SAFE_BRANCH.fullmatch(intent["branch"]) or intent["branch"] != f"taskalong/{intent['run_id']}":
        raise _error("publication_intent_invalid", "Publication requires the durable owned branch name.")
    if (not isinstance(intent["base_branch"], str) or not intent["base_branch"] or intent["base_branch"].startswith("-")
        or any(x in intent["base_branch"] for x in ("..", "@{", "\\", " ", "\n", "\r", "\0"))):
        raise _error("publication_intent_invalid", "The publication base branch is invalid.")
    if (not isinstance(intent["title"], str) or not intent["title"].strip() or len(intent["title"].encode()) > 256
        or any(ord(c) < 32 for c in intent["title"]) or not isinstance(intent["body"], str)
        or len(intent["body"].encode()) > 65536 or intent["draft"] is not True):
        raise _error("publication_intent_invalid", "The exact draft payload is invalid.")
    if (intent["body"].count(f"<!-- taskalong:run:{intent['run_id']} -->") != 1
        or intent["body"].count(f"<!-- taskalong:acceptance:{intent['acceptance_digest']} -->") != 1
        or _digest(intent) != intent["digest"]):
        raise _error("publication_intent_changed", "The publication payload changed after intent admission.")


class GitHubPublisher:
    def __init__(self, gh_path: str | Path, *, git_remote: str | Path | None = None,
                 qualification: str = "production", git_path: str | Path | None = None) -> None:
        if qualification not in {"production", "synthetic"}:
            raise _error("publication_qualification_invalid", "The configured publication qualification is unsupported.")
        if qualification == "production" and git_remote is not None:
            raise _error("fixture_in_production", "Production publication cannot use a synthetic Git transport mapping.")
        self.gh_path = str(Path(gh_path).absolute())
        self.git_path = str(Path(git_path or shutil.which("git") or "/usr/bin/git").absolute())
        self.qualification = qualification
        self.git_remote = str(git_remote) if git_remote is not None else None
        self.executable_sha256 = fingerprint(self.gh_path)
        fingerprint(self.git_path)

    def _gh(self, args: list[str], *, cwd: Path, write: bool = False) -> Any:
        process = run_bounded([self.gh_path, "api", "--hostname", "github.com", *args], cwd=cwd,
                              timeout_seconds=30, max_output_bytes=2 * 1024 * 1024,
                              env=minimal_environment(runtime_parent=True))
        if (process.exit_code != 0 or process.timed_out or process.output_limited or not process.termination_confirmed):
            raise _error("publication_response_unknown" if write else "publication_lookup_failed",
                         "The publication service response could not be verified.", uncertain=write)
        try:
            return loads(process.stdout, max_bytes=2 * 1024 * 1024)
        except TaskAlongError:
            # The strict public loader permits only objects. PR pagination is a
            # bounded list at this external protocol boundary, validated below.
            import json
            try:
                value = json.loads(process.stdout, object_pairs_hook=_pairs, parse_float=_invalid_number, parse_constant=_invalid_number)
                if not isinstance(value, list):
                    raise ValueError()
                return value
            except Exception:
                raise _error("publication_response_unknown" if write else "publication_lookup_failed",
                             "The publication service returned an invalid bounded document.", uncertain=write) from None

    def _git(self, args: list[str], *, workspace: Path, write: bool = False):
        process = run_bounded([self.git_path, "-c", "core.hooksPath=/dev/null", *args], cwd=workspace,
                              timeout_seconds=30, max_output_bytes=1024 * 1024,
                              env=minimal_environment(runtime_parent=True))
        # Git is a trusted tool with hooks disabled, not untrusted worker code.
        # A successful protocol plus exact remote read-back establishes this
        # effect; it does not assert general escaped-descendant containment.
        if process.exit_code != 0 or process.timed_out or process.output_limited or not process.group_termination_confirmed:
            raise _error("publication_response_unknown" if write else "publication_git_lookup_failed",
                         "The publication Git transport response could not be verified.", uncertain=write)
        return process.stdout

    def _remote(self, intent: dict, workspace: Path) -> str:
        if self.git_remote is not None:
            if self.qualification != "synthetic":
                raise _error("fixture_in_production", "Synthetic Git transport cannot publish production evidence.")
            return self.git_remote
        raw = self._git(["remote", "get-url", "origin"], workspace=workspace).decode("utf-8", "strict").strip()
        repository = intent["repository_full_name"]
        if raw not in {f"https://github.com/{repository}.git", f"git@github.com:{repository}.git", f"ssh://git@github.com/{repository}.git"}:
            raise _error("publication_remote_mismatch", "The existing Git remote differs from the admitted GitHub repository.")
        return raw

    def _remote_oid(self, remote: str, ref: str, workspace: Path) -> str | None:
        value = self._git(["ls-remote", "--refs", remote, ref], workspace=workspace).decode("ascii", "strict").strip()
        if not value:
            return None
        fields = value.split("\t")
        if len(fields) != 2 or fields[1] != ref or not HEX40.fullmatch(fields[0]):
            raise _error("publication_remote_ambiguous", "The remote branch lookup is ambiguous.")
        return fields[0]

    def _target(self, intent: dict, workspace: Path) -> None:
        repository = intent["repository_full_name"]
        info = self._gh([f"repos/{repository}"], cwd=workspace)
        if (not isinstance(info, dict) or type(info.get("id")) is not int or info.get("id") != intent["repository_id"]
            or info.get("full_name") != repository or info.get("private") is not True
            or info.get("permissions", {}).get("push") is not True):
            raise _error("publication_repository_mismatch", "The private publication repository identity or push permission differs.")
        base = self._gh([f"repos/{repository}/branches/{quote(intent['base_branch'], safe='')}"], cwd=workspace)
        if not isinstance(base, dict) or base.get("commit", {}).get("sha") != intent["base_commit"]:
            raise _error("publication_base_changed", "The publication base changed since acceptance.")

    def _matching_pr(self, intent: dict, workspace: Path) -> dict | None:
        # Search all states without a base filter: a run marker or owned head
        # on a different base is a conflict, not permission for another draft.
        query = f"repos/{intent['repository_full_name']}/pulls?state=all&per_page=100"
        values = self._gh(["--paginate", "--slurp", query], cwd=workspace)
        if not isinstance(values, list):
            raise _error("publication_lookup_failed", "The all-state pull request lookup is invalid.")
        if values and all(isinstance(v, list) for v in values):
            values = [item for page in values for item in page]
        if any(not isinstance(v, dict) for v in values) or len(values) > 10000:
            raise _error("publication_lookup_failed", "The all-state pull request lookup exceeds its contract.")
        marker = f"<!-- taskalong:run:{intent['run_id']} -->"
        values = [pr for pr in values if pr.get("head", {}).get("ref") == intent["branch"]
                  or marker in str(pr.get("body", ""))]
        if len(values) > 1:
            raise _error("publication_pr_conflict", "Multiple pull requests match the owned head or run marker.")
        if not values:
            return None
        self._validate_pr(intent, values[0])
        return values[0]

    def _validate_pr(self, intent: dict, pr: dict) -> None:
        head, base = pr.get("head", {}), pr.get("base", {})
        if (type(pr.get("number")) is not int or pr["number"] < 1 or pr.get("state") != "open"
            or pr.get("draft") is not True or pr.get("merged_at") is not None
            or head.get("sha") != intent["candidate_commit"] or head.get("ref") != intent["branch"]
            or base.get("sha") != intent["base_commit"] or base.get("ref") != intent["base_branch"]
            or head.get("repo", {}).get("id") != intent["repository_id"]
            or base.get("repo", {}).get("id") != intent["repository_id"]
            or head.get("repo", {}).get("full_name") != intent["repository_full_name"]
            or base.get("repo", {}).get("full_name") != intent["repository_full_name"]
            or pr.get("title") != intent["title"] or pr.get("body") != intent["body"]
            or pr.get("html_url") != f"https://github.com/{intent['repository_full_name']}/pull/{pr['number']}"):
            raise _error("publication_pr_conflict", "An existing pull request differs from the exact admitted draft intent.")

    def publish(self, intent: dict, *, workspace: str | Path, effects: dict[str, dict],
                record: Callable[[str, str, dict], None], reconcile_only: bool = False) -> dict:
        """Apply once or observe only. ``record`` must commit each phase durably.

        An interruption after ``prepared`` is intentionally conservative: absence
        of a remote response remains unknown until positively reconciled.
        """
        validate_intent(intent)
        if intent["qualification"] != self.qualification:
            raise _error("fixture_in_production", "Publication qualification differs from the accepted run.")
        directory = Path(workspace)
        self._target(intent, directory)
        remote = self._remote(intent, directory)
        ref = f"refs/heads/{intent['branch']}"
        branch_oid = self._remote_oid(remote, ref, directory)
        if branch_oid not in {None, intent["candidate_commit"]}:
            raise _error("publication_branch_conflict", "The owned remote branch contains another object.")
        branch_request = {"intent_digest": intent["digest"], "ref": ref, "commit": intent["candidate_commit"]}
        branch_effect = effects.get("push_branch")
        if branch_effect and branch_effect.get("request_digest") not in {None, _digest(branch_request)}:
            raise _error("publication_effect_conflict", "The publication effect belongs to different exact inputs.")
        if branch_oid is None:
            if branch_effect or reconcile_only:
                raise _error("publication_branch_unknown", "A prior branch effect has not been positively reconciled.", uncertain=True)
            record("push_branch", "prepared", {"request_digest": _digest(branch_request), "request": branch_request})
            record("push_branch", "sending", {})
            try:
                self._git(["push", f"--force-with-lease={ref}:", remote,
                           f"{intent['candidate_commit']}:{ref}"], workspace=directory, write=True)
                if self._remote_oid(remote, ref, directory) != intent["candidate_commit"]:
                    raise _error("publication_branch_unknown", "The branch create could not be read back.", uncertain=True)
            except TaskAlongError:
                record("push_branch", "unknown", {})
                raise
        record("push_branch", "observed", {"ref": ref, "commit": intent["candidate_commit"]})
        pr = self._matching_pr(intent, directory)
        pr_effect = effects.get("create_draft_pr")
        if pr_effect and pr_effect.get("request_digest") not in {None, intent["digest"]}:
            raise _error("publication_effect_conflict", "The draft effect belongs to different exact inputs.")
        if pr is None:
            if pr_effect or reconcile_only:
                raise _error("publication_pr_unknown", "A prior draft create has not been positively reconciled.", uncertain=True)
            payload = {"title": intent["title"], "body": intent["body"], "head": intent["branch"],
                       "base": intent["base_branch"], "draft": True}
            # Trusted caller-owned workspace control path; never a worker-selected file.
            import tempfile
            with tempfile.TemporaryDirectory(prefix="taskalong-publish-") as temporary:
                request = Path(temporary) / "request.json"
                request.write_bytes(canonical_bytes(payload))
                request.chmod(0o600)
                record("create_draft_pr", "prepared", {"request_digest": intent["digest"]})
                record("create_draft_pr", "sending", {})
                try:
                    response = self._gh(["--method", "POST", f"repos/{intent['repository_full_name']}/pulls", "--input", str(request)],
                                        cwd=directory, write=True)
                    if not isinstance(response, dict) or type(response.get("number")) is not int:
                        raise _error("publication_pr_unknown", "The draft create response is invalid.", uncertain=True)
                    pr = self._gh([f"repos/{intent['repository_full_name']}/pulls/{response['number']}"], cwd=directory)
                    self._validate_pr(intent, pr)
                except TaskAlongError:
                    record("create_draft_pr", "unknown", {})
                    raise _error("publication_pr_unknown", "The draft create requires read-only reconciliation.", uncertain=True) from None
        self._validate_pr(intent, pr)
        receipt = {"kind": "fixture" if self.qualification == "synthetic" else "github", "qualification": self.qualification,
                   "run_id": intent["run_id"], "repository_id": intent["repository_id"],
                   "repository_full_name": intent["repository_full_name"], "number": pr["number"],
                   "url": pr["html_url"], "head": intent["candidate_commit"], "base": intent["base_commit"],
                   "draft": True, "branch": intent["branch"], "intent_digest": intent["digest"]}
        record("create_draft_pr", "observed", receipt)
        return receipt


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _invalid_number(_value):
    raise ValueError("unsupported numeric value")
