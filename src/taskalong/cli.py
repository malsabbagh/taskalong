"""Thin versioned local CLI; application behavior lives in RunService."""
from __future__ import annotations

import argparse
import json
import sys
import sqlite3
import time

from . import __version__
from .errors import TaskAlongError
from .validation import canonical_bytes, load_json


def parser():
    root = argparse.ArgumentParser(prog="taskalong", description="Experimental bounded development-task core. Live production dispatch is disabled.")
    root.add_argument("--version", action="version", version=f"taskalong {__version__} (API/schema 1.0)")
    root.add_argument("--state-dir")
    root.add_argument("--json", action="store_true")
    sub = root.add_subparsers(dest="command", required=True)
    def command(name):
        p = sub.add_parser(name)
        p.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        return p
    p = command("guide"); p.add_argument("name", nargs="?", default="fixture", choices=("fixture", "operations", "contracts", "qualification", "ordered"))
    p = command("register-repository"); p.add_argument("path"); p.add_argument("--workspace-root")
    p = command("register-profile"); p.add_argument("--profile", required=True)
    p = command("configure-muse-driver"); p.add_argument("--config", required=True)
    p = command("configure-muse"); p.add_argument("--config", required=True)
    p = command("muse-readiness"); p.add_argument("--profile-id", required=True); p.add_argument("--configuration-digest", required=True)
    p = command("prepare-muse"); p.add_argument("--spec", required=True); p.add_argument("--inputs", required=True)
    command("muse-exposure")
    p = command("muse-mac-probe"); p.add_argument("--executable", required=True); p.add_argument("--evidence-dir", required=True)
    p = command("muse-preparation"); p.add_argument("preparation_digest")
    p = command("supervised-pilot-prepare"); p.add_argument("--request", required=True); p.add_argument("--output", required=True)
    p = command("supervised-pilot-stage"); p.add_argument("--bundle", required=True); p.add_argument("--response", required=True); p.add_argument("--output", required=True)
    p = command("supervised-pilot-run"); p.add_argument("--bundle", required=True)
    p = command("supervised-muse-exec-plan"); p.add_argument("--bundle", required=True); p.add_argument("--executable", required=True); p.add_argument("--model-id", required=True); p.add_argument("--output", required=True)
    p = command("supervised-muse-plan"); p.add_argument("--bundle", required=True); p.add_argument("--executable", required=True); p.add_argument("--output", required=True)
    p = command("supervised-muse-replay"); p.add_argument("--bundle", required=True); p.add_argument("--plan", required=True); p.add_argument("--transcript", required=True); p.add_argument("--output", required=True)
    p = command("configure-review"); p.add_argument("--config", required=True); p.add_argument("--fixture-response"); p.add_argument("--executable"); p.add_argument("--python-executable")
    p = command("configure-sandbox"); p.add_argument("--executable", required=True)
    p = command("configure-publication"); p.add_argument("--gh", required=True); p.add_argument("--git-remote", required=True)
    p = command("authorize"); p.add_argument("run_id"); p.add_argument("--decision-digest", required=True); p.add_argument("--scope", nargs="+", required=True)
    p = command("submit"); p.add_argument("--spec", required=True); p.add_argument("--key", required=True)
    p = command("validate"); p.add_argument("--spec", required=True)
    for name in ("advance", "retry"):
        p = command(name); p.add_argument("run_id"); p.add_argument("--step-id", required=True)
        p.add_argument("--key", required=True); p.add_argument("--expected-revision", type=int, required=True)
        if name == "advance": p.add_argument("--predecessor-digest", required=True)
    for name in ("start", "cancel", "retire-workspace", "resume", "reconcile", "verify", "publish"):
        p = command(name); p.add_argument("run_id"); p.add_argument("--key", required=True); p.add_argument("--expected-revision", type=int, required=True)
        if name == "resume": p.add_argument("--mode", choices=("native", "restart"), required=True)
        if name in {"start", "resume"}: p.add_argument("--authority-id")
        if name == "publish": p.add_argument("--intent-digest", required=True)
        if name == "cancel": p.add_argument("--wait", type=int, default=0)
    for name in ("status", "result", "publish-intent"):
        p = command(name); p.add_argument("run_id")
    p = command("events"); p.add_argument("run_id"); p.add_argument("--after-seq", type=int, default=0); p.add_argument("--jsonl", action="store_true")
    p = command("export"); p.add_argument("run_id"); p.add_argument("--output", required=True)
    p = command("doctor"); p.add_argument("--profile-id"); p.add_argument("--workspace"); p.add_argument("--git-common-dir")
    return root


def envelope(command, *, data=None, operation_key=None, error=None):
    data = data or {}
    return {"kind": "command_result", "schema_version": "1.0", "command": command, "operation_key": operation_key,
            "ok": error is None, "disposition": "rejected" if error else "observed", "run_id": data.get("run_id"),
            "run_revision": data.get("revision"), "state": data.get("state"), "data": data,
            "errors": [error.to_dict()] if error else [], "warnings": [], "next_actions": error.recovery if error else [], "extensions": {}}


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    json_output = "--json" in arguments or "--jsonl" in arguments
    args = None
    try:
        try:
            args = parser().parse_args(arguments)
        except SystemExit as exc:
            if exc.code and json_output:
                error = TaskAlongError("invalid_cli", "The command syntax is invalid; use --help.")
                print(json.dumps(envelope("unknown", error=error), ensure_ascii=False))
            return exc.code
        if args.command == "guide":
            from importlib import resources
            guides = json.loads(resources.files("taskalong.resources").joinpath("docs/guides.json").read_text(encoding="utf-8"))
            markdown = guides[args.name]
            if json_output:
                print(canonical_bytes(envelope("guide", data={"name": args.name, "markdown": markdown})).decode())
            else:
                print(markdown, end="" if markdown.endswith("\n") else "\n")
            return 0
        if args.command == "muse-mac-probe":
            from .muse_mac_probe import probe
            result = probe(executable=args.executable, evidence_dir=args.evidence_dir)
            print(canonical_bytes(envelope(args.command, data=result)).decode() if json_output else json.dumps(result,indent=2))
            return 0
        if args.command.startswith("supervised-muse-"):
            from . import supervised_muse_runner
            from .supervised_pilot import read_document
            if args.command == "supervised-muse-exec-plan":
                result = supervised_muse_runner.prepare_exec(bundle=args.bundle, executable=args.executable, model_id=args.model_id, output=args.output)
            elif args.command == "supervised-muse-plan":
                result = supervised_muse_runner.prepare(bundle=args.bundle, executable=args.executable, output=args.output)
            else:
                result = supervised_muse_runner.replay(plan_path=args.plan, bundle=args.bundle, transcript=read_document(args.transcript), output=args.output)
            print(canonical_bytes(envelope(args.command, data=result)).decode() if json_output else json.dumps(result, indent=2))
            return 0
        if args.command.startswith("supervised-pilot-"):
            from . import supervised_pilot
            if args.command == "supervised-pilot-prepare":
                result = supervised_pilot.prepare(supervised_pilot.read_document(args.request), output=args.output)
            elif args.command == "supervised-pilot-stage":
                result = supervised_pilot.stage(bundle=args.bundle, response=supervised_pilot.read_document(args.response), output=args.output)
            else:
                supervised_pilot.refuse_live(bundle=args.bundle)
            print(canonical_bytes(envelope(args.command, data=result)).decode() if json_output else json.dumps(result, indent=2))
            return 0
        from .api import RunService
        with RunService(args.state_dir) as service:
            cmd = args.command
            mutation = {"operation_key": getattr(args, "key", None), "expected_revision": getattr(args, "expected_revision", None)}
            if cmd == "register-repository": result = service.register_repository(args.path, args.workspace_root)
            elif cmd == "register-profile": result = service.register_profile(load_json(args.profile))
            elif cmd == "configure-muse-driver": result = service.configure_muse_driver(load_json(args.config))
            elif cmd == "configure-muse": result = service.configure_muse(load_json(args.config))
            elif cmd == "muse-readiness": result = service.muse_readiness(args.profile_id, args.configuration_digest)
            elif cmd == "prepare-muse": result = service.prepare_muse(load_json(args.spec), inputs=load_json(args.inputs))
            elif cmd == "muse-exposure": result = service.muse_exposure()
            elif cmd == "muse-preparation": result = service.muse_preparation(args.preparation_digest)
            elif cmd == "configure-review": result = service.configure_review(args.config, fixture_response=args.fixture_response, executable=args.executable, python_executable=args.python_executable)
            elif cmd == "configure-sandbox": result = service.configure_command_sandbox(args.executable)
            elif cmd == "configure-publication": result = service.configure_publication(args.gh, args.git_remote)
            elif cmd == "authorize": result = service.authorize(args.run_id, decision_digest=args.decision_digest, scope=args.scope)
            elif cmd == "submit": result = service.submit(load_json(args.spec), operation_key=args.key)
            elif cmd == "validate": result = service.validate_task(load_json(args.spec))
            elif cmd == "advance": result = service.advance(args.run_id, expected_step_id=args.step_id, predecessor_digest=args.predecessor_digest, **mutation)
            elif cmd == "retry": result = service.retry(args.run_id, expected_step_id=args.step_id, **mutation)
            elif cmd == "start": result = service.start(args.run_id, authority_id=args.authority_id, **mutation)
            elif cmd == "resume": result = service.resume(args.run_id, mode=args.mode, authority_id=args.authority_id, **mutation)
            elif cmd == "cancel":
                if not 0 <= args.wait <= 60: raise TaskAlongError("invalid_wait", "Cancellation wait must be 0–60 seconds.")
                result = service.cancel(args.run_id, **mutation)
                until = time.monotonic() + args.wait
                while result["state"] == "cancel_pending" and time.monotonic() < until:
                    time.sleep(0.1); result = service.inspect(args.run_id)
            elif cmd == "retire-workspace": result = service.retire_workspace(args.run_id, **mutation)
            elif cmd == "reconcile": result = service.reconcile(args.run_id, **mutation)
            elif cmd == "verify": result = service.verify(args.run_id, **mutation)
            elif cmd == "status": result = service.inspect(args.run_id)
            elif cmd == "result": result = service.result(args.run_id)
            elif cmd == "publish-intent": result = service.publish_intent(args.run_id)
            elif cmd == "publish": result = service.publish(args.run_id, intent_digest=args.intent_digest, **mutation)
            elif cmd == "export": result = service.export(args.run_id, output=args.output)
            elif cmd == "doctor": result = service.doctor(profile_id=args.profile_id, workspace=args.workspace, git_common_dir=args.git_common_dir)
            elif cmd == "events":
                result = service.events(args.run_id, after_seq=args.after_seq)
                if args.jsonl:
                    for event in result: print(canonical_bytes(event).decode())
                    return 0
                result = {"run_id": args.run_id, "events": result}
            else: raise TaskAlongError("invalid_command", "Unsupported command.")
        output = envelope(cmd, data=result, operation_key=getattr(args, "key", None))
        if cmd == "doctor":
            output["next_actions"] = result.get("next_actions", [])
        if json_output: print(canonical_bytes(output).decode())
        elif cmd == "doctor":
            print("doctor: production dispatch blocked")
            for requirement in result.get("blocker_details", []):
                print(requirement["code"] + ": " + requirement.get("requirement", requirement.get("limitation", "")))
        else: print(f"{cmd}: {result.get('state', 'completed')}" + (f" ({result['run_id']})" if "run_id" in result else ""))
        if cmd in {"start", "advance", "retry", "resume", "cancel", "reconcile", "verify", "publish"}:
            if result.get("state") == "cancel_pending": return 6
            if result.get("state") == "blocked":
                return 5 if any(b.get("effect_outcome") == "uncertain" for b in result.get("blockers", [])) else 3
            if result.get("state") == "failed": return 1
        return 0
    except TaskAlongError as exc:
        if json_output: print(canonical_bytes(envelope(args.command if args else "unknown", operation_key=getattr(args, "key", None), error=exc)).decode())
        else: print(f"{exc.code}: {exc.message}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, sqlite3.Error):
        exc = TaskAlongError("local_operation_failed", "The local operation could not complete; preserve state and inspect prerequisites.", exit_code=70)
        if json_output: print(canonical_bytes(envelope(args.command if args else "unknown", error=exc)).decode())
        else: print(exc.message, file=sys.stderr)
        return 70
