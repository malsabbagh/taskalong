"""Trusted test-only crash observation. Never alters installed/source files."""
import os
from pathlib import Path
import time


def install_exit_barrier(probe, function, *, event="call"):
    """Exit the client/supervisor only after observing the exact Python boundary.

    Use a directory containing only sitecustomize, plus any explicit source
    development path. Installed imports still come from site-packages. Record
    this PYTHONPATH exception separately from ordinary installed qualification.
    No successful process receipt or application state is fabricated.
    """
    directory = probe.root / ("fault-" + function)
    directory.mkdir()
    marker = directory / "reached.json"
    program = "import json,os,sys\n"
    program += "def observe(frame,event,arg):\n"
    program += f"    if event != {event!r} or frame.f_code.co_name != {function!r}: return observe\n"
    program += "    if '/taskalong/' not in frame.f_code.co_filename.replace('\\\\','/'): return observe\n"
    program += "    sys.settrace(None)\n"
    program += f"    with open({str(marker)!r},'w') as stream:\n"
    program += "        json.dump({'pid':os.getpid(),'event':event,'function':frame.f_code.co_name,'file':frame.f_code.co_filename},stream); stream.flush(); os.fsync(stream.fileno())\n"
    program += "    os._exit(77)\nsys.settrace(observe)\n"
    (directory / "sitecustomize.py").write_text(program)
    previous = probe.env.get("PYTHONPATH")
    probe.env["PYTHONPATH"] = str(directory) + (os.pathsep + previous if previous else "")
    return marker, previous


def remove_barrier(probe, previous):
    if previous is None:
        probe.env.pop("PYTHONPATH", None)
    else:
        probe.env["PYTHONPATH"] = previous


def require_boundary(marker, timeout=20):
    deadline = time.monotonic() + timeout
    while not marker.exists():
        if time.monotonic() >= deadline:
            raise AssertionError("Requested crash boundary was not reached: " + str(marker))
        time.sleep(.025)
