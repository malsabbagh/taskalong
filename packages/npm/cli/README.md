# @taskalong/cli

Zero-dependency, Python-required thin launcher for exact TaskAlong Python `0.1.0a1`, npm `0.1.0-alpha.1`. Requires Python `>=3.11,<3.15` and Node `>=22.14.0`. No registry release is implied yet.

After separately approved future publication, install `taskalong==0.1.0a1` into an explicit venv, select its interpreter, and install `@taskalong/cli@0.1.0-alpha.1`:

POSIX: `export TASKALONG_PYTHON=/path/to/venv/bin/python`

PowerShell: `$env:TASKALONG_PYTHON="C:\path\to\venv\Scripts\python.exe"`

Nothing is automatically installed, downloaded, or updated. Keep Python/npm versions paired and prior environments for rollback; arbitrary state downgrade is not guaranteed. Source builds and local artifacts are separate from registry ownership and trusted-publisher setup. Platform compatibility of this stateless CLI does not qualify native Muse or all Python versions; provider support remains TaskAlong's existing experimental boundary.
