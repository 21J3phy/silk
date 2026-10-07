"""Install footprint: du -sk of site-packages in a fresh, dedicated venv per server.

broker  : requirements-dev.txt                 (all `python -m silk` needs)
mailbox : services/mailbox/requirements.txt    (what the mailbox service declares)

Measured right after `uv pip install` (uv does not compile .pyc by default), then
an import smoke test proves the venv can load the server, and the venvs are
deleted. Writes bench/v1/.footprint/footprint.json.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
OUT = HERE / ".footprint"


def du_mb(*paths: Path) -> float:
    existing = [str(p) for p in paths if p.exists()]
    if not existing:
        return 0.0
    output = subprocess.check_output(["du", "-sk", *existing], text=True)
    return sum(int(line.split()[0]) for line in output.splitlines()) / 1024


def build(name: str, requirements: list[Path], import_check: str, pythonpath: Path):
    venv = OUT / name
    subprocess.run(["uv", "venv", "--no-project", "--clear", "-q", "--python", "3.12", str(venv)], check=True)
    python = venv / "bin" / "python"
    args = ["uv", "pip", "install", "-q", "--python", str(python)]
    for requirement in requirements:
        args += ["-r", str(requirement)]
    subprocess.run(args, check=True, cwd=REPO)
    site = next((venv / "lib").glob("python3.*/site-packages"))
    size = du_mb(site)
    packages = json.loads(subprocess.check_output(["uv", "pip", "list", "--python", str(python), "--format", "json"], text=True))
    env = {**os.environ, "PYTHONPATH": str(pythonpath), "PYTHONDONTWRITEBYTECODE": "1"}
    subprocess.run([str(python), "-c", import_check], check=True, env=env, cwd=REPO)
    version = subprocess.check_output([str(python), "-c", "import platform; print(platform.python_version())"], text=True).strip()
    base = Path(subprocess.check_output([str(python), "-c", "import sys; print(sys.base_prefix)"], text=True).strip())
    return venv, site, size, packages, version, base


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir(parents=True)
    result = {}

    venv, site, size, packages, version, base = build(
        "broker", [REPO / "requirements-dev.txt"], "import silk.server, silk.service", REPO)
    listing = ", ".join(f"{p['name']} {p['version']}" for p in packages)
    result["broker"] = {"site_packages_mb": round(size, 1), "note": (
        f"du -sk of site-packages in a fresh `uv venv --python 3.12` (Python {version}) with only requirements-dev.txt installed "
        f"({listing}) = {size:.1f} MB; .pyc caches excluded (uv does not byte-compile); the CPython interpreter itself "
        f"({base}, {du_mb(base):.0f} MB) is not included. Import of silk.server verified from that venv.")}
    shutil.rmtree(venv)

    venv, site, size, packages, version, base = build(
        "mailbox", [REPO / "services" / "mailbox" / "requirements.txt"], "import silk_live.app, silk_live.auth, silk_live.storage, uvicorn",
        REPO / "services" / "mailbox")
    pg = du_mb(*[p for p in site.iterdir() if p.name.lower().startswith("psycopg")])
    listing = ", ".join(f"{p['name']} {p['version']}" for p in packages)
    result["mailbox"] = {"site_packages_mb": round(size, 1), "note": (
        f"du -sk of site-packages in a fresh `uv venv --python 3.12` (Python {version}) with services/mailbox/requirements.txt installed "
        f"({len(packages)} distributions: {listing}) = {size:.1f} MB, of which psycopg/psycopg_binary (PostgreSQL driver, "
        f"required for deployment, unused by the SQLite fixture server benchmarked here) = {pg:.1f} MB, i.e. {size - pg:.1f} MB without it; "
        f".pyc caches excluded; interpreter ({du_mb(base):.0f} MB) not included. Imports of silk_live.app and uvicorn verified from that venv.")}
    shutil.rmtree(venv)

    (OUT / "footprint.json").write_text(json.dumps(result, indent=2) + "\n")
    for name, entry in result.items():
        print(f"{name}: {entry['site_packages_mb']} MB")


if __name__ == "__main__":
    sys.exit(main())
