#!/usr/bin/env python3
"""Create an exact allowlist deployment bundle; never deploy or read credentials."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import zipfile

from check_deploy import check

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_FILES = [
    "api/status.py", "api/messages.py", "api/connections.py",
    "production/__init__.py", "production/http.py", "production/readiness.py", "production/interfaces.py",
    "scripts/check_deploy.py", "vercel.json", ".python-version", "requirements.txt", ".vercelignore",
]


def package(output: Path):
    assets = check(ROOT)
    selected = sorted(["public/" + name for name in assets] + RUNTIME_FILES)
    files_dir = output / "files"
    if files_dir.exists():
        raise SystemExit("Output already exists; choose a fresh --output directory to avoid stale deployment files.")
    files_dir.mkdir(parents=True)
    records = []
    for relative in selected:
        source = ROOT / relative
        if source.is_symlink() or not source.is_file():
            raise SystemExit("Invalid deployment source: " + relative)
        raw = source.read_bytes()
        if raw.startswith(b"SQLite format") or b"-----BEGIN PRIVATE KEY-----" in raw:
            raise SystemExit("Runtime database/private key material cannot be deployed.")
        target = files_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        records.append({"path": relative, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    check(files_dir)
    archive = output / "silk-public-deploy.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for entry in records:
            z.write(files_dir / entry["path"], entry["path"])
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        assert sorted(z.namelist()) == selected
        for entry in records:
            assert hashlib.sha256(z.read(entry["path"])).hexdigest() == entry["sha256"]
    manifest = {
        "product": "Silk", "purpose": "Public development preview; live messaging disabled",
        "deployment_performed": False, "files_directory": str(files_dir), "files": records,
        "archive": str(archive), "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "excluded": ["local fixture broker", "owner switcher", "runtime databases", "private keys", "environment files", "tests", "dependencies"],
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "public-deployment")
    result = package(parser.parse_args().output.resolve())
    print(json.dumps({"file_count": len(result["files"]), "files_directory": result["files_directory"], "archive": result["archive"], "archive_sha256": result["archive_sha256"], "deployment_performed": False}, indent=2))
