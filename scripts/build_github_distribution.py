#!/usr/bin/env python3
"""Generate a version-pinned GitHub installer; no network or credentials needed."""
import argparse
import json
from pathlib import Path
import re


def build(root, version, output):
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("version must have three numeric components")
    manifest = json.loads((root / "releases" / f"{version}.json").read_text())
    if manifest["version"] != version:
        raise ValueError("manifest version mismatch")
    cases = []
    for platform, entry in sorted(manifest["files"].items()):
        if platform not in ("darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64"):
            continue
        expected = f"https://github.com/21J3phy/silk/releases/download/v{version}/silk-{platform}"
        if entry["url"] != expected or not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"]):
            raise ValueError("invalid release asset URL or checksum")
        cases.append(f'    {platform}) url="{expected}"; sum="{entry["sha256"]}" ;;')
    if len(cases) != 4:
        raise ValueError("release must include all four supported Unix platforms")
    template = (root / "deploy/github/install.sh").read_text()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(template.replace("__VERSION__", version).replace("__CASES__", "\n".join(cases)))
    output.chmod(0o755)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    build(Path(__file__).resolve().parents[1], args.version, args.output)
