#!/usr/bin/env python3
"""Fail a public build if its static assets or API cross the fixture boundary."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_FILES = {'walkthrough.html', 'index.html', 'styles.css', 'llms.txt', 'robots.txt', '404.html', 'discovery.json', 'walkthrough.css', 'sitemap.xml', 'fonts/OFL.txt', 'reference.css', 'journey.js', 'silk-road.webp', 'silk-road-small.webp', 'app.js', 'favicon.svg', 'fonts/fira-code-latin.woff', 'agents.html'}
API_FILES = {"status.py", "messages.py", "connections.py"}
ALLOWED_IMPORT_ROOTS = {"production", "http", "json", "dataclasses", "typing", "__future__"}
FORBIDDEN_ROUTES = ("/api/session", "/api/invitations", "/api/grants", "/api/envelopes")


def check(root=ROOT):
    errors = []
    config = json.loads((root / "vercel.json").read_text())
    if config.get("outputDirectory") != "public" or config.get("framework") is not None:
        errors.append("Public output must be the isolated public/ folder with no framework preset.")
    if config.get("git", {}).get("deploymentEnabled") is not False:
        errors.append("Automatic Git deployment must remain disabled.")
    if config.get("public") is True:
        errors.append("Public source/log exposure must not be enabled.")
    for path in (root / "public").rglob("*"):
        if path.is_symlink():
            errors.append(f"Public symlink is not allowed: {path.relative_to(root)}")
    actual = {p.relative_to(root / "public").as_posix() for p in (root / "public").rglob("*") if p.is_file()}
    if not {"index.html", "styles.css", "app.js"}.issubset(actual):
        errors.append("Required public page assets are missing.")
    if not actual.issubset(PUBLIC_FILES):
        errors.append("Unexpected public assets: " + ", ".join(sorted(actual - PUBLIC_FILES)))
    for relative in actual:
        path = root / "public" / relative
        if path.is_symlink():
            errors.append(f"Public symlink is not allowed: {relative}")
        reviewed_binary_hashes = {'fonts/fira-code-latin.woff': '0d6cd41d86ddcb021c765e2286f150dddbea5f13db0a24fcc5abc94767760d87', 'silk-road.webp': '5609dd6512d91d1bc4f2c27663cf71b30d9d33801749195c295a3da8a555dc45', 'silk-road-small.webp': 'ebb50acbc70f8a297da96810f30f17d63f50d42a19f85c52a2d0dcf43eedc439'}
        if relative in reviewed_binary_hashes:
            if hashlib.sha256(path.read_bytes()).hexdigest() != reviewed_binary_hashes[relative]:
                errors.append("Public binary differs from the reviewed asset: " + relative)
            continue
        source = path.read_text()
        if any(route in source for route in FORBIDDEN_ROUTES):
            errors.append(f"Public asset refers to a local fixture route: {relative}")
        if re.search(r"\b(?:innerHTML|outerHTML|insertAdjacentHTML)\b|document\.write\(|\beval\(", source):
            errors.append(f"Unsafe dynamic HTML/code sink in {relative}")
        if relative.endswith(".html"):
            if re.search(r"\son\w+\s*=|\sstyle\s*=", source, re.I):
                errors.append("Inline handlers/styles violate the public CSP.")
            if re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>\s*\S", source, re.I):
                errors.append("Inline scripts violate the public CSP.")
        if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", source):
            errors.append("Private key material is not a public asset.")
    api_files = {p.relative_to(root / "api").as_posix() for p in (root / "api").rglob("*.py")}
    if api_files != API_FILES:
        errors.append("Only the readiness and fail-closed connection/message APIs may deploy.")
    for directory in (root / "api", root / "production"):
        for path in directory.rglob("*.py"):
            source = path.read_text()
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [item.name.split(".")[0] for item in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level:
                        continue
                    names = [(node.module or "").split(".")[0]]
                else:
                    continue
                if any(name not in ALLOWED_IMPORT_ROOTS for name in names):
                    errors.append(f"Unexpected public API dependency in {path.relative_to(root)}: {names}")
            if "sqlite3" in source or "fixture_keys" in source or "silk.service" in source:
                errors.append(f"Local broker material in public API: {path.relative_to(root)}")
    exclusions = " ".join(str(value.get("excludeFiles", "")) for value in config.get("functions", {}).values())
    for required in ("services/**", "silk/**", "web/**", "tests/**", "var/**", "artifacts/**", "*.sqlite3"):
        if required not in exclusions:
            errors.append("Missing function bundle exclusion: " + required)
    if errors:
        raise SystemExit("Public deployment check failed:\n- " + "\n- ".join(errors))
    return sorted(actual)


if __name__ == "__main__":
    assets = check()
    print(f"Silk public boundary verified: {len(assets)} static assets, three fail-closed/readiness API routes, no fixture imports.")
