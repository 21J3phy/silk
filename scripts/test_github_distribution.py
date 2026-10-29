#!/usr/bin/env python3
"""Offline tests: no real binary downloads, credentials, or relay requests."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("builder", Path(__file__).with_name("build_github_distribution.py"))
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)
ROOT = Path(__file__).resolve().parents[1]


class InstallerTests(unittest.TestCase):
    def run_case(self, fail=False):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            (t / "releases").mkdir()
            (t / "deploy/github").mkdir(parents=True)
            (t / "deploy/github/install.sh").write_text((ROOT / "deploy/github/install.sh").read_text())
            binary = b'#!/bin/sh\n[ "$1" = self-verify ] && [ "$2" = --bundle ] && [ -f "$3" ] || exit 8\nexit ${VERIFY_EXIT:-0}\n'
            (t / "binary").write_bytes(binary)
            files = {p: {"url": f"https://github.com/21J3phy/silk/releases/download/v9.0.0/silk-{p}", "sha256": hashlib.sha256(binary).hexdigest()} for p in ("darwin-arm64", "darwin-amd64", "linux-arm64", "linux-amd64")}
            (t / "releases/9.0.0.json").write_text(json.dumps({"version": "9.0.0", "files": files}))
            installer = t / "install.sh"
            builder.build(t, "9.0.0", installer)
            subprocess.run(["sh", "-n", str(installer)], check=True)
            mock = t / "mock"
            mock.mkdir()
            curl = mock / "curl"
            curl.write_text('''#!/bin/sh
case "$2" in
 https://github.com/21J3phy/silk/releases/download/v9.0.0/silk-*) cp "$TEST_ROOT/binary" "$4";;
 https://github.com/21J3phy/silk/releases/download/v9.0.0/release-bundle.json) printf '{}' > "$4";;
 *) echo "unexpected network target: $2" >&2; exit 9;;
esac
''')
            curl.chmod(0o755)
            env = dict(os.environ, PATH=str(mock)+":"+os.environ["PATH"], TEST_ROOT=str(t), SILK_INSTALL_DIR=str(t/"installed"), VERIFY_EXIT="7" if fail else "0")
            result = subprocess.run(["sh", str(installer)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 7 if fail else 0, result.stderr)
            self.assertEqual((t/"installed/silk").exists(), not fail)

    def test_offline_installer(self):
        self.run_case()

    def test_failed_verification_does_not_install(self):
        self.run_case(fail=True)

    def test_reject_version_injection(self):
        with self.assertRaises(ValueError):
            builder.build(ROOT, '1.0.0;echo unsafe', Path('/nonexistent'))


if __name__ == '__main__':
    unittest.main()
