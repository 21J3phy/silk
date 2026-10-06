"""Adversarial build-guard fixtures, never modifications to the real app tree."""

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from scripts.check_deploy import check


ROOT = Path(__file__).resolve().parents[1]


class BuildGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="silk-public-boundary-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copyfile(ROOT / "vercel.json", self.root / "vercel.json")
        for folder in ("production", "api"):
            shutil.copytree(ROOT / folder, self.root / folder, ignore=shutil.ignore_patterns("__pycache__"))
        (self.root / "public").mkdir()
        for name, source in {"index.html": '<!doctype html><title>Test only</title><script src="/app.js" defer></script>',
                             "app.js": '"use strict";', "styles.css": "body { color: black; }"}.items():
            (self.root / "public" / name).write_text(source)

    def change_config(self, operation):
        path = self.root / "vercel.json"
        config = json.loads(path.read_text())
        operation(config)
        path.write_text(json.dumps(config))

    def assert_rejected(self, expected):
        with self.assertRaises(SystemExit) as caught:
            check(self.root)
        self.assertIn(expected, str(caught.exception))

    def test_clean_isolated_fixture_passes(self):
        self.assertEqual(check(self.root), ["app.js", "index.html", "styles.css"])

    def test_database_or_unknown_file_in_public_is_rejected(self):
        (self.root / "public" / "silk.sqlite3").write_text("synthetic, not a database")
        self.assert_rejected("Unexpected public assets")

    def test_private_key_material_is_rejected_even_in_allowlisted_asset(self):
        (self.root / "public" / "app.js").write_text('const fake = "-----BEGIN PRIVATE KEY-----";')
        self.assert_rejected("Private key material")

    def test_public_file_symlink_is_rejected(self):
        (self.root / "synthetic-private.txt").write_text("synthetic")
        (self.root / "public" / "app.js").unlink()
        (self.root / "public" / "app.js").symlink_to(self.root / "synthetic-private.txt")
        self.assert_rejected("symlink")

    def test_public_directory_symlink_is_rejected(self):
        (self.root / "private").mkdir()
        (self.root / "private" / "demo.html").write_text("synthetic local fixture")
        (self.root / "public" / "leak").symlink_to(self.root / "private", target_is_directory=True)
        self.assert_rejected("symlink")

    def test_fixture_api_endpoint_is_rejected(self):
        (self.root / "api" / "session.py").write_text("from production.http import PublicHandler\n")
        self.assert_rejected("Only the readiness")

    def test_nested_fixture_api_endpoint_is_rejected(self):
        (self.root / "api" / "nested").mkdir()
        (self.root / "api" / "nested" / "session.py").write_text("from production.http import PublicHandler\n")
        self.assert_rejected("Only the readiness")

    def test_fixture_import_is_rejected(self):
        with (self.root / "api" / "status.py").open("a") as output:
            output.write("\nfrom silk.service import Service\n")
        self.assert_rejected("Unexpected public API dependency")

    def test_browser_fixture_route_is_rejected(self):
        (self.root / "public" / "app.js").write_text('fetch("/api/session");')
        self.assert_rejected("local fixture route")

    def test_dynamic_html_sink_is_rejected(self):
        (self.root / "public" / "app.js").write_text('element.innerHTML = "unsafe";')
        self.assert_rejected("Unsafe dynamic HTML")

    def test_inline_event_handler_is_rejected(self):
        (self.root / "public" / "index.html").write_text('<button onclick="send()">Send</button>')
        self.assert_rejected("Inline handlers/styles")

    def test_nonpublic_output_directory_is_rejected(self):
        self.change_config(lambda config: config.update(outputDirectory="."))
        self.assert_rejected("isolated public/")

    def test_public_source_view_is_rejected(self):
        self.change_config(lambda config: config.update(public=True))
        self.assert_rejected("Public source/log exposure")

    def test_missing_bundle_exclusions_are_rejected(self):
        self.change_config(lambda config: config.update(functions={}))
        self.assert_rejected("Missing function bundle exclusion")


if __name__ == "__main__":
    unittest.main()
