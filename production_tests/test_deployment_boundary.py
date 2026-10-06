"""Source-level isolation checks; these do not certify a Vercel deployment."""

import ast
import fnmatch
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"


def expand_braces(pattern):
    """Expand the comma-only brace groups used in Vercel exclusion globs."""
    match = re.search(r"\{([^{}]*)\}", pattern)
    if not match:
        return [pattern]
    expanded = []
    for alternative in match.group(1).split(","):
        expanded.extend(expand_braces(pattern[:match.start()] + alternative + pattern[match.end():]))
    return expanded


def glob_matches(path, pattern):
    """Treat **/ as zero-or-more folders, unlike stdlib fnmatch's literal slash."""
    return fnmatch.fnmatchcase(path, pattern) or (
        "**/" in pattern and glob_matches(path, pattern.replace("**/", "", 1))
    )


class AssetReferences(HTMLParser):
    def __init__(self):
        super().__init__()
        self.references = []
        self.inline_scripts = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script":
            if "src" in attrs:
                self.references.append(attrs["src"])
            else:
                self.inline_scripts += 1
        if tag == "link" and attrs.get("rel") in {"stylesheet", "icon", "modulepreload"}:
            self.references.append(attrs.get("href", ""))


class DeploymentBoundaryTests(unittest.TestCase):
    def config(self):
        return json.loads((ROOT / "vercel.json").read_text())

    def test_static_output_is_only_public_and_source_view_is_private(self):
        config = self.config()
        self.assertEqual(config.get("outputDirectory"), "public")
        self.assertIsNot(config.get("public", False), True)
        self.assertNotIn("builds", config, "Legacy builds can bypass the reviewed output layout")
        self.assertNotIn("routes", config, "Re-review any low-level route override before release")
        self.assertNotIn("rewrites", config, "Re-review any rewrite before release")

    def test_function_bundles_explicitly_exclude_local_fixture_material(self):
        functions = self.config().get("functions", {})
        self.assertTrue(functions, "Python bundles need explicit fixture exclusions")
        fixtures = (
            "silk/server.py", "silk/service.py", "web/index.html", "web/app.js",
            "tests/test_http.py", "scripts/demo.py", "artifacts/review.png",
            "var/silk.sqlite3", "test.sqlite3", "var/silk.sqlite3-wal",
        )
        for endpoint in ("api/status.py", "api/messages.py", "api/connections.py"):
            matching = [value for pattern, value in functions.items()
                        if glob_matches(endpoint, pattern)]
            self.assertTrue(matching, endpoint)
            for settings in matching:
                patterns = expand_braces(settings.get("excludeFiles", ""))
                for fixture in fixtures:
                    with self.subTest(endpoint=endpoint, fixture=fixture):
                        self.assertTrue(any(glob_matches(fixture, pattern) for pattern in patterns),
                                        f"{fixture} is not explicitly excluded")

    def test_vercel_upload_boundary_is_present(self):
        path = ROOT / ".vercelignore"
        self.assertTrue(path.is_file(), "Deployment upload must explicitly exclude local fixtures")
        rules = [line.strip() for line in path.read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        if "/*" in rules or "*" in rules:
            for local in ("silk", "web", "tests", "var", "artifacts"):
                self.assertNotIn("!" + local, rules)
                self.assertNotIn("!" + local + "/", rules)
                self.assertNotIn("!" + local + "/**", rules)
        else:
            for local in ("silk", "web", "tests", "var", "artifacts"):
                self.assertTrue(any(rule in {local, local + "/", local + "/**", "/" + local}
                                    for rule in rules), local)

    def test_only_reviewed_http_functions_are_present(self):
        functions = {path.stem for path in (ROOT / "api").rglob("*.py")
                     if path.name != "__init__.py"}
        self.assertEqual(functions, {"status", "messages", "connections"})
        self.assertFalse((ROOT / "api" / "session.py").exists())

    def test_public_assets_contain_no_fixture_routes_or_owner_switcher(self):
        files = [path for path in PUBLIC.rglob("*") if path.is_file()]
        self.assertTrue(files)
        forbidden = ("/api/session", "/api/state", "silk_session", "owner-switch", "ownerSwitch",
                     "data-owner-id", "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
                     "BEGIN OPENSSH PRIVATE KEY")
        for path in files:
            if path.suffix.lower() in {".html", ".js", ".css", ".json", ".svg", ".txt"}:
                content = path.read_text()
                for token in forbidden:
                    with self.subTest(path=path.relative_to(PUBLIC), token=token):
                        self.assertNotIn(token, content)

    def test_public_tree_has_no_private_or_executable_server_files(self):
        allowed = {".html", ".css", ".js", ".json", ".svg", ".png", ".jpg", ".jpeg",
                   ".webp", ".ico", ".woff", ".woff2", ".txt"}
        for path in PUBLIC.rglob("*"):
            with self.subTest(path=path.relative_to(PUBLIC)):
                self.assertFalse(path.is_symlink(), "Symlinks could escape the static boundary")
                self.assertFalse(any(part.startswith(".") for part in path.relative_to(PUBLIC).parts))
                if path.is_file():
                    self.assertIn(path.suffix.lower(), allowed)
                    self.assertFalse(any(token in path.name.lower() for token in
                                         ("sqlite", ".db", ".pem", ".key", "secret", "credential")))

    def test_html_dependencies_resolve_inside_public(self):
        parser = AssetReferences()
        parser.feed((PUBLIC / "index.html").read_text())
        self.assertEqual(parser.inline_scripts, 0, "Inline scripts require a separate CSP review")
        for reference in parser.references:
            with self.subTest(reference=reference):
                self.assertTrue(reference)
                self.assertNotRegex(reference, r"^(?:[a-z]+:)?//")
                asset = (PUBLIC / reference.split("?", 1)[0].lstrip("/")).resolve()
                self.assertTrue(asset.is_relative_to(PUBLIC.resolve()))
                self.assertTrue(asset.is_file(), reference)

    def test_public_runtime_does_not_import_fixture_broker_or_sqlite(self):
        for directory in (ROOT / "production", ROOT / "api"):
            for path in directory.rglob("*.py"):
                tree = ast.parse(path.read_text())
                for node in ast.walk(tree):
                    modules = []
                    if isinstance(node, ast.Import):
                        modules = [alias.name for alias in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        modules = [node.module]
                    for module in modules:
                        with self.subTest(path=path.relative_to(ROOT), module=module):
                            self.assertNotIn(module.split(".")[0], {"silk", "sqlite3", "cryptography"})


if __name__ == "__main__":
    unittest.main()
