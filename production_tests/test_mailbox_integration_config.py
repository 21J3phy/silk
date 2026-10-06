"""Source-controlled mailbox isolation; not a remote Vercel account attestation."""
import ast
import fnmatch
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PUBLIC_FILES = {
    '.python-version', '.vercelignore', 'requirements.txt', 'vercel.json',
    'scripts/check_deploy.py',
    'api/status.py', 'api/messages.py', 'api/connections.py',
    'production/__init__.py', 'production/http.py', 'production/readiness.py', 'production/interfaces.py',
    'public/index.html', 'public/styles.css', 'public/app.js', 'public/favicon.svg',
}


class MailboxIntegrationConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / 'vercel.json').read_text())

    def test_automatic_git_deployment_is_explicitly_disabled(self):
        self.assertIs(self.config.get('git', {}).get('deploymentEnabled'), False)

    def test_every_python_function_excludes_services(self):
        functions = self.config['functions']
        sources = [path.relative_to(ROOT).as_posix() for path in (ROOT / 'services' / 'mailbox').rglob('*') if path.is_file()]
        self.assertTrue(sources)
        for endpoint in ('api/status.py', 'api/messages.py', 'api/connections.py'):
            configurations = [value for pattern, value in functions.items() if fnmatch.fnmatchcase(endpoint, pattern)]
            self.assertTrue(configurations)
            for entry in configurations:
                pattern = entry['excludeFiles']
                self.assertTrue(pattern.startswith('{') and pattern.endswith('}'))
                exclusions = pattern[1:-1].split(',')
                self.assertIn('services/**', exclusions)
                for source in sources:
                    self.assertTrue(any(fnmatch.fnmatchcase(source, exclusion) for exclusion in exclusions), source)

    def test_upload_excludes_the_services_directory_without_negation(self):
        rules = [line.strip() for line in (ROOT / '.vercelignore').read_text().splitlines() if line.strip() and not line.lstrip().startswith('#')]
        self.assertIn('services/', rules)
        self.assertFalse(any(rule.startswith('!services') or rule.startswith('!/services') for rule in rules))

    def test_static_and_function_entrypoint_boundaries_stay_the_same(self):
        self.assertEqual(self.config['outputDirectory'], 'public')
        self.assertIsNone(self.config['framework'])
        self.assertIs(self.config['public'], False)
        self.assertNotIn('services', self.config)
        self.assertEqual({p.relative_to(ROOT).as_posix() for p in (ROOT / 'api').rglob('*.py')}, {'api/status.py', 'api/messages.py', 'api/connections.py'})
        self.assertFalse((ROOT / 'public' / 'services').exists())

    def test_public_packaging_allowlist_has_no_mailbox_files(self):
        tree = ast.parse((ROOT / 'scripts' / 'package_public.py').read_text())
        runtime = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'RUNTIME_FILES' for target in node.targets))
        public_assets = [p.relative_to(ROOT).as_posix() for p in (ROOT / 'public').iterdir() if p.is_file()]
        selected = set(runtime) | set(public_assets)
        self.assertEqual(selected, EXPECTED_PUBLIC_FILES)
        self.assertFalse(any(path.startswith('services/') for path in selected))


if __name__ == '__main__':
    unittest.main()
