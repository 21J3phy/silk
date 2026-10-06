"""Crawlability, asset budgets, and static trust boundaries for the public site."""
import gzip
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import unittest
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / 'public'
BASE = 'https://silk-landing.onrender.com'

class Document(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.tags = []
        self.feed(source)
    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
    def find(self, tag):
        return [attrs for name, attrs in self.tags if name == tag]

class WebsiteTests(unittest.TestCase):
    def test_primary_pages_are_static_semantic_and_canonical(self):
        for name, canonical in [('index.html','/'), ('agents.html','/agents.html')]:
            with self.subTest(name=name):
                source = (PUBLIC / name).read_text()
                doc = Document(source)
                self.assertEqual(len(doc.find('h1')), 1)
                self.assertEqual(len(doc.find('main')), 1)
                self.assertEqual(doc.find('html')[0]['lang'], 'en')
                if name == 'agents.html':
                    self.assertFalse(doc.find('script'))
                else:
                    self.assertEqual([a.get('src') for a in doc.find('script')], ['/journey.js'])
                self.assertTrue(any(a.get('href') == '#main' for a in doc.find('a')))
                self.assertEqual([a['href'] for a in doc.find('link') if a.get('rel') == 'canonical'], [BASE+canonical])
                self.assertTrue(any(a.get('name') == 'description' and len(a.get('content','')) > 80 for a in doc.find('meta')))
                self.assertNotIn('noindex', source)
                self.assertNotRegex(source, r'<(?:iframe|form)\b')
                self.assertLess(len(source.encode()), 12_000)

    def test_all_local_links_assets_and_fragments_resolve(self):
        for path in PUBLIC.glob('*.html'):
            doc = Document(path.read_text())
            ids = [a['id'] for _, a in doc.tags if 'id' in a]
            self.assertEqual(len(ids), len(set(ids)), path.name)
            for tag, attrs in doc.tags:
                ref = attrs.get('href') or attrs.get('src')
                if not ref or urlsplit(ref).scheme or ref.startswith('//'):
                    continue
                link = urlsplit(ref)
                target = PUBLIC / (link.path.lstrip('/') or (path.name if not link.path else 'index.html'))
                if link.path == '/': target = PUBLIC / 'index.html'
                with self.subTest(page=path.name, ref=ref):
                    self.assertTrue(target.is_file())
                    if link.fragment:
                        target_ids = {a['id'] for _, a in Document(target.read_text()).tags if 'id' in a}
                        self.assertIn(link.fragment, target_ids)

    def test_sitemap_and_robots_are_consistent(self):
        sitemap = ET.parse(PUBLIC / 'sitemap.xml')
        urls = [node.text for node in sitemap.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}loc')]
        self.assertEqual(urls, [BASE+'/', BASE+'/agents.html'])
        robots = (PUBLIC / 'robots.txt').read_text()
        self.assertIn('User-agent: *\nAllow: /', robots)
        self.assertIn('Sitemap: '+BASE+'/sitemap.xml', robots)
        self.assertNotIn('Disallow:', robots)
        self.assertIn('noindex,follow', (PUBLIC / 'walkthrough.html').read_text())
        self.assertIn('noindex', (PUBLIC / '404.html').read_text())

    def test_discovery_never_fabricates_a_live_connection(self):
        data = json.loads((PUBLIC / 'discovery.json').read_text())
        self.assertIs(data['live_messaging'], False)
        self.assertIsNone(data['mcp_endpoint'])
        self.assertEqual(data['stage'], 'development_preview')
        self.assertEqual(len(data['tools_implemented']), 6)
        self.assertEqual(data['protocol_implemented'], '2025-11-25')
        self.assertIn('not a standard MCP discovery document', ' '.join(data['limitations']))
        self.assertIn('optional reading-guide convention', (PUBLIC / 'llms.txt').read_text())

    def test_sharp_primary_surface_and_grayscale_reference(self):
        for filename in ('reference.css','walkthrough.css','favicon.svg'):
            source = (PUBLIC / filename).read_text()
            for h in re.findall(r'#([0-9a-fA-F]{3,8})\b', source):
                if len(h) in {3,4}: h = ''.join(v*2 for v in h)
                self.assertEqual(h[:2],h[2:4], filename)
                self.assertEqual(h[2:4],h[4:6], filename)
            self.assertNotRegex(source, r'\b(?:blue|red|green|purple|orange|yellow)\s*[;}]')
        self.assertNotIn('border-radius', (PUBLIC / 'styles.css').read_text())
        self.assertIn('border-radius:0!important', (PUBLIC / 'walkthrough.css').read_text())

    def test_font_license_and_first_load_budget(self):
        css = (PUBLIC / 'styles.css').read_text()
        self.assertIn('"SF Pro Display"',css)
        self.assertIn('font-display:swap',css)
        self.assertIn('SIL OPEN FONT LICENSE', (PUBLIC / 'fonts/OFL.txt').read_text())
        required = ['index.html','styles.css','journey.js','fonts/fira-code-latin.woff','favicon.svg','silk-road.webp']
        raw = sum((PUBLIC / f).stat().st_size for f in required)
        compressed = sum(len(gzip.compress((PUBLIC / f).read_bytes(),mtime=0)) for f in required)
        self.assertLess(raw, 280_000)
        self.assertLess(compressed, 255_000)
        self.assertEqual([p.name for p in (PUBLIC/'fonts').glob('*.woff')],['fira-code-latin.woff'])
        self.assertNotRegex(css, r'@import|https?://|data:')
        self.assertLess((PUBLIC/'silk-road-small.webp').stat().st_size, 110_000)
        self.assertFalse(Document((PUBLIC/'agents.html').read_text()).find('script'))

    def test_visual_landing_has_only_heading_description_and_accessible_icons(self):
        source = (PUBLIC/'index.html').read_text()
        doc = Document(source)
        self.assertEqual(len(doc.find('h1')),1)
        self.assertEqual(len(doc.find('p')),1)
        self.assertFalse(doc.find('h2'))
        self.assertFalse(doc.find('footer'))
        for attrs in doc.find('button'):
            self.assertTrue(attrs.get('aria-label'))
        self.assertIn('aria-live="polite"',source)
        self.assertIn('No live messages.',source)
        self.assertIn('prefers-reduced-motion:reduce',(PUBLIC/'styles.css').read_text())
        self.assertIn('prefers-reduced-transparency:reduce',(PUBLIC/'styles.css').read_text())
        script = (PUBLIC/'journey.js').read_text()
        self.assertNotRegex(script,r'fetch\(|XMLHttpRequest|WebSocket|localStorage|sessionStorage|document.cookie')

    def test_structured_data_is_source_code_not_a_fake_live_product(self):
        source = (PUBLIC/'index.html').read_text()
        self.assertIn('itemtype="https://schema.org/SoftwareSourceCode"',source)
        self.assertIn('itemprop="name"',source)
        self.assertNotIn('AggregateRating',source)
        self.assertNotIn('Offer',source)

if __name__ == '__main__':
    unittest.main()
