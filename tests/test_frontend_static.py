"""Source-level UI checks. These do not claim browser/visual verification."""
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Markup(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.elements = []
        self.feed(source)

    def handle_starttag(self, tag, attributes):
        self.elements.append((tag, dict(attributes)))


class FrontendStaticTests(unittest.TestCase):
    def setUp(self):
        self.html = (ROOT / "web/index.html").read_text()
        self.js = (ROOT / "web/app.js").read_text()
        self.css = (ROOT / "web/styles.css").read_text()
        self.markup = Markup(self.html)

    def test_static_ids_are_unique_and_required_controls_exist(self):
        identifiers = [attributes["id"] for _, attributes in self.markup.elements if "id" in attributes]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        for required in ("owner-select", "invitation-form", "invitation-purpose", "send-invitation", "message-form", "meeting-title", "meeting-options", "send-message", "live-status", "retry-connection"):
            self.assertIn(required, identifiers)

    def test_no_inline_script_style_or_event_handlers(self):
        for tag, attributes in self.markup.elements:
            self.assertNotIn("style", attributes, tag)
            self.assertFalse(any(name.lower().startswith("on") for name in attributes), (tag, attributes))
            if tag == "script":
                self.assertEqual(attributes.get("src"), "/app.js")

    def test_assets_and_links_are_local(self):
        for tag, attributes in self.markup.elements:
            for attribute in ("src", "href"):
                if attribute in attributes:
                    self.assertFalse(re.match(r"(?:https?:)?//", attributes[attribute]), (tag, attributes))
        self.assertNotRegex(self.css, r"(?i)@import|url\(\s*['\"]?(?:https?:)?//")

    def test_untrusted_rendering_avoids_html_insertion_and_code_execution(self):
        for dangerous in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function("):
            self.assertNotIn(dangerous, self.js)
        self.assertIn("textContent", self.js)

    def test_ui_has_owner_epoch_abort_and_retry_key_mechanisms(self):
        # Presence checks supplement code review; only real browser tests can prove their behavior.
        for guard in ("AbortController", "mutationEpoch", "requestEpoch", "stateSequence", "pendingMessageAttempt", "idempotency_key", "X-CSRF-Token"):
            self.assertIn(guard, self.js)
        self.assertIn("Number(b.id) - Number(a.id)", self.js)


if __name__ == "__main__":
    unittest.main()
