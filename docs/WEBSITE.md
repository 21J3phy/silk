# Silk visual website

## Art-direction revision (October 2026)

The new landing removes the text card entirely. Exposed oversized typography sits in the painting's ivory negative space, with a vermilion full stop echoing the caravan trail. Two substantial optical-glass gates make the consent journey legible. The glass has no content blur: a low-frequency SVG displacement filter refracts the visible scene in supporting browsers; directional bevel highlights and transparent gradients remain the fallback. It is a web approximation, not Apple's native material. Glyphs remain sharp and accessible. The description changes to explain the current action without adding extra copy blocks.

The replacement artwork is an original built-in image-generation output, 1672×941 pixels, with a deliberately art-directed 690×1100 portrait crop. Desktop WebP is 275,248 bytes at quality 86; mobile is 103,474 bytes at quality 86. This revision raises the critical desktop budget to 325KB raw / 300KB gzip to preserve crisp brushwork. No runtime resize, framework, animation library, continuous animation, external requests, or telemetry is introduced. The original master is retained outside the published folder.

Final generation prompt: Original premium landscape website painting; a Chinese Silk Road handscroll interpretation with an immense desert valley, monumental mineral-turquoise and smoky ink-blue crags, ochre dunes, five tiny camels along a cinnabar trail, a distant Tang-era watchtower, crisp gongbi contour and dry-ink brushwork on ivory paper. Upper 45 percent quiet negative space, foreground detail below, asymmetrical cliffs at the edges. No lettering, watermark, seal, frame or UI. Built-in image generation used; no third-party painting copied.

Publication stays limited to the exact public asset allowlist. Preview and production publish only public/. The original backend and source access controls are unchanged.

## Local visual demonstration

The source gate creates a fictional request, which stops at the boundary. A separate receiving-gate action gives simulated permission to cross. The resulting check is explicitly announced as a local fictional receipt, not real delivery or task completion. Reset declines a waiting request or cancels an in-flight animation. No network calls, cookies, local storage, account state, tokens, or real messages are used. The source gate only pulses twice over 3.2 seconds; other motion requires interaction. Reduced motion disables transitions and completes the visual immediately. Without JavaScript, the art and reference link work, and demo controls stay disabled.

`journey.js` is a small dependency-free script, loaded only on the landing page. `/agents.html` stays fully usable without JavaScript. The old detailed simulation remains at `/walkthrough.html` (noindex, not in sitemap).


## Typography and validation

System SF Pro on Apple systems, system sans-serif fallbacks elsewhere. Fira Code uses the existing licensed self-hosted Latin WOFF. No Apple font is redistributed.

Run `python scripts/check_deploy.py`, `python -m unittest discover -v`, `node scripts/test_public_ui.cjs`, `node scripts/test_journey.cjs`, and `node --check public/journey.js`.

## Security and deployment

Render publishes only `public/`. Keep the reviewed site-wide CSP, frame, MIME, referrer and permissions headers. No additional header relaxation is needed for this revision. Main-page CSP permits only same-origin scripts, styles, fonts and images and disallows connections/forms; no inline script, style or event handlers. No repository visibility, credentials, permissions, resources, or paid plan changes.

Verify actual deployed assets, MIME, headers, 404 behavior, desktop and narrow rendering, keyboard operation, and full demo sequence. Local preview and browser DevTools are blocked in the assistant cloud browser; do not bypass. Ordinary browser zoom is available for narrow-width/reflow checks; this does not substitute for a physical touch-device test.

The source repository is public under Apache-2.0; reference links point to it directly. No public MCP endpoint, live OAuth/database connection, or Grok/dot integration is advertised. A source implementation and isolated tests do not make messaging live. Native OpenClaw/Hermes roundtrip evidence is distinct from separate scripted-model orchestration tests. Crawler access, metadata and sitemap improve discoverability but do not guarantee indexing or ranking.


Browser QA used the cloud Chromium browser at 1180×757, 500×932 and 400×746 CSS pixels. The portrait crop preserves the caravan and right cliff. An observed low-contrast lock over the dark cliff was corrected with a light glyph and dark edge shadow only in the portrait layout.
