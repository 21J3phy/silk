# Silk visual website

The landing page is now an original Chinese Silk Road ink-wash landscape with clear, lightly refractive, sharp-edged glass controls. It contains only a visible heading and one description. Links and demo controls use icons with accessible names. The separate `/agents.html` reference retains the technical contract, implementation boundaries, limitations and crawlable links; `/llms.txt`, `/discovery.json`, robots, sitemap and canonical metadata remain available.

The latest user direction permits color in the painting and requests Apple's Liquid Glass rather than frosted panels. The website uses a small CSS approximation inspired by the [Apple materials guidance](https://developer.apple.com/design/human-interface-guidelines/materials), not an Apple-native material/API. Borders, directional highlights and subtle saturation retain the visible scene. Backdrop blur is only 1.5px. Reduced transparency, increased contrast, forced colors and unsupported-browser fallbacks prioritize legibility. UI geometry remains sharp.

## Local visual demonstration

The source gate creates a fictional request, which stops at the boundary. A separate receiving-gate action gives simulated permission to cross. The resulting check is explicitly announced as a local fictional receipt, not real delivery or task completion. Reset declines a waiting request or cancels an in-flight animation. No network calls, cookies, local storage, account state, tokens, or real messages are used. The source gate only pulses twice over four seconds; other motion requires interaction. Reduced motion disables transitions and completes the visual immediately. Without JavaScript, the art and reference link work, and demo controls stay disabled.

`journey.js` is a small dependency-free script, loaded only on the landing page. `/agents.html` stays fully usable without JavaScript. The old detailed simulation remains at `/walkthrough.html` (noindex, not in sitemap).

## Original artwork

Built-in image generation created an original shan-shui-inspired landscape with misty mountains, a winding caravan path, tiny camels and a distant pavilion. A second image-generation edit preserved the composition while adding traditional jade/blue-green mineral washes, warm ivory paper, muted ochre and sienna. No third-party artwork, signature, lettering, or watermark was supplied. Original raster: 1536×1024. WebP encoding and a 900×600 responsive version reduce transfer without changing the composition. The site publishes only those optimized files; build guards pin their exact hashes.

Final prompt: “Preserve the beautiful mountain composition, mist, brush texture, caravan trail, tiny camels and pavilion, and large quiet negative space on the left. Add refined traditional Chinese mineral-pigment watercolor color: soft jade and blue-green mountain washes, pale warm ivory mist and rice paper, muted ochre desert trails, restrained rusty sienna rocks and distant sky. Subtle natural color with deep charcoal ink contours, sophisticated and luminous, not oversaturated. No text, signature, seals, watermark, frame, UI or glass elements.”

## Typography and budget

System SF Pro on Apple systems, system sans-serif fallbacks elsewhere; no Apple font is redistributed. Fira Code regular uses the existing licensed 7,636-byte self-hosted Latin WOFF subset. License is at `public/fonts/OFL.txt`; source is [Google Fonts Fira Code](https://github.com/google/fonts/tree/main/ofl/firacode). No external font requests.

Desktop painting is under 240KB; responsive painting under 110KB. Critical desktop assets stay under 280KB raw / 255KB gzip. This deliberately replaces the earlier 23KB text-only homepage budget with artwork; it remains framework-free with no video, canvas/WebGL loop, or analytics. These are file-size budgets, not Core Web Vitals measurements.

## Validation

    python scripts/check_deploy.py
    python -m unittest discover -v
    node scripts/test_public_ui.cjs
    node scripts/test_journey.cjs
    node --check public/journey.js
    python scripts/package_public.py --output /tmp/new-reviewed-silk-package

Tests cover exact assets, links/fragments, semantic metadata, heading/description-only structure, accessibility hooks, discovery truthfulness, finite motion/fallbacks, local state transitions, duplicate input, reset races, and byte budgets. Existing fixture isolation and backend tests remain unchanged. Automatic Git deployment stays off. `services/**` remains excluded from website bundles.

## Security and deployment

Render publishes only `public/`. Keep the reviewed site-wide CSP, frame, MIME, referrer and permissions headers. No additional header relaxation is needed for this revision. Main-page CSP permits only same-origin scripts, styles, fonts and images and disallows connections/forms; no inline script, style or event handlers. No repository visibility, credentials, permissions, resources, or paid plan changes.

Verify actual deployed assets, MIME, headers, 404 behavior, desktop and narrow rendering, keyboard operation, and full demo sequence. Local preview and browser DevTools are blocked in the assistant cloud browser; do not bypass. Ordinary browser zoom is available for narrow-width/reflow checks; this does not substitute for a physical touch-device test.

The source repository is private; public reference links clearly require access. No public MCP endpoint, live OAuth/database connection, or Grok/dot integration is advertised. A source implementation and isolated tests do not make messaging live. Native OpenClaw/Hermes roundtrip evidence is distinct from separate scripted-model orchestration tests. Crawler access, metadata and sitemap improve discoverability but do not guarantee indexing or ranking.
