# Public website

The Render static site publishes only `public/`. The homepage and agent reference need no JavaScript, cookies, third-party font service, analytics, or connection to the mailbox. The existing fictional walkthrough is retained at `/walkthrough.html`, with its script loaded only on that route. It remains a simulation and is excluded from the sitemap and marked `noindex,follow`.

## Content and discovery

- `/`: semantic, source-code microdata, descriptive title and metadata, canonical URL, consent principles and qualified implementation status.
- `/agents.html`: crawlable transport, authority, tools, evidence limitations, and setup reference.
- `/discovery.json`: explicitly Silk-specific documentation metadata. `mcp_endpoint` is null and `live_messaging` is false. It is not standard MCP service discovery.
- `/llms.txt`: optional plaintext reading guide, with no indexing or tool-compatibility guarantee.
- `/robots.txt` and `/sitemap.xml`: permit crawling and identify the two indexable canonical pages. No deployment-time claim of indexing or ranking.
- `/404.html`: explicit missing-page content, noindex; no catch-all SPA rewrite.

Do not advertise an MCP endpoint until its exact hosted URL, OAuth flow, database, permissions and actual client roundtrip are verified. A native OpenClaw/Hermes round trip used synthetic identities; separate orchestration tests used deterministic local models. No general efficiency, live-provider, Grok or dot integration claim is justified by those tests.

## Design and font provenance

Grayscale only, sharp corners, system SF Pro on Apple systems (`-apple-system` / `BlinkMacSystemFont` / installed SF Pro), with system sans-serif fallback elsewhere. No Apple font is redistributed.

Fira Code regular is self-hosted as a 7,636-byte Latin WOFF subset. Source: [Google Fonts Fira Code](https://github.com/google/fonts/tree/main/ofl/firacode), variable `FiraCode[wght].ttf`, pinned to weight 400 during subsetting. The source license is shipped unchanged at `public/fonts/OFL.txt`. The modified subset covers U+0020–U+007E and U+00B7/U+2013/U+2014/U+2192/U+2194, with optional ligature layout removed. FontTools generated the subset; WOFF avoids adding a build dependency. The build guard pins its exact SHA-256. `font-display:swap` preserves immediate text rendering.

## Budgets and checks

The homepage critical HTML/CSS/font/favicon total is under 30,000 raw bytes and 16,000 bytes when each is gzipped. This is an asset budget, not a measured network-speed or Core Web Vitals claim. Rendering, protocol, TLS, caching, and server compression depend on actual delivery. The complete public folder also includes optional walkthrough assets and the font license.

Run:

    python scripts/check_deploy.py
    python -m unittest discover -s production_tests -v
    python -m unittest discover -s tests -v
    node scripts/test_public_ui.cjs
    python scripts/package_public.py --output /tmp/new-reviewed-silk-package

The website tests check metadata, local links/fragments, sitemap, static/no-script primary routes, grayscale colors, font provenance, disclosure consistency and asset budgets. Existing API, deployment-isolation and fictional-walkthrough checks remain active. `services/**` stays excluded and automatic Git deployment remains disabled.

## Security headers and deployment

`vercel.json` records the header contract for that host; it does not configure Render. The Render static service must separately retain its existing security headers and add `font-src 'self'` to its CSP before using the self-hosted font. Do not widen script/style sources, add `unsafe-inline`, change account permissions, or expose services/fixture paths.

Recommended site-wide header contract:

    Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'
    X-Content-Type-Options: nosniff
    X-Frame-Options: DENY
    Referrer-Policy: no-referrer
    Permissions-Policy: camera=(), microphone=(), geolocation=()

Primary-page CSP metadata is stricter (no scripts or network connections), but frame protection must be an HTTP header. Validate actual headers, MIME types, non-SPA 404 status, font load, desktop/mobile layout, keyboard focus and simulation behavior on the deployed site. A local browser restriction is not a visual test pass.

## Source guidance

- [Google Search developer guidance](https://developers.google.com/search/docs/fundamentals/get-started-developers): discoverable links and crawlable content.
- [Google crawlable links](https://developers.google.com/search/docs/crawling-indexing/links-crawlable): normal anchor links with href.
- [OpenAI crawler documentation](https://developers.openai.com/api/docs/bots): crawler controls and their distinct uses.

Search engines decide crawling, indexing, ranking, and result presentation independently.
