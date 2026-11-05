# Crawl Mode — design notes

## Why (PRD)

**Problem.** NeuralSchema's normal views show the finished graph all at once.
For a real project that is a hairball: everything is visible, nothing is
understood.

**Idea.** Show the same graph *being discovered* the way a search-engine
crawler walks the web: start at a root, follow every link, queue what you
find, repeat. The order of discovery explains the structure. You see what
hangs off what, how deep call chains go, and which nodes are hubs.

**Users.** Students reading an unfamiliar codebase, teachers explaining
BFS vs DFS, and anyone curious how crawlers work.

**Goals.**
- One offline `.html` file. No CDN, no server, so it works with no internet.
- Works for every source NeuralSchema already supports (code, OS) and for websites.
- BFS, DFS, and an exact replay of a real web crawl.
- No new dependencies. Only the standard library is used.

**Non-goals.** This is not a large-scale scraper. There is no JavaScript
rendering, no login, and no bypassing of anti-bot protections.

**Acceptance criteria** (all covered by `tests/test_crawl.py`):
- Every node appears exactly once, and every parent is discovered before its child.
- BFS depths never decrease. DFS dives before it widens.
- Disconnected islands get their own root.
- Paths blocked by robots.txt are never fetched. `nofollow` is respected. The page cap is respected.
- Duplicate content (`/` vs `/index.html`) is detected and not re-parsed.
- A hostile node label cannot inject script into the page.
- An empty graph and an unreachable host both work without crashing.

## How (TRD)

| Piece | Where | What it does |
|---|---|---|
| `WebCrawler` | `neural_schema.py` | A polite crawler built on `urllib`, `html.parser` and `robotparser`. It outputs an ordinary `SchemaGraph`, so json/html/png/report exports work on websites too. |
| `normalize_url` | same | Canonicalises URLs (absolute, no `#fragment`, lower-case host, no default port) and drops non-web schemes. |
| `crawl_order` | same | Turns any graph into ordered discovery steps: `bfs`, `dfs` (iterative, so deep chains cause no recursion limit), or `replay`. |
| `crawl_payload` / `export_crawl` | same | Packs nodes, edges and orders as index arrays and writes the page. Every `<`, `>` and `&` in the data is `\u`-escaped. |
| Player | `_CRAWL_TEMPLATE` | Canvas 2D. Every frame is a pure function of time `t`, so the timeline scrubs both ways. HUD updates are throttled to about 8 Hz. |

**Time model.** Step *i* starts at `i / W`, where `W` is the number of
parallel crawlers. It then travels for one time unit from its parent to
itself.

**Politeness defaults.**
- 1 s between requests to a host, or the robots `Crawl-delay` if that is larger.
- 40 pages per crawl.
- 2 MB per page.
- 200 links per page.
- 30 off-site hosts, each shown as one aggregated node.

**robots.txt handling.**

| robots.txt response | What the crawler does |
|---|---|
| 200 | Parses the rules |
| 401 / 403 | Fetches nothing on that host |
| Any other 4xx | Treats every path as allowed |
| 5xx or network error | Fetches nothing on that host (conservative) |

## Worst case — and what happens

| Situation | Behaviour |
|---|---|
| 2,000+ node project | Defaults to 6 crawlers, tags capped at 48, faint context edges skipped above 20k edges. |
| Site blocks us / is down | Node marked `blocked by robots.txt` or `error`; crawl continues. |
| Crawler trap (endless calendar pages) | Hard page cap stops it. |
| Non-HTML (PDF, image) | Recorded as a leaf, never parsed. |
| Low-end laptop | Canvas 2D only, no WebGL; `prefers-reduced-motion` starts paused. |
| Disconnected code islands | Each gets its own root, so the final picture is always complete. |

## Victory path

- The `docs/crawl-mode.jpg` hero image and a one-line command in the README make the repo easy to grasp at a glance.
- A screen-recorded crawl of a well-known open-source repo makes a strong YouTube Short for *Cooding with Kanak*.
- Next upgrades, if wanted: GIF/WebM export of the animation, and colouring blocked or error pages differently.

## Known limits

- The GUI button was not run in CI, because tkinter is not available there. The underlying `export_crawl` is fully tested.
- JavaScript-rendered sites (SPAs) show only the links present in the initial HTML.
- The watermark uses `logo-mark.svg` (next to the script, in the current folder, or via `--logo`). If it is missing, a text "KP" badge is shown instead.
