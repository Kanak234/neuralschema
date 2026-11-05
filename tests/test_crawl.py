"""Tests for Crawl Mode: crawl_order, WebCrawler and export_crawl.

The web tests spin up a tiny local website (stdlib http.server on 127.0.0.1)
so they never touch the internet and always behave the same in CI.
"""
import json
import os
import re
import tempfile
import threading
import unittest
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from neural_schema import (
    K_CLASS,
    K_FUNCTION,
    K_MODULE,
    K_PROJECT,
    K_SITE,
    R_CALLS,
    R_CONTAINS,
    SchemaGraph,
    WebCrawler,
    crawl_order,
    crawl_payload,
    export_crawl,
    main,
    normalize_url,
)


def small_code_graph():
    """project -> 2 modules -> classes/functions, plus one isolated node."""
    sg = SchemaGraph(title="demo", kind="code", language="python")
    sg.add_node("p", K_PROJECT, "demo")
    for m in ("a", "b"):
        sg.add_node(f"m:{m}", K_MODULE, f"{m}.py")
        sg.add_edge("p", f"m:{m}", R_CONTAINS)
    sg.add_node("c:A", K_CLASS, "A")
    sg.add_edge("m:a", "c:A", R_CONTAINS)
    for f in ("f1", "f2", "f3"):
        sg.add_node(f"f:{f}", K_FUNCTION, f)
    sg.add_edge("c:A", "f:f1", R_CONTAINS)
    sg.add_edge("f:f1", "f:f2", R_CALLS)
    sg.add_edge("f:f2", "f:f3", R_CALLS)
    sg.add_edge("m:b", "f:f3", R_CONTAINS)
    sg.add_node("lonely", K_FUNCTION, "orphan")     # disconnected island
    return sg


class TestCrawlOrder(unittest.TestCase):
    def test_every_node_exactly_once_with_valid_parents(self):
        sg = small_code_graph()
        for strategy in ("bfs", "dfs"):
            steps = crawl_order(sg, strategy)
            ids = [s["id"] for s in steps]
            self.assertEqual(sorted(ids), sorted(sg.nodes()), strategy)
            seen = set()
            for s in steps:
                if s["parent"] is not None:
                    self.assertIn(s["parent"], seen, "parent must come first")
                seen.add(s["id"])

    def test_starts_at_project_root_and_island_gets_own_root(self):
        steps = crawl_order(small_code_graph(), "bfs")
        self.assertEqual(steps[0]["id"], "p")
        roots = [s["id"] for s in steps if s["parent"] is None]
        self.assertEqual(roots, ["p", "lonely"])

    def test_bfs_depths_never_decrease_within_component(self):
        steps = [s for s in crawl_order(small_code_graph(), "bfs")
                 if s["id"] != "lonely"]
        depths = [s["depth"] for s in steps]
        self.assertEqual(depths, sorted(depths))

    def test_dfs_goes_deep_before_wide(self):
        steps = crawl_order(small_code_graph(), "dfs")
        ids = [s["id"] for s in steps]
        # DFS dives p -> a.py -> A -> f1 -> f2 -> f3 before visiting b.py
        self.assertLess(ids.index("f:f3"), ids.index("m:b"))
        bfs = [s["id"] for s in crawl_order(small_code_graph(), "bfs")]
        self.assertNotEqual(ids, bfs)

    def test_explicit_start_by_label(self):
        steps = crawl_order(small_code_graph(), "bfs", start="f2")
        self.assertEqual(steps[0]["id"], "f:f2")

    def test_empty_graph(self):
        self.assertEqual(crawl_order(SchemaGraph(), "bfs"), [])

    def test_replay_falls_back_without_disc_step(self):
        self.assertEqual(crawl_order(small_code_graph(), "replay"),
                         crawl_order(small_code_graph(), "bfs"))


class TestNormalizeUrl(unittest.TestCase):
    def test_canonical_forms(self):
        b = "http://Example.com:80/docs/"
        self.assertEqual(normalize_url(b, "a#top"), "http://example.com/docs/a")
        self.assertEqual(normalize_url(b, "/x?q=1"), "http://example.com/x?q=1")
        self.assertEqual(normalize_url("https://h:443", "https://h:443"), "https://h/")
        for bad in ("mailto:a@b.c", "javascript:void(0)", "#", "", "ftp://h/x"):
            self.assertIsNone(normalize_url(b, bad), bad)


SITE = {
    "robots.txt": "User-agent: *\nDisallow: /secret\n",
    "index.html": "<html><head><title>Home Page</title></head><body>"
                  "<a href='/a.html'>a</a> <a href='b.html#x'>b</a>"
                  "<a href='/secret/s.html'>s</a>"
                  "<a href='https://external.example/'>ext</a>"
                  "<a href='mailto:x@y.z'>mail</a>"
                  "<a href='/c.html' rel='nofollow'>c</a>"
                  "<a href='/'>same page, other url</a></body></html>",
    "a.html": "<title>A</title><a href='/deep1.html'>d</a>"
              "<a href='/index.html#top'>home</a>",
    "b.html": "<title>B &amp; co</title><a href='/a.html'>a</a>",
    "deep1.html": "<title>D1</title><a href='/deep2.html'>d</a>",
    "deep2.html": "<title>D2</title>",
    "c.html": "<title>C</title>",
    "secret/s.html": "<title>SECRET</title>",
}


class _Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


class TestWebCrawler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        for rel, body in SITE.items():
            p = os.path.join(cls.tmp.name, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(body)
        handler = partial(_Quiet, directory=cls.tmp.name)
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        cls.th = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.th.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def crawl(self, **kw):
        kw.setdefault("delay", 0)
        return WebCrawler(**kw).crawl(self.base + "/index.html")

    def test_crawls_site_respecting_robots_and_nofollow(self):
        sg = self.crawl(max_pages=20)
        nodes = sg.nodes()
        fetched = {a["url"].rsplit("/", 1)[-1] for a in nodes.values()
                   if a.get("fetched") and not a.get("duplicate_of")}
        self.assertEqual(fetched, {"index.html", "a.html", "b.html",
                                   "deep1.html", "deep2.html"})
        # "/" serves the same bytes as /index.html -> flagged, not re-parsed
        self.assertEqual(nodes[f"url:{self.base}/"]["duplicate_of"],
                         f"{self.base}/index.html")
        secret = [a for a in nodes.values() if "secret" in a.get("url", "")]
        self.assertEqual(len(secret), 1)
        self.assertTrue(secret[0].get("blocked"))
        self.assertFalse(any("c.html" in a.get("url", "") for a in nodes.values()),
                         "rel=nofollow link must not be followed")
        self.assertIn("site:external.example", nodes)
        self.assertEqual(nodes["site:external.example"]["kind"], K_SITE)
        self.assertEqual(nodes[f"url:{self.base}/index.html"]["label"], "Home Page")
        self.assertEqual(nodes[f"url:{self.base}/b.html"]["label"], "B & co")

    def test_page_cap(self):
        sg = self.crawl(max_pages=2)
        fetched = [a for a in sg.nodes().values() if a.get("fetched")]
        self.assertEqual(len(fetched), 2)
        self.assertTrue(any(a.get("status") == "not crawled (page cap)"
                            for a in sg.nodes().values()))

    def test_replay_order_matches_discovery(self):
        sg = self.crawl(max_pages=20)
        steps = crawl_order(sg, "replay")
        self.assertEqual(len(steps), len(sg.nodes()))
        self.assertEqual(steps[0]["id"], f"url:{self.base}/index.html")
        seen = set()
        for s in steps:
            if s["parent"]:
                self.assertIn(s["parent"], seen)
            seen.add(s["id"])
        self.assertIn("replay", crawl_payload(sg)["orders"])

    def test_dfs_crawl_dives(self):
        sg = self.crawl(max_pages=20, strategy="dfs")
        order = sorted((a["fetch_order"], a["url"].rsplit("/", 1)[-1])
                       for a in sg.nodes().values() if a.get("fetched"))
        names = [n for _o, n in order]
        # DFS pops the newest link: b.html was found after a.html on the
        # index, so it is fetched first, then a.html dives into deep1/deep2
        self.assertEqual(names[0], "index.html")
        self.assertLess(names.index("deep1.html"), len(names))

    def test_unreachable_start_does_not_crash(self):
        sg = WebCrawler(delay=0, timeout=2).crawl("http://127.0.0.1:9/")
        self.assertEqual(len(sg.nodes()), 1)

    def test_bad_url_raises(self):
        with self.assertRaises(ValueError):
            WebCrawler().crawl("not a url")

    def test_cli_url_export_crawl(self):
        with tempfile.TemporaryDirectory() as out:
            rc = main(["--url", self.base + "/index.html", "--crawl-delay", "0",
                       "--max-pages", "5", "--export", "crawl", "json",
                       "--strategy", "replay", "--out", out + "/", "--no-gui"])
            self.assertEqual(rc, 0)
            files = sorted(os.listdir(out))
            self.assertTrue(any(f.endswith(".crawl.html") for f in files), files)
            self.assertTrue(any(f.endswith(".json") for f in files), files)


class TestExportCrawl(unittest.TestCase):
    def test_writes_self_contained_page_with_data(self):
        sg = small_code_graph()
        with tempfile.TemporaryDirectory() as d:
            p = export_crawl(sg, os.path.join(d, "x.html"), strategy="dfs")
            html = open(p, encoding="utf-8").read()
        self.assertNotIn("__DATA__", html)
        self.assertNotIn("__TITLE__", html)
        self.assertNotRegex(html, r"<script[^>]+src=")      # fully offline
        blob = re.search(r'<script type="application/json" id="ns-data">(.*?)</script>',
                         html, re.S).group(1)
        data = json.loads(blob)
        self.assertEqual(len(data["nodes"]), len(sg.nodes()))
        self.assertEqual(data["initial"], "dfs")
        self.assertEqual(set(data["orders"]), {"bfs", "dfs"})
        for st, steps in data["orders"].items():
            self.assertEqual(sorted(s[0] for s in steps),
                             list(range(len(sg.nodes()))), st)
        for n in data["nodes"]:
            self.assertTrue(-1.0001 <= n[0] <= 1.0001 and -1.0001 <= n[1] <= 1.0001)

    def test_hostile_label_cannot_break_out_of_script(self):
        sg = SchemaGraph(title="<b>t</b>")
        sg.add_node("x", K_FUNCTION, "</script><script>alert(1)</script>")
        with tempfile.TemporaryDirectory() as d:
            html = open(export_crawl(sg, os.path.join(d, "x.html")),
                        encoding="utf-8").read()
        self.assertNotIn("<script>alert(1)", html)
        self.assertIn("&lt;b&gt;t&lt;/b&gt;", html)

    def test_empty_graph_still_writes(self):
        with tempfile.TemporaryDirectory() as d:
            p = export_crawl(SchemaGraph(), os.path.join(d, "e.html"))
            self.assertTrue(os.path.getsize(p) > 1000)

    def test_cli_on_own_source(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as out:
            rc = main(["--file", os.path.join(here, "neural_schema.py"),
                       "--export", "crawl", "--out", out + "/", "--no-gui"])
            self.assertEqual(rc, 0)
            self.assertTrue(any(f.endswith(".crawl.html") for f in os.listdir(out)))


if __name__ == "__main__":
    unittest.main()


class TestDirectionFlag(unittest.TestCase):
    def test_backward_walk_is_flagged(self):
        sg = SchemaGraph()
        sg.add_node("m", K_MODULE, "m.py")
        sg.add_node("f", K_FUNCTION, "f")
        sg.add_node("g", K_FUNCTION, "g")
        sg.add_edge("m", "f", R_CONTAINS)
        sg.add_edge("g", "f", R_CALLS)        # g is only reachable backwards
        steps = {s["id"]: s for s in crawl_order(sg, "bfs")}
        self.assertTrue(steps["f"]["out"])
        self.assertFalse(steps["g"]["out"])
