"""Tests for the universal AI connector (any provider) and its Studio/CLI use.

One local stub server speaks all four wire formats (OpenAI-compatible,
Anthropic, Gemini, Ollama) and records every request, so we can check the
exact URL, headers and body each provider receives -- and that API keys never
leak into responses, errors or files with loose permissions.
"""
import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from neural_schema import (  # noqa: E402
    AIError,
    ai_provider_status,
    ask_ai,
    list_ai_models,
    load_ai_config,
    main,
    make_studio_server,
    resolve_ai,
    save_ai_config,
)

KEY = "sk-test-SECRET-1234567890"
PACK = "# Reverse-engineering pack: `demo`\n| format | `ELF` |"


class Stub(BaseHTTPRequestHandler):
    log = []

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _rec(self, body=None):
        Stub.log.append({"method": self.command, "path": self.path,
                         "headers": {k.lower(): v for k, v in self.headers.items()},
                         "body": body})

    def do_GET(self):
        self._rec()
        p = self.path
        if p.startswith("/v1/models?"):                         # anthropic
            return self._json({"data": [{"id": "claude-test"}]})
        if p.endswith("/v1/models"):                            # openai-compatible
            return self._json({"data": [{"id": "gpt-test"}, {"id": "aaa-test"}]})
        if p.startswith("/v1beta/models"):                      # gemini
            return self._json({"models": [
                {"name": "models/gemini-test", "supportedGenerationMethods": ["generateContent"]},
                {"name": "models/embed-only", "supportedGenerationMethods": ["embedContent"]}]})
        if p == "/api/tags":                                    # ollama
            return self._json({"models": [{"name": "llama-test"}]})
        if p.startswith("/bad/"):
            return self._json({"error": {"message": f"invalid key {KEY}"}}, 401)
        return self._json({"error": "nope"}, 404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self._rec(body)
        p = self.path
        if p.startswith("/bad/"):
            return self._json({"error": {"message": f"invalid key {KEY}"}}, 401)
        if p.endswith("/chat/completions"):
            return self._json({"choices": [{"message": {"content": "openai-style answer"}}]})
        if p == "/v1/messages":
            return self._json({"content": [{"type": "text", "text": "claude answer"}]})
        if ":generateContent" in p:
            return self._json({"candidates": [{"content": {"parts": [{"text": "gemini answer"}]}}]})
        if p == "/api/generate":
            return self._json({"response": "ollama answer"})
        return self._json({"error": "nope"}, 404)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        Stub.log.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.env = {"NEURALSCHEMA_AI_CONFIG": os.path.join(self.tmp.name, "ai.json"),
                    "OLLAMA_HOST": self.url.replace("http://", "")}
        self._old = {k: os.environ.get(k) for k in list(self.env) + [
            "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
            "NEURALSCHEMA_AI_KEY", "NEURALSCHEMA_AI_BASE"]}
        for k in self._old:
            os.environ.pop(k, None)
        os.environ.update(self.env)

    def tearDown(self):
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def last(self, method="POST"):
        return [r for r in Stub.log if r["method"] == method][-1]


class TestWireFormats(Base):
    def test_openai_compatible_custom(self):
        o = {"base": self.url + "/v1", "key": KEY}
        self.assertEqual(list_ai_models("custom", o), ["aaa-test", "gpt-test"])
        self.assertEqual(self.last("GET")["headers"]["authorization"], f"Bearer {KEY}")
        ans = ask_ai(PACK, "what is it?", "custom", "gpt-test", overrides=o)
        self.assertEqual(ans, "openai-style answer")
        r = self.last()
        self.assertEqual(r["path"], "/v1/chat/completions")
        self.assertEqual(r["body"]["model"], "gpt-test")
        self.assertEqual(r["body"]["messages"][0]["role"], "system")
        self.assertIn("untrusted data", r["body"]["messages"][0]["content"])
        self.assertIn("EVIDENCE PACK", r["body"]["messages"][1]["content"])
        self.assertIn("what is it?", r["body"]["messages"][1]["content"])

    def test_anthropic(self):
        o = {"base": self.url, "key": KEY}
        self.assertEqual(list_ai_models("anthropic", o), ["claude-test"])
        self.assertEqual(ask_ai(PACK, "q", "anthropic", "claude-test", overrides=o),
                         "claude answer")
        r = self.last()
        self.assertEqual(r["path"], "/v1/messages")
        self.assertEqual(r["headers"]["x-api-key"], KEY)
        self.assertEqual(r["headers"]["anthropic-version"], "2023-06-01")
        self.assertNotIn("authorization", r["headers"])
        self.assertIn("untrusted data", r["body"]["system"])
        self.assertEqual(r["body"]["messages"][0]["role"], "user")

    def test_gemini(self):
        o = {"base": self.url + "/v1beta", "key": KEY}
        self.assertEqual(list_ai_models("gemini", o), ["gemini-test"])   # embed-only filtered
        self.assertEqual(ask_ai(PACK, "q", "gemini", "gemini-test", overrides=o),
                         "gemini answer")
        r = self.last()
        self.assertEqual(r["path"], "/v1beta/models/gemini-test:generateContent")
        self.assertEqual(r["headers"]["x-goog-api-key"], KEY)
        self.assertNotIn("key=", r["path"])                                # never in the URL
        self.assertIn("systemInstruction", r["body"])

    def test_ollama_local_needs_no_key(self):
        self.assertEqual(list_ai_models("ollama"), ["llama-test"])
        self.assertEqual(ask_ai(PACK, "q", "ollama", "llama-test"), "ollama answer")
        self.assertNotIn("authorization", self.last()["headers"])

    def test_env_key_is_used(self):
        os.environ["OPENAI_API_KEY"] = KEY
        cfg = resolve_ai("openai")
        self.assertEqual(cfg["key"], KEY)
        self.assertEqual(cfg["base"], "https://api.openai.com/v1")
        self.assertFalse(cfg["local"])


class TestSafety(Base):
    def test_cloud_without_key_explains_env_var(self):
        with self.assertRaises(AIError) as c:
            ask_ai(PACK, "q", "openai", "gpt-x")
        self.assertIn("OPENAI_API_KEY", str(c.exception))

    def test_plain_http_to_remote_is_refused(self):
        with self.assertRaises(AIError) as c:
            ask_ai(PACK, "q", "custom", "m", overrides={"base": "http://example.com/v1", "key": KEY})
        self.assertIn("https", str(c.exception))

    def test_key_scrubbed_from_provider_errors(self):
        with self.assertRaises(AIError) as c:
            ask_ai(PACK, "q", "custom", "m", overrides={"base": self.url + "/bad", "key": KEY})
        self.assertIn("401", str(c.exception))
        self.assertNotIn(KEY, str(c.exception))

    def test_status_never_contains_key(self):
        os.environ["ANTHROPIC_API_KEY"] = KEY
        blob = json.dumps(ai_provider_status())
        self.assertNotIn(KEY, blob)
        st = [p for p in ai_provider_status() if p["id"] == "anthropic"][0]
        self.assertTrue(st["ready"])
        self.assertTrue(st["key"].startswith("sk-") and st["key"].endswith("7890"))

    def test_config_file_is_private_and_has_priority(self):
        os.environ["OPENAI_API_KEY"] = "env-key-xxxxxxxx"
        path = save_ai_config({"openai": {"key": "saved-key-xxxxxxxx", "model": "m1"}})
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(resolve_ai("openai")["key"], "saved-key-xxxxxxxx")        # saved > env
        self.assertEqual(resolve_ai("openai", {"key": "typed"})["key"], "typed")    # typed > saved
        self.assertEqual(resolve_ai("openai")["model"], "m1")

    def test_unknown_provider(self):
        with self.assertRaises(AIError):
            resolve_ai("not-a-provider")


class TestStudioAndCLI(Base):
    def setUp(self):
        super().setUp()
        self.studio = make_studio_server(port=0)
        threading.Thread(target=self.studio.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.studio.server_address[1]}"
        self.tok = {"X-NS-Token": self.studio.token, "Content-Type": "application/json"}

    def tearDown(self):
        self.studio.shutdown()
        self.studio.server_close()
        super().tearDown()

    def req(self, path, payload=None, raw=None, headers=None):
        data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
        r = urllib.request.Request(self.base + path, data=data, headers=headers or self.tok)
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_connect_any_provider_and_ask(self):
        code, j = self.req("/api/providers")
        self.assertEqual(code, 200)
        self.assertGreaterEqual(len(j["providers"]), 10)
        code, j = self.req("/api/providers", {"provider": "custom", "key": KEY,
                                              "base": self.url + "/v1", "model": "gpt-test"})
        self.assertEqual(code, 200)
        self.assertTrue(j["provider"]["ready"])
        self.assertNotIn(KEY, json.dumps(j))                    # key never echoed
        self.assertNotIn(KEY, json.dumps(self.req("/api/providers")[1]))
        self.assertIsNone(j["saved_to"])                        # not remembered
        self.assertFalse(os.path.exists(os.environ["NEURALSCHEMA_AI_CONFIG"]))
        code, j = self.req("/api/models?provider=custom")
        self.assertEqual(j["models"], ["aaa-test", "gpt-test"])
        # drop a file, then ask the connected provider about it
        up = urllib.request.Request(self.base + "/api/reverse", data=b"\x00asm\x01\x00\x00\x00",
                                    headers={"X-NS-Token": self.studio.token, "X-Filename": "m.wasm"})
        rid = json.loads(urllib.request.urlopen(up, timeout=30).read())["id"]
        code, j = self.req("/api/ask", {"id": rid, "question": "q", "provider": "custom",
                                        "model": "gpt-test"})
        self.assertEqual(code, 200, j)
        self.assertEqual(j["answer"], "openai-style answer")
        self.assertIn("WebAssembly", self.last()["body"]["messages"][1]["content"])

    def test_remember_writes_private_file(self):
        code, j = self.req("/api/providers", {"provider": "groq", "key": KEY, "remember": True})
        self.assertEqual(code, 200)
        self.assertEqual(load_ai_config()["groq"]["key"], KEY)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(j["saved_to"]).st_mode), 0o600)

    def test_remote_http_base_rejected(self):
        code, j = self.req("/api/providers", {"provider": "custom", "base": "http://evil.example/v1"})
        self.assertEqual(code, 400)

    def test_provider_api_needs_token(self):
        code, _ = self.req("/api/providers", {"provider": "openai", "key": KEY},
                           headers={"Content-Type": "application/json"})
        self.assertEqual(code, 403)

    def test_ask_with_missing_key_is_clear(self):
        up = urllib.request.Request(self.base + "/api/reverse", data=b"hello world data",
                                    headers={"X-NS-Token": self.studio.token, "X-Filename": "x.bin"})
        rid = json.loads(urllib.request.urlopen(up, timeout=30).read())["id"]
        code, j = self.req("/api/ask", {"id": rid, "question": "q", "provider": "anthropic",
                                        "model": "x"})
        self.assertEqual(code, 502)
        self.assertIn("ANTHROPIC_API_KEY", j["error"])

    def test_cli_ask_and_list_models(self):
        f = os.path.join(self.tmp.name, "m.wasm")
        with open(f, "wb") as fh:
            fh.write(b"\x00asm\x01\x00\x00\x00")
        os.environ["NEURALSCHEMA_AI_KEY"] = KEY
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = main(["--list-models", "--ai-provider", "custom", "--ai-base", self.url + "/v1"])
        self.assertEqual(rc, 0)
        self.assertIn("gpt-test", out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = main(["--file", f, "--ask", "what is this?", "--ai-provider", "custom",
                       "--ai-base", self.url + "/v1", "--ai-model", "gpt-test", "--no-gui"])
        self.assertEqual(rc, 0)
        self.assertIn("openai-style answer", out.getvalue())
        self.assertNotIn(KEY, out.getvalue())


if __name__ == "__main__":
    unittest.main()
