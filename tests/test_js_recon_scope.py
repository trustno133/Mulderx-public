import importlib.util
import io
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_script(filename: str, module_name: str):
    import sys
    scripts_dir = str(ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class JSReconScopeTests(unittest.TestCase):
    def test_sourcemap_runner_skips_out_of_scope_bundle_without_request(self):
        sourcemap = load_script("sourcemap_recon.py", "sourcemap_recon_test")
        with tempfile.TemporaryDirectory() as tmp:
            with redirect_stdout(io.StringIO()):
                result = sourcemap.process_js_url(
                    "https://outside.invalid/app.js", Path(tmp), 0, "example.test",
                )
        self.assertFalse(result["found"])
        self.assertEqual(result["error"], "URL de JavaScript fuera de scope")

    def test_sourcemap_from_another_host_is_not_fetched(self):
        sourcemap = load_script("sourcemap_recon.py", "sourcemap_recon_external_map_test")
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                sourcemap, "fetch_text",
                return_value=({}, "//# sourceMappingURL=https://cdn.example.test/app.js.map"),
            ) as fetch, patch.object(sourcemap, "check_accessible") as check:
                with redirect_stdout(io.StringIO()):
                    result = sourcemap.process_js_url(
                        "https://app.example.test/app.js", Path(tmp), 0, "app.example.test",
                    )
        self.assertEqual(fetch.call_count, 1)
        check.assert_not_called()
        self.assertFalse(result["found"])
        self.assertIn("fuera de scope", result["error"])

    def test_wayback_cdx_host_filter_rejects_suffix_and_non_scope_hosts(self):
        wayback = load_script("wayback_js_recon.py", "wayback_scope_test")
        rows = [
            ["20260101000000", "https://app.example.test/app.js", "200", "application/javascript"],
            ["20260101000000", "https://example.test/app.js", "200", "application/javascript"],
            ["20260101000000", "https://app.example.test.evil/app.js", "200", "application/javascript"],
            ["20260101000000", "https://cdn.example.test/app.js", "200", "application/javascript"],
        ]
        with patch.object(wayback, "_cdx_get", side_effect=[rows, []]):
            exact = wayback.fetch_js_urls("app.example.test", "app.example.test", None, 10, 0)
        self.assertEqual([item.url for item in exact], ["https://app.example.test/app.js"])

        with patch.object(wayback, "_cdx_get", side_effect=[rows, []]):
            wildcard = wayback.fetch_js_urls("example.test", "*.example.test", None, 10, 0)
        self.assertEqual({item.url for item in wildcard}, {
            "https://app.example.test/app.js", "https://cdn.example.test/app.js",
        })

    def test_wayback_live_redirect_leaves_scope_before_following(self):
        wayback = load_script("wayback_js_recon.py", "wayback_redirect_test")
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                self.send_response(302)
                self.send_header("Location", "http://outside.invalid/private.js")
                self.end_headers()

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(thread.join, 2)
        with tempfile.TemporaryDirectory() as tmp:
            url = f"http://127.0.0.1:{server.server_port}/app.js"
            result = wayback.download_live(url, Path(tmp) / "app.js", 0, "127.0.0.1")
        self.assertFalse(result)
        self.assertEqual(seen, ["/app.js"])

    def test_fingerprint_requires_explicit_wildcard_for_subdomains(self):
        fingerprint = load_script(
            "recon_fingerprint_v3.6_handoff_slim.py", "fingerprint_scope_test",
        )
        with self.assertRaises(fingerprint.ScopeError):
            fingerprint.Fingerprinter(
                "https://app.example.test", scope="example.test",
            )
        instance = fingerprint.Fingerprinter(
            "https://app.example.test", scope="*.example.test",
        )
        self.addCleanup(instance.session.close)
        self.assertTrue(instance.scope_policy.matches_host("app.example.test"))
        self.assertFalse(instance.scope_policy.matches_host("example.test"))

    def test_fingerprint_session_blocks_out_of_scope_redirect(self):
        import requests
        fingerprint = load_script(
            "recon_fingerprint_v3.6_handoff_slim.py", "fingerprint_redirect_test",
        )
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                self.send_response(302)
                self.send_header("Location", "http://outside.invalid/private")
                self.end_headers()

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(thread.join, 2)
        url = f"http://127.0.0.1:{server.server_port}/redirect"
        fingerprinter = fingerprint.Fingerprinter(url, scope="127.0.0.1")
        self.addCleanup(fingerprinter.session.close)
        with self.assertRaises(requests.RequestException):
            fingerprinter.session.get(url, timeout=2)
        self.assertEqual(seen, ["/redirect"])


if __name__ == "__main__":
    unittest.main()
