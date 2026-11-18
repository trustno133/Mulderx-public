import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from orchestrator import build_katana_regex
from scripts.scope_policy import (
    HostScope,
    ScopeError,
    normalize_domain_input,
    open_scoped_url,
    url_in_scope,
    validate_program_name,
)


class ScopePolicyTests(unittest.TestCase):
    def test_exact_scope_regex_has_host_boundary_and_no_subdomains(self):
        pattern = build_katana_regex("example.com", "domain")
        self.assertRegex("https://example.com/path", pattern)
        self.assertRegex("https://example.com:8443/path", pattern)
        self.assertNotRegex("https://a.example.com/path", pattern)
        self.assertNotRegex("https://example.com.evil.test/path", pattern)
        self.assertNotRegex("https://example.com@evil.test/path", pattern)

    def test_wildcard_scope_requires_wildcard_syntax_and_subdomain_boundary(self):
        pattern = build_katana_regex("*.example.com", "wildcard")
        self.assertRegex("https://a.example.com/path", pattern)
        self.assertRegex("https://deep.a.example.com/path", pattern)
        self.assertNotRegex("https://example.com/path", pattern)
        self.assertNotRegex("https://a.example.com.evil.test/path", pattern)
        with self.assertRaises(ScopeError):
            build_katana_regex("example.com", "wildcard")
        with self.assertRaises(ScopeError):
            build_katana_regex("*.example.com", "domain")
        with self.assertRaises(ScopeError):
            HostScope.parse("*.127.0.0.1")
        with self.assertRaises(ScopeError):
            build_katana_regex("*.127.0.0.1", "wildcard")

    def test_host_scope_checks_relative_urls_against_base_and_rejects_active_schemes(self):
        scope = HostScope.parse("example.com", include_subdomains_for_root=True)
        self.assertTrue(scope.matches_url("/search?q=x", base_url="https://app.example.com/"))
        self.assertTrue(scope.matches_url("//app.example.com/path", base_url="https://example.com/"))
        self.assertFalse(scope.matches_url("//outside.test/path", base_url="https://example.com/"))
        self.assertFalse(scope.matches_url("javascript:alert(1)", base_url="https://example.com/"))
        self.assertFalse(scope.matches_url("https://user:pass@example.com/private"))
        self.assertTrue(url_in_scope("https://app.example.com:8443/", "example.com", include_subdomains_for_root=True))

    def test_domain_and_program_input_reject_paths_and_traversal(self):
        self.assertEqual(normalize_domain_input("https://Example.COM/"), "example.com")
        for value in ("example.com/path", "https://user:pass@example.com", "example.com:8080", "../outside"):
            with self.subTest(value=value), self.assertRaises(ScopeError):
                normalize_domain_input(value)
        for value in ("../private", "..", ".hidden", "CON", "a\\b", "x/y"):
            with self.subTest(value=value), self.assertRaises(ScopeError):
                validate_program_name(value)
        self.assertEqual(validate_program_name("Sample City"), "Sample City")

    def test_http_redirect_outside_scope_is_stopped_before_following(self):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                self.send_response(302)
                self.send_header("Location", "http://example.invalid/private")
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
        with self.assertRaises(ScopeError):
            open_scoped_url(url, "127.0.0.1")
        self.assertEqual(seen, ["/redirect"])


if __name__ == "__main__":
    unittest.main()
