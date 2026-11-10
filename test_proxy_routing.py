import unittest
from unittest.mock import patch, Mock
from app import proxy_url, configure_session, browser_proxy_options, routing_status


class ProxyTests(unittest.TestCase):
    def test_app_routes_requests_and_browser(self):
        import app
        with patch.dict('os.environ', {'RIPPER_PROXY_URL':'http://127.0.0.1:8080'}):
            session = app.get_cf_session()
            try:
                self.assertEqual(session.proxies['https'], 'http://127.0.0.1:8080')
            finally:
                session.close()
            pw = Mock()
            app._make_pw_browser(pw)
            self.assertEqual(pw.chromium.launch.call_args.kwargs['proxy']['server'], 'http://127.0.0.1:8080')
            with patch.object(app, 'get_cf_session') as factory:
                factory.return_value.get.side_effect = RuntimeError('proxy failed')
                with self.assertRaisesRegex(RuntimeError, 'proxy failed'):
                    app.smart_get('https://example.com/')
                factory.return_value.close.assert_called_once()

    def test_default_routing(self):
        with patch.dict('os.environ', {'RIPPER_PROXY_URL':''}):
            self.assertIsNone(proxy_url())
            self.assertEqual(browser_proxy_options(), {})

    def test_http_credentials_are_not_in_status(self):
        with patch.dict('os.environ', {'RIPPER_PROXY_URL':'http://user:p%40ss@proxy.example:8080'}):
            self.assertEqual(browser_proxy_options()['proxy'], {
                'server':'http://proxy.example:8080', 'username':'user', 'password':'p@ss'})
            self.assertNotIn('user', str(routing_status()))
            session = Mock(proxies={})
            configure_session(session)
            self.assertFalse(session.trust_env)
            self.assertEqual(session.proxies['https'], proxy_url())

    def test_socks_auth_browser_rejected(self):
        with patch.dict('os.environ', {'RIPPER_PROXY_URL':'socks5h://u:p@proxy.example:1080'}):
            with self.assertRaisesRegex(ValueError, 'without authentication'):
                browser_proxy_options()

    def test_bad_url_redacted(self):
        with patch.dict('os.environ', {'RIPPER_PROXY_URL':'http://u:secret@example:bad'}):
            with self.assertRaises(ValueError) as ctx:
                proxy_url()
            self.assertNotIn('secret', str(ctx.exception))
