import asyncio
import threading
import unittest
from unittest.mock import patch, Mock
import app
from app import isolated_browser_thread, navigation_error, extract_live_frame_urls, access_block_reason


class BrowserRuntimeTests(unittest.TestCase):
    def test_explicit_block_page_is_not_challenge_success(self):
        page = Mock()
        page.content.return_value = '<h1>Sorry, you have been blocked</h1><p>You are unable to access example.com</p>'
        page.goto.return_value.status = 403
        log = []
        self.assertEqual(app.pw_fetch_page(page, 'https://example.com/', log), (None, None))
        self.assertIn('Access blocked:', log[0])
        page.reload.assert_not_called()

    def test_challenge_and_normal_content_are_not_hard_blocks(self):
        self.assertIsNone(access_block_reason('<title>Just a moment...</title>Checking your browser'))
        self.assertIsNone(access_block_reason('<h1>Video library</h1>'))
        self.assertIsNotNone(access_block_reason('<h1>Access denied</h1>Cloudflare Error 1020'))

    def test_detached_frame_does_not_hide_live_results(self):
        detached = Mock()
        detached.is_detached.return_value = False
        detached.evaluate.side_effect = Exception('Frame.evaluate: Frame was detached')
        live = Mock(url='https://example.com/')
        live.is_detached.return_value = False
        live.evaluate.return_value = ['clip.mp4']
        page = Mock(frames=[detached, live])
        page.is_closed.return_value = False
        log = []
        self.assertEqual(extract_live_frame_urls(page, 'script', log), [('clip.mp4', live.url)])
        self.assertEqual(log, [])
        live.evaluate.assert_called_once()

    def test_navigation_context_is_retried_once(self):
        frame = Mock(url='https://example.com/')
        frame.is_detached.return_value = False
        frame.evaluate.side_effect = [Exception('Execution context was destroyed'), ['clip.mp4']]
        page = Mock(frames=[frame])
        page.is_closed.return_value = False
        self.assertEqual(extract_live_frame_urls(page, 'script', []), [('clip.mp4', frame.url)])
        self.assertEqual(frame.evaluate.call_count, 2)

    def test_persistent_navigation_race_is_bounded(self):
        frame = Mock()
        frame.is_detached.return_value = False
        frame.evaluate.side_effect = Exception('Execution context was destroyed')
        page = Mock(frames=[frame])
        page.is_closed.return_value = False
        self.assertEqual(extract_live_frame_urls(page, 'script', []), [])
        self.assertEqual(frame.evaluate.call_count, 2)

    def test_browser_worker_has_no_running_async_loop(self):
        caller = threading.get_ident()
        @isolated_browser_thread
        def browser_work():
            with self.assertRaises(RuntimeError):
                asyncio.get_running_loop()
            return threading.get_ident()
        async def invoke():
            self.assertNotEqual(browser_work(), caller)
        asyncio.run(invoke())

    def test_worker_exceptions_propagate(self):
        @isolated_browser_thread
        def fail():
            raise ValueError('navigation failed')
        with self.assertRaisesRegex(ValueError, 'navigation failed'):
            fail()

    def test_cookie_status_and_favicon(self):
        client = app.app.test_client()
        with patch.object(app, 'get_cookie_file', return_value=None):
            response = client.get('/cookie_status')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, {'loaded': False, 'count': 0})
        with patch.object(app, 'get_cookie_file', return_value='cookies.txt'), patch.object(
                app, '_load_pw_cookies', return_value=[{'name':'session', 'value':'secret'}]):
            self.assertEqual(client.get('/cookie_status').json, {'loaded':True, 'count':1})
        self.assertEqual(client.get('/favicon.ico').status_code, 204)

    def test_dns_error_is_actionable(self):
        message = navigation_error('https://invalid.example/path', Exception('Page.goto: net::ERR_NAME_NOT_RESOLVED'))
        self.assertIn('DNS lookup failed for invalid.example', message)
        self.assertNotIn('asyncio', message)

    def test_navigation_dns_failure_returns_without_cf_retry(self):
        from unittest.mock import Mock
        page = Mock()
        page.goto.side_effect = Exception('Page.goto: net::ERR_NAME_NOT_RESOLVED')
        log = []
        self.assertEqual(app.pw_fetch_page(page, 'https://invalid.example', log), (None, None))
        self.assertIn('DNS lookup failed', log[0])
        page.reload.assert_not_called()


if __name__ == '__main__':
    unittest.main()
