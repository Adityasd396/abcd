import json
import unittest
from unittest.mock import MagicMock, patch
import requests
import app


def response(payload=None, status=200, headers=None):
    value = requests.Response()
    value.status_code = status
    value.headers.update(headers or {})
    value._content = json.dumps(payload).encode()
    value._content_consumed = True
    return value


class ApiTests(unittest.TestCase):
    def test_response_context_protocol_not_required(self):
        item = MagicMock()
        item.status_code = 200
        item.headers = {}
        item.iter_content.return_value = [b'{"videoUrl":"/clip.mp4"}']
        item.__enter__.side_effect = TypeError('Unsupported response context manager')
        r, session = self.run_scan([item])
        self.assertEqual(r['status'], 'done')
        item.__enter__.assert_not_called()
        item.close.assert_called_once()
        session.close.assert_called_once()

    def test_transport_errors_are_actionable_and_redacted(self):
        for error, expected in [
                (requests.exceptions.ProxyError('http://user:secret@proxy'), 'Proxy connection failed'),
                (requests.exceptions.ConnectionError('https://example.com/?token=secret'), 'API connection failed'),
                (requests.exceptions.Timeout('secret'), 'timed out'),
                (requests.exceptions.RequestException('secret'), 'API transport failed'),
                (TypeError('secret response'), 'response type')]:
            with self.subTest(error=type(error).__name__):
                r, _ = self.run_scan([error])
                self.assertEqual(r['status'], 'error')
                self.assertIn(expected, r['log'][-1])
                self.assertNotIn('secret', r['log'][-1])

    def test_api_transport_is_requests_even_with_curl_available(self):
        with patch.object(app, 'CURL_CFFI_OK', True), patch.object(app, '_load_pw_cookies', return_value=[]), patch.dict(app._cf_solved_cookies, {}, clear=True):
            session = app.get_api_session()
            try:
                self.assertIsInstance(session, requests.Session)
            finally:
                session.close()

    def setUp(self):
        app.scan_store['api-test'] = {'status':'running', 'time_limit_s':60,
            'pages_scraped':0, 'mp4_links':[], 'stream_diagnostics':[], 'log':[]}

    def tearDown(self):
        app.scan_store.pop('api-test', None)

    def run_scan(self, responses, headers='{}'):
        session = MagicMock()
        session.__enter__.return_value = session
        session.get.side_effect = responses
        with patch.object(app, 'get_api_session', return_value=session), patch.dict(
                'os.environ', {'RIPPER_API_HEADERS_JSON':headers}), patch.object(app.time, 'sleep'):
            app.run_api_scan('api-test', 'https://example.com/api', max_pages=5, skip_validate=True)
        return app.scan_store['api-test'], session

    def test_nested_media_and_opaque_sources(self):
        result = app.extract_api_media({'data':[
            {'sources':[{'file':'/opaque'}]}, {'type':'video/mp4', 'url':'/get?id=1'},
            {'hls':'https://cdn.example/master.m3u8'}, {'url':'/users/123'},
            {'thumbnail':'/poster.jpg'}, {'video_url':'javascript:bad()'}]}, 'https://example.com/api')
        self.assertEqual({item['url'] for item in result}, {
            'https://example.com/opaque', 'https://example.com/get?id=1', 'https://cdn.example/master.m3u8'})

    def test_pagination_and_cycle(self):
        r, session = self.run_scan([
            response({'videoUrl':'/one.mp4', 'links':{'next':{'href':'?page=2'}}}),
            response({'sources':[{'src':'/two.m3u8'}], 'next':'/api'})])
        self.assertEqual(r['status'], 'done')
        self.assertEqual(r['pages_scraped'], 2)
        self.assertEqual(session.get.call_count, 2)
        self.assertEqual(set(r['mp4_links']), {'https://example.com/one.mp4', 'https://example.com/two.m3u8'})

    def test_cross_origin_pagination_not_requested(self):
        r, session = self.run_scan([response({'next':'https://other.example/private'})],
            '{"Authorization":"Bearer test-secret"}')
        session.get.assert_called_once()
        self.assertFalse(session.get.call_args.kwargs['allow_redirects'])
        self.assertNotIn('test-secret', str(r))

    def test_cross_origin_redirect_not_requested(self):
        r, session = self.run_scan([response(status=302, headers={'Location':'https://other.example/'})])
        self.assertEqual(r['status'], 'error')
        session.get.assert_called_once()

    def test_rate_limit_and_access_denial_stop(self):
        for code, status in [(429, 'rate_limited'), (403, 'blocked'), (401, 'blocked')]:
            with self.subTest(code=code):
                r, session = self.run_scan([response(status=code)])
                self.assertEqual(r['status'], status)
                session.get.assert_called_once()

    def test_html_and_large_response_rejected(self):
        for content in (b'<html>blocked</html>', b'x' * (2*1024*1024+1)):
            item = response()
            item._content = content
            r, _ = self.run_scan([item])
            self.assertEqual(r['status'], 'error')
            self.assertEqual(r['mp4_links'], [])

    def test_link_pagination_and_numeric_cursor(self):
        self.assertEqual(app.api_next_url({}, 'https://example.com/api', '</api?page=2>; rel="next"'), 'https://example.com/api?page=2')
        self.assertIsNone(app.api_next_url({'next':2}, 'https://example.com/api'))

    def test_start_api_uses_api_worker(self):
        with patch.object(app.threading, 'Thread') as worker:
            result = app.app.test_client().post('/start_scan', json={
                'url':'https://example.com/api', 'source_type':'api', 'api_max_pages':100})
            self.assertEqual(result.status_code, 200)
            self.assertIs(worker.call_args.kwargs['target'], app.run_api_scan)
            self.assertEqual(worker.call_args.kwargs['args'][2], 20)
            app.scan_store.pop(result.json['scan_id'])
