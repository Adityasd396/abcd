import unittest
from unittest.mock import Mock
import app


class ExtractionTests(unittest.TestCase):
    def test_structured_and_escaped_urls(self):
        links = []
        app._extract_from_raw('''<base href="/media/">
            <video data-src="clip.mp4?a=1&amp;b=2"></video>
            <script type="application/ld+json">{"@graph":[{"contentUrl":"../stream.m3u8"}]}</script>
            <script>var x="https:\\/\\/cdn.example\\/movie.webm";</script>
            <a href="javascript:bad.mp4">bad</a>''',
            'https://example.com/watch/page', links, [])
        self.assertEqual(set(links), {
            'https://example.com/media/clip.mp4?a=1&b=2',
            'https://example.com/stream.m3u8',
            'https://cdn.example/movie.webm',
        })

    def test_crawl_depth_cycles_and_session(self):
        responses = {
            'https://example.com/': '<a href="/child">child</a>' * 20 + '<a href="https://other.com/">external</a>',
            'https://example.com/child': '<a href="/">cycle</a><a href="/deep">deep</a><video src="clip.mp4"></video>',
        }
        session = Mock()
        session.get.side_effect = lambda url, **kw: Mock(
            url=url, status_code=200, headers={'Content-Type': 'text/html'}, text=responses[url])
        links = []
        count = app.crawl_site(session, 'https://example.com/', links, [], 1, max_pages=10)
        self.assertEqual(count, 2)
        self.assertEqual(session.get.call_count, 2)
        self.assertEqual(links, ['https://example.com/clip.mp4'])

    def test_page_cap_and_zero_depth(self):
        session = Mock()
        session.get.return_value = Mock(url='https://example.com/', status_code=200,
            headers={'Content-Type': 'text/html'}, text='<a href="/child">child</a>')
        count = app.crawl_site(session, 'https://example.com/', [], [], 0,
            max_pages=1, seed_urls=['https://example.com/seed'])
        self.assertEqual(count, 1)
        self.assertEqual(session.get.call_count, 1)

    def test_domain_names(self):
        self.assertTrue(app.is_same_domain('https://www.example.com/a', 'example.com'))
        self.assertFalse(app.is_same_domain('https://wevil.com', 'evil.com'))

    def test_home_page(self):
        response = app.app.test_client().get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'<html', response.data.lower())


if __name__ == '__main__':
    unittest.main()
