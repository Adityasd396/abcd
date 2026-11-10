import unittest
from unittest.mock import patch
import app
from unittest.mock import MagicMock
from test_api_scan import response


class EngineTests(unittest.TestCase):
    def test_nested_hls_with_extensionless_variant(self):
        self.r['manifest_store']={}
        self.r['stream_diagnostics']=[app.identify_stream('https://example.com/master',
            {'content-type':'application/vnd.apple.mpegurl'})]
        first=response();first._content=b'#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=800000,RESOLUTION=640x360\nquality/low\n';first.url='https://example.com/master'
        second=response();second._content=b'#EXTM3U\n#EXTINF:5,\nsegment.ts\n';second.url='https://example.com/quality/low'
        session=MagicMock();session.get.side_effect=[first,second]
        with patch.object(app,'get_api_session',return_value=session):
            self.engine.inspect_manifests()
        self.assertIn('https://example.com/quality/low',self.r['mp4_links'])
        self.assertEqual(session.get.call_count,2)
        self.assertEqual(self.r['manifest_store']['https://example.com/master']['variants'][0]['resolution'],'360p')

    def test_dash_inherited_base_url(self):
        self.r['manifest_store']={}
        self.r['stream_diagnostics']=[app.identify_stream('https://example.com/a.mpd')]
        document=response();document.url='https://example.com/a.mpd'
        document._content=b'<MPD><BaseURL>https://cdn.example/assets/</BaseURL><Period><AdaptationSet><Representation id="1"><BaseURL>movie.mp4</BaseURL></Representation></AdaptationSet></Period></MPD>'
        session=MagicMock();session.get.return_value=document
        with patch.object(app,'get_api_session',return_value=session):self.engine.inspect_manifests()
        self.assertIn('https://cdn.example/assets/movie.mp4',self.r['mp4_links'])

    def setUp(self):
        self.r = {'status':'running', 'time_limit_s':30, 'mp4_links':[], 'stream_diagnostics':[],
            'broken_links':[], 'validation_results':{}, 'log':[], 'player_store':[],
            'pages_scraped':0, 'sitemap_size':0}
        app.scan_store['engine-test'] = self.r
        self.engine = app.DiscoveryEngine('engine-test', 'https://example.com/',
            app.DiscoveryPlan(pages=5, browser=False, sitemap=False, validate=False))

    def tearDown(self):
        app.scan_store.pop('engine-test', None)

    def test_frontier_dedup_depth_and_scope(self):
        for _ in range(3):
            self.engine.enqueue('https://example.com/watch', 1)
        self.engine.enqueue('https://other.com/watch', 1)
        self.engine.enqueue('https://example.com/deep', 10)
        self.engine.enqueue('javascript:bad()', 1)
        self.assertEqual(len(self.engine.frontier), 1)

    def test_combines_static_json_and_script_api_references(self):
        self.engine.consume({'url':'https://example.com/', 'status':200, 'headers':{},
            'text':'''<video src="/clip.mp4"></video><script type="application/json">{"contentUrl":"/opaque"}</script>
                <script>fetch('/api/videos');</script><a href="/watch">watch</a>'''}, 0, 'page')
        self.assertEqual(set(self.r['mp4_links']), {'https://example.com/clip.mp4', 'https://example.com/opaque'})
        self.assertIn('https://example.com/api/videos', self.engine.queued)
        self.assertIn('https://example.com/watch', self.engine.queued)

    def test_cancelled_scan_does_not_fetch(self):
        self.r['cancel_requested'] = True
        with patch.object(self.engine, 'fetch') as fetch:
            self.engine.run()
            fetch.assert_not_called()
        self.assertEqual(self.r['status'], 'cancelled')

    def test_rate_limit_stops_discovery(self):
        with patch.object(self.engine, 'fetch', return_value={
                'url':'https://example.com/', 'status':429, 'headers':{}, 'text':''}) as fetch:
            self.engine.run()
            fetch.assert_called_once()
        self.assertEqual(self.r['status'], 'rate_limited')

    def test_export_and_stop_routes(self):
        client = app.app.test_client()
        self.r['mp4_links'] = ['https://example.com/clip.mp4']
        self.assertEqual(client.post('/stop_scan/engine-test').status_code, 200)
        self.assertTrue(self.r['cancel_requested'])
        self.assertIn('clip.mp4', client.get('/export_scan/engine-test?format=txt').text)
        self.assertTrue(client.get('/export_scan/engine-test').is_json)
        self.assertEqual(client.get('/export_scan/engine-test?format=exe').status_code, 400)

    def test_invalid_start_data(self):
        client = app.app.test_client()
        self.assertEqual(client.post('/start_scan', json={'url':'https://example.com', 'depth':'bad'}).status_code, 400)
        self.assertEqual(client.post('/start_scan', json={'url':None}).status_code, 400)


if __name__ == '__main__':
    unittest.main()
