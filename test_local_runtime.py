import gzip
import unittest
from unittest.mock import patch, MagicMock
import app


class RuntimeTests(unittest.TestCase):
    def test_external_ai_requires_explicit_opt_in(self):
        with patch.dict('os.environ',{'RIPPER_ALLOW_EXTERNAL_AI':''}), patch.object(app,'_download_image_b64') as download:
            self.assertIn('disabled',app.classify_thumbnail_with_ai('https://example.com/')['error'])
            download.assert_not_called()
            self.assertEqual(app.app.test_client().post('/classify_single',json={}).status_code,403)

    def test_response_compression_preserves_payload(self):
        app.scan_store['runtime-test']={'status':'done','mp4_links':[], 'log':['Repeated scan observation '+str(i%10) for i in range(1000)]}
        try:
            client=app.app.test_client()
            plain=client.get('/poll/runtime-test')
            compressed=client.get('/poll/runtime-test',headers={'Accept-Encoding':'gzip'})
            self.assertEqual(compressed.headers.get('Content-Encoding'),'gzip')
            self.assertEqual(app.app.json.loads(gzip.decompress(compressed.data)),plain.json)
            self.assertLess(len(compressed.data),len(plain.data)//2)
            self.assertEqual(compressed.headers['Cache-Control'],'no-store')
            self.assertNotIn('Content-Encoding',client.get('/poll/runtime-test',headers={'Accept-Encoding':'gzip;q=0'}).headers)
        finally:app.scan_store.pop('runtime-test')

    def test_cross_origin_browser_mutation_is_rejected(self):
        response=app.app.test_client().post('/start_scan',json={'url':'https://example.com/'},headers={'Origin':'https://unrelated.example'})
        self.assertEqual(response.status_code,403)
        self.assertEqual(app.app.test_client().get('/',headers={'Host':'unrelated.example'}).status_code,403)

    def test_local_json_fallback(self):
        with patch.object(app,'_fast_json',None):
            provider=app.LocalJSONProvider(app.app)
            data={'name':'परीक्षण','items':[1,False,None]}
            self.assertEqual(provider.loads(provider.dumps(data)),data)

    def test_worker_connection_reuse_and_cleanup(self):
        app.scan_store['pool-test']={'mp4_links':[]}
        engine=app.DiscoveryEngine('pool-test','https://example.com/',app.DiscoveryPlan())
        try:
            with patch.object(app,'get_api_session',return_value=MagicMock()) as factory:
                with engine.pooled_connection() as first:
                    with engine.pooled_connection() as second:self.assertIs(first,second)
                factory.assert_called_once()
                first.close.assert_not_called()
                engine.close_connections()
                first.close.assert_called_once()
        finally:app.scan_store.pop('pool-test')


if __name__=='__main__':unittest.main()
