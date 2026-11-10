import unittest
from app import identify_stream, merge_stream


class StreamTests(unittest.TestCase):
    def test_mse_identity_survives_generic_blob_observation(self):
        store = []
        record = identify_stream('blob:https://example.com/123')
        record.update(kind='mse_source', confidence='browser_api')
        merge_stream(store, record)
        merge_stream(store, identify_stream(record['url']))
        self.assertEqual(store[0]['kind'], 'mse_source')

    def test_extensionless_manifests(self):
        for mime, kind in [('application/vnd.apple.mpegurl','hls_manifest'), ('application/dash+xml','dash_manifest')]:
            record = identify_stream('https://example.com/opaque', {'content-type':mime})
            self.assertEqual(record['kind'], kind)
            self.assertFalse(record['download_candidate'])

    def test_fragments_and_blob_are_not_file_downloads(self):
        for url in ['https://example.com/part.m4s', 'https://example.com/part.ts', 'blob:https://example.com/123']:
            self.assertFalse(identify_stream(url)['download_candidate'])

    def test_html_is_not_media(self):
        self.assertIsNone(identify_stream('https://example.com/fake.mp4', {'content-type':'text/html'}))

    def test_range_is_not_confirmed_complete_file(self):
        record = identify_stream('https://example.com/opaque', {'content-type':'video/mp4', 'content-range':'bytes 0-99/200'})
        self.assertEqual(record['kind'], 'ranged_media')
        self.assertFalse(record['download_candidate'])

    def test_evidence_merging_and_bounds(self):
        store = []
        merge_stream(store, identify_stream('https://example.com/clip.mp4', source='request'))
        merge_stream(store, identify_stream('https://example.com/clip.mp4', {'content-type':'video/mp4'}, source='response'))
        self.assertEqual(len(store), 1)
        self.assertEqual(store[0]['confidence'], 'response_headers')
        self.assertEqual(store[0]['evidence'], ['request', 'response'])
        merge_stream(store, identify_stream('https://example.com/other.mp4'), limit=1)
        self.assertEqual(len(store), 1)
