import unittest
from unittest.mock import MagicMock
from app import classify_file_type, probe_file_type


class FileTypeTests(unittest.TestCase):
    def test_extensionless_mime(self):
        result = classify_file_type('https://example.com/get?id=1', {'Content-Type':'video/mp4; charset=binary'})
        self.assertEqual(result['type'], 'mp4')
        self.assertGreaterEqual(result['confidence'], 40)

    def test_html_overrides_disguised_filename(self):
        result = classify_file_type('https://example.com/movie.mp4', {'Content-Type':'video/mp4'}, b'<!DOCTYPE html><html>challenge</html>')
        self.assertEqual(result['type'], 'html')
        self.assertFalse(result['is_media'])

    def test_signatures(self):
        cases = [(b'\x00\x00\x00\x18ftypisom', 'mp4'),
                 (b'\x1a\x45\xdf\xa3xxxwebm', 'webm'),
                 (b'\x1a\x45\xdf\xa3xxx', 'ebml'),
                 (b'#EXTM3U\n#EXT-X-VERSION:3', 'm3u8'),
                 (b'<?xml version="1.0"?><MPD xmlns="test">', 'mpd'),
                 (b'RIFF1234WAVE', 'wav'), (b'OggS1234', 'ogg')]
        for sample, expected in cases:
            with self.subTest(expected=expected):
                result = classify_file_type('https://example.com/download', {}, sample)
                self.assertEqual(result['type'], expected)
                self.assertTrue(result['is_media'])

    def test_weak_hints_not_confirmation(self):
        result = classify_file_type('https://example.com/fake.mp4')
        self.assertLess(result['confidence'], 40)
        self.assertFalse(classify_file_type('https://example.com/', {'Content-Type':'application/octet-stream'})['is_media'])

    def test_disposition(self):
        result = classify_file_type('https://example.com/get', {'Content-Disposition':"attachment; filename*=UTF-8''sample.webm"})
        self.assertEqual(result['type'], 'webm')

    def test_probe_is_bounded_and_closes(self):
        session = MagicMock()
        response = session.get.return_value.__enter__.return_value
        response.status_code = 206
        response.url = 'https://example.com/get'
        response.headers = {'Content-Type':'application/octet-stream'}
        response.raw.read.return_value = b'\0\0\0\x18ftypisom'
        result = probe_file_type(response.url, session)
        response.raw.read.assert_called_once_with(8192, decode_content=False)
        session.get.return_value.__exit__.assert_called_once()
        self.assertEqual(result['type'], 'mp4')


if __name__ == '__main__':
    unittest.main()
