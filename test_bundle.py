import ast
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class BundleTests(unittest.TestCase):
    def test_no_runtime_imports_of_workspace_helpers(self):
        tree = ast.parse(Path('app.py').read_text(encoding='utf-8'))
        helpers = {'media_detection', 'proxy_routing', 'browser_runtime', 'stream_detection'}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                self.assertNotIn(node.module, helpers)

    def test_single_file_runs_from_an_empty_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'app.py'
            target.write_bytes(Path('app.py').read_bytes())
            code = '''import runpy, sys, site
sys.path.append(site.getusersitepackages())
ns = runpy.run_path(sys.argv[1], run_name='bundle_test')
assert ns['app'].test_client().get('/').status_code == 200
assert ns['app'].test_client().get('/cookie_status').is_json
assert ns['identify_stream']('https://example.com/part.m4s')['kind'] == 'segment_candidate'
for name in ('VIDEO_EXTRACTION_SCRIPT', 'STREAM_OBSERVER_SCRIPT', 'DRM_OBSERVER_SCRIPT', 'MEDIA_OBSERVER_SCRIPT'):
    assert len(ns[name]) > 100
print('Standalone app passed')
'''
            result = subprocess.run([sys.executable, '-I', '-c', code, str(target)],
                cwd=directory, capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Standalone app passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
