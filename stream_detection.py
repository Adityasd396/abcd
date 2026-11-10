"""Evidence records for JavaScript-served streams; no media-body capture."""
import re
from urllib.parse import urlparse
from media_detection import classify_file_type


def identify_stream(url, headers=None, source='network', resource_type='', frame_url=''):
    scheme = urlparse(url).scheme
    if scheme not in ('http', 'https', 'blob'):
        return None
    headers = {key.lower(): value for key, value in (headers or {}).items()}
    file = classify_file_type(url, headers)
    path = urlparse(url).path.lower()
    kind, confidence = None, 'candidate'
    if scheme == 'blob':
        kind = 'browser_blob'
    elif file['mime'] in ('text/html', 'application/xhtml+xml'):
        return None
    elif file['type'] == 'm3u8':
        kind = 'hls_manifest'
    elif file['type'] == 'mpd':
        kind = 'dash_manifest'
    elif re.search(r'\.(m4s|cmfv|cmfa|ts)$', path):
        kind = 'segment_candidate'
    elif file['is_media']:
        kind = 'ranged_media' if 'content-range' in headers else 'media_file_candidate'
    if kind is None:
        return None
    if file['confidence'] >= 40:
        confidence = 'response_headers'
    return {'url':url, 'kind':kind, 'file_type':file['type'],
            'mime':file['mime'], 'source':source, 'resource_type':resource_type,
            'frame_url':frame_url, 'confidence':confidence,
            'download_candidate':kind == 'media_file_candidate',
            'evidence':[source]}


def merge_stream(store, record, limit=1000):
    if not record:
        return
    # Same URL in different frames does not establish a relationship.
    key = (record['url'], record.get('frame_url', ''))
    for old in store:
        if (old['url'], old.get('frame_url', '')) == key:
            evidence = list(dict.fromkeys(old['evidence'] + record['evidence']))[:12]
            keep_specific_mse = old['kind'] == 'mse_source' and record['kind'] == 'browser_blob'
            if not keep_specific_mse and (record['confidence'] == 'response_headers' or old['confidence'] != 'response_headers'):
                old.update(record)
            old['evidence'] = evidence
            return
    if len(store) < limit:
        store.append(record)


def collect_stream_snapshot(page, store, log):
    for frame in list(page.frames):
        if frame.is_detached():
            continue
        try:
            snapshot = frame.evaluate('''() => ({
                streams: window.__streamDiagnostics?.snapshot() || [],
                resources: window.__mediaDiscovery?.snapshot() || []
            })''')
            base = frame.url
            for item in snapshot.get('resources', [])[:2000]:
                merge_stream(store, identify_stream(item.get('url', ''),
                    {'content-type':item.get('mime', '')}, item.get('source', 'dom'), frame_url=base))
            for item in snapshot.get('streams', [])[:200]:
                if item.get('kind') not in ('mse_source', 'browser_blob', 'mse_buffer'):
                    continue
                record = {'url':item.get('url', ''), 'kind':item['kind'],
                    'file_type':'unknown', 'mime':item.get('mime', ''),
                    'frame_url':base, 'source':'browser_api', 'resource_type':'',
                    'confidence':'browser_api', 'download_candidate':False,
                    'evidence':[item.get('evidence', 'browser_api')]}
                merge_stream(store, record)
        except Exception as exc:
            if not frame.is_detached() and 'context was destroyed' not in str(exc).lower():
                log.append(f'Stream diagnostics unavailable: {str(exc)[:100]}')
