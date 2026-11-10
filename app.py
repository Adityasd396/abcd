# Self-contained application: helper implementations and browser scripts are embedded.
# Bundled media_detection.py
"""Bounded, evidence-based media classification and in-page observation."""
import re
from urllib.parse import urlparse, unquote

MIME_TYPES = {
    'video/mp4': 'mp4', 'application/mp4': 'mp4', 'audio/mp4': 'm4a',
    'video/webm': 'webm', 'audio/webm': 'webm', 'video/x-matroska': 'mkv',
    'application/vnd.apple.mpegurl': 'm3u8', 'application/x-mpegurl': 'm3u8',
    'application/dash+xml': 'mpd', 'video/mp2t': 'ts',
    'video/ogg': 'ogv', 'audio/ogg': 'ogg', 'audio/mpeg': 'mp3',
    'video/quicktime': 'mov', 'video/x-msvideo': 'avi',
}
EXTENSIONS = set(MIME_TYPES.values()) | {'m4v', 'flv', 'aac', 'wav'}


def classify_file_type(url, headers=None, sample=b''):
    """Rank independent evidence; signatures override misleading filenames/MIME.

    Confidence is an evidence ranking, not a statistical probability.
    Container identification does not imply a video track is present.
    """
    headers = {k.lower(): str(v) for k, v in (headers or {}).items()}
    mime = headers.get('content-type', '').split(';')[0].strip().lower()
    evidence = []
    scores = {}
    def vote(kind, weight, source):
        scores[kind] = scores.get(kind, 0) + weight
        evidence.append({'type': kind, 'source': source, 'weight': weight})
    def extension(value):
        match = re.search(r'\.([a-z0-9]+)$', value.lower())
        return match.group(1) if match and match.group(1) in EXTENSIONS else None
    ext = extension(unquote(urlparse(url).path))
    if ext:
        vote(ext, 15, 'URL extension')
    disposition = headers.get('content-disposition', '')
    match = re.search(r"filename\*?\s*=\s*(?:UTF-8''|\")?([^\";]+)", disposition, re.I)
    if match:
        ext = extension(unquote(match.group(1).strip()))
        if ext:
            vote(ext, 25, 'download filename')
    if mime in MIME_TYPES:
        vote(MIME_TYPES[mime], 50, 'Content-Type')
    data = sample[:8192]
    stripped = data.lstrip(b'\xef\xbb\xbf \r\n\t')
    signature = None
    if re.match(br'(?is)(?:<!doctype\s+html|<html\b|<head\b|<body\b)', stripped):
        signature = 'html'
    elif stripped.startswith(b'#EXTM3U'):
        signature = 'm3u8'
    elif re.search(br'<(?:[A-Za-z_][\w.-]*:)?MPD(?:\s|>)', stripped):
        signature = 'mpd'
    elif len(data) >= 12 and data[4:8] == b'ftyp':
        signature = 'mov' if data[8:12] == b'qt  ' else 'mp4'
    elif data.startswith(b'\x1a\x45\xdf\xa3'):
        # EBML alone cannot distinguish Matroska from WebM.
        signature = 'webm' if b'webm' in data else 'mkv' if b'matroska' in data else 'ebml'
    elif data.startswith(b'OggS'):
        signature = 'ogg'
    elif data.startswith(b'FLV'):
        signature = 'flv'
    elif data.startswith(b'RIFF') and data[8:12] in (b'AVI ', b'WAVE'):
        signature = 'avi' if data[8:12] == b'AVI ' else 'wav'
    elif data.startswith(b'ID3'):
        signature = 'mp3'
    elif len(data) >= 377 and all(data[i] == 0x47 for i in (0, 188, 376)):
        signature = 'ts'
    if signature:
        vote(signature, 100, 'file signature')
        kind = signature
        confidence = 100
    elif mime in ('text/html', 'application/xhtml+xml'):
        kind, confidence = 'html', 90
        vote(kind, 90, 'Content-Type')
    else:
        ranked = sorted(scores, key=scores.get, reverse=True)
        kind = ranked[0] if ranked else 'unknown'
        confidence = min(90, scores.get(kind, 0))
    return {'type': kind, 'confidence': confidence, 'mime': mime,
            'is_media': kind in EXTENSIONS or kind == 'ebml',
            'evidence': evidence, 'bytes_examined': len(data)}


def probe_file_type(url, session, timeout=10):
    """Read at most 8 KiB even when the server ignores Range; always close."""
    with session.get(url, headers={'Range': 'bytes=0-8191', 'Accept-Encoding': 'identity'},
                     timeout=timeout, stream=True, allow_redirects=True) as response:
        sample = response.raw.read(8192, decode_content=False) if response.status_code < 400 else b''
        result = classify_file_type(response.url, response.headers, sample)
        result['status_code'] = response.status_code
        result['url'] = response.url
        return result


# Runs before site scripts. Observes metadata without consuming responses or
# replacing media bytes; keeps only bounded URL records within this document.
MEDIA_OBSERVER_SCRIPT = r"""(() => {
    if (window.__mediaDiscovery) return;
    const records = new Map();
    const media = /(?:video|audio)\/|mpegurl|dash\+xml/i;
    const ext = /\.(mp4|mkv|webm|mov|m4v|m3u8|mpd|ogv|ogg|ts|mp3|aac|wav)(?:[?#]|$)/i;
    function add(value, mime = '', source = 'dom', force = false) {
        if (typeof value !== 'string' || !value || records.size >= 2000) return;
        try {
            const url = new URL(value, document.baseURI);
            if (!/^https?:$/.test(url.protocol)) return;
            if (!force && !ext.test(url.href) && !media.test(mime)) return;
            url.hash = '';
            const old = records.get(url.href);
            records.set(url.href, {url: url.href, mime: mime || old?.mime || '', source});
        } catch (_) {}
    }
    Object.defineProperty(window, '__mediaDiscovery', {value: {snapshot: () => [...records.values()]}});
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
        return originalFetch.apply(this, args).then(response => {
            try { add(response.url, response.headers.get('content-type') || '', 'fetch'); } catch (_) {}
            return response;
        });
    };
    const send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(...args) {
        this.addEventListener('load', () => {
            try { add(this.responseURL, this.getResponseHeader('content-type') || '', 'xhr'); } catch (_) {}
        }, {once: true});
        return send.apply(this, args);
    };
    function inspect(node) {
        if (!(node instanceof Element)) return;
        const typed = /^(VIDEO|AUDIO|SOURCE)$/.test(node.tagName);
        for (const attr of ['src','href','data-src','data-video','data-url','data-file'])
            add(node.getAttribute(attr), node.getAttribute('type') || '', 'dom', typed);
        if (typed) add(node.currentSrc, '', 'currentSrc', true);
    }
    const observed = new WeakSet();
    let work = 0;
    function scan(root) {
        if (!root || work >= 20000) return;
        inspect(root);
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
        let node;
        while ((node = walker.nextNode()) && work++ < 20000) {
            inspect(node);
            if (node.shadowRoot) watch(node.shadowRoot);
        }
    }
    function watch(root) {
        if (observed.has(root)) return;
        observed.add(root);
        new MutationObserver(changes => {
            work = 0;
            for (const change of changes) {
                if (change.type === 'attributes') inspect(change.target);
                else for (const node of change.addedNodes) scan(node);
                if (work >= 20000) break;
            }
        }).observe(root, {subtree:true, childList:true, attributes:true,
            attributeFilter:['src','href','data-src','data-video','data-url','data-file','type']});
        scan(root);
    }
    const attach = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function(...args) {
        const root = attach.apply(this, args);
        if (args[0]?.mode === 'open') watch(root);
        return root;
    };
    try {
        new PerformanceObserver(list => {
            for (const entry of list.getEntries()) add(entry.name, '', 'resource');
        }).observe({type:'resource', buffered:true});
    } catch (_) {}
    document.addEventListener('loadedmetadata', event => inspect(event.target), true);
    watch(document);
})();"""


# Bundled proxy_routing.py
"""Explicit upstream routing, configured locally without exposing credentials."""
import os
from urllib.parse import urlparse, unquote


def proxy_url():
    value = os.environ.get('RIPPER_PROXY_URL', '').strip()
    if not value:
        return None
    try:
        parsed = urlparse(value)
        valid = parsed.scheme in ('http', 'https', 'socks5', 'socks5h') and parsed.hostname and parsed.port
    except ValueError:
        valid = False
    if not valid:
        raise ValueError('RIPPER_PROXY_URL must be an HTTP(S) or SOCKS5 URL with a host and port')
    return value


def configure_session(session):
    value = proxy_url()
    if value:
        session.trust_env = False
        session.proxies.update({'http': value, 'https': value})
    return session


def browser_proxy_options():
    value = proxy_url()
    if not value:
        return {}
    parsed = urlparse(value)
    if parsed.scheme.startswith('socks') and (parsed.username or parsed.password):
        raise ValueError('Browser SOCKS5 routing requires a proxy without authentication; use an HTTP proxy for authenticated browser routing')
    host = f'[{parsed.hostname}]' if ':' in parsed.hostname else parsed.hostname
    scheme = 'socks5' if parsed.scheme == 'socks5h' else parsed.scheme
    proxy = {'server': f'{scheme}://{host}:{parsed.port}'}
    if parsed.username:
        proxy['username'] = unquote(parsed.username)
    if parsed.password:
        proxy['password'] = unquote(parsed.password)
    return {'proxy': proxy}


def routing_status():
    return {'configured': bool(proxy_url()), 'mode': 'configured proxy' if proxy_url() else 'default routing'}


# Bundled browser_runtime.py
"""Keep browser engines and their asyncio state on disposable worker threads."""
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from urllib.parse import urlparse


def isolated_browser_thread(function):
    @wraps(function)
    def run(*args, **kwargs):
        # Never pass live Playwright pages across this boundary. Each decorated
        # function creates, uses and disposes its browser on this same worker.
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix='browser-engine') as pool:
            return pool.submit(function, *args, **kwargs).result()
    return run


def access_block_reason(html):
    text = re.sub(r"<[^>]+>", " ", (html or "")[:200000]).lower()
    text = " ".join(text.split())
    if "sorry, you have been blocked" in text or "sorry you have been blocked" in text:
        return "The website denied access. This is a block page, not a browser verification challenge."
    if "cloudflare" in text and ("error 1020" in text or "access denied" in text):
        return "The website's access rules denied this request."
    return None


def navigation_error(url, error):
    message = str(error)
    if 'ERR_NAME_NOT_RESOLVED' in message or 'NS_ERROR_UNKNOWN_HOST' in message:
        host = urlparse(url).hostname or url
        return f'DNS lookup failed for {host}. Check the website address and your DNS/network connection.'
    return message[:180]


def extract_live_frame_urls(page, script, log):
    """Skip detached frames; retry navigation races once using fresh frames."""
    results = []
    completed = set()
    for attempt in range(2):
        retry = False
        if page.is_closed():
            break
        for frame in list(page.frames):
            if id(frame) in completed or frame.is_detached():
                continue
            try:
                urls = frame.evaluate(script)
                base = frame.url
                if isinstance(urls, list):
                    results.extend((url, base) for url in urls if isinstance(url, str))
                completed.add(id(frame))
            except Exception as exc:
                message = str(exc).lower()
                if frame.is_detached() or 'frame was detached' in message or 'frame has been detached' in message:
                    completed.add(id(frame))
                    retry = True
                elif 'execution context was destroyed' in message or 'cannot find context' in message:
                    retry = True
                elif page.is_closed() or 'target page, context or browser has been closed' in message:
                    return results
                else:
                    completed.add(id(frame))
                    log.append(f"   DOM extraction unavailable: {str(exc)[:120]}")
        if not retry or attempt:
            break
        try:
            page.wait_for_timeout(100)
        except Exception:
            break
    return results


# Bundled stream_detection.py
"""Evidence records for JavaScript-served streams; no media-body capture."""
import re
from urllib.parse import urlparse


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


DOM_EXTRACTION_SCRIPT = "() => {\n    const found = new Set(), roots = [document], seenRoots = new Set();\n    const extensions = /\\.(mp4|mkv|webm|mov|m4v|m3u8|mpd|ogv|ogg|ts|mp3|aac|wav|flv|avi)(?:[?#]|$)/i;\n    const attributes = ['src', 'href', 'data', 'data-src', 'data-video', 'data-url',\n        'data-file', 'data-hd', 'data-sd', 'data-hls', 'data-dash', 'data-stream'];\n    let nodes = 0, values = 0;\n    function add(value, base, mediaContext = false) {\n        if (typeof value !== 'string' || !value.trim() || found.size >= 2000) return;\n        try {\n            const url = new URL(value.trim(), base);\n            if (!/^https?:$/.test(url.protocol)) return;\n            if (!mediaContext && !extensions.test(url.href)) return;\n            url.hash = '';\n            found.add(url.href);\n        } catch (_) {}\n    }\n    function json(text, base) {\n        if (!text || text.length > 1000000) return;\n        try {\n            const stack = [{value:JSON.parse(text), depth:0, media:false}];\n            while (stack.length && values++ < 10000) {\n                const {value, depth, media} = stack.pop();\n                if (typeof value === 'string') add(value, base, media);\n                else if (value && typeof value === 'object' && depth < 20) {\n                    const typed = /^(video|audio)/i.test(String(value.type || value['@type'] || ''));\n                    for (const [key, item] of Object.entries(value).slice(0, 1000)) {\n                        stack.push({value:item, depth:depth+1,\n                            media: /^(contentUrl|streamUrl|hls|dash)$/i.test(key) ||\n                                (typed && /^(url|src|file)$/i.test(key))});\n                    }\n                }\n            }\n        } catch (_) {}\n    }\n    while (roots.length && nodes < 20000) {\n        const root = roots.pop();\n        if (seenRoots.has(root)) continue;\n        seenRoots.add(root);\n        const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);\n        let el;\n        while ((el = walker.nextNode()) && nodes++ < 20000) {\n            const tag = el.tagName.toUpperCase();\n            const base = /^https?:/.test(el.baseURI || '') ? el.baseURI : document.baseURI;\n            const mediaElement = /^(VIDEO|AUDIO)$/.test(tag) ||\n                (tag === 'SOURCE' && /^(VIDEO|AUDIO)$/.test(el.parentElement?.tagName || ''));\n            for (const attr of attributes) {\n                const mediaAttr = mediaElement && /^(src|data-src|data-file|data-url)$/.test(attr);\n                add(el.getAttribute(attr), base, mediaAttr);\n            }\n            if (mediaElement) add(el.currentSrc, base, true);\n            for (const attr of ['data-setup', 'data-config', 'data-player', 'data-sources'])\n                json(el.getAttribute(attr), base);\n            if (tag === 'SCRIPT' && /^(application\\/(ld\\+)?json)$/i.test(el.type || ''))\n                json(el.textContent, base);\n            if (el.shadowRoot) roots.push(el.shadowRoot);\n            if (tag === 'TEMPLATE' && el.content) roots.push(el.content);\n        }\n    }\n    for (const entry of performance.getEntriesByType('resource').slice(0, 2000))\n        add(entry.name, document.baseURI);\n    if (window.__mediaDiscovery) {\n        for (const record of window.__mediaDiscovery.snapshot().slice(0, 2000))\n            add(record.url, document.baseURI, true);\n    }\n    return [...found];\n}\n"

STREAM_OBSERVER_SCRIPT = "(() => {\n    if (window.__streamDiagnostics) return;\n    const records = new Map();\n    function add(kind, url = '', mime = '', evidence = '') {\n        const key = kind + ':' + url + ':' + mime;\n        if (records.size < 200 || records.has(key))\n            records.set(key, {kind, url, mime, evidence});\n    }\n    Object.defineProperty(window, '__streamDiagnostics', {value:{snapshot() {\n        const roots = [document], visited = new Set();\n        let budget = 20000;\n        while (roots.length && budget > 0) {\n            const root = roots.pop();\n            if (visited.has(root)) continue;\n            visited.add(root);\n            const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);\n            let el;\n            while ((el = walker.nextNode()) && budget-- > 0) {\n                if (el.shadowRoot) roots.push(el.shadowRoot);\n                if (!/^(VIDEO|AUDIO)$/.test(el.tagName)) continue;\n                const src = el.currentSrc || el.src || '';\n                if (src.startsWith('blob:')) add('browser_blob', src, '', 'media element blob source');\n            }\n        }\n        return [...records.values()];\n    }}});\n    const create = URL.createObjectURL;\n    if (typeof create === 'function') {\n        URL.createObjectURL = function(object) {\n            const url = create.call(this, object);\n            if (typeof MediaSource !== 'undefined' && object instanceof MediaSource)\n                add('mse_source', url, '', 'MediaSource object URL');\n            else if (typeof Blob !== 'undefined' && object instanceof Blob && /^(video|audio)\\//.test(object.type))\n                add('browser_blob', url, object.type, 'media Blob object URL');\n            return url;\n        };\n    }\n    if (typeof MediaSource !== 'undefined') {\n        const original = MediaSource.prototype.addSourceBuffer;\n        MediaSource.prototype.addSourceBuffer = function(type) {\n            const buffer = original.call(this, type);\n            add('mse_buffer', '', String(type).slice(0, 300), 'successful addSourceBuffer');\n            return buffer;\n        };\n    }\n})();\n"

DRM_OBSERVER_SCRIPT = "(() => {\n    if (window.__drmDiagnostics) return;\n    const events = [], systems = new Set();\n    function record(kind, details = {}) {\n        if (events.length < 100) events.push({kind, ...details});\n    }\n    Object.defineProperty(window, '__drmDiagnostics', {value: {\n        snapshot: () => ({keySystems:[...systems], events:events.slice(),\n            encryptedMediaObserved:events.some(e => e.kind === 'encrypted')})\n    }});\n    document.addEventListener('encrypted', event => {\n        record('encrypted', {initDataType:String(event.initDataType || '')});\n    }, true);\n    document.addEventListener('waitingforkey', () => record('waiting-for-key'), true);\n    const original = navigator.requestMediaKeySystemAccess;\n    if (typeof original === 'function') {\n        try {\n            navigator.requestMediaKeySystemAccess = function(system, ...args) {\n                // Observe only the key-system name. Do not read initialization\n                // data, license messages, session IDs or key material.\n                if (typeof system === 'string' && systems.size < 20) systems.add(system.slice(0, 200));\n                record('key-system-request');\n                return original.call(this, system, ...args);\n            };\n        } catch (_) {}\n    }\n})();\n"


API_JSON_OBSERVER_SCRIPT = "(() => {\n    if (window.__apiDocuments) return;\n    const documents = [];\n    const limit = 512000;\n    let pending = 0;\n    Object.defineProperty(window, '__apiDocuments', {value:{snapshot:()=>documents.slice()}});\n    function save(url, text) {\n        if (documents.length >= 6 || typeof text !== 'string' || text.length > limit) return;\n        try { JSON.parse(text); documents.push({url, text}); } catch (_) {}\n    }\n    const original = window.fetch;\n    window.fetch = function(...args) {\n        return original.apply(this, args).then(response => {\n            if (!response.ok || !/json/i.test(response.headers.get('content-type') || '') ||\n                documents.length + pending >= 6) return response;\n            let clone;\n            try { clone = response.clone(); } catch (_) { return response; }\n            pending++;\n            (async () => {\n                let reader;\n                try {\n                    if (!clone.body) return;\n                    reader = clone.body.getReader();\n                    const chunks = []; let length = 0;\n                    while (true) {\n                        const part = await reader.read();\n                        if (part.done) break;\n                        length += part.value.byteLength;\n                        if (length > limit) { reader.cancel().catch(()=>{}); return; }\n                        chunks.push(part.value);\n                    }\n                    const bytes = new Uint8Array(length); let offset = 0;\n                    for (const chunk of chunks) { bytes.set(chunk,offset); offset += chunk.byteLength; }\n                    save(response.url, new TextDecoder().decode(bytes));\n                } catch (_) {} finally { pending--; if (reader) reader.releaseLock(); }\n            })();\n            return response;\n        });\n    };\n    const send = XMLHttpRequest.prototype.send;\n    XMLHttpRequest.prototype.send = function(...args) {\n        this.addEventListener('load', () => {\n            try {\n                if (this.status >= 200 && this.status < 300 && /json/i.test(this.getResponseHeader('content-type') || '') &&\n                    (this.responseType === '' || this.responseType === 'text')) save(this.responseURL,this.responseText);\n            } catch (_) {}\n        }, {once:true});\n        return send.apply(this,args);\n    };\n})();\n"

PLAYER_ADAPTER_SCRIPT = "(() => {\n    if (window.__playerDiscovery) return;\n    const sources = new Map(), players = new Set(), events = [];\n    const observed = new WeakSet(), initiated = new Map();\n    function add(value, mime = '', adapter = 'HTML media') {\n        if (typeof value !== 'string' || !value.trim() || sources.size >= 500) return;\n        try {\n            const url = new URL(value, document.baseURI);\n            if (!/^https?:$/.test(url.protocol)) return;\n            url.hash = '';\n            const aliases={hls:'application/vnd.apple.mpegurl',dash:'application/dash+xml',mp4:'video/mp4',webm:'video/webm'};\n            mime=typeof mime==='string'?(aliases[mime.toLowerCase()] || mime):'';\n            sources.set(url.href, {url:url.href, mime, adapter});\n        } catch (_) {}\n    }\n    function walk(value, adapter, depth = 0, key = '', mime = '', budget = {n:0}) {\n        if (++budget.n > 3000 || depth > 12 || !value) return;\n        if (typeof value === 'string') {\n            if (/^(file|src|url|contentUrl|manifest|hls|dash)$/i.test(key) || /\\.(m3u8|mpd|mp4|webm)(?:[?#]|$)/i.test(value)) add(value,mime,adapter);\n        } else if (Array.isArray(value)) {\n            for (const item of value.slice(0,100)) walk(item,adapter,depth+1,key,mime,budget);\n        } else if (typeof value === 'object') {\n            const type=typeof value.type==='string'?value.type:mime;\n            for (const [name,item] of Object.entries(value).slice(0,100)) {\n                if (/drm|license|token|key|thumbnail|image|poster|track/i.test(name)) continue;\n                walk(item,adapter,depth+1,name,type,budget);\n            }\n        }\n    }\n    function record(kind, video) {\n        if (events.length < 150) events.push({event:kind, source:video.currentSrc || video.src || '',\n            readyState:video.readyState, networkState:video.networkState,\n            errorCode:video.error?.code || 0});\n    }\n    function sample(attemptPlayback=false) {\n        try {\n            if (window.videojs?.getPlayers) for (const player of Object.values(window.videojs.getPlayers()).slice(0,30)) {\n                if (!player) continue;\n                try {\n                    players.add('Video.js');\n                    if (typeof player.currentSources==='function') walk(player.currentSources(),'Video.js');\n                    if (typeof player.currentSrc==='function') add(player.currentSrc(),player.currentType?.() || '', 'Video.js');\n                } catch (_) {}\n            }\n        } catch (_) {}\n        if (typeof window.jwplayer === 'function') {\n            const ids=[undefined,...Array.from(document.querySelectorAll('.jwplayer[id]')).slice(0,20).map(el=>el.id)];\n            for (const id of ids) try {\n                const player = window.jwplayer(id);\n                if (player && typeof player.getPlaylist==='function') { players.add('JW Player'); walk(player.getPlaylist(),'JW Player'); }\n            } catch (_) {}\n        }\n        for (const name of ['player','shakaPlayer','hls','hlsPlayer','dashPlayer','videoPlayer']) try {\n            const player=Object.getOwnPropertyDescriptor(window,name)?.value;\n            if (!player || typeof player!=='object') continue;\n            if (typeof player.getAssetUri==='function' && typeof player.getVariantTracks==='function') {\n                players.add('Shaka'); add(player.getAssetUri(),'','Shaka');\n            }\n            if (typeof player.getSource==='function' && typeof player.getActiveStream==='function') {\n                players.add('dash.js'); add(player.getSource(),'application/dash+xml','dash.js');\n            }\n            if (typeof player.loadSource==='function' && typeof player.attachMedia==='function') {\n                players.add('HLS.js'); add(player.url,'application/vnd.apple.mpegurl','HLS.js');\n                for (const level of (player.levels || []).slice(0,50)) walk(level.url,'HLS.js',0,'url','application/vnd.apple.mpegurl');\n            }\n        } catch (_) {}\n        const roots=[document], seen=new Set(); let count=0;\n        while(roots.length && count<10000) {\n            const root=roots.pop(); if(seen.has(root))continue; seen.add(root);\n            const walker=document.createTreeWalker(root,NodeFilter.SHOW_ELEMENT);let el;\n            while((el=walker.nextNode()) && count++<10000) {\n                if(el.shadowRoot) roots.push(el.shadowRoot);\n                if(!/^(VIDEO|AUDIO)$/.test(el.tagName))continue;\n                const video=el;\n                add(el.currentSrc || el.src,'','HTML media');\n                if(!observed.has(el)) {\n                    observed.add(el);\n                    for(const event of ['loadstart','loadedmetadata','playing','waiting','stalled','error','ended'])\n                        el.addEventListener(event,()=>record(event,video));\n                    record('observed',el);\n                }\n                if(attemptPlayback && el.paused && !initiated.has(el) && initiated.size<3) {\n                    initiated.set(el,{muted:el.muted}); el.muted=true;\n                    try { const promise=el.play(); if(promise?.catch)promise.catch(()=>record('playback-unavailable',video)); }\n                    catch(_){record('playback-unavailable',el)}\n                }\n            }\n        }\n        return {sources:[...sources.values()],players:[...players],playback:events.slice()};\n    }\n    Object.defineProperty(window,'__playerDiscovery',{value:{sample, finish(){\n        for(const [video,state] of initiated) try{video.pause();video.muted=state.muted}catch(_){}\n        initiated.clear();\n    }}});\n})();\n"

from flask import Flask, request, jsonify
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
import re, threading, uuid, time, logging, asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Suppress noisy warnings ───────────────────────────────────────────────────
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Suppress Flask's per-request poll logs (keep only errors)
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)

try:
    import aiohttp as _aiohttp
    AIOHTTP_OK = True
except ImportError:
    AIOHTTP_OK = False

"""Embedded local runtime configuration; standard-library fallbacks supported."""
import gzip
from flask.json.provider import DefaultJSONProvider

try:
    import orjson as _fast_json
except ImportError:
    _fast_json=None


def external_ai_enabled():
    return os.environ.get('RIPPER_ALLOW_EXTERNAL_AI','').strip()=='1'


class LocalJSONProvider(DefaultJSONProvider):
    sort_keys=False
    def dumps(self,obj,**kwargs):
        if _fast_json is None:
            return super().dumps(obj,**kwargs)
        option=_fast_json.OPT_NON_STR_KEYS
        if kwargs.get('indent'):option|=_fast_json.OPT_INDENT_2
        if kwargs.get('sort_keys',self.sort_keys):option|=_fast_json.OPT_SORT_KEYS
        return _fast_json.dumps(obj,default=self.default,option=option).decode('utf-8')

    def loads(self,value,**kwargs):
        if _fast_json is None or kwargs:
            return super().loads(value,**kwargs)
        return _fast_json.loads(value)


def configure_local_runtime(app):
    app.json=LocalJSONProvider(app)
    @app.before_request
    def restrict_browser_origins():
        if urlparse(request.host_url).hostname not in ('localhost','127.0.0.1','::1'):
            return jsonify({'error':'Use the local app address.'}),403
        if request.method in ('POST','PUT','PATCH','DELETE'):
            origin=request.headers.get('Origin')
            if origin and origin!=request.host_url.rstrip('/'):
                return jsonify({'error':'Open this action from the local app.'}),403
    @app.after_request
    def private_compact_responses(response):
        response.headers.pop('Access-Control-Allow-Origin',None)
        response.headers['Cache-Control']='no-store'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['X-Content-Type-Options']='nosniff'
        if (response.mimetype=='application/json' and not response.is_streamed
                and not response.headers.get('Content-Encoding')
                and not response.headers.get('Content-Disposition')):
            response.vary.add('Accept-Encoding')
            if request.accept_encodings['gzip']>0:
                content=response.get_data()
                if len(content)>=4096:
                    compact=gzip.compress(content,compresslevel=1,mtime=0)
                    if len(compact)<len(content):
                        response.set_data(compact)
                        response.headers['Content-Encoding']='gzip'
        return response


app = Flask(__name__)
configure_local_runtime(app)

try:
    import yt_dlp
    YTDLP_OK = True
except ImportError:
    YTDLP_OK = False

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

# ── Video extensions ──────────────────────────────────────────────────────────
VIDEO_EXTS = (
    "mp4", "mkv", "webm", "avi", "mov", "wmv", "flv", "f4v",
    "m4v", "hevc", "h264", "h265", "ts", "m2ts", "mts",
    "mpeg", "mpg", "mp2", "mpe", "mpv", "m2v",
    "3gp", "3g2", "ogv", "ogg", "rm", "rmvb", "divx",
    "xvid", "vob", "asf", "amv", "m3u8", "mpd",
)
_EXT_PAT = "|".join(re.escape(e) for e in VIDEO_EXTS)

# ── Precompiled regex patterns (compiled ONCE at startup = zero per-request cost)
# Two focused patterns beat one mega-pattern due to less backtracking

# Pattern A: full https?:// video URLs
_RE_URL = re.compile(
    r"https?://[^\s\"'<>{}|\[\]\\]{4,500}\.(?:" + _EXT_PAT + r")(?:[?#][^\s\"'<>]{0,200})?",
    re.IGNORECASE
)
# Pattern B: relative /path video URLs inside attribute values
_RE_REL = re.compile(
    r"""(?:src|href|file|url|source|data-src|data-video|data-url|data-file|data-hd|data-sd)\s*[=:]\s*["']"""
    r"(/[^\s\"'<>]{2,400}\.(?:" + _EXT_PAT + r")[^\s\"'<>]{0,100})",
    re.IGNORECASE
)
# Pattern C: quoted/unquoted values in JS objects  { key: "value.mp4" }
_RE_JS = re.compile(
    r"""["'](/[^"'<>\s]{2,400}\.(?:""" + _EXT_PAT + r""")(?:[?#][^"'<>\s]{0,100})?)["']""",
    re.IGNORECASE
)

# ── m3u8 manifest parser ──────────────────────────────────────────────────────
try:
    import m3u8 as _m3u8_lib
    M3U8_OK = True
except ImportError:
    M3U8_OK = False

# ── JS player fingerprints ────────────────────────────────────────────────────
PLAYER_SIGNATURES = {
    "Video.js":   ["videojs", "video.js", "vjs-tech", "VideoJS"],
    "JW Player":  ["jwplayer", "jwplatform", "jwpsrv"],
    "Shaka":      ["shaka-player", "shaka.Player", "ShakaPlayer"],
    "HLS.js":     ["hls.js", "Hls.isSupported", "new Hls("],
    "Plyr":       ["plyr.js", "new Plyr", "plyr.io"],
    "Flowplayer": ["flowplayer.js", "flowplayer("],
    "DPlayer":    ["DPlayer", "new DPlayer"],
    "Clappr":     ["clappr.js", "new Clappr"],
    "Bitmovin":   ["bitmovin-player", "bitmovin.player"],
    "THEOplayer": ["THEOplayer", "theoplayer.js"],
}

def detect_players(html):
    """Return list of detected player frameworks."""
    html_l = html.lower()
    found  = []
    for name, sigs in PLAYER_SIGNATURES.items():
        if any(s.lower() in html_l for s in sigs):
            found.append(name)
    return found

def parse_m3u8_manifest(url, text=None, session=None):
    """
    Parse an m3u8 URL or text and return dict with quality ladder info.
    Returns None if not a master playlist.
    """
    if not M3U8_OK:
        return None
    try:
        if text:
            pl = _m3u8_lib.loads(text)
        else:
            if proxy_url():
                with get_cf_session() as routed:
                    response = routed.get(url, timeout=10)
                    response.raise_for_status()
                    pl = _m3u8_lib.loads(response.text)
            else:
                pl = _m3u8_lib.load(url)
        if not pl.is_variant:
            return None
        variants = []
        for stream in sorted(pl.playlists, key=lambda s: s.stream_info.bandwidth or 0):
            si   = stream.stream_info
            w, h = si.resolution or (0, 0)
            variants.append({
                "resolution": f"{h}p" if h else "?",
                "width":      w,
                "height":     h,
                "bandwidth":  si.bandwidth or 0,
                "kbps":       (si.bandwidth or 0) // 1000,
                "codecs":     si.codecs or "",
                "uri":        stream.uri,
            })
        return {"type": "HLS", "variants": variants, "count": len(variants)}
    except Exception:
        return None

def is_video_url(url):
    path = urlparse(url).path.lower()
    return any(path.endswith("." + e) for e in VIDEO_EXTS)

_EXT_RE = re.compile(r"\.(" + _EXT_PAT + r")(?:[?#]|$)", re.IGNORECASE)
def video_ext(url):
    m = _EXT_RE.search(urlparse(url).path)
    return m.group(1).lower() if m else "?"

scan_store = {}


# ─── helpers ──────────────────────────────────────────────────────────────────

def normalise_url(url, base):
    full = urljoin(base, url.strip())
    p = urlparse(full)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))

def is_same_domain(url, base_netloc):
    netloc = urlparse(url).netloc
    a = netloc.lower().removeprefix("www.")
    b = base_netloc.lower().removeprefix("www.")
    return a == b or a.endswith("." + b) or b.endswith("." + a)

def get_session():
    s = configure_session(requests.Session())
    s.headers.update(HEADERS)
    return s


# ─── link validator ────────────────────────────────────────────────────────────

def check_link(url, timeout=10, verify_video_content=False):
    """
    Returns (url, status_code, ok, reason)
    Uses HEAD first, falls back to GET with stream if HEAD fails/unsupported.
    If verify_video_content=True, also checks Content-Type is actually video media.
    """
    if verify_video_content:
        try:
            with get_session() as session:
                result = probe_file_type(url, session, timeout)
            code = result['status_code']
            ok = code < 400 and result['is_media'] and result['confidence'] >= 40
            return (url, code, ok,
                    f"{result['type']} (evidence score {result['confidence']}/100)" if code < 400 else f"HTTP {code}")
        except requests.exceptions.RequestException as exc:
            return (url, 0, False, str(exc)[:80])

    parsed = urlparse(url)
    streaming_hosts = ["googlevideo.com", "akamaihd.net", "fbcdn.net",
                       "twimg.com", "cdninstagram.com", "tiktokcdn.com"]
    if any(h in parsed.netloc for h in streaming_hosts):
        return (url, 200, True, "stream-cdn (assumed live)")

    route = {"http": proxy_url(), "https": proxy_url()} if proxy_url() else {}
    hdrs = {**HEADERS, "Range": "bytes=0-0"}
    try:
        r = requests.head(url, headers=hdrs, timeout=timeout, proxies=route,
                          allow_redirects=True, verify=False)
        code = r.status_code
        if code == 405:
            r = requests.get(url, headers={**HEADERS, "Range": "bytes=0-0"}, proxies=route,
                             timeout=timeout, stream=True,
                             allow_redirects=True, verify=False)
            r.close()
            code = r.status_code
        ok = code < 400

        # ── Video content-type verification ───────────────────────────────────
        if ok and verify_video_content:
            ct = r.headers.get("Content-Type", "").lower()
            # Accept any video/* type, octet-stream (CDN default), or m3u8/mpd manifests
            VIDEO_CONTENT_TYPES = (
                "video/", "application/octet-stream",
                "application/x-mpegurl", "application/vnd.apple.mpegurl",
                "application/dash+xml", "audio/mp4",
                "binary/octet-stream", "application/mp4",
            )
            is_video_ct = any(ct.startswith(vt) for vt in VIDEO_CONTENT_TYPES)
            # Also trust Content-Disposition: attachment
            is_attachment = "attachment" in r.headers.get("Content-Disposition", "").lower()
            # If Content-Type is explicitly HTML/text, it's NOT a video
            is_html = ct.startswith("text/html") or ct.startswith("text/plain")
            if is_html and not is_attachment:
                return (url, code, False, f"not-video (Content-Type: {ct[:40]})")
            # If we got a video content-type, mark as confirmed
            if is_video_ct:
                return (url, code, True, f"✓ video ({ct.split('/')[1].split(';')[0][:20]})")
            # Unknown content-type but URL has video extension — trust extension
            ext = video_ext(url)
            if ext and ext != "?":
                return (url, code, True, f"ok (ext:{ext})")
            return (url, code, True, "ok")

        return (url, code, ok, "ok" if ok else f"HTTP {code}")
    except requests.exceptions.SSLError:
        return (url, 0, False, "SSL error")
    except requests.exceptions.ConnectionError:
        return (url, 0, False, "connection error")
    except requests.exceptions.Timeout:
        return (url, 0, False, "timeout")
    except Exception as e:
        return (url, 0, False, str(e)[:60])


def validate_links(scan_id, verify_video_content=True):
    """
    Validates every discovered video link concurrently.
    With verify_video_content=True (default), also checks Content-Type
    to confirm the URL actually serves video data — not an HTML error page.
    Removes broken/non-video links from mp4_links.
    
    Scales workers automatically:
      ≤100 links  → 20 workers
      ≤1000 links → 50 workers
      >1000 links → 100 workers (HTTP HEAD only, 5s timeout, very fast)
    """
    r = scan_store[scan_id]
    links = list(dict.fromkeys(r["mp4_links"]))
    total = len(links)

    if total == 0:
        return

    # Scale concurrency to volume
    if total <= 100:
        workers, timeout = 20, 10
    elif total <= 1000:
        workers, timeout = 30, 8
    else:
        workers, timeout = 40, 6   # capped so validation can't saturate the machine

    r["log"].append(
        f"🔎 Validating {total:,} link(s) — {workers} workers"
        + (" + video Content-Type check" if verify_video_content else "")
        + (" (this may take a moment for large sets...)" if total > 500 else "")
    )
    r["validating"]          = True
    r["validation_results"]  = {}
    r["validation_progress"] = {"checked": 0, "total": total, "confirmed": 0}

    broken    = []
    confirmed = [0]
    checked   = [0]
    lock      = threading.Lock()

    def do_check(url):
        if r.get("cancel_requested"):
            return False
        result = check_link(url, timeout=timeout,
                            verify_video_content=verify_video_content)
        url_r, code, ok, reason = result
        with lock:
            checked[0] += 1
            r["validation_results"][url_r] = {"ok": ok, "code": code, "reason": reason}
            r["validation_progress"]["checked"] = checked[0]
            if ok:
                confirmed[0] += 1
                r["validation_progress"]["confirmed"] = confirmed[0]
                # Only log individual results for small sets; batch-log for large
                if total <= 200:
                    r["log"].append(f"   ✅ [{reason}] {url_r[:80]}")
                elif checked[0] % 100 == 0 or checked[0] == total:
                    pct = checked[0] * 100 // total
                    r["log"].append(
                        f"   ⚡ Validated {checked[0]:,}/{total:,} ({pct}%) "
                        f"— {confirmed[0]:,} confirmed video"
                    )
            else:
                broken.append(url_r)
                if total <= 200:
                    r["log"].append(f"   💀 [{reason}] → {url_r[:70]}")
        return ok

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(do_check, links))

    # Remove non-video / broken links
    if broken:
        before = len(r["mp4_links"])
        r["mp4_links"] = [u for u in r["mp4_links"] if u not in broken]
        removed = before - len(r["mp4_links"])
        r["log"].append(
            f"🗑️  Removed {removed:,} non-video/broken link(s). "
            f"{len(r['mp4_links']):,} confirmed video link(s) remain."
        )
    elif not r.get("cancel_requested"):
        r["log"].append(
            f"✅ All {total:,} link(s) confirmed as valid video content."
        )

    r["validating"] = False
    r["broken_links"] = broken


# ─── sitemap discovery ───────────────────────────────────────────────────────

SITEMAP_CANDIDATES = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap-index.xml",
    "/sitemaps/sitemap.xml",
    "/sitemap/sitemap.xml",
    "/wp-sitemap.xml",          # WordPress
    "/page-sitemap.xml",
    "/post-sitemap.xml",
    "/video-sitemap.xml",
    "/news-sitemap.xml",
    "/sitemap1.xml",
    "/sitemap2.xml",
]

def fetch_sitemap_urls(session, base_url, log,
                       parse_limit=100_000, timeout_deadline=None):
    """
    Discovers all page URLs from sitemaps.
    parse_limit: max total URLs to collect (stops early for huge sitemaps)
    timeout_deadline: unix timestamp — stops parsing new sitemaps if exceeded
    Returns a set of URLs found (capped at parse_limit).
    """
    parsed     = urlparse(base_url)
    origin     = f"{parsed.scheme}://{parsed.netloc}"
    found_urls = set()
    tried      = set()

    sitemap_urls_to_try = []

    # ── Step 1: parse robots.txt for Sitemap: entries ──
    robots_url = f"{origin}/robots.txt"
    try:
        r = smart_get(robots_url, timeout=8, retries=2)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("sitemap:"):
                    sm = line.split(":", 1)[1].strip()
                    if sm not in tried:
                        sitemap_urls_to_try.append(sm)
                        log.append(f"🗺️  robots.txt → sitemap: {sm}")
    except Exception:
        pass

    # ── Step 2: add common candidates ──
    for path in SITEMAP_CANDIDATES:
        u = origin + path
        if u not in tried:
            sitemap_urls_to_try.append(u)

    # ── Step 3: fetch & parse each sitemap ──
    def parse_sitemap(sm_url, depth=0):
        # Stop if we already have enough URLs or time is up
        if len(found_urls) >= parse_limit:
            return
        if timeout_deadline and time.time() > timeout_deadline:
            return
        if sm_url in tried or depth > 4:
            return
        tried.add(sm_url)
        try:
            r = smart_get(sm_url, timeout=10, retries=1)
            if r.status_code != 200:
                return
            ct = r.headers.get("Content-Type", "")
            if "gzip" in ct or sm_url.endswith(".gz"):
                import gzip
                raw_content = gzip.decompress(r.content).decode("utf-8", errors="ignore")
            else:
                raw_content = r.text

            if "<sitemapindex" in raw_content:
                from xml.etree import ElementTree as ET
                root = ET.fromstring(raw_content)
                ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                children = [loc.text.strip() for loc in root.findall(".//sm:loc", ns) if loc.text]
                log.append(f"🗺️  Sitemap index: {sm_url} → {len(children)} child sitemap(s)")
                for child in children:
                    if len(found_urls) >= parse_limit:
                        log.append(f"🗺️  Parse limit ({parse_limit:,}) reached — stopping sitemap parse")
                        break
                    if timeout_deadline and time.time() > timeout_deadline:
                        log.append(f"🗺️  Sitemap timeout — stopping after {len(found_urls):,} URLs")
                        break
                    parse_sitemap(child, depth + 1)

            elif "<urlset" in raw_content or "<url>" in raw_content:
                from xml.etree import ElementTree as ET
                root = ET.fromstring(raw_content)
                ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                locs = [loc.text.strip() for loc in root.findall(".//sm:loc", ns) if loc.text]
                video_ns = {"v": "http://www.google.com/schemas/sitemap-video/1.1"}
                video_locs = [loc.text.strip() for loc in root.findall(".//v:content_loc", video_ns) if loc.text]
                video_locs += [loc.text.strip() for loc in root.findall(".//v:player_loc", video_ns) if loc.text]
                # Only take up to parse_limit total
                remaining = parse_limit - len(found_urls)
                locs = locs[:remaining]
                log.append(f"🗺️  Sitemap: {sm_url} → {len(locs)} URL(s)" + (f", {len(video_locs)} video loc(s)" if video_locs else ""))
                found_urls.update(locs)
                for vl in video_locs:
                    if is_video_url(vl):
                        found_urls.add(vl)
            else:
                lines_found = [l.strip() for l in raw_content.splitlines() if l.strip().startswith("http")]
                if lines_found:
                    remaining = parse_limit - len(found_urls)
                    lines_found = lines_found[:remaining]
                    log.append(f"🗺️  Plain sitemap: {sm_url} → {len(lines_found)} URL(s)")
                    found_urls.update(lines_found)

        except Exception:
            pass

    for sm_url in sitemap_urls_to_try:
        if len(found_urls) >= parse_limit:
            break
        if timeout_deadline and time.time() > timeout_deadline:
            break
        parse_sitemap(sm_url)

    log.append(f"🗺️  Sitemap discovery complete — {len(found_urls)} URL(s) found across all sitemaps")
    return found_urls


# ─── Advanced bypass engine ───────────────────────────────────────────────────

try:
    import curl_cffi.requests as cffi_requests
    CURL_CFFI_OK = True
except ImportError:
    CURL_CFFI_OK = False

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    PLAYWRIGHT_OK = True
except ImportError:
    PLAYWRIGHT_OK = False

try:
    import cloudscraper as _cloudscraper
    CLOUDSCRAPER_OK = True
except ImportError:
    CLOUDSCRAPER_OK = False

import sys as _sys

# ── nodriver: requires Python <=3.13 (uses `str | Path` union type syntax) ────
try:
    import nodriver as _nodriver
    NODRIVER_OK = True
except (ImportError, TypeError, Exception):
    NODRIVER_OK = False
    _nodriver = None

# ── seleniumbase: supports Python 3.14+ ✅ (updated Mar 2026) ─────────────────
try:
    from seleniumbase import SB as _SB
    SELENIUMBASE_OK = True
except (ImportError, Exception):
    SELENIUMBASE_OK = False
    _SB = None

# ── camoufox: requires Python <=3.13 (last release Jan 2025) ─────────────────
try:
    from camoufox.sync_api import Camoufox as _Camoufox
    CAMOUFOX_OK = True
except (ImportError, TypeError, Exception):
    CAMOUFOX_OK = False
    _Camoufox = None

try:
    import httpx as _httpx
    HTTPX_OK = True
except ImportError:
    HTTPX_OK = False

# Global cookie file
_cookie_file_path = None
def set_cookie_file(p): global _cookie_file_path; _cookie_file_path = p
def get_cookie_file(): return _cookie_file_path

# Rotating Chrome versions for TLS fingerprint diversity
_CHROME_TARGETS = [
    "chrome124", "chrome123", "chrome120", "chrome119",
    "chrome116", "chrome110", "chrome107", "chrome104",
    "chrome101", "chrome99",
]
_target_idx = 0
def _next_chrome_target():
    global _target_idx
    t = _CHROME_TARGETS[_target_idx % len(_CHROME_TARGETS)]
    _target_idx += 1
    return t

# Rotating User-Agents
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
]
_ua_idx = 0
def _next_ua():
    global _ua_idx
    ua = _USER_AGENTS[_ua_idx % len(_USER_AGENTS)]
    _ua_idx += 1
    return ua


# ─── Adaptive Fingerprint Mutation Engine ─────────────────────────────────────
# Tracks per-domain success/failure for each (chrome_target, ua) combo.
# Uses UCB1 bandit algorithm + periodic AI re-ranking via Claude API.

import json as _json_mod
import math as _math_mod

# Fingerprint combos: (chrome_target, ua_index, label)
_FP_COMBOS = [
    ("chrome124", 0, "Chrome 124 Win"),
    ("chrome124", 3, "Chrome 124 Mac"),
    ("chrome123", 0, "Chrome 123 Win"),
    ("chrome120", 0, "Chrome 120 Win"),
    ("chrome116", 1, "Chrome 116 Win"),
    ("chrome110", 2, "Firefox 125 Win"),
    ("chrome107", 4, "Chrome 124 Linux"),
    ("chrome104", 5, "Edge 120 Win"),
    ("chrome101", 6, "Safari 17 Mac"),
    ("chrome99",  0, "Chrome 99 Win"),
]

# Per-domain bandit stats: domain -> {combo_idx: {wins, trials}}
_fp_stats: dict = {}
_fp_stats_lock = threading.Lock()

# AI re-ranking cache: domain -> {ranked_order: [idx,...], timestamp}
_fp_ai_cache: dict = {}
_FP_AI_CACHE_TTL = 3600  # re-rank every hour per domain


def _fp_record(domain: str, combo_idx: int, success: bool):
    """Record a trial outcome for the given domain + fingerprint combo."""
    with _fp_stats_lock:
        if domain not in _fp_stats:
            _fp_stats[domain] = {}
        entry = _fp_stats[domain].setdefault(combo_idx, {"wins": 0, "trials": 0})
        entry["trials"] += 1
        if success:
            entry["wins"] += 1


def _fp_ucb1_score(wins: int, trials: int, total_trials: int) -> float:
    """UCB1 score — balances exploitation (win rate) with exploration."""
    if trials == 0:
        return float("inf")
    exploitation = wins / trials
    exploration  = _math_mod.sqrt(2 * _math_mod.log(max(total_trials, 1)) / trials)
    return exploitation + exploration


def _fp_best_combo_ucb1(domain: str) -> int:
    """Pick best fingerprint combo index for domain using UCB1 bandit."""
    with _fp_stats_lock:
        stats = _fp_stats.get(domain, {})
        total = sum(v["trials"] for v in stats.values())
        best_idx, best_score = 0, -1.0
        for i in range(len(_FP_COMBOS)):
            s = stats.get(i, {"wins": 0, "trials": 0})
            score = _fp_ucb1_score(s["wins"], s["trials"], total)
            if score > best_score:
                best_score = score
                best_idx   = i
        return best_idx


_fp_rerank_inflight = {}   # domain -> last attempt time (prevents a thread per request)

def _fp_request_ai_rerank(domain: str, log=None):
    if not external_ai_enabled():
        return None
    """
    Ask Claude AI to re-rank fingerprint combos based on observed domain stats.
    Runs in background thread. Results cached in _fp_ai_cache.
    """
    with _fp_stats_lock:
        stats = dict(_fp_stats.get(domain, {}))
    if not stats:
        return

    summary_rows = []
    for i, (chrome_target, ua_idx, label) in enumerate(_FP_COMBOS):
        s = stats.get(i, {"wins": 0, "trials": 0})
        win_rate = (s["wins"] / s["trials"] * 100) if s["trials"] else 0
        summary_rows.append(
            f"  [{i}] {label} ({chrome_target}): "
            f"{s['wins']}/{s['trials']} = {win_rate:.0f}% success"
        )
    summary = "\n".join(summary_rows)

    prompt = (
        f"You are an expert in browser TLS fingerprinting and bot detection evasion.\n"
        f"I am scraping the domain '{domain}' and collected these fingerprint success rates:\n\n"
        f"{summary}\n\n"
        f"Based on this data and your knowledge of anti-bot systems used by '{domain}', "
        f"rank these combos from best to worst for future requests. "
        f"Consider win rate, sample size, and which TLS fingerprints are most trusted by this domain.\n"
        f"Respond ONLY with a JSON array of indices from best to worst. "
        f"Example: [2,0,5,1,3,4,6,7,8,9]\n"
        f"No explanation, no markdown, just the JSON array."
    )

    try:
        import urllib.request as _urlreq
        payload = _json_mod.dumps({
            "model":      "claude-sonnet-4-20250514",
            "max_tokens": 60,
            "messages":   [{"role": "user", "content": prompt}],
        }).encode()
        req = _urlreq.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type":      "application/json",
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        with _urlreq.urlopen(req, timeout=15) as resp:
            data = _json_mod.loads(resp.read())
        raw_text = data["content"][0]["text"].strip()
        # Strip any accidental markdown
        raw_text = re.sub(r"```[a-z]*", "", raw_text).strip().strip("`").strip()
        ranked = _json_mod.loads(raw_text)
        if isinstance(ranked, list) and len(ranked) == len(_FP_COMBOS):
            with _fp_stats_lock:
                _fp_ai_cache[domain] = {
                    "ranked_order": ranked,
                    "timestamp":    time.time(),
                }
            if log is not None:
                log.append(
                    f"🤖 AI re-ranked fingerprints for {domain} → "
                    f"best: {_FP_COMBOS[ranked[0]][2]}"
                )
    except Exception as e:
        if log is not None:
            log.append(f"   ℹ️  Fingerprint AI re-rank skipped: {str(e)[:60]}")


def fp_pick(domain: str, log=None) -> tuple:
    """
    Pick best (chrome_target, user_agent, label) for a domain.
    Uses AI-ranked order when available, otherwise UCB1.
    Triggers background AI re-rank when enough data exists.
    """
    cache = _fp_ai_cache.get(domain)
    if cache and (time.time() - cache["timestamp"]) < _FP_AI_CACHE_TTL:
        ranked = cache["ranked_order"]
        combo_idx = ranked[0] if ranked else 0
    else:
        combo_idx = _fp_best_combo_ucb1(domain)

    # Trigger background re-rank if stale and enough trials
    with _fp_stats_lock:
        domain_stats  = _fp_stats.get(domain, {})
        total_trials  = sum(v["trials"] for v in domain_stats.values())
    cache_stale = not cache or (time.time() - cache["timestamp"]) >= _FP_AI_CACHE_TTL
    if total_trials >= 5 and cache_stale and \
            time.time() - _fp_rerank_inflight.get(domain, 0) > _FP_AI_CACHE_TTL:
        _fp_rerank_inflight[domain] = time.time()
        threading.Thread(
            target=_fp_request_ai_rerank, args=(domain, log), daemon=True
        ).start()

    chrome_target, ua_idx, label = _FP_COMBOS[combo_idx]
    return chrome_target, _USER_AGENTS[ua_idx], label, combo_idx


def fp_smart_get(url: str, timeout: int = 8, extra_headers: dict = None):
    """
    Adaptive fingerprint-aware fetch. Records outcomes to improve future picks.
    Falls back to standard smart_get on failure.
    """
    domain = urlparse(url).netloc
    chrome_target, user_agent, fp_label, combo_idx = fp_pick(domain)

    hdrs = _browser_headers(ua=user_agent)
    if extra_headers:
        hdrs.update(extra_headers)

    if CURL_CFFI_OK:
        try:
            s = cffi_requests.Session(impersonate=chrome_target, verify=False)
            s.headers.update(hdrs)
            cookies = _load_cookie_dict()
            if cookies:
                s.cookies.update(cookies)
            r = s.get(url, timeout=timeout, allow_redirects=True)
            success = r.status_code < 400
            _fp_record(domain, combo_idx, success)
            if success:
                return r
            _fp_record(domain, combo_idx, False)  # double-record explicit block
        except Exception:
            _fp_record(domain, combo_idx, False)

    return smart_get(url, timeout=timeout, extra_headers=extra_headers)


def get_fp_stats_summary() -> dict:
    """Return per-domain fingerprint performance stats for the /fp_stats API."""
    with _fp_stats_lock:
        result = {}
        for domain, combos in _fp_stats.items():
            rows = []
            total_trials = sum(v["trials"] for v in combos.values())
            for idx, s in sorted(combos.items(), key=lambda x: -x[1]["wins"]):
                if idx < len(_FP_COMBOS):
                    _, _, label = _FP_COMBOS[idx]
                    win_rate = (s["wins"] / s["trials"] * 100) if s["trials"] else 0
                    rows.append({
                        "combo":    label,
                        "wins":     s["wins"],
                        "trials":   s["trials"],
                        "win_rate": round(win_rate, 1),
                    })
            ai_cache = _fp_ai_cache.get(domain)
            result[domain] = {
                "combos":       rows,
                "total_trials": total_trials,
                "ai_ranked":    bool(ai_cache),
                "ai_best":      _FP_COMBOS[ai_cache["ranked_order"][0]][2] if ai_cache else None,
            }
        return result

def _browser_headers(ua=None):
    ua = ua or _USER_AGENTS[0]
    return {
        "User-Agent":                ua,
        "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language":           "en-US,en;q=0.9",
        "Accept-Encoding":           "gzip, deflate, br",
        "Sec-Ch-Ua":                 '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "Sec-Ch-Ua-Mobile":          "?0",
        "Sec-Ch-Ua-Platform":        '"Windows"',
        "Sec-Fetch-Dest":            "document",
        "Sec-Fetch-Mode":            "navigate",
        "Sec-Fetch-Site":            "none",
        "Sec-Fetch-User":            "?1",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control":             "max-age=0",
        "Connection":                "keep-alive",
    }


def _load_cookie_dict():
    """Load cookies from uploaded .txt AND CDP-captured CF cookies combined."""
    import http.cookiejar
    cookies = {}

    # 1. Uploaded cookies.txt
    cookie_file = get_cookie_file()
    if cookie_file and __import__("os").path.exists(cookie_file):
        try:
            cj = http.cookiejar.MozillaCookieJar(cookie_file)
            cj.load(ignore_discard=True, ignore_expires=True)
            cookies.update({c.name: c.value for c in cj})
        except Exception:
            pass

    # 2. CDP-captured cookies override uploaded (more recent)
    for domain_cookies in _cf_solved_cookies.values():
        for c in domain_cookies:
            name = c.get("name", "")
            val  = c.get("value", "")
            if name:
                cookies[name] = val

    return cookies


def _load_pw_cookies():
    import http.cookiejar
    cookie_file = get_cookie_file()
    if not cookie_file or not __import__("os").path.exists(cookie_file):
        return []
    try:
        cj = http.cookiejar.MozillaCookieJar(cookie_file)
        cj.load(ignore_discard=True, ignore_expires=True)
        return [{"name": c.name, "value": c.value, "domain": c.domain.lstrip("."),
                 "path": c.path or "/", "secure": bool(c.secure), "httpOnly": False}
                for c in cj]
    except Exception:
        return []


# ─── Shared persistent sessions (connection pooling = 3-5x faster) ───────────

_bulk_session = None   # reused across all threads for same-domain scraping
_bulk_session_lock = threading.Lock()

def _get_bulk_session():
    """Get or create the shared bulk scraping session with connection pooling."""
    if proxy_url():
        session = get_session()
        session.cookies.update(_load_cookie_dict())
        return session
    global _bulk_session
    if _bulk_session is not None:
        return _bulk_session
    with _bulk_session_lock:
        if _bulk_session is not None:
            return _bulk_session
        cookie_dict = _load_cookie_dict()
        if CURL_CFFI_OK:
            s = cffi_requests.Session(impersonate="chrome124", verify=False)
            s.headers.update({
                "User-Agent":      _USER_AGENTS[0],
                "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
            })
            if cookie_dict:
                s.cookies.update(cookie_dict)
        else:
            s = requests.Session()
            s.headers.update(HEADERS)
            if cookie_dict:
                s.cookies.update(cookie_dict)
        _bulk_session = s
        return s

def reset_bulk_session():
    """Call after CF cookies are updated to force session refresh."""
    global _bulk_session
    with _bulk_session_lock:
        _bulk_session = None


# ─── Scan mode presets ────────────────────────────────────────────────────────
# Each mode defines: time_limit_s, max_pages, max_sitemap_urls, depth, label

SCAN_MODES = {
    "quick": {
        "label":               "⚡ Quick Scan",
        "time_limit_s":        60,
        "sitemap_timeout_s":   20,
        "sitemap_parse_limit": 50_000,
        "max_pages":           100,
        "max_sitemap_urls":    2_000,   # pages to scrape from sitemap
        "depth":               1,
        "concurrency":         200,
    },
    "moderate": {
        "label":               "🔍 Moderate Scan",
        "time_limit_s":        120,
        "sitemap_timeout_s":   30,
        "sitemap_parse_limit": 200_000,
        "max_pages":           200,
        "max_sitemap_urls":    10_000,  # scrape up to 10k sitemap pages
        "depth":               2,
        "concurrency":         400,
    },
    "deep": {
        "label":               "🌊 Deep Scan",
        "time_limit_s":        300,
        "sitemap_timeout_s":   45,
        "sitemap_parse_limit": 1_000_000,
        "max_pages":           500,
        "max_sitemap_urls":    100_000, # scrape up to 100k sitemap pages
        "depth":               3,
        "concurrency":         500,
    },
}


# ─── URL pre-filter — skip pages that never have video links ──────────────────

# Always skip: admin, feeds, sitemaps, static assets — these NEVER have video
_SKIP_URL_RE = re.compile(
    r"/(?:wp-json|feed|sitemap|rss\.xml|amp/|cdn-cgi|wp-admin|wp-login|wp-signup|"
    r"wp-content/(?:themes|plugins|uploads/\d{4}/$)|"
    r"favicon\.ico|robots\.txt|ads\.txt|"
    r"page/\d+/?$|/\d{4}/\d{2}/?$)",
    re.IGNORECASE,
)

# Video-only filter: only skip KNOWN non-content pages like taxonomy indices,
# pure listing pages, and static info pages.
# IMPORTANT: slug-style post URLs like /14978/, /movie-title-2024/ are KEPT
# because we cannot know from the URL alone whether they embed video.
_LISTING_ONLY_URL_RE = re.compile(
    r"^/(?:"
    r"category(?:/|$)|categories(?:/|$)|cat(?:/|$)|"   # taxonomy
    r"tag(?:/|$)|tags(?:/|$)|"
    r"author(?:/|$)|"
    r"search(?:\?|/|$)|"
    r"contact/?$|about/?$|privacy/?$|terms(?:-of-service)?/?$|dmca/?$|"
    r"latest/?$|trending/?$|most(?:-viewed)?/?$|best/?$|favorites/?$|"
    r"photos/?$|gallery/?$|stories/?$|enhance/?$|mactor/?$|"
    r"tim/?$|rimg/?$|"                                  # site-specific listing pages
    r"actor(?:-list)?/?$|actors/?$|"
    r"all-youtubers-nude-list/?$|"                      # lolpol2/mydesi specific
    r"indian-actors/?$|desi-cams-actos-list/?$|"
    r"tango-starts-list/?$|onlyfans-star-list/?$|"
    r"app-actor-list/?$|faphouse-indian-profile-list/?$|"
    r"xvideos-red/?$|stripchat-all-actors/?$|"
    r"webseries-siterps/?$|premium-siterips/?$|"
    r"country(?:/|$)|countries(?:/|$)|"
    r"page/\d+/?$"
    r")",
    re.IGNORECASE,
)

def should_skip_url(url, video_only: bool = False):
    """
    Return True for URLs that should be skipped.

    Always skips: wp-admin, feeds, sitemaps, static assets (never have video).
    
    video_only mode: ONLY additionally skips confirmed listing/taxonomy/info pages.
    Slug-style URLs (/14978/, /movie-name-2024/, /some-post/) are ALWAYS kept —
    we can't determine from the URL alone if they contain video.
    Direct video file URLs (.mp4, .m3u8 etc.) always pass through.
    """
    # Direct video files always pass
    if is_video_url(url):
        return False
    path = urlparse(url).path
    # Always skip structural/admin/feed pages
    if _SKIP_URL_RE.search(path):
        return True
    # video_only: skip confirmed listing/taxonomy pages only
    if video_only and _LISTING_ONLY_URL_RE.match(path):
        return True
    return False


# ─── Fast single-attempt fetcher for bulk scraping ────────────────────────────

def fast_get(url, timeout=5):
    """
    Single-attempt fetch using the shared pooled session.
    Fails fast — no retries, no fallback strategies.
    For bulk scraping where speed > reliability.
    """
    if proxy_url():
        return smart_get(url, timeout=timeout)
    s = _get_bulk_session()
    try:
        return s.get(url, timeout=timeout, allow_redirects=True)
    except Exception:
        return None


def smart_get(url, timeout=8, extra_headers=None, retries=2):
    """
    Multi-strategy fetcher for individual/important requests.
    Uses persistent sessions, not new sessions per request.
    retries reduced from 4 to 2 for faster failure.
    """
    if proxy_url():
        session = get_cf_session()
        try:
            return session.get(url, timeout=timeout, headers=extra_headers or {}, allow_redirects=True)
        finally:
            session.close()
    cookie_dict = _load_cookie_dict()
    errors      = []

    # ── Strategy 1: curl_cffi shared session ──────────────────────────────────
    if CURL_CFFI_OK:
        s = _get_bulk_session()
        try:
            if extra_headers:
                r = s.get(url, timeout=timeout, allow_redirects=True,
                          headers=extra_headers)
            else:
                r = s.get(url, timeout=timeout, allow_redirects=True)
            if r.status_code < 400:
                return r
            if r.status_code not in (403, 429, 503):
                errors.append(f"HTTP {r.status_code}")
                # Don't retry non-CF errors
                raise Exception(f"HTTP {r.status_code}")
            errors.append(f"curl_cffi: HTTP {r.status_code}")
        except Exception as e:
            if "HTTP" in str(e) and "403" not in str(e):
                raise
            errors.append(f"curl_cffi: {str(e)[:50]}")

    # ── Strategy 2: httpx HTTP/2 (different TLS fingerprint — bypasses some CF) ─
    if HTTPX_OK and retries > 1:
        try:
            hdrs = {"User-Agent": _next_ua(), "Accept-Language": "en-US,en;q=0.9"}
            if extra_headers:
                hdrs.update(extra_headers)
            with _httpx.Client(http2=True, verify=False, follow_redirects=True,
                               cookies=cookie_dict, timeout=timeout) as client:
                r = client.get(url, headers=hdrs)
                if r.status_code < 400:
                    class _R:
                        status_code = r.status_code
                        text        = r.text
                        content     = r.content
                        headers     = dict(r.headers)
                        url         = str(r.url)
                    return _R()
                errors.append(f"httpx: HTTP {r.status_code}")
        except Exception as e:
            errors.append(f"httpx: {str(e)[:50]}")

    # ── Strategy 3: cloudscraper (only for JS challenge sites, slow) ───────────
    # Skipped in bulk mode (retries=1), only used for manual requests
    if CLOUDSCRAPER_OK and retries > 2:
        try:
            s = _cloudscraper.create_scraper(
                browser={"browser": "chrome", "platform": "windows"},
                delay=1,  # reduced from 3
            )
            if cookie_dict:
                s.cookies.update(cookie_dict)
            r = s.get(url, timeout=timeout, allow_redirects=True)
            if r.status_code < 400:
                return r
            errors.append(f"cloudscraper: HTTP {r.status_code}")
        except Exception as e:
            errors.append(f"cloudscraper: {str(e)[:50]}")

    # NOTE: no automatic browser launching here. Cracking CF opens real browser
    # windows, so it only runs when the user clicks CRACK CF (see /solve_cf).
    raise Exception(f"All strategies failed: {' | '.join(errors[-3:])}")


def get_cf_session():
    """
    Returns the best available session object.
    Prefers curl_cffi for TLS impersonation. Falls back to requests.
    For per-request use, prefer smart_get() which rotates strategies.
    """
    if proxy_url():
        session = get_session()
        session.cookies.update(_load_cookie_dict())
        return session
    cookie_dict = _load_cookie_dict()
    if CURL_CFFI_OK:
        s = cffi_requests.Session(impersonate="chrome124", verify=False)
        s.headers.update(_browser_headers())
        if cookie_dict:
            s.cookies.update(cookie_dict)
        return s
    s = requests.Session()
    s.headers.update(_browser_headers())
    if cookie_dict:
        s.cookies.update(cookie_dict)
    return s


# ── Enhanced stealth JS ───────────────────────────────────────────────────
STEALTH_JS = """
// Fully hide all automation signals
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
delete navigator.__proto__.webdriver;

// Realistic plugins
const mockPlugins = ['Chrome PDF Plugin','Chrome PDF Viewer','Native Client'];
Object.defineProperty(navigator, 'plugins', {
    get: () => { const arr = mockPlugins.map(n=>({name:n,filename:n,description:n,length:1}));
                 arr.length = mockPlugins.length; return arr; }
});
Object.defineProperty(navigator, 'mimeTypes', {get: () => ({length: 4})});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});
Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});
Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});
Object.defineProperty(navigator, 'platform', {get: () => 'Win32'});
Object.defineProperty(navigator, 'maxTouchPoints', {get: () => 0});

// Chrome runtime
window.chrome = {
    app: {isInstalled: false, InstallState: {DISABLED:'d',INSTALLED:'i',NOT_INSTALLED:'n'}, RunningState: {CANNOT_RUN:'c',READY_TO_RUN:'r',RUNNING:'ru'}},
    runtime: {OnInstalledReason: {}, OnRestartRequiredReason: {}, PlatformArch: {}, PlatformNaclArch: {}, PlatformOs: {}, RequestUpdateCheckStatus: {}},
    csi: () => {}, loadTimes: () => {},
};

// Permissions — avoid Notification.permission crash in headless
try {
    const origQuery = window.navigator.permissions.query;
    window.navigator.permissions.__proto__.query = function(p) {
        if (p.name === 'notifications') return Promise.resolve({state:'denied'});
        if (p.name === 'clipboard-read' || p.name === 'clipboard-write') return Promise.resolve({state:'granted'});
        return origQuery.call(this, p);
    };
} catch(e) {}

// WebGL — realistic GPU fingerprint
try {
    const getParam = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(p) {
        if (p === 37445) return 'Google Inc. (NVIDIA)';
        if (p === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)';
        return getParam.call(this, p);
    };
} catch(e) {}

// Hide iframe srcdoc automation tell
try { Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {get: function(){return window;}}); } catch(e) {}

// Fake screen
Object.defineProperty(screen, 'width', {get: () => 1920});
Object.defineProperty(screen, 'height', {get: () => 1080});
Object.defineProperty(screen, 'availWidth', {get: () => 1920});
Object.defineProperty(screen, 'availHeight', {get: () => 1040});
Object.defineProperty(screen, 'colorDepth', {get: () => 24});

// Pass Cloudflare's JS VM checks
window.outerWidth = 1920;
window.outerHeight = 1080;
window.innerWidth = 1920;
window.innerHeight = 940;
"""


def _make_pw_browser(playwright_instance, headless=True):
    args = [
        "--no-sandbox",
        "--disable-blink-features=AutomationControlled",
        "--disable-dev-shm-usage",
        "--disable-features=IsolateOrigins,site-per-process",
        "--window-size=1920,1080",
        "--start-maximized",
        "--disable-infobars",
        "--lang=en-US,en",
    ]
    if not headless:
        args.append("--disable-popup-blocking")

    return playwright_instance.chromium.launch(
        headless=headless,
        args=args,
        ignore_default_args=["--enable-automation"],
        **browser_proxy_options(),
    )


def _make_pw_context(browser, cookies=None, headless=True):
    ctx = browser.new_context(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        viewport={"width": 1920, "height": 1080},
        screen={"width": 1920, "height": 1080},
        locale="en-US",
        timezone_id="America/New_York",
        java_script_enabled=True,
        accept_downloads=False,
        color_scheme="light",
        extra_http_headers={
            "Accept-Language":       "en-US,en;q=0.9",
            "Sec-Ch-Ua":             '"Chromium";v="124","Google Chrome";v="124","Not-A.Brand";v="99"',
            "Sec-Ch-Ua-Mobile":      "?0",
            "Sec-Ch-Ua-Platform":    '"Windows"',
        },
    )
    ctx.add_init_script("\n;\n".join((STEALTH_JS, MEDIA_OBSERVER_SCRIPT, STREAM_OBSERVER_SCRIPT, DRM_OBSERVER_SCRIPT, API_JSON_OBSERVER_SCRIPT, PLAYER_ADAPTER_SCRIPT)))
    if cookies:
        # Playwright requires specific cookie format — fix domain and required fields
        clean = []
        for c in cookies:
            if not c.get("name") or not c.get("value"):
                continue
            domain = c.get("domain", "")
            # Playwright needs domain to start with dot for subdomain cookies
            if domain and not domain.startswith("."):
                domain = "." + domain
            entry = {
                "name":   c["name"],
                "value":  c["value"],
                "domain": domain,
                "path":   c.get("path", "/"),
            }
            # Only add optional bool fields if present
            if "secure" in c:
                entry["secure"] = bool(c["secure"])
            if "httpOnly" in c:
                entry["httpOnly"] = bool(c["httpOnly"])
            clean.append(entry)
        if clean:
            try:
                ctx.add_cookies(clean)
            except Exception as e:
                # Try one by one to add as many as possible
                added = 0
                for cookie in clean:
                    try:
                        ctx.add_cookies([cookie])
                        added += 1
                    except Exception:
                        pass
    return ctx


# ── CF challenge solver using real Chrome/Edge via CDP ────────────────────────
# This is undetectable — launches YOUR actual Chrome with no automation flags

_cf_solved_cookies = {}   # domain -> list of cookies
_cf_solve_log      = {}   # domain -> log lines (so UI can poll progress)
_CDP_PORT = 9222

def _find_browser_executable():
    """Find Chrome or Edge on the system."""
    import shutil
    candidates = [
        # Chrome Windows
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Users\{}\AppData\Local\Google\Chrome\Application\chrome.exe".format(
            __import__("os").environ.get("USERNAME", "user")),
        # Edge Windows
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        # Linux
        "/usr/bin/google-chrome", "/usr/bin/chromium-browser",
        "/usr/bin/chromium", "/snap/bin/chromium",
        # macOS
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ]
    for path in candidates:
        if __import__("os").path.exists(path):
            return path
    # Try PATH
    for name in ["google-chrome", "chrome", "chromium", "chromium-browser", "msedge"]:
        found = shutil.which(name)
        if found:
            return found
    return None


def _cdp_request(path, port=_CDP_PORT):
    """Make a CDP HTTP request."""
    try:
        r = requests.get(f"http://localhost:{port}{path}", timeout=3)
        return r.json()
    except Exception:
        return None


def _cdp_get_cookies(tab_ws_url):
    """Get cookies from a tab via CDP websocket."""
    import json, threading
    try:
        import websocket
    except ImportError:
        return []
    cookies = []
    done    = threading.Event()

    def on_message(ws, msg):
        data = json.loads(msg)
        if data.get("id") == 1:
            cookies.extend(data.get("result", {}).get("cookies", []))
            done.set()
            ws.close()

    ws = websocket.WebSocketApp(tab_ws_url, on_message=on_message)
    t  = threading.Thread(target=ws.run_forever, daemon=True)
    t.start()
    time.sleep(0.5)
    ws.send(json.dumps({"id": 1, "method": "Network.getAllCookies"}))
    done.wait(timeout=5)
    return cookies


# ─── Multi-strategy Cloudflare Crack Engine (2026) ───────────────────────────
# Python 3.14 compatibility:
#   ✅ seleniumbase (CDP mode)  — works on Python 3.14+, strongest bypass
#   ✅ Pure CDP via websockets  — works on any Python, no extra libs needed
#   ⚠️  nodriver                — Python ≤3.13 only
#   ⚠️  camoufox                — Python ≤3.13 only
#   ✅ real Chrome CDP          — always works as manual fallback
#
# Strategy order: seleniumbase → nodriver → camoufox → pure-CDP → real Chrome

def _cookies_to_dict(cookie_list):
    return {c.get("name",""):c.get("value","") for c in cookie_list if c.get("name")}


@isolated_browser_thread
def _solve_seleniumbase_cdp(url, log):
    """
    SeleniumBase CDP Mode — supports Python 3.14+, updated Mar 2026.
    Uses UC Mode + CDP Mode together for maximum stealth.
    Automatically handles Turnstile, hCaptcha, and CF challenges.
    """
    if not SELENIUMBASE_OK:
        return None
    domain = urlparse(url).netloc
    log.append("🤖 [SB CDP] SeleniumBase UC+CDP mode (Python 3.14 compatible)...")
    try:
        with _SB(uc=True, headless=False, no_sandbox=True,
                 chromium_arg="--window-size=1920,1080") as sb:
            try:
                sb.activate_cdp_mode(url)
            except Exception:
                sb.open(url)

            # Wait up to 30s for CF to pass
            for i in range(30):
                time.sleep(1)
                try:
                    title = sb.get_page_title().lower()
                except Exception:
                    title = ""

                if "just a moment" in title or "checking your browser" in title or "please wait" in title:
                    if i % 5 == 0:
                        log.append(f"   ⏳ SB CDP: CF challenge active ({i}s)...")
                    # Try to auto-click Turnstile if present
                    try:
                        sb.uc_gui_click_captcha()
                    except Exception:
                        pass
                    try:
                        sb.cdp.gui_click_element("iframe")
                    except Exception:
                        pass
                    continue
                log.append(f"   ✅ SB CDP: CF bypassed — {sb.get_page_title()[:60]}")
                break
            else:
                log.append("   ⚠️  SB CDP: CF challenge not resolved in 30s")
                return None

            # Extract all cookies
            try:
                raw = sb.driver.get_cookies()
            except Exception:
                raw = []
            try:
                cdp_cookies = sb.cdp.get_all_cookies()
                if cdp_cookies:
                    raw = cdp_cookies
            except Exception:
                pass

            if raw:
                cookies = [{"name": c.get("name",""), "value": c.get("value",""),
                            "domain": c.get("domain", domain)} for c in raw]
                _cf_solved_cookies[domain] = cookies
                has_cf = any(c["name"] == "cf_clearance" for c in cookies)
                log.append(
                    f"   🍪 SB CDP: {len(cookies)} cookie(s) captured"
                    + (" — cf_clearance ✅" if has_cf else "")
                )
                return cookies
    except Exception as e:
        log.append(f"   ⚠️  SB CDP error: {str(e)[:100]}")
    return None


async def _solve_nodriver_async(url, log):
    """nodriver — Python ≤3.13 only. Direct CDP, no webdriver binary."""
    if not NODRIVER_OK or _nodriver is None:
        return None
    import asyncio
    domain = urlparse(url).netloc
    log.append("🟢 [nodriver] Direct CDP mode (Python ≤3.13)...")
    try:
        browser = await _nodriver.start(
            headless=False,
            browser_args=["--no-sandbox","--disable-blink-features=AutomationControlled",
                          "--window-size=1920,1080","--lang=en-US"],
        )
        page = await browser.get(url)
        for i in range(30):
            await asyncio.sleep(1)
            try:
                title = (await page.evaluate("document.title") or "").lower()
            except Exception:
                title = ""
            if "just a moment" in title or "checking" in title:
                if i % 5 == 0:
                    log.append(f"   ⏳ nodriver: CF active ({i}s)...")
                continue
            log.append(f"   ✅ nodriver: CF bypassed")
            break
        else:
            log.append("   ⚠️  nodriver: timeout")
            await browser.stop()
            return None

        # Get cookies
        raw = []
        try:
            raw = await browser.cookies()
        except Exception:
            try:
                raw = await page.evaluate(
                    "document.cookie.split(';').map(c=>{const[n,...v]=c.trim().split('=');return{name:n.trim(),value:v.join('=').trim(),domain:location.hostname}})"
                )
            except Exception:
                pass
        await browser.stop()
        if raw:
            cookies = [{"name": c.get("name",""), "value": c.get("value",""),
                        "domain": c.get("domain", domain)} for c in raw if c.get("name")]
            _cf_solved_cookies[domain] = cookies
            has_cf = any(c["name"] == "cf_clearance" for c in cookies)
            log.append(f"   🍪 nodriver: {len(cookies)} cookie(s)" + (" — cf_clearance ✅" if has_cf else ""))
            return cookies
    except Exception as e:
        log.append(f"   ⚠️  nodriver error: {str(e)[:80]}")
    return None


@isolated_browser_thread
def _solve_nodriver_sync(url, log):
    """Run nodriver async solver in a fresh event loop."""
    if not NODRIVER_OK:
        return None
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(_solve_nodriver_async(url, log))
        loop.close()
        return result
    except Exception as e:
        log.append(f"   nodriver loop error: {str(e)[:60]}")
        return None


@isolated_browser_thread
def _solve_camoufox(url, log):
    """Camoufox — Python ≤3.13 only. Firefox C++ fingerprint spoofing."""
    if not CAMOUFOX_OK or _Camoufox is None:
        return None
    domain = urlparse(url).netloc
    log.append("🦊 [Camoufox] Firefox stealth mode (Python ≤3.13)...")
    try:
        with _Camoufox(headless=False, geoip=True) as browser:
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            for i in range(30):
                time.sleep(1)
                title = page.title().lower()
                if "just a moment" in title or "checking" in title:
                    if i % 5 == 0:
                        log.append(f"   ⏳ Camoufox: CF active ({i}s)...")
                    continue
                log.append(f"   ✅ Camoufox: CF bypassed")
                break
            else:
                log.append("   ⚠️  Camoufox: timeout")
                return None
            cookies = page.context.cookies()
            if cookies:
                _cf_solved_cookies[domain] = cookies
                has_cf = any(c.get("name") == "cf_clearance" for c in cookies)
                log.append(f"   🍪 Camoufox: {len(cookies)} cookie(s)" + (" — cf_clearance ✅" if has_cf else ""))
                return cookies
    except Exception as e:
        log.append(f"   ⚠️  Camoufox error: {str(e)[:80]}")
    return None


def _solve_pure_cdp(url, log):
    """
    Pure CDP via subprocess + websockets — zero extra libraries needed.
    Launches Chrome with --remote-debugging-port, connects via websockets,
    navigates and extracts cookies. Works on any Python version.
    """
    import subprocess, json as _json, socket
    domain = urlparse(url).netloc
    log.append("🔌 [Pure CDP] Launching Chrome via subprocess + DevTools Protocol...")

    browser_exe = None if proxy_url() else _find_browser_executable()
    if not browser_exe:
        log.append("   ❌ No Chrome/Edge found for Pure CDP mode")
        return None

    import tempfile, os
    profile_dir = tempfile.mkdtemp(prefix="ripper_cdp_")
    with socket.socket() as _s:
        _s.bind(("127.0.0.1", 0))
        port = _s.getsockname()[1]   # free port, avoids clashes between runs

    cmd = [
        browser_exe,
        f"--remote-debugging-port={port}",
        "--no-first-run", "--no-default-browser-check",
        "--disable-blink-features=AutomationControlled",
        "--no-sandbox", "--disable-gpu",
        f"--user-data-dir={profile_dir}",
        "--window-size=1920,1080",
    ]

    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Wait for CDP port
        for _ in range(20):
            time.sleep(0.5)
            try:
                with socket.create_connection(("localhost", port), timeout=1):
                    break
            except OSError:
                pass
        else:
            log.append("   ❌ Chrome CDP port not responding")
            return None

        # Get WebSocket URL
        r = requests.get(f"http://localhost:{port}/json/new?{url}", timeout=5)
        tab_info = r.json()
        ws_url = tab_info.get("webSocketDebuggerUrl", "")
        if not ws_url:
            r2 = requests.get(f"http://localhost:{port}/json", timeout=5)
            tabs = r2.json()
            ws_url = tabs[0]["webSocketDebuggerUrl"] if tabs else ""

        if not ws_url:
            log.append("   ❌ Could not get WebSocket URL")
            return None

        # Connect and navigate
        try:
            import websocket as _ws_lib
            WS_OK = True
        except ImportError:
            WS_OK = False

        if WS_OK:
            result_cookies = []
            done_evt = threading.Event()
            nav_done = threading.Event()
            msg_id = [1]

            def on_msg(ws, msg):
                data = _json.loads(msg)
                mid = data.get("id")
                if mid == 2:  # navigate response
                    nav_done.set()
                elif mid == 99:  # getCookies response
                    result_cookies.extend(data.get("result", {}).get("cookies", []))
                    done_evt.set()
                    ws.close()
                # Also check page load events
                if data.get("method") == "Page.loadEventFired":
                    nav_done.set()

            def on_open(ws):
                # Enable Page events and navigate
                ws.send(_json.dumps({"id": 1, "method": "Page.enable"}))
                ws.send(_json.dumps({"id": 2, "method": "Page.navigate", "params": {"url": url}}))

            ws_conn = _ws_lib.WebSocketApp(ws_url, on_message=on_msg, on_open=on_open)
            wt = threading.Thread(target=ws_conn.run_forever, daemon=True)
            wt.start()

            # Wait for page load then poll for CF resolution
            nav_done.wait(timeout=15)
            for i in range(30):
                time.sleep(1)
                # Check title via CDP
                title_resp = []
                title_done = threading.Event()
                def on_title(ws, msg):
                    d = _json.loads(msg)
                    if d.get("id") == 50:
                        res = d.get("result", {})
                        title_resp.append(res.get("result", {}).get("value", ""))
                        title_done.set()
                ws_conn.on_message = on_title
                ws_conn.send(_json.dumps({"id": 50, "method": "Runtime.evaluate",
                                          "params": {"expression": "document.title"}}))
                title_done.wait(timeout=2)
                ws_conn.on_message = on_msg  # restore
                title = (title_resp[0] if title_resp else "").lower()
                if "just a moment" in title or "checking" in title:
                    if i % 5 == 0:
                        log.append(f"   ⏳ Pure CDP: CF active ({i}s)...")
                    continue
                log.append(f"   ✅ Pure CDP: CF passed")
                break
            else:
                log.append("   ⚠️  Pure CDP: CF not resolved in 30s")

            # Get cookies
            ws_conn.send(_json.dumps({"id": 99, "method": "Network.getAllCookies"}))
            done_evt.wait(timeout=5)

            if result_cookies:
                cookies = [{"name": c.get("name",""), "value": c.get("value",""),
                            "domain": c.get("domain", domain)} for c in result_cookies]
                _cf_solved_cookies[domain] = cookies
                has_cf = any(c["name"] == "cf_clearance" for c in cookies)
                log.append(f"   🍪 Pure CDP: {len(cookies)} cookie(s)" + (" — cf_clearance ✅" if has_cf else ""))
                return cookies
    except Exception as e:
        log.append(f"   ⚠️  Pure CDP error: {str(e)[:80]}")
    finally:
        try:
            if proc:
                proc.terminate()
        except Exception:
            pass
        try:
            import shutil
            shutil.rmtree(profile_dir, ignore_errors=True)
        except Exception:
            pass
    return None


_crack_lock       = threading.Lock()      # only ONE browser-based crack at a time
_crack_last_try   = {}                    # domain -> unix time of last attempt
_CRACK_COOLDOWN_S = 120


def crack_cf(url, log):
    """
    Master CF cracker — tries all strategies in order, stops at first success.
    Python 3.14 compatible: SeleniumBase CDP always runs first.
    nodriver/camoufox auto-activate on Python ≤3.13 as bonus layers.
    """
    if proxy_url():
        log.append("Configured proxy: use the routed browser session or upload cookies; auxiliary browser engines are disabled.")
        return None
    domain = urlparse(url).netloc
    if not _crack_lock.acquire(blocking=False):
        log.append("⚠️  Another CF crack is already running — not starting a second browser.")
        return None
    try:
        last = _crack_last_try.get(domain, 0)
        if time.time() - last < _CRACK_COOLDOWN_S:
            log.append(f"⚠️  CF crack for {domain} ran {int(time.time()-last)}s ago — cooling down.")
            return None
        _crack_last_try[domain] = time.time()
        return _crack_cf_locked(url, log, domain)
    finally:
        _crack_lock.release()


def _crack_cf_locked(url, log, domain):
    log.append(f"🔓 CF Cracker starting for {domain}...")

    import sys
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}"

    # Build strategy list based on what's available
    strategies = []

    # SeleniumBase CDP — works on Python 3.14+ ✅
    if SELENIUMBASE_OK:
        strategies.append(("SeleniumBase CDP [Python 3.14✅]", _solve_seleniumbase_cdp))

    # nodriver — Python ≤3.13 only
    if NODRIVER_OK:
        strategies.append(("nodriver [Python ≤3.13]", _solve_nodriver_sync))

    # Camoufox — Python ≤3.13 only
    if CAMOUFOX_OK:
        strategies.append(("Camoufox Firefox [Python ≤3.13]", _solve_camoufox))

    # Pure CDP — always available
    strategies.append(("Pure CDP via subprocess", _solve_pure_cdp))

    if not strategies:
        log.append(f"⚠️  No CF crack libraries found. Install: pip install seleniumbase")
        return None

    log.append(f"   Python {py_ver} | {len(strategies)} strategy/strategies available")

    for name, fn in strategies:
        log.append(f"   ▶ Trying: {name}")
        try:
            result = fn(url, log)
        except Exception as e:
            log.append(f"   ✗ {name} exception: {str(e)[:60]}")
            result = None

        if result:
            has_cf = any(c.get("name") == "cf_clearance" for c in result)
            log.append(
                f"✅ CF cracked via {name}! "
                f"{len(result)} cookies" + (" — cf_clearance obtained" if has_cf else "")
            )
            reset_bulk_session()
            return result
        log.append(f"   ✗ {name} — no cookies, trying next...")

    log.append("   All automated strategies failed — launching manual Chrome solve...")
    return None


@isolated_browser_thread
def solve_cf_challenge_visible(url, log):
    """
    Launch real Chrome/Edge via subprocess (no automation flags — CF can't detect it).
    Then connect Playwright to it via CDP to cleanly extract cookies.
    Falls back to Playwright visible browser if no real Chrome found.
    """
    import subprocess, os

    domain      = urlparse(url).netloc
    browser_exe = None if proxy_url() else _find_browser_executable()

    # ── Strategy 1: real Chrome + Playwright connect_over_cdp ────────────────
    if browser_exe and PLAYWRIGHT_OK:
        log.append(f"🌐 Launching: {os.path.basename(browser_exe)}")
        log.append("   No automation flags — Cloudflare sees a real browser")
        log.append("   ⏳ Waiting for page to load (up to 90s)...")

        # Use a dedicated profile so it doesn't interfere with the user's normal Chrome
        profile_dir = os.path.join(os.environ.get("TEMP", os.environ.get("TMPDIR", "/tmp")),
                                   "ripper_cf_profile")
        cmd = [
            browser_exe,
            f"--remote-debugging-port={_CDP_PORT}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-popup-blocking",
            f"--user-data-dir={profile_dir}",
            url,
        ]

        proc = None
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log.append(f"   Browser PID: {proc.pid}")

            # Wait for CDP port to open
            cdp_url = f"http://localhost:{_CDP_PORT}"
            log.append(f"   Waiting for CDP on {cdp_url}...")
            for i in range(25):
                time.sleep(1)
                try:
                    r = requests.get(f"{cdp_url}/json/version", timeout=1)
                    if r.status_code == 200:
                        browser_name = r.json().get("Browser", "?")[:40]
                        log.append(f"   ✅ CDP ready — {browser_name}")
                        break
                except Exception:
                    pass
            else:
                log.append("   ❌ CDP port not responding — Chrome may have failed to launch")
                log.append("   💡 Try closing all Chrome windows and click SOLVE CF again")
                return []

            # Connect Playwright to the running real Chrome
            log.append("   Connecting to browser via CDP...")
            with sync_playwright() as pw:
                browser = pw.chromium.connect_over_cdp(cdp_url)
                log.append("   ✅ Connected to real Chrome")

                # Get existing context/page or create new one
                contexts = browser.contexts
                if contexts:
                    ctx  = contexts[0]
                    pages = ctx.pages
                    page  = pages[0] if pages else ctx.new_page()
                else:
                    ctx  = browser.new_context()
                    page = ctx.new_page()
                    page.goto(url, wait_until="domcontentloaded", timeout=30000)

                # Poll until CF challenge resolves
                deadline  = time.time() + 90
                solved    = False
                last_title = ""

                while time.time() < deadline:
                    time.sleep(1.5)
                    try:
                        reason = access_block_reason(page.content())
                        if reason:
                            log.append(f"Access blocked: {reason} Contact the site owner if access should be allowed.")
                            return []
                        title   = page.title()
                        cur_url = page.url
                        title_l = title.lower()

                        if title_l != last_title:
                            log.append(f"   📄 {title[:70]}")
                            last_title = title_l

                        is_cf = any(k in title_l for k in [
                            "just a moment", "performing security",
                            "checking your browser", "verify you are human",
                            "attention required",
                        ])

                        if not is_cf and domain in cur_url:
                            solved = True
                            log.append("   ✅ Page loaded — capturing cookies...")
                            time.sleep(2)
                            break
                    except Exception:
                        pass

                if solved:
                    # Grab all cookies from the context
                    raw = ctx.cookies()
                    if raw:
                        _cf_solved_cookies[domain] = raw
                        # Also store without www prefix
                        domain2 = domain.replace("www.", "") if domain.startswith("www.") else "www." + domain
                        _cf_solved_cookies[domain2] = raw
                        reset_bulk_session()   # force session refresh with new cookies

                        cf_c = next((c for c in raw if c.get("name") == "cf_clearance"), None)
                        if cf_c:
                            log.append(f"   🍪 cf_clearance: {cf_c['value'][:35]}...")
                        else:
                            log.append(f"   🍪 {len(raw)} session cookies captured (no cf_clearance — site uses token auth)")
                        log.append(f"   ✅ Done! {len(raw)} cookies saved. Now click SCAN.")
                    else:
                        log.append("   ⚠️  No cookies found — try visiting the site manually first")
                else:
                    log.append("   ⏱  Timed out — CF challenge may still be running")
                    log.append("   💡 Try waiting longer or upload cookies.txt manually")

                try:
                    browser.disconnect()
                except Exception:
                    pass

        except Exception as e:
            log.append(f"   ❌ Error: {navigation_error(url, e)}")
            # If CDP port already in use, give clear instructions
            if "10061" in str(e) or "Connection refused" in str(e):
                log.append("   💡 Close all Chrome windows and try again")
            elif "already" in str(e).lower() or "in use" in str(e).lower():
                log.append(f"   💡 Port {_CDP_PORT} in use — close Chrome and retry")

        return _cf_solved_cookies.get(domain, [])

    # ── Strategy 2: Playwright visible browser (fallback) ─────────────────────
    if not PLAYWRIGHT_OK:
        log.append("❌ No browser found and Playwright not installed.")
        log.append("   Options:")
        log.append("   1. Install Chrome: https://www.google.com/chrome/")
        log.append("   2. Or: python -m playwright install chromium")
        return []

    log.append("🪟 No real Chrome/Edge found — using Playwright Chromium (visible)")
    log.append("   ⏳ Waiting for CF to pass automatically (up to 90s)...")

    captured = []
    try:
        with sync_playwright() as pw:
            browser = _make_pw_browser(pw, headless=False)
            ctx     = _make_pw_context(browser, headless=False)
            page    = ctx.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=30000)

            deadline   = time.time() + 90
            solved     = False
            last_title = ""

            while time.time() < deadline:
                time.sleep(1.5)
                try:
                    reason = access_block_reason(page.content())
                    if reason:
                        log.append(f"Access blocked: {reason} Contact the site owner if access should be allowed.")
                        browser.close()
                        return []
                    title   = page.title()
                    title_l = title.lower()
                    if title_l != last_title:
                        log.append(f"   📄 {title[:70]}")
                        last_title = title_l
                    is_cf = any(k in title_l for k in [
                        "just a moment", "performing security",
                        "checking your browser", "cf-browser-verification",
                    ])
                    if not is_cf and domain in page.url:
                        solved = True
                        log.append("   ✅ Passed! Capturing cookies...")
                        time.sleep(2)
                        break
                except Exception:
                    pass

            if solved:
                captured = ctx.cookies()
                _cf_solved_cookies[domain] = captured
                cf_c = next((c for c in captured if c.get("name") == "cf_clearance"), None)
                if cf_c:
                    log.append(f"   🍪 cf_clearance: {cf_c['value'][:35]}...")
                log.append(f"   ✅ {len(captured)} cookies captured. Now click SCAN.")
            else:
                log.append("   ⏱  Timed out — Playwright Chromium may be detected")
                log.append("   💡 Install real Chrome for better results")

            try:
                browser.close()
            except Exception:
                pass
    except Exception as e:
        log.append(f"   ❌ {navigation_error(url, e)}")

    return captured


def _get_best_pw_cookies(url):
    """Merge uploaded cookies.txt + CDP-captured cookies. CDP cookies take priority."""
    parsed   = urlparse(url)
    domain   = parsed.netloc
    # Also try without www prefix
    domain2  = domain.replace("www.", "") if domain.startswith("www.") else "www." + domain

    uploaded = _load_pw_cookies()
    solved   = _cf_solved_cookies.get(domain, []) or _cf_solved_cookies.get(domain2, [])

    if not solved:
        return uploaded

    # Merge: solved cookies override uploaded ones with same name
    merged = {c["name"]: c for c in uploaded}
    for c in solved:
        merged[c["name"]] = c
    return list(merged.values())


# ── Playwright page fetcher ────────────────────────────────────────────────

def pw_fetch_page(page, url, log, cf_cookies=None, wait_cf=True, timeout=30000):
    """
    Navigate to a page with CF-aware waiting.
    Returns (html, final_url) or (None, None).
    """
    has_cf_cookie = cf_cookies and any(
        c.get("name") == "cf_clearance" for c in cf_cookies
    )
    try:
        response = page.goto(url, wait_until="domcontentloaded", timeout=timeout)
        reason = access_block_reason(page.content())
        if reason:
            log.append(f"Access blocked: {reason} No media extracted from this page.")
            return None, None
        if response is not None and response.status >= 400:
            log.append(f"HTTP {response.status}: website did not return an accessible page — {url[:100]}")
            return None, None

        if wait_cf:
            cf_hit    = False
            cf_passed = False
            for i in range(60):   # up to 30s
                try:
                    title   = page.title().lower()
                    content = page.content().lower()
                    is_cf   = any(k in title for k in [
                        "just a moment", "performing security",
                        "checking your browser", "attention required",
                        "verify you are human",
                    ]) or "cf-browser-verification" in content

                    if not is_cf:
                        cf_passed = True
                        break

                    cf_hit = True
                    # If we have cf_clearance but still seeing CF page,
                    # try reloading — the cookie should make it pass
                    if has_cf_cookie and i == 5:
                        log.append(f"   🔄 CF persists despite cookies — trying reload...")
                        try:
                            page.reload(wait_until="domcontentloaded", timeout=15000)
                        except Exception:
                            pass
                    time.sleep(0.5)
                except Exception:
                    break
            else:
                if cf_hit and not cf_passed:
                    log.append(f"   ⚠️  CF blocking {url[:60]} — cookies may be stale, re-run SOLVE CF")
                    return None, None

        time.sleep(0.4)
        return page.content(), page.url

    except PWTimeout:
        log.append(f"   ⏱  Timeout: {url[:70]}")
        return None, None
    except Exception as e:
        log.append(f"   ❌ {navigation_error(url, e)}")
        return None, None


# ── Playwright whole-site crawler ─────────────────────────────────────────


# Corrected implementations of the dynamic extraction/deep-crawl export snippets.
from collections import deque
from html import unescape

VIDEO_EXTRACTION_SCRIPT = DOM_EXTRACTION_SCRIPT


def execute_javascript_on_page(page, url=None, script=VIDEO_EXTRACTION_SCRIPT):
    """Evaluate an extraction function on an already navigated browser page."""
    return page.evaluate(script)

def _extract_structured_video_urls(text, base_url):
    """Handle document-relative attributes, HTML entities and nested JSON-LD."""
    soup = BeautifulSoup(text, "html.parser")
    found = set()
    def add(value):
        if not isinstance(value, str):
            return
        full = normalise_url(unescape(value), base_url)
        if urlparse(full).scheme in ("http", "https") and is_video_url(full):
            found.add(full)
    def walk(value):
        if isinstance(value, str):
            add(value)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
    base = soup.find("base", href=True)
    if base:
        base_url = normalise_url(base["href"], base_url)
    for tag in soup.find_all(True):
        for attr in ("src", "href", "data-src", "data-video", "data-url", "data-file", "data-hd", "data-sd"):
            add(tag.get(attr))
    for tag in soup.find_all("script", type="application/ld+json"):
        try:
            walk(_json_mod.loads(tag.string or tag.get_text()))
        except (ValueError, RecursionError):
            continue
    return sorted(found)


@isolated_browser_thread
def crawl_site_playwright(start_url, mp4_links, log, max_depth, max_pages=150,
                          seed_urls=None, video_only=False, deadline=None, stream_store=None):
    if not PLAYWRIGHT_OK:
        log.append("❌ Playwright not installed")
        return

    stream_store = stream_store if stream_store is not None else []
    base_netloc = urlparse(start_url).netloc
    pw_cookies  = _get_best_pw_cookies(start_url)
    intercepted = []

    visited = set()
    queue   = deque([(start_url, 0)])
    queued = {start_url}
    if seed_urls:
        for u in seed_urls:
            if u and u not in queued and len(queued) < max_pages and max_depth >= 1 and is_same_domain(u, base_netloc):
                queue.append((u, 1))
                queued.add(u)
        log.append(f"🔍 Browser crawl: {len(queue)} URLs queued")
    else:
        log.append(f"🔍 Browser crawl: starting (depth={max_depth}, max={max_pages} pages)")

    # Log cookie status
    has_cf = any(c.get("name") == "cf_clearance" for c in pw_cookies)
    if pw_cookies:
        cf_val = next((c["value"] for c in pw_cookies if c.get("name") == "cf_clearance"), None)
        log.append(f"   🍪 Injecting {len(pw_cookies)} cookies into browser" +
                   (f" (cf_clearance: {cf_val[:20]}...)" if cf_val else ""))
    else:
        log.append("   ℹ️  No CF cookies — use 'Solve CF Challenge' if site blocks")

    pages_done = 0

    with sync_playwright() as pw:
        browser = _make_pw_browser(pw, headless=True)
        ctx     = _make_pw_context(browser, cookies=pw_cookies, headless=True)

        def frame_url(req):
            try:
                return req.frame.url
            except Exception:
                return ""

        def on_request(req):
            record = identify_stream(req.url, source="request", resource_type=req.resource_type,
                                     frame_url=frame_url(req))
            merge_stream(stream_store, record)
            if record and record['kind'] not in ('segment_candidate', 'browser_blob'):
                if req.url not in mp4_links:
                    intercepted.append(req.url)
                    mp4_links.append(req.url)
                    log.append(f"Stream candidate ({record['kind']}): {req.url[:100]}")

        def on_response(response):
            try:
                if response.status >= 400:
                    return
                req = response.request
                record = identify_stream(response.url, response.headers, source="response",
                    resource_type=req.resource_type, frame_url=frame_url(req))
                merge_stream(stream_store, record)
                if record and record['confidence'] == 'response_headers' and record['kind'] != 'segment_candidate':
                    if response.url not in mp4_links:
                        mp4_links.append(response.url)
                        log.append(f"Response stream ({record['kind']}): {response.url[:100]}")
            except Exception:
                pass

        ctx.on("response", on_response)
        ctx.on("request", on_request)
        page = ctx.new_page()

        try:
            while queue and pages_done < max_pages:
                # Time-budget hard stop
                if deadline and time.time() > deadline:
                    log.append(f"⏱️  Time limit reached — stopping browser crawl at {pages_done} pages")
                    break

                url, depth = queue.popleft()
                if url in visited or depth > max_depth:
                    continue
                # Video-only filter — never skip the entry URL itself
                if video_only and url != start_url and should_skip_url(url, video_only=True):
                    continue
                visited.add(url)
                pages_done += 1

                log.append(f"🌐 [{pages_done}] {url}")
                html, final_url = pw_fetch_page(page, url, log, pw_cookies)
                if not html:
                    continue

                _extract_from_raw(html, final_url or url, mp4_links, log)

                for src, frame_base in extract_live_frame_urls(page, VIDEO_EXTRACTION_SCRIPT, log):
                    full = normalise_url(src, frame_base or final_url or url)
                    if full not in mp4_links:
                        mp4_links.append(full)
                        log.append(f"✅ Found DOM ({video_ext(full)}): {full[:100]}")

                collect_stream_snapshot(page, stream_store, log)

                for drm_frame in list(page.frames):
                    if drm_frame.is_detached():
                        continue
                    try:
                        diagnostic = drm_frame.evaluate("() => window.__drmDiagnostics?.snapshot() || null")
                        if diagnostic and (diagnostic.get("events") or diagnostic.get("keySystems")):
                            systems = ", ".join(diagnostic.get("keySystems", [])) or "unspecified key system"
                            encrypted = diagnostic.get("encryptedMediaObserved", False)
                            log.append(f"DRM diagnostics: {systems}; encrypted media observed={encrypted}; events={len(diagnostic.get('events', []))}")
                    except Exception:
                        pass

                if depth < max_depth:
                    try:
                        hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                        for href in hrefs:
                            if not href:
                                continue
                            full = normalise_url(href, final_url or url)
                            if full not in queued and len(queued) < max_pages and urlparse(full).scheme in ("http", "https") and is_same_domain(full, base_netloc):
                                if not should_skip_url(full, video_only=video_only):
                                    queue.append((full, depth + 1))
                                    queued.add(full)
                    except Exception:
                        pass

        finally:
            try:
                browser.close()
            except Exception:
                pass

    log.append(f"🌐 Browser crawl done — {pages_done} page(s) visited")
    if intercepted:
        log.append(f"📡 Interceptor caught {len(intercepted)} video URL(s)")

    return pages_done


# ── Fallback: requests-based crawler (for non-CF sites) ───────────────────
def crawl_site(session, start_url, mp4_links, log, max_depth, max_pages=150,
               seed_urls=None, video_only=False, deadline=None):
    base_netloc = urlparse(start_url).netloc
    visited = set()
    pages   = 0

    queue = deque([(start_url, 0)])
    queued = {start_url}
    if seed_urls:
        for u in seed_urls:
            if u and u not in queued and len(queued) < max_pages and max_depth >= 1 and is_same_domain(u, base_netloc):
                queue.append((u, 1))
                queued.add(u)
        log.append(f"🔍 Crawling {len(queue)} URLs ({len(seed_urls)} from sitemap + entry page)")
    else:
        log.append(f"🔍 Starting site crawl (depth={max_depth}, max={max_pages} pages)")

    while queue and pages < max_pages:
        # Time-budget hard stop
        if deadline and time.time() > deadline:
            log.append(f"⏱️  Time limit reached — stopping crawl at {pages} pages")
            break

        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue
        # Video-only filter — never skip the entry URL itself
        if video_only and url != start_url and should_skip_url(url, video_only=True):
            continue
        visited.add(url)
        pages += 1

        try:
            log.append(f"🔍 [{pages}] {url}")
            try:
                resp = session.get(url, timeout=12) if session is not None else smart_get(url, timeout=12, retries=3)
            except Exception as _e:
                log.append(f"   ⚠️  All strategies failed: {str(_e)[:80]}")
                continue
            final_url = getattr(resp, 'url', url)
            ct = (resp.headers.get("Content-Type", "") if isinstance(resp.headers, dict)
                  else resp.headers.get("Content-Type", ""))

            if resp.status_code >= 400:
                log.append(f"   HTTP {resp.status_code} — skipping")
                continue

            if "text" not in ct and "javascript" not in ct:
                if is_video_url(final_url) and final_url not in mp4_links:
                    mp4_links.append(final_url)
                    log.append(f"✅ Direct video ({video_ext(final_url)}): {final_url}")
                continue

            raw = resp.text
            _extract_from_raw(raw, final_url, mp4_links, log)

            if "html" in ct and depth < max_depth:
                soup = BeautifulSoup(raw, "lxml")
                for tag in soup.find_all("a", href=True):
                    href = tag["href"].strip()
                    if not href or href.startswith("#") or href.startswith("mailto:"):
                        continue
                    full = normalise_url(href, final_url)
                    if full not in queued and len(queued) < max_pages and urlparse(full).scheme in ("http", "https") and is_same_domain(full, base_netloc):
                        if not should_skip_url(full, video_only=video_only):
                            queue.append((full, depth + 1))
                            queued.add(full)
                for tag in soup.find_all("script", src=True):
                    js = normalise_url(tag["src"], final_url)
                    if js not in queued and len(queued) < max_pages and urlparse(js).scheme in ("http", "https") and is_same_domain(js, base_netloc):
                        queue.append((js, depth + 1))
                        queued.add(js)
                for tag in soup.find_all("script"):
                    if tag.string:
                        _extract_from_raw(tag.string, final_url, mp4_links, log, label="inline JS")
                for tag in soup.find_all("iframe", src=True):
                    src = normalise_url(tag["src"], final_url)
                    if src not in queued and len(queued) < max_pages and urlparse(src).scheme in ("http", "https") and is_same_domain(src, base_netloc):
                        queue.append((src, depth + 1))
                        queued.add(src)

        except requests.exceptions.SSLError:
            log.append(f"⚠️  SSL error — retrying: {url}")
            try:
                r2 = smart_get(url, timeout=12, retries=2)
                _extract_from_raw(r2.text, url, mp4_links, log)
            except Exception as e2:
                log.append(f"❌ {url}: {str(e2)[:80]}")
        except requests.exceptions.Timeout:
            log.append(f"⏱  Timeout: {url}")
        except Exception as e:
            log.append(f"❌ {url}: {str(e)[:80]}")

    log.append(f"🔍 Crawl done — {pages} page(s) scanned")
    return pages


# ─── yt-dlp pass ─────────────────────────────────────────────────────────────

def _make_ytdlp_opts(log, cookie_file=None, impersonate=False):
    """Build yt-dlp options dict."""

    class _Log:
        def debug(self, m):
            if not m.startswith("[debug]"):
                log.append(f"   {m[:120]}")
        def warning(self, m):
            if "Cloudflare" not in m and "bot" not in m.lower() and "cookie" not in m.lower():
                log.append(f"⚠️  {m[:120]}")
        def error(self, m):
            # Strip ANSI escape codes from error messages
            clean = re.sub(r'\x1b\[[0-9;]*m', '', m)
            log.append(f"❌ yt-dlp: {clean[:120]}")

    opts = {
        "quiet":            True,
        "no_warnings":      False,
        "logger":           _Log(),
        "skip_download":    True,
        "noplaylist":       False,
        "ignoreerrors":     True,
        "format":           "bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best",
        "retries":          3,
        # Tell generic extractor to impersonate a real browser — bypasses Cloudflare 403
        "extractor_args":   {"generic": {"impersonate": ["chrome"]}},
        "http_headers": {
            "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Fetch-Mode":  "navigate",
        },
    }

    if proxy_url():
        opts["proxy"] = proxy_url()

    # Cookie file (Netscape format — exported from browser extension)
    if cookie_file and __import__("os").path.exists(cookie_file):
        opts["cookiefile"] = cookie_file
        log.append(f"   Using cookie file: {cookie_file}")

    # TLS fingerprint impersonation via curl_cffi
    if impersonate and CURL_CFFI_OK:
        try:
            from yt_dlp.networking.impersonate import ImpersonateTarget
            opts["impersonate"] = ImpersonateTarget("chrome", "124")
        except Exception:
            try:
                from yt_dlp.networking.impersonate import ImpersonateTarget
                opts["impersonate"] = ImpersonateTarget("chrome")
            except Exception:
                pass

    return opts


def _process_ytdlp_info(info, log, mp4_links):
    entries = info.get("entries") or [info]
    if len(entries) > 1:
        log.append(f"📋 Playlist: {info.get('title','?')} ({len(entries)} item(s))")

    added = 0
    for entry in entries:
        if not entry: continue
        title = (entry.get("title") or "untitled")[:70]
        fmts  = entry.get("formats") or []

        best, best_h = None, -1
        for f in fmts:
            if not f.get("url"): continue
            if f.get("vcodec", "none") == "none": continue
            h = f.get("height") or 0
            if f.get("ext") == "mp4" and h > best_h:
                best, best_h = f, h
        if not best:
            for f in fmts:
                if f.get("url") and f.get("vcodec", "none") != "none":
                    best = f; break
        if not best:
            du = entry.get("url", "")
            if du and du not in mp4_links:
                mp4_links.append(du)
                log.append(f"✅ (stream) {title}")
                added += 1
            continue

        furl = best["url"]
        if furl not in mp4_links:
            mp4_links.append(furl)
            h   = best.get("height", "?")
            ext = best.get("ext", "?")
            tbr = best.get("tbr", "?")
            log.append(f"✅ [{h}p|{ext}|{tbr}kbps] {title}")
            added += 1
    return added


# Known streaming platforms that yt-dlp actually supports
STREAMING_DOMAINS = {
    "youtube.com", "youtu.be", "vimeo.com", "dailymotion.com",
    "facebook.com", "fb.watch", "twitter.com", "x.com",
    "instagram.com", "tiktok.com", "twitch.tv", "reddit.com",
    "bilibili.com", "rumble.com", "odysee.com", "ok.ru",
    "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com",
    "redtube.com", "youporn.com", "tube8.com", "spankbang.com",
    "eporner.com", "thisvid.com", "coub.com", "streamable.com",
    "twitch.tv", "kick.com", "medal.tv", "streamff.com",
    "vm.tiktok.com", "fb.com",
}

def is_streaming_site(url):
    """Return True only for known streaming platforms yt-dlp supports."""
    domain = urlparse(url).netloc.lower().replace("www.", "")
    return any(domain == d or domain.endswith("." + d) for d in STREAMING_DOMAINS)


def run_ytdlp(url, log, mp4_links):
    if not YTDLP_OK:
        log.append("⚠️  yt-dlp not installed — skipping (pip install yt-dlp)")
        return

    # Skip yt-dlp entirely for non-streaming sites — it can't help and just wastes time
    if not is_streaming_site(url):
        log.append("⏭️  yt-dlp: skipping (not a streaming platform — HTML crawler will handle this site)")
        return

    log.append("🤖 yt-dlp: probing streaming URL...")

    def _try(opts_dict, label):
        try:
            with yt_dlp.YoutubeDL(opts_dict) as ydl:
                info = ydl.extract_info(url, download=False)
                if info:
                    return info
        except yt_dlp.utils.DownloadError as e:
            err = re.sub(r'\x1b\[[0-9;]*m', '', str(e))
            if any(k in err for k in ("Cloudflare", "403", "Forbidden", "anti-bot", "bot challenge", "captcha")):
                return "CF"
            if "Unsupported URL" in err or "No video formats" in err:
                return "UNSUPPORTED"
            log.append(f"   [{label}] {err[:130]}")
        except Exception as e:
            log.append(f"   [{label}] {str(e)[:130]}")
        return None

    cookie_file = get_cookie_file()

    # ── Attempt 1: TLS impersonation + cookie file ────────────────────────────
    if CURL_CFFI_OK:
        log.append("   Trying: TLS impersonation" + (" + cookie file" if cookie_file else "") + "...")
        result = _try(_make_ytdlp_opts(log, cookie_file=cookie_file, impersonate=True), "impersonate")
        if result not in (None, "CF", "UNSUPPORTED"):
            log.append("   ✅ Success!")
            _process_ytdlp_info(result, log, mp4_links)
            return
        if result == "UNSUPPORTED":
            log.append("   yt-dlp: unsupported — HTML scraper will handle it")
            return

    # ── Attempt 2: plain + cookie file ───────────────────────────────────────
    log.append("   Trying: plain request" + (" + cookie file" if cookie_file else "") + "...")
    result = _try(_make_ytdlp_opts(log, cookie_file=cookie_file), "plain")
    if result not in (None, "CF", "UNSUPPORTED"):
        log.append("   ✅ Success!")
        _process_ytdlp_info(result, log, mp4_links)
        return
    if result == "UNSUPPORTED":
        log.append("   yt-dlp: unsupported — HTML scraper will handle it")
        return

    # ── All failed ────────────────────────────────────────────────────────────
    log.append("🛡️  yt-dlp blocked (403/Cloudflare). HTML scraper will still run.")
    if not cookie_file:
        log.append("   💡 Upload cookies.txt from your browser to improve success rate")



def _extract_from_raw(text, base_url, mp4_links, log, label="", manifest_store=None, player_store=None):
    """
    Fast video URL extractor — regex-only (8x faster than BS4).
    Also detects JS players and parses m3u8 manifests.
    
    manifest_store: dict to accumulate m3u8 metadata {url: {variants}}
    player_store:   list to accumulate detected player names
    """
    tag_label  = f" ({label})" if label else ""
    found_here = 0
    seen       = set(mp4_links)   # fast O(1) dedup

    def _add(raw_url):
        nonlocal found_here
        raw_url = raw_url.strip().strip("\"'").rstrip("\\,;)")
        if not raw_url:
            return
        full = raw_url if raw_url.startswith("http") else normalise_url(raw_url, base_url)
        if full and is_video_url(full) and full not in seen:
            seen.add(full)
            mp4_links.append(full)
            found_here += 1
            ext = video_ext(full)
            log.append(f"✅ Found{tag_label} ({ext}): {full}")

            # Parse m3u8 manifests inline
            if ext == "m3u8" and manifest_store is not None and full not in manifest_store:
                info = parse_m3u8_manifest(full)
                if info and info.get("variants"):
                    manifest_store[full] = info
                    ladder = " | ".join(
                        f"{v['resolution']}@{v['kbps']}k" for v in info["variants"]
                    )
                    log.append(f"   📊 HLS ladder: {ladder}")

    if "<" in text:
        for structured_url in _extract_structured_video_urls(text, base_url):
            _add(structured_url)
    text = unescape(text).replace(r"\/", "/")

    # ── Pass 1: full https?:// URLs ──────────────────────────────────────────
    for m in _RE_URL.finditer(text):
        _add(m.group(0))

    # ── Pass 2: relative paths in src=/href= attributes ──────────────────────
    for m in _RE_REL.finditer(text):
        _add(m.group(1))

    # ── Pass 3: quoted relative paths in JS objects ───────────────────────────
    for m in _RE_JS.finditer(text):
        _add(m.group(1))

    # ── Pass 4: player detection (once per page, cheap string search) ─────────
    if player_store is not None:
        for name in detect_players(text):
            if name not in player_store:
                player_store.append(name)
                log.append(f"🎮 Player detected: {name}")

    return found_here


# ─── scan runner ──────────────────────────────────────────────────────────────

def scrape_url_for_mp4(url, mp4_links, log, lock,
                       manifest_store=None, player_store=None):
    """
    Fetch one URL and extract video links.
    Uses fast_get (shared pooled session, 5s timeout, no retries).
    """
    try:
        resp = fast_get(url, timeout=5)
        if resp is None:
            return 0
        if resp.status_code >= 400:
            return 0

        ct = (resp.headers.get("Content-Type", "") if isinstance(resp.headers, dict)
              else resp.headers.get("Content-Type", ""))

        if "text" not in ct and "javascript" not in ct:
            if is_video_url(url):
                with lock:
                    if url not in mp4_links:
                        mp4_links.append(url)
                        log.append(f"✅ Direct ({video_ext(url)}): {url}")
                        return 1
            return 0

        raw = resp.text
        tmp_links, tmp_log = [], []

        _extract_from_raw(raw, url, tmp_links, tmp_log,
                          manifest_store=manifest_store,
                          player_store=player_store)

        added = 0
        with lock:
            for full in tmp_links:
                if full not in mp4_links:
                    mp4_links.append(full)
                    added += 1
            log.extend(tmp_log)
        return added
    except Exception:
        return 0


def scrape_sitemap_urls_concurrent(sitemap_urls, mp4_links, log,
                                   max_workers=100, max_urls=5000,
                                   video_only=False, url_cap=None, deadline=None,
                                   scan_id=None):
    """Scrapes sitemap URLs as fast as physically possible. Uses async engine when available."""
    if not sitemap_urls:
        return

    reset_bulk_session()
    all_urls      = list(sitemap_urls)[:max_urls]
    filtered      = [u for u in all_urls if not should_skip_url(u, video_only=video_only)]
    skipped_count = len(all_urls) - len(filtered)
    total         = len(filtered)

    if not filtered:
        log.append("⚠️  All sitemap URLs filtered — try increasing sitemap limit")
        return

    # Apply URL cap (hard stop at N total URLs visited across the whole scan)
    if url_cap is not None and url_cap > 0:
        remaining = max(0, url_cap - getattr(scrape_sitemap_urls_concurrent, '_urls_visited', 0))
        filtered  = filtered[:remaining]
        total     = len(filtered)
        if not filtered:
            log.append(f"🛑 URL cap ({url_cap}) reached — stopping sitemap scrape")
            return

    cookie_dict    = _load_cookie_dict()
    cf_val         = cookie_dict.get("cf_clearance")
    manifest_store = {}
    player_store   = []

    video_tag = " [video-only filter ON]" if video_only else ""
    cap_tag   = f" [cap: {url_cap}]" if url_cap else ""

    # ── Async engine (fastest: all requests fire simultaneously) ────────────────────────
    if AIOHTTP_OK:
        conc = min(total, 100)
        log.append(
            f"⚡ ASYNC: {total} URLs (skipped {skipped_count}){video_tag}{cap_tag} — {conc} concurrent"
            + (f" — CF bypass active" if cf_val else "")
        )
        start = time.time()
        ok = scrape_async(filtered, mp4_links, log, manifest_store, player_store,
                          concurrency=conc, timeout=5, deadline=deadline)
        elapsed = time.time() - start
        if ok:
            rate = total / elapsed if elapsed > 0 else 0
            log.append(f"✅ {total} pages in {elapsed:.1f}s ({rate:.0f} p/s) — {len(mp4_links)} links")
            if manifest_store:
                log.append(f"📊 {len(manifest_store)} HLS manifest(s) parsed")
            if player_store:
                log.append(f"🎮 Players: {', '.join(set(player_store))}")
            return

    # ── Thread pool fallback ─────────────────────────────────────────────────
    log.append(f"🚀 {total} URLs — {max_workers} threads{video_tag}{cap_tag} (pip install aiohttp for 5x faster)")
    lock = threading.Lock()
    done = [0]

    def worker(u):
        if deadline and time.time() > deadline:
            return 0
        n = scrape_url_for_mp4(u, mp4_links, log, lock,
                               manifest_store=manifest_store, player_store=player_store)
        with lock:
            done[0] += 1
            c = done[0]
            # Update live pages_scraped counter in scan_store
            if scan_id and scan_id in scan_store:
                scan_store[scan_id]["pages_scraped"] = c
            if c % 200 == 0 or c == total:
                pct = c * 100 // total if total else 0
                log.append(f"   ⚡ {c:,}/{total:,} ({pct}%) scraped — {len(mp4_links)} video link(s) found")
        return n

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        list(ex.map(worker, filtered))

    log.append(f"✅ Done — {done[0]} pages, {len(mp4_links)} links")
    if manifest_store:
        log.append(f"📊 {len(manifest_store)} HLS manifest(s)")
    if player_store:
        log.append(f"🎮 Players: {', '.join(set(player_store))}")



# ─── Async scraping engine (fastest possible — all requests truly parallel) ────

async def _async_fetch_one(session, url, semaphore, mp4_links, lock,
                           manifest_store, player_store, done_counter, total):
    """Fetch one URL asynchronously — zero thread overhead."""
    async with semaphore:
        try:
            async with session.get(url, allow_redirects=True) as resp:
                if resp.status >= 400:
                    return 0
                ct = resp.headers.get("Content-Type", "")
                if "text" not in ct and "javascript" not in ct:
                    if is_video_url(url):
                        async with lock:
                            if url not in mp4_links:
                                mp4_links.append(url)
                        return 1
                    return 0
                # Read with size limit (avoid downloading huge files)
                try:
                    text = await resp.text(errors="ignore")
                except Exception:
                    return 0
        except Exception:
            return 0

    # Extraction is CPU-bound — do it outside semaphore
    tmp_links, tmp_log = [], []
    _extract_from_raw(text, url, tmp_links, tmp_log,
                      manifest_store=manifest_store, player_store=player_store)

    async with lock:
        added = 0
        for full in tmp_links:
            if full not in mp4_links:
                mp4_links.append(full)
                added += 1
        done_counter[0] += 1
        return added


async def _async_scrape_all(urls, mp4_links, log, manifest_store, player_store,
                            concurrency=500, timeout=5, deadline=None):
    """
    Fire ALL requests concurrently using aiohttp.
    concurrency=500 means up to 500 simultaneous connections.
    DNS is cached. TCP keepalive reuses connections.
    Stops early if deadline (unix timestamp) is exceeded.
    """
    cookie_dict = _load_cookie_dict()
    cookies     = cookie_dict if cookie_dict else None

    connector = _aiohttp.TCPConnector(
        limit=concurrency,
        limit_per_host=min(concurrency, 100),
        ssl=False,
        ttl_dns_cache=300,
        use_dns_cache=True,
        keepalive_timeout=30,
        enable_cleanup_closed=True,
        force_close=False,
    )
    hdrs = {
        "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    }
    to      = _aiohttp.ClientTimeout(total=timeout, connect=3)
    lock    = asyncio.Lock()
    sema    = asyncio.Semaphore(concurrency)
    done    = [0]
    total   = len(urls)

    async with _aiohttp.ClientSession(
        connector=connector,
        headers=hdrs,
        timeout=to,
        cookies=cookies,
        skip_auto_headers=["Content-Type"],
        connector_owner=True,
    ) as session:

        tasks = [
            _async_fetch_one(session, url, sema, mp4_links, lock,
                             manifest_store, player_store, done, total)
            for url in urls
        ]

        # Fire all tasks — progress reported every 500 completions
        completed = 0
        _tasks = [asyncio.ensure_future(t) for t in tasks]
        for coro in asyncio.as_completed(_tasks):
            # Hard time-budget check — cancel remaining if deadline passed
            if deadline and time.time() > deadline:
                log.append(f"⏱️  Time limit reached — stopping async engine ({completed}/{total} done)")
                for _t in _tasks:
                    if not _t.done():
                        _t.cancel()
                break
            try:
                await coro
            except Exception:
                pass
            completed += 1
            if completed % 500 == 0 or completed == total:
                pct = completed * 100 // total
                log.append(f"   ⚡ {completed}/{total} ({pct}%) — {len(mp4_links)} links")


def scrape_async(urls, mp4_links, log, manifest_store, player_store,
                 concurrency=500, timeout=5, deadline=None):
    """
    Run the async scraper in a new event loop (called from Flask thread).
    This is the FASTEST possible scraping — all requests fire simultaneously.
    """
    if proxy_url() or not AIOHTTP_OK:
        return False

    try:
        # Create fresh event loop for this scrape
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(
                _async_scrape_all(urls, mp4_links, log, manifest_store,
                                  player_store, concurrency, timeout, deadline)
            )
        finally:
            loop.close()
        return True
    except Exception as e:
        log.append(f"   ⚠️  Async engine error: {str(e)[:80]}")
        return False


def _check_deadline(deadline, log, label=""):
    """Return True if the scan deadline has been exceeded."""
    if deadline and time.time() > deadline:
        log.append(f"⏱️  Time limit reached{(' — ' + label) if label else ''} — stopping early")
        return True
    return False


"""Development source embedded into app.py; not required at runtime."""
"""Development source embedded into app.py; not required at runtime."""
"""Development source embedded into app.py; not required at runtime."""
"""Development source embedded into app.py; not required at runtime."""
"""Development source embedded into app.py; not required at runtime."""
"""Development source embedded into app.py; not required at runtime."""
"""Development source embedded into app.py; not required at runtime."""
"""Development source embedded into app.py; not required at runtime."""
DEEP_RECOGNITION_SCRIPT = '() => {\n    // Optional read-only pass. Does not execute script strings, click controls,\n    // change player state or issue additional network requests.\n    if (!window.__sourceStudioDeep) {\n        const records = new Map(), parsed = new WeakMap();\n        const mediaExtension = /\\.(?:mp4|webm|mkv|mov|m4v|m3u8|mpd|m4s|ts|mp3|aac|ogg)(?:[?#]|$)/i;\n        let parseCount = 0, remainingText = 1000000;\n        function add(value, base, source, mime=\'\', explicit=false) {\n            if (typeof value!==\'string\' || !value.trim() || value.length>8192 || records.size>=600) return;\n            try {\n                const url=new URL(value,base);\n                if (!/^https?:$/.test(url.protocol) || /\\.(?:drmkey)(?:[?#]|$)/i.test(url.href)) return;\n                if (!explicit && !mediaExtension.test(url.href)) return;\n                url.hash=\'\';\n                records.set(url.href,{url:url.href,source,mime});\n            } catch (_) {}\n        }\n        function json(value,base,source) {\n            if (typeof value!==\'string\' || value.length>150000) return;\n            const text=value.trim();\n            try {\n                const queue=[{value:JSON.parse(text),key:\'\',depth:0,mime:\'\'}];\n                let count=0;\n                while(queue.length && count++<3000) {\n                    const item=queue.pop(),node=item.value;\n                    if(item.depth>15)continue;\n                    if(typeof node===\'string\') {\n                        const explicit=/^(contenturl|videourl|audiourl|playbackurl|streamurl|hls|dash|manifesturl)$/i.test(item.key) ||\n                            (/^(src|file|url)$/i.test(item.key) && /^(video|audio)\\//i.test(item.mime));\n                        add(node,base,source,item.mime,explicit);\n                    } else if(Array.isArray(node)) {\n                        for(const child of node.slice(0,100))queue.push({...item,value:child,depth:item.depth+1});\n                    } else if(node && typeof node===\'object\') {\n                        const mime=typeof (node.mimeType||node.type)===\'string\'?(node.mimeType||node.type):item.mime;\n                        for(const [key,child] of Object.entries(node).slice(0,100)) {\n                            if(/token|secret|password|license|drm|key|image|poster|thumbnail/i.test(key))continue;\n                            queue.push({value:child,key:key.replaceAll(\'_\',\'\'),depth:item.depth+1,mime});\n                        }\n                    }\n                }\n            } catch (_) {}\n        }\n        function inspect(el,base) {\n            const config=[\'data-config\',\'data-setup\',\'data-player\',\'data-sources\',\'data-options\'];\n            const texts=[];\n            for(const attr of config) {\n                const value=el.getAttribute(attr);\n                if(value && value.length<=150000)texts.push([attr,value]);\n            }\n            if(el.tagName===\'SCRIPT\' && el.textContent.length<=150000)texts.push([\'script\',el.textContent]);\n            const signature=texts.map(([name,value])=>name+\':\'+value).join(\'\\n\');\n            if(signature && parsed.get(el)!==signature && signature.length<=remainingText && parseCount<300) {\n                remainingText-=signature.length;\n                parsed.set(el,signature); parseCount++;\n                for(const [name,text]of texts) {\n                    json(text,base,\'deep_config\');\n                    if(name!==\'script\' && /^[A-Za-z0-9+/=\\s]+$/.test(text) && text.length<50000) {\n                        try {json(atob(text),base,\'deep_encoded_config\')}catch(_){}\n                    }\n                    // Decode JSON/JS escaped URL syntax without evaluating code.\n                    const normalized=text.replace(/\\\\u002[fF]/g,\'/\').replace(/\\\\\\//g,\'/\').replace(/\\\\u0026/gi,\'&\');\n                    const urls=normalized.match(/https?:\\/\\/[^\\s"\'<>\\\\]{1,2048}/g)||[];\n                    for(const url of urls.slice(0,100))add(url,base,\'deep_script\');\n                }\n            }\n            for(const attr of [\'data-hls\',\'data-dash\',\'data-stream\',\'data-video-src\',\'data-mp4\']) {\n                const value=el.getAttribute(attr);\n                const mime=attr===\'data-hls\'?\'application/vnd.apple.mpegurl\':attr===\'data-dash\'?\'application/dash+xml\':\'\';\n                add(value,base,\'deep_attribute\',mime,true);\n            }\n            if(el.tagName===\'LINK\' && /^(preload|prefetch)$/i.test(el.rel))add(el.href,base,\'resource_hint\');\n            if(el.tagName===\'META\' && /^(og:video(?::url|:secure_url)?|twitter:player:stream)$/i.test(el.getAttribute(\'property\')||el.name||\'\'))\n                add(el.content,base,\'media_metadata\',\'\',true);\n        }\n        window.__sourceStudioDeep={snapshot(){\n            remainingText=1000000;\n            const roots=[document],seen=new Set();let nodes=0;\n            while(roots.length && nodes<12000) {\n                const root=roots.pop();if(seen.has(root))continue;seen.add(root);\n                const walker=document.createTreeWalker(root,NodeFilter.SHOW_ELEMENT);let el;\n                while((el=walker.nextNode()) && nodes++<12000) {\n                    inspect(el,el.baseURI?.startsWith(\'http\')?el.baseURI:document.baseURI);\n                    if(el.shadowRoot)roots.push(el.shadowRoot);\n                    if(el.tagName===\'TEMPLATE\' && el.content)roots.push(el.content);\n                }\n            }\n            for(const entry of performance.getEntriesByType(\'resource\').slice(-1000))add(entry.name,document.baseURI,\'deep_resource\');\n            return {sources:[...records.values()],nodes_scanned:nodes,configs_parsed:parseCount,capped:nodes>=12000||records.size>=600};\n        }};\n    }\n    return window.__sourceStudioDeep.snapshot();\n}\n'

"""Development source embedded into app.py; not required at runtime."""
from dataclasses import dataclass
import heapq
from contextlib import closing
from contextlib import contextmanager
from xml.etree import ElementTree


@dataclass(frozen=True)
class DiscoveryPlan:
    pages: int = 80
    depth: int = 3
    workers: int = 3
    browser_pages: int = 8
    dwell_ms: int = 1800
    seconds: int = 120
    validate: bool = True
    sitemap: bool = True
    browser: bool = True
    attempt_playback: bool = True
    deep_js: bool = False


class DiscoveryEngine:
    """One bounded frontier, a media registry, and separate render/verify budgets."""
    def __init__(self, scan_id, url, plan):
        self.r = scan_store[scan_id]
        self.url, self.plan = url, plan
        self.deadline = time.monotonic() + plan.seconds
        self.frontier, self.queued, self.visited = [], set(), set()
        self.render_targets, self.media = [], set(self.r['mp4_links'])
        self.sequence = 0
        self.connections=threading.local()
        self.sessions=[]
        self.sessions_lock=threading.Lock()
        self.r.update(phase='discovering', queue_size=0, browser_pages=0,
            requests_failed=0, blocked_pages=0, api_responses=0, started_at=time.time(),
            limits={'pages':plan.pages, 'depth':plan.depth, 'browser_pages':plan.browser_pages,
                    'seconds':plan.seconds}, coverage_notes=[])

    def active(self):
        return not self.r.get('cancel_requested') and not self.r.get('rate_limited') and time.monotonic() < self.deadline

    def emit(self, message):
        self.r['log'].append(message)

    @contextmanager
    def pooled_connection(self):
        session=getattr(self.connections,'session',None)
        if session is None:
            session=get_api_session()
            self.connections.session=session
            with self.sessions_lock:self.sessions.append(session)
        yield session

    def close_connections(self):
        with self.sessions_lock:
            sessions,self.sessions=self.sessions,[]
        for session in sessions:session.close()

    def scope(self, url):
        try:
            return _api_origin(url) == _api_origin(self.url)
        except ValueError:
            return False

    def enqueue(self, url, depth=0, kind='page'):
        url = normalise_url(url, self.url)
        if not self.scope(url) or url in self.queued or depth > self.plan.depth:
            return
        if len(self.queued) >= self.plan.pages * 8:
            return
        path = urlparse(url).path.lower()
        if re.search(r'\.(?:png|jpe?g|gif|svg|css|woff2?|pdf|zip|ico)$', path):
            return
        if any(word in path for word in ('/logout', '/signout', '/delete')):
            return
        priority = depth * 10 - (5 if re.search(r'video|watch|play|episode|stream|/api/', path) else 0)
        self.sequence += 1
        heapq.heappush(self.frontier, (priority, self.sequence, url, depth, kind))
        self.queued.add(url)

    def add(self, record):
        if not record:
            return
        merge_stream(self.r['stream_diagnostics'], record)
        if record['kind'] not in ('segment_candidate', 'browser_blob', 'mse_source', 'mse_buffer'):
            url = record['url']
            if url not in self.media and len(self.media) < 5000:
                self.media.add(url)
                self.r['mp4_links'].append(url)

    def fetch(self, url):
        """Workers own sessions; redirects and decoded body sizes are bounded."""
        if not self.active():
            return {'url':url, 'skip':True}
        try:
            with self.pooled_connection() as session:
                current = url
                for _ in range(5):
                    if not self.scope(current):
                        return {'url':url, 'error':'Cross-origin page redirect skipped'}
                    with closing(session.get(current, stream=True, allow_redirects=False,
                            timeout=min(10, max(1, self.deadline-time.monotonic())))) as response:
                        status, headers = response.status_code, dict(response.headers)
                        if status in (301, 302, 303, 307, 308):
                            current = normalise_url(headers.get('Location', ''), current)
                            continue
                        content_type = response.headers.get('Content-Type', '').lower()
                        record = identify_stream(current, headers, source='response', frame_url=url)
                        # Do not download full media bodies while discovering links.
                        if record and record['confidence'] == 'response_headers':
                            return {'url':current, 'status':status, 'headers':headers, 'record':record, 'text':''}
                        if status >= 400:
                            return {'url':current, 'status':status, 'headers':headers, 'text':''}
                        body = bytearray()
                        for chunk in response.iter_content(65536):
                            if not self.active():
                                return {'url':url, 'skip':True}
                            body.extend(chunk)
                            if len(body) > 2*1024*1024:
                                return {'url':url, 'error':'Page exceeded 2 MiB discovery limit'}
                        return {'url':current, 'status':status, 'headers':headers,
                            'text':body.decode(response.encoding or 'utf-8', errors='replace')}
                return {'url':url, 'error':'Redirect limit reached'}
        except Exception as exc:
            return {'url':url, 'error':api_failure_message(exc, 'page discovery')}

    def consume(self, item, depth, kind):
        if item.get('skip'):
            return
        self.r['pages_scraped'] += 1
        url = item['url']
        if item.get('error'):
            self.r['requests_failed'] += 1
            self.emit(item['error'])
            return
        status = item['status']
        if status in (401, 403, 429):
            self.r['blocked_pages'] += 1
            self.emit(f'HTTP {status}: access unavailable; no repeated retries.')
            if status == 429:
                self.r['rate_limited'] = True
            return
        if status >= 400:
            self.r['requests_failed'] += 1
            return
        self.add(item.get('record'))
        text = item.get('text', '')
        if not text:
            return
        reason = access_block_reason(text)
        if reason:
            self.r['blocked_pages'] += 1
            self.emit(reason)
            return
        try:
            payload = _json_mod.loads(text)
        except (ValueError, RecursionError):
            payload = None
        if payload is not None:
            self.r['api_responses'] += 1
            for record in extract_api_media(payload, url):
                self.add(record)
            following = api_next_url(payload, url, item['headers'].get('Link', ''))
            if following:
                self.enqueue(following, depth, 'api')
        raw_links = []
        _extract_from_raw(text.replace(r'\u002f', '/').replace(r'\u002F', '/'), url,
            raw_links, [], player_store=self.r['player_store'])
        for link in raw_links:
            self.add(identify_stream(link, source='page_source', frame_url=url))
        if kind in ('sitemap', 'robots'):
            if kind == 'robots':
                for match in re.finditer(r'(?im)^sitemap:\s*(https?://\S+)', text):
                    self.enqueue(match.group(1), 0, 'sitemap')
            else:
                try:
                    if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
                        return
                    root = ElementTree.fromstring(text)
                    child_kind = 'sitemap' if root.tag.endswith('sitemapindex') else 'page'
                    for element in root.iter():
                        if element.tag.split('}')[-1] == 'loc' and element.text:
                            self.enqueue(element.text.strip(), 0 if child_kind == 'sitemap' else 1, child_kind)
                            self.r['sitemap_size'] += 1
                except ElementTree.ParseError:
                    pass
            return
        soup = BeautifulSoup(text, 'html.parser')
        if kind == 'page' and '<' in text:
            self.render_targets.append(url)
        for tag in soup.find_all('script', type=re.compile(r'application/(?:ld\+)?json', re.I)):
            try:
                for record in extract_api_media(_json_mod.loads(tag.get_text()), url):
                    self.add(record)
            except (ValueError, RecursionError):
                pass
        for tag in soup.find_all(['a', 'iframe', 'script']):
            target = tag.get('href') if tag.name == 'a' else tag.get('src')
            if target:
                full = normalise_url(target, url)
                record = identify_stream(full, source='dom', frame_url=url)
                if record:
                    self.add(record)
                elif tag.name == 'script':
                    self.enqueue(full, depth, 'script')
                else:
                    self.enqueue(full, depth+1, 'page')
        # Only explicit GET-like API references; never execute arbitrary JS or POSTs.
        for match in re.finditer(r'''(?:fetch|axios\.get)\s*\(\s*["']([^"']+)["']''', text):
            candidate = normalise_url(match.group(1), url)
            if '/api/' in urlparse(candidate).path:
                self.enqueue(candidate, depth, 'api')

    def render(self):
        if not PLAYWRIGHT_OK:
            self.r['coverage_notes'].append('Browser rendering unavailable: install Playwright and Chromium.')
            return
        self.r['phase'] = 'rendering'
        targets = list(dict.fromkeys([self.url] + self.render_targets))[:self.plan.browser_pages]
        with sync_playwright() as pw:
            browser = _make_pw_browser(pw, headless=True)
            try:
                context = _make_pw_context(browser, cookies=_get_best_pw_cookies(self.url))
                def observed(response):
                    if response.status == 429:
                        self.r['rate_limited'] = True
                    if not self.active() or response.status >= 400:
                        return
                    try:
                        request = response.request
                        try:
                            frame = request.frame.url
                        except Exception:
                            frame = ''
                        self.add(identify_stream(response.url, response.headers, 'browser_response', request.resource_type, frame))
                        mime = response.headers.get('content-type', '').lower()
                        size = int(response.headers.get('content-length', '0'))
                        if 'json' in mime and 0 < size <= 512000 and self.r['api_responses'] < 100:
                            body = response.body()
                            if len(body) <= 512000:
                                for record in extract_api_media(_json_mod.loads(body), response.url):
                                    self.add(record)
                                self.r['api_responses'] += 1
                    except Exception:
                        pass
                context.on('response', observed)
                page = context.new_page()
                for target in targets:
                    if not self.active():
                        break
                    if self.scope(target):
                        self.emit(f'Rendering page {self.r["browser_pages"]+1}: observing DOM, APIs and media requests.')
                        try:
                            response = page.goto(target, wait_until='domcontentloaded',
                                timeout=min(12000, max(1000, int((self.deadline-time.monotonic())*1000))))
                            if response and response.status in (401, 403, 429):
                                self.r['blocked_pages'] += 1
                                if response.status == 429:
                                    self.r['rate_limited'] = True
                                continue
                            if access_block_reason(page.content()):
                                self.r['blocked_pages'] += 1
                                continue
                            for _ in range(3):
                                if not self.active():
                                    break
                                page.evaluate('window.scrollBy(0, Math.min(window.innerHeight, 900))')
                                for frame in list(page.frames):
                                    if frame.is_detached():
                                        continue
                                    try:
                                        report=frame.evaluate('(play) => window.__playerDiscovery?.sample(play) || null', self.plan.attempt_playback)
                                        if report:
                                            for player in report['players']:
                                                if player not in self.r['player_store']:
                                                    self.r['player_store'].append(player)
                                            for source in report['sources']:
                                                record=identify_stream(source['url'],{'content-type':source.get('mime','')},
                                                    source='player_adapter:'+source['adapter'],frame_url=frame.url)
                                                if record is None:
                                                    record={'url':source['url'],'kind':'api_media_candidate','file_type':'unknown',
                                                        'mime':source.get('mime',''),'source':'player_adapter','frame_url':frame.url,
                                                        'confidence':'candidate','download_candidate':False,'evidence':[source['adapter']]}
                                                self.add(record)
                                            self.r.setdefault('playback_observations',{})[frame.url]=report['playback']
                                    except Exception:
                                        pass
                                page.wait_for_timeout(min(self.plan.dwell_ms//3, max(1, int((self.deadline-time.monotonic())*1000))))
                            for value, base in extract_live_frame_urls(page, VIDEO_EXTRACTION_SCRIPT, self.r['log']):
                                self.add(identify_stream(normalise_url(value, base or target), source='rendered_dom', frame_url=base))
                            collect_stream_snapshot(page, self.r['stream_diagnostics'], self.r['log'])
                            for frame in list(page.frames):
                                if frame.is_detached():
                                    continue
                                try:
                                    if self.plan.deep_js:
                                        try:
                                            deep=frame.evaluate(DEEP_RECOGNITION_SCRIPT)
                                            self.r.setdefault('deep_recognition',{})[frame.url]={k:v for k,v in deep.items() if k!='sources'}
                                            for source in deep['sources']:
                                                record=identify_stream(source['url'],{'content-type':source.get('mime','')},source=source['source'],frame_url=frame.url)
                                                if record is None:
                                                    record={'url':source['url'],'kind':'api_media_candidate','file_type':'unknown',
                                                        'mime':source.get('mime',''),'source':source['source'],'frame_url':frame.url,
                                                        'confidence':'candidate','download_candidate':False,'evidence':[source['source']]}
                                                record['confidence']='candidate'
                                                self.add(record)
                                        except Exception:
                                            self.emit("Optional deep JS pass unavailable; standard discovery continues.")
                                    final_report=frame.evaluate('() => window.__playerDiscovery?.sample(false) || null')
                                    if final_report:
                                        self.r.setdefault('playback_observations',{})[frame.url]=final_report['playback']
                                        for source in final_report['sources']:
                                            record=identify_stream(source['url'],{'content-type':source.get('mime','')},
                                                source='player_adapter:'+source['adapter'],frame_url=frame.url)
                                            self.add(record)
                                    frame.evaluate('() => window.__playerDiscovery?.finish()')
                                    documents = frame.evaluate('() => window.__apiDocuments?.snapshot() || []')
                                    for document in documents:
                                        for record in extract_api_media(_json_mod.loads(document['text']), document['url']):
                                            self.add(record)
                                    drm = frame.evaluate('() => window.__drmDiagnostics?.snapshot() || null')
                                    if drm and (drm.get('events') or drm.get('keySystems')):
                                        self.r.setdefault('drm_diagnostics', []).append({'page':target, **drm})
                                except Exception:
                                    pass
                            for href in page.eval_on_selector_all('a[href]', 'els => els.slice(0,500).map(e=>e.href)'):
                                self.enqueue(href, 1)
                        except Exception as exc:
                            self.r['requests_failed'] += 1
                            self.emit(navigation_error(target, exc))
                        finally:
                            self.r['browser_pages'] += 1
                    if self.r.get('rate_limited'):
                        break
            finally:
                browser.close()

    def inspect_manifests(self):
        self.r['phase'] = 'manifests'
        manifests = [r for r in self.r['stream_diagnostics'] if r['kind'] in ('hls_manifest','dash_manifest')][:12]
        inspected=set()
        for record in manifests:
            if not self.active() or len(inspected)>=20:
                break
            if record['url'] in inspected:
                continue
            inspected.add(record['url'])
            try:
                with closing(get_api_session()) as session:
                    with closing(session.get(record['url'],stream=True,timeout=min(5,max(1,self.deadline-time.monotonic())))) as response:
                        if response.status_code >= 400:
                            continue
                        body = bytearray()
                        for chunk in response.iter_content(32768):
                            body.extend(chunk)
                            if len(body) > 512000 or not self.active():
                                break
                        if len(body)>512000 or not self.active():
                            continue
                        text=body.decode('utf-8-sig',errors='replace')
                        base=response.url
                if record['kind']=='hls_manifest' and text.lstrip().startswith('#EXTM3U'):
                    ladder=parse_m3u8_manifest(base,text=text)
                    if ladder:
                        self.r['manifest_store'][base]=ladder
                        for variant in ladder.get('variants',[]):
                            candidate=identify_stream(normalise_url(variant['uri'],base),
                                {'content-type':'application/vnd.apple.mpegurl'},source='hls_variant',frame_url=base)
                            if candidate:
                                candidate['quality']=variant.get('resolution', '')
                            self.add(candidate)
                            if candidate and len(manifests)<40:
                                manifests.append(candidate)
                    if M3U8_OK:
                        for rendition in _m3u8_lib.loads(text).media[:40]:
                            if rendition.uri:
                                candidate=identify_stream(normalise_url(rendition.uri,base),
                                    {'content-type':'application/vnd.apple.mpegurl'},source='hls_rendition',frame_url=base)
                                self.add(candidate)
                                if candidate and len(manifests)<40:
                                    manifests.append(candidate)
                    if '#EXT-X-KEY:' in text and 'METHOD=NONE' not in text:
                        self.r.setdefault('drm_diagnostics',[]).append({'page':base,'signal':'HLS encryption declared; not proof of a particular DRM system'})
                elif record['kind']=='dash_manifest' and '<!DOCTYPE' not in text.upper() and '<!ENTITY' not in text.upper():
                    root=ElementTree.fromstring(text)
                    if any(el.tag.split('}')[-1]=='ContentProtection' for el in root.iter()):
                        self.r.setdefault('drm_diagnostics',[]).append({'page':base,'signal':'DASH ContentProtection declared'})
                    self.r['manifest_store'][base]={'type':'DASH','representations':[
                        {key:value for key,value in el.attrib.items() if key in ('id','bandwidth','width','height','codecs','mimeType')}
                        for el in root.iter() if el.tag.split('}')[-1]=='Representation'][:100]}
                    stack=[(root,base,False)]
                    nodes=0
                    while stack and nodes<5000:
                        element,parent,segmented=stack.pop();nodes+=1
                        segmented=segmented or any(child.tag.split('}')[-1] in ('SegmentTemplate','SegmentList','SegmentBase') for child in element)
                        urls=[child.text.strip() for child in element if child.tag.split('}')[-1]=='BaseURL' and child.text]
                        current=normalise_url(urls[0],parent) if urls else parent
                        if element.tag.split('}')[-1]=='Representation' and urls and not segmented:
                            candidate=identify_stream(current,source='dash_representation',frame_url=base)
                            self.add(candidate)
                        stack.extend((child,current,segmented) for child in element if child.tag.split('}')[-1] not in ('BaseURL','SegmentTemplate','SegmentList','SegmentBase'))
            except Exception:
                self.emit('Manifest metadata unavailable; source URL retained.')

    def discover(self, until=None):
        self.r['phase'] = 'discovering'
        with ThreadPoolExecutor(max_workers=self.plan.workers) as pool:
            while self.frontier and self.r['pages_scraped'] < self.plan.pages and self.active() and (until is None or time.monotonic() < until):
                batch = []
                while self.frontier and len(batch) < min(self.plan.workers, self.plan.pages-self.r['pages_scraped']):
                    _, _, url, depth, kind = heapq.heappop(self.frontier)
                    if url not in self.visited:
                        self.visited.add(url)
                        batch.append((pool.submit(self.fetch, url), depth, kind))
                for future, depth, kind in batch:
                    self.consume(future.result(), depth, kind)
                self.r['queue_size'] = len(self.frontier)
                if self.r.get('rate_limited'):
                    break

        self.close_connections()

    def run(self):
        self.enqueue(self.url)
        if self.plan.sitemap:
            origin = urlunparse((*urlparse(self.url)[:2], '', '', '', ''))
            self.enqueue(origin+'/robots.txt', 0, 'robots')
            self.enqueue(origin+'/sitemap.xml', 0, 'sitemap')
        self.emit('Discovery engine v2: bounded page frontier → rendered DOM/API observation → media verification.')
        try:
            if YTDLP_OK and is_streaming_site(self.url) and self.active():
                self.emit('Checking the platform extractor for available media formats.')
                try:
                    options=_make_ytdlp_opts(self.r['log'], get_cookie_file())
                    options.update(socket_timeout=6, retries=0, extractor_retries=0,
                        noplaylist=True, playlistend=10,
                        match_filter=lambda info, **kwargs: None if self.active() else 'Scan budget ended')
                    with yt_dlp.YoutubeDL(options) as extractor:
                        info=extractor.extract_info(self.url,download=False)
                        temporary=[]
                        if info:
                            _process_ytdlp_info(info,self.r['log'],temporary)
                        for url in temporary:
                            self.add(identify_stream(url,source='platform_extractor',frame_url=self.url))
                except Exception:
                    self.emit('Platform extractor unavailable; continuing page and browser discovery.')
            self.discover(time.monotonic() + self.plan.seconds * .45)
            if self.active() and self.plan.browser and not self.r.get('rate_limited'):
                try:
                    self.render()
                except Exception as exc:
                    self.r['coverage_notes'].append('Browser stage unavailable; static/API results retained.')
                    self.emit(navigation_error(self.url, exc))
                self.discover()
            if self.active() and not self.r.get('rate_limited'):
                self.inspect_manifests()
            if self.r.get('cancel_requested'):
                self.r['status'] = 'cancelled'
            elif self.r.get('rate_limited'):
                self.r['status'] = 'rate_limited'
            else:
                if self.active() and self.plan.validate:
                    self.r['phase'] = 'validating'
                    for url in list(self.r['mp4_links'])[:1000]:
                        if not self.active():
                            break
                        _, code, ok, reason = check_link(url, timeout=min(5, max(1,self.deadline-time.monotonic())), verify_video_content=True)
                        self.r['validation_results'][url] = {'code':code, 'ok':ok, 'reason':reason}
                        if not ok:
                            self.r['broken_links'].append(url)
                    self.r['mp4_links'] = [url for url in self.r['mp4_links'] if url not in self.r['broken_links']]
                self.r['status'] = 'cancelled' if self.r.get('cancel_requested') else 'done'
            if self.frontier:
                self.r['coverage_notes'].append(f'{len(self.frontier)} queued URLs remain beyond the configured limits.')
            if time.monotonic() >= self.deadline:
                self.r['coverage_notes'].append('Time budget reached; results collected so far are retained.')
            if self.r['blocked_pages']:
                self.r['coverage_notes'].append('Some pages denied access. Extraction cannot establish complete coverage.')
            self.r['phase'] = 'finished'
            self.emit(f"Finished: {len(self.r['mp4_links'])} media candidates, {self.r['pages_scraped']} responses, {self.r['browser_pages']} rendered pages.")
        except Exception as exc:
            self.r['status'] = 'error'
            self.emit(api_failure_message(exc, self.r['phase']))
        finally:
            self.close_connections()


def run_scan(scan_id, url, max_depth, skip_validate, max_sitemap_urls=5000,
             scan_mode='moderate', url_cap=0, video_only=False):
    r = scan_store[scan_id]
    plan = DiscoveryPlan(pages=r.get('page_limit', url_cap or 80), depth=max_depth,
        workers=r.get('concurrency', 3), browser_pages=r.get('browser_limit', 8),
        dwell_ms=r.get('dwell_ms', 1800), seconds=r['time_limit_s'],
        validate=not skip_validate, sitemap=r.get('discover_sitemap', True),
        browser=r.get('render_browser', True))
    plan = DiscoveryPlan(**{**plan.__dict__, 'attempt_playback':r.get('attempt_playback', True), 'deep_js':r.get('deep_js', False)})
    DiscoveryEngine(scan_id, url, plan).run()



def extract_api_media(payload, base_url, max_nodes=50000):
    """Iterative, bounded JSON traversal with media-key and MIME context."""
    found = {}
    stack = [(payload, '', 0, '')]
    nodes = 0
    media_keys = {'contenturl', 'playbackurl', 'videourl', 'audiourl', 'streamurl',
                  'hls', 'dash', 'hlsurl', 'dashurl', 'manifesturl'}
    while stack and nodes < max_nodes and len(found) < 1000:
        value, key, depth, mime = stack.pop()
        nodes += 1
        if depth > 25:
            continue
        if isinstance(value, dict):
            local_mime = str(value.get('mimeType') or value.get('mime_type') or value.get('type') or mime or '')[:200]
            typed = local_mime.lower().startswith(('video', 'audio')) or local_mime.lower() in MIME_TYPES
            for child_key, child in list(value.items())[:2000]:
                name = str(child_key).lower().replace('_', '')
                # In sources arrays, src/file are media candidates even without
                # extensions. Generic API resource URLs remain unclassified.
                contextual = name in ('src', 'file', 'url') and (typed or key in ('sources', 'streams', 'hls', 'dash', 'playback', 'video', 'audio', 'files', 'renditions', 'formats'))
                stack.append((child, 'contenturl' if contextual else name, depth+1, local_mime))
        elif isinstance(value, list):
            for child in value[:5000]:
                stack.append((child, key, depth+1, mime))
        elif isinstance(value, str) and len(value) <= 8192:
            if key not in media_keys and not re.search(r'\.(mp4|webm|mkv|mov|m4v|m3u8|mpd|mp3|m4s|ts)(?:[?#]|$)', value, re.I):
                continue
            if not value.strip() or value.startswith(('#', 'data:', 'javascript:', 'blob:')):
                continue
            full = normalise_url(value, base_url)
            if urlparse(full).scheme not in ('http', 'https'):
                continue
            mime = mime if '/' in mime else 'application/vnd.apple.mpegurl' if key in ('hls','hlsurl') else 'application/dash+xml' if key in ('dash','dashurl') else ''
            headers = {'content-type': mime} if mime else {}
            record = identify_stream(full, headers, source='api_json', frame_url=base_url)
            if record is None and key in media_keys:
                record = {'url':full, 'kind':'api_media_candidate', 'file_type':'unknown',
                    'mime':mime, 'source':'api_json', 'resource_type':'json', 'frame_url':base_url,
                    'confidence':'candidate', 'download_candidate':False, 'evidence':['API media field']}
            if record:
                found[full] = record
    return list(found.values())


def api_next_url(payload, base_url, link_header=''):
    """Follow explicit next links only, never guess page numbers or cursors."""
    values = []
    if isinstance(payload, dict):
        values.extend(payload.get(k) for k in ('next', 'next_url', 'nextUrl', '@odata.nextLink'))
        for group in ('links', 'pagination', 'paging'):
            block = payload.get(group)
            if isinstance(block, dict):
                values.extend(block.get(k) for k in ('next', 'next_url', 'nextUrl'))
    for match in re.finditer(r'<([^>]+)>\s*;\s*rel=["\']?next(?:["\']|\s|,|$)', link_header, re.I):
        values.append(match.group(1))
    for value in values:
        if isinstance(value, dict):
            value = value.get('href') or value.get('url')
        if isinstance(value, str) and value.strip() and not value.strip().isdigit():
            return normalise_url(value, base_url)
    return None


def _api_origin(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('API URL must be HTTP(S), without embedded credentials')
    return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == 'https' else 80)


def get_api_session():
    """Use one Requests-compatible transport for bounded JSON streaming."""
    session = get_session()
    # Preserve cookie domain/path restrictions when transferring browser cookies.
    cookies = list(_load_pw_cookies())
    for values in _cf_solved_cookies.values():
        cookies.extend(values)
    for cookie in cookies:
        if cookie.get('name') and cookie.get('domain'):
            try:
                session.cookies.set(cookie['name'], cookie.get('value', ''),
                    domain=cookie['domain'], path=cookie.get('path', '/'),
                    secure=bool(cookie.get('secure', False)))
            except (TypeError, ValueError):
                continue
    return session


def api_failure_message(exc, stage):
    """Return useful diagnostics without exception URLs, headers or tokens."""
    if isinstance(exc, requests.exceptions.ProxyError):
        return 'Proxy connection failed. Check the configured proxy address, credentials and availability.'
    if isinstance(exc, requests.exceptions.SSLError):
        return 'TLS certificate verification failed. Check the endpoint certificate and local CA/proxy configuration.'
    if isinstance(exc, requests.exceptions.Timeout):
        return 'API request timed out. Check endpoint availability or reduce the API page limit.'
    if isinstance(exc, requests.exceptions.HTTPError):
        code = exc.response.status_code if exc.response is not None else 'error'
        return f'API returned HTTP {code}. Check the endpoint and its required parameters.'
    if isinstance(exc, requests.exceptions.ConnectionError):
        return 'API connection failed. Check the hostname, DNS, network connection and proxy settings.'
    if isinstance(exc, requests.exceptions.InvalidHeader):
        return 'API headers are invalid. Check the local RIPPER_API_HEADERS_JSON configuration.'
    if isinstance(exc, requests.exceptions.RequestException):
        return f'API transport failed during {stage}. Check the endpoint, network and proxy configuration.'
    if isinstance(exc, TypeError):
        return f'Incompatible data or response type during {stage}. No credentials or response contents were logged.'
    if isinstance(exc, ValueError):
        return str(exc)
    return f'{type(exc).__name__} during {stage}'


def run_api_scan(scan_id, url, max_pages=5, skip_validate=False):
    r = scan_store[scan_id]
    deadline = time.time() + r['time_limit_s']
    stage = 'API configuration'
    try:
        origin = _api_origin(url)
        import os
        auth_headers = _json_mod.loads(os.environ.get('RIPPER_API_HEADERS_JSON', '{}'))
        if not isinstance(auth_headers, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in auth_headers.items()):
            raise ValueError('RIPPER_API_HEADERS_JSON must be a JSON object of header strings')
        if any(k.lower() in ('host', 'content-length', 'connection', 'transfer-encoding') for k in auth_headers):
            raise ValueError('API header configuration contains an unsupported transport header')
        headers = {'Accept':'application/json', **auth_headers}
        visited = set()
        from contextlib import closing
        with closing(get_api_session()) as session:
            current = url
            while current and r['pages_scraped'] < max_pages and time.time() < deadline and not r.get('cancel_requested'):
                if current in visited:
                    r['log'].append('API pagination cycle detected; stopped.')
                    break
                if _api_origin(current) != origin:
                    r['log'].append('API pagination stopped at a different origin; credentials were not forwarded.')
                    break
                visited.add(current)
                # Same-origin redirect checks apply before every authenticated request.
                for redirect in range(6):
                    stage = 'requesting API JSON'
                    response = session.get(current, headers=headers, timeout=min(12, max(1, deadline-time.time())),
                        stream=True, allow_redirects=False)
                    with closing(response):
                        if response.status_code in (301, 302, 303, 307, 308):
                            target = normalise_url(response.headers.get('Location', ''), current)
                            if not response.headers.get('Location') or _api_origin(target) != origin:
                                raise ValueError('API redirect stopped: destination is missing or has a different origin')
                            current = target
                            continue
                        if response.status_code in (401, 403, 429):
                            suffix = ' Respect Retry-After before retrying.' if response.status_code == 429 else ' Check your authorized API access.'
                            r['log'].append(f'API stopped: HTTP {response.status_code}.' + suffix)
                            r['status'] = 'blocked' if response.status_code != 429 else 'rate_limited'
                            return
                        response.raise_for_status()
                        stage = 'reading API response'
                        body = bytearray()
                        for chunk in response.iter_content(65536):
                            if r.get('cancel_requested'):
                                r['status'] = 'cancelled'
                                return
                            body.extend(chunk)
                            if len(body) > 2 * 1024 * 1024:
                                raise ValueError('API response exceeded the 2 MiB limit')
                            if time.time() > deadline:
                                raise ValueError('API time budget reached')
                        try:
                            stage = 'parsing API JSON'
                            payload = _json_mod.loads(body)
                        except (ValueError, UnicodeError):
                            raise ValueError('API response is not valid JSON; no HTML block page was scanned') from None
                        r['pages_scraped'] += 1
                        stage = 'extracting media fields'
                        records = extract_api_media(payload, current)
                        for record in records:
                            merge_stream(r['stream_diagnostics'], record)
                            if record['kind'] != 'segment_candidate' and record['url'] not in r['mp4_links']:
                                r['mp4_links'].append(record['url'])
                        r['log'].append(f"API page {r['pages_scraped']}: {len(records)} media candidate(s).")
                        following = api_next_url(payload, current, response.headers.get('Link', ''))
                        break
                else:
                    raise ValueError('API redirect limit reached')
                current = following
                if current and r['pages_scraped'] < max_pages and time.time() < deadline:
                    time.sleep(min(0.5, max(0, deadline-time.time())))
        if r.get('cancel_requested'):
            r['status'] = 'cancelled'
            return
        if not skip_validate and r['mp4_links'] and deadline-time.time() >= 10:
            # API credentials are deliberately scoped to the API origin's JSON
            # requests; do not automatically send them to returned CDN links.
            r['log'].append('Validating media using existing media sessions; API-only headers are not forwarded to media URLs.')
            r['status'] = 'validating'
            r['phase'] = 'validating'
            stage = 'validating media URLs'
            validate_links(scan_id, verify_video_content=True)
        r['status'] = 'cancelled' if r.get('cancel_requested') else 'done'
        r['phase'] = 'finished'
        r['log'].append(f"API scan complete: {r['pages_scraped']} page(s), {len(r['mp4_links'])} media URL(s).")
    except Exception as exc:
        r['status'] = 'error'
        detail = api_failure_message(exc, stage)
        r['log'].append(f'API scan stopped: {detail}')


# ─── Flask routes ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return HTML_PAGE

@app.route("/start_scan", methods=["POST"])
def start_scan():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error":"Send a JSON object"}), 400
    source_type = data.get("source_type", "website")
    if source_type not in ("website", "api"):
        return jsonify({"error":"Unknown scan source"}), 400
    try:
        url = data.get("url", "").strip()
        if not url:
            raise ValueError("Enter a target URL")
        if "://" not in url:
            url = "https://" + url
        _api_origin(url)
        def number(key, default, low, high):
            return max(low, min(int(data.get(key, default)), high))
        settings = {
            "page_limit":number("page_limit", data.get("url_cap") or 80, 1, 1000),
            "concurrency":number("concurrency", 3, 1, 6),
            "time_limit_s":number("time_limit_s", 120, 20, 900),
            "browser_limit":number("browser_limit", 8, 1, 50),
            "dwell_ms":number("dwell_ms", 1800, 300, 10000),
            "render_browser":bool(data.get("render_browser", True)),
            "attempt_playback":bool(data.get("attempt_playback", True)),
            "deep_js":data.get("deep_js", False) is True,
            "discover_sitemap":bool(data.get("discover_sitemap", True))}
        depth = number("depth", 3, 0, 8)
        api_max_pages = number("api_max_pages", 5, 1, 20)
    except (ValueError, TypeError, AttributeError):
        return jsonify({"error":"Enter a valid HTTP(S) URL and numeric discovery limits; URLs must not contain credentials."}), 400
    if sum(r.get("status") in ("running", "validating") for r in scan_store.values()) >= 2:
        return jsonify({"error":"Two scans are already active. Stop or wait for one before starting another."}), 409
    # Retain recent scan results while bounding long-lived local memory.
    if len(scan_store) >= 50:
        for key, value in list(scan_store.items()):
            if value.get("status") not in ("running", "validating"):
                del scan_store[key]
                break
    scan_id = str(uuid.uuid4())[:12]
    scan_store[scan_id] = {
        "status":"running", "phase":"discovering", "cancel_requested":False,
        "mp4_links":[], "broken_links":[], "validation_results":{},
        "validating":False, "stream_diagnostics":[], "drm_diagnostics":[],
        "manifest_store":{}, "player_store":[], "thumbnail_classifications":{},
        "classifying_thumbnails":False, "source_type":source_type,
        "scan_mode":data.get("scan_mode", "moderate"), "pages_scraped":0,
        "sitemap_size":0, "coverage_notes":[], "log":["Discovery workspace initialized."], **settings}
    if source_type == "api":
        t = threading.Thread(target=run_api_scan,
            args=(scan_id, url, api_max_pages, bool(data.get("skip_validate", False))), daemon=True)
    else:
        t = threading.Thread(target=run_scan,
            args=(scan_id, url, depth, bool(data.get("skip_validate", False)),
                  settings['page_limit'], data.get('scan_mode', 'moderate'), settings['page_limit'], False), daemon=True)
    t.start()
    return jsonify({"scan_id":scan_id})


@app.route("/poll/<scan_id>")
def poll(scan_id):
    r = scan_store.get(scan_id)
    if not r:
        return jsonify({"error": "Unknown scan ID"}), 404
    return jsonify({
        "phase":r.get("phase", "discovering"),
        "queue_size":r.get("queue_size", 0),
        "browser_pages":r.get("browser_pages", 0),
        "requests_failed":r.get("requests_failed", 0),
        "blocked_pages":r.get("blocked_pages", 0),
        "api_responses":r.get("api_responses", 0),
        "limits":r.get("limits", {}),
        "coverage_notes":r.get("coverage_notes", []),
        "drm_diagnostics":r.get("drm_diagnostics", []),
        "playback_observations":r.get("playback_observations", {}),
        "deep_recognition":r.get("deep_recognition", {}),
        "status":                    r["status"],
        "mp4_links":                 r["mp4_links"],
        "broken_links":              r.get("broken_links", []),
        "validation_results":        r.get("validation_results", {}),
        "validating":                r.get("validating", False),
        "validation_progress":       r.get("validation_progress", {}),
        "stream_diagnostics":        r.get("stream_diagnostics", []),
        "manifest_store":            r.get("manifest_store", {}),
        "player_store":              r.get("player_store", []),
        "thumbnail_classifications": r.get("thumbnail_classifications", {}),
        "classifying_thumbnails":    r.get("classifying_thumbnails", False),
        "pages_scraped":             r.get("pages_scraped", 0),
        "sitemap_size":              r.get("sitemap_size", 0),
        "log":                       r["log"],
    })


@app.route("/stop_scan/<scan_id>", methods=["POST"])
def stop_scan(scan_id):
    result = scan_store.get(scan_id)
    if result is None:
        return jsonify({"error":"Unknown scan"}), 404
    result['cancel_requested'] = True
    return jsonify({"ok":True, "status":"stopping"})


@app.route("/export_scan/<scan_id>")
def export_scan(scan_id):
    from flask import Response
    result = scan_store.get(scan_id)
    if result is None:
        return jsonify({"error":"Unknown scan"}), 404
    format = request.args.get('format', 'json')
    urls = list(dict.fromkeys(result['mp4_links'] + [r['url'] for r in result['stream_diagnostics'] if r.get('url', '').startswith(('http://', 'https://'))]))
    if format == 'txt':
        return Response('\n'.join(urls), mimetype='text/plain', headers={'Content-Disposition':f'attachment; filename="sources-{scan_id}.txt"'})
    if format != 'json':
        return jsonify({"error":"Choose JSON or TXT"}), 400
    data = {'status':result['status'], 'urls':urls, 'streams':result['stream_diagnostics'],
        'validation':result['validation_results'], 'coverage_notes':result.get('coverage_notes', [])}
    return Response(_json_mod.dumps(data, indent=2), mimetype='application/json', headers={'Content-Disposition':f'attachment; filename="sources-{scan_id}.json"'})


@app.route("/favicon.ico")
def favicon():
    return "", 204


@app.route("/routing_status")
def proxy_routing_status():
    return jsonify(routing_status())


@app.route("/cookie_status")
def cookie_status():
    path = get_cookie_file()
    cookies = _load_pw_cookies() if path else []
    return jsonify({"loaded": bool(cookies), "count": len(cookies)})


@app.route("/upload_cookies", methods=["POST"])
def upload_cookies():
    import os, tempfile
    f = request.files.get("cookies")
    if not f:
        return jsonify({"ok": False, "error": "No file sent"}), 400
    # Save to a temp file that persists for the app's lifetime
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="wb")
    f.save(tmp)
    tmp.close()
    set_cookie_file(tmp.name)
    # Count cookie lines to give user feedback
    try:
        with open(tmp.name) as cf:
            lines = [l for l in cf if l.strip() and not l.startswith("#")]
        count = len(lines)
    except Exception:
        count = "?"
    return jsonify({"ok": True, "path": tmp.name, "count": count})

@app.route("/clear_cookies", methods=["POST"])
def clear_cookies():
    import os
    old = get_cookie_file()
    set_cookie_file(None)
    if old:
        try: os.unlink(old)
        except Exception: pass
    return jsonify({"ok": True})

@app.route("/solve_cf", methods=["POST"])
def solve_cf():
    """
    Multi-strategy Cloudflare bypass:
    1. nodriver (direct CDP, best for 2026 CF)
    2. Camoufox (Firefox fingerprint spoofing)
    3. SeleniumBase UC mode (auto-Turnstile)
    4. Real Chrome CDP (manual fallback)
    """
    data = request.get_json()
    url  = data.get("url", "").strip()
    if not url.startswith("http"):
        url = "https://" + url

    domain = urlparse(url).netloc
    _cf_solve_log[domain] = []

    def _run():
        log = _cf_solve_log[domain]
        # Try automated crack first
        result = crack_cf(url, log)
        if not result:
            # Fall back to real-browser visible solve (user manual)
            log.append("🌐 All automated strategies failed — launching visible Chrome for manual solve...")
            solve_cf_challenge_visible(url, log)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return jsonify({"ok": True, "domain": domain})


@app.route("/cf_status")
def cf_status():
    """Poll CF solve progress and cookie status."""
    url    = request.args.get("url", "")
    domain = urlparse(url).netloc if url else ""
    cookies = _cf_solved_cookies.get(domain, [])
    log     = _cf_solve_log.get(domain, [])

    # Consider solved if we have ANY cookies from the domain (not just cf_clearance)
    # because some CF setups use session tokens instead
    has_cf      = any(c.get("name") == "cf_clearance" for c in cookies)
    has_cookies = len(cookies) > 0

    return jsonify({
        "solved":       has_cf or has_cookies,
        "has_cf_clear": has_cf,
        "cookie_count": len(cookies),
        "domain":       domain,
        "log":          log,
    })


# ─── Proxy download — solves CORS by streaming file through Flask backend ─────

@app.route("/proxy_download")
def proxy_download():
    """
    Stream a remote video file through Flask to the browser.
    Bypasses CORS restrictions. Supports Range requests for resumable downloads.
    """
    import os
    target_url = request.args.get("url", "").strip()
    if not target_url or not target_url.startswith("http"):
        return "Invalid URL", 400

    filename = os.path.basename(urlparse(target_url).path) or "video.mp4"

    # Forward Range header if present (enables seek/resume)
    range_header = request.headers.get("Range", None)
    req_headers = {**HEADERS}
    if range_header:
        req_headers["Range"] = range_header

    try:
        session = get_cf_session()
        upstream = session.get(target_url, headers=req_headers,
                               stream=True, timeout=30, verify=False)

        # Build response headers
        resp_headers = {
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Accept-Ranges":       "bytes",
            "Access-Control-Allow-Origin": "*",
        }
        for h in ["Content-Type", "Content-Length", "Content-Range"]:
            if h in upstream.headers:
                resp_headers[h] = upstream.headers[h]

        status = upstream.status_code  # preserve 206 Partial Content

        def generate():
            try:
                for chunk in upstream.iter_content(chunk_size=1024 * 512):  # 512 KB chunks
                    if chunk:
                        yield chunk
            finally:
                upstream.close()

        from flask import Response, stream_with_context
        return Response(
            stream_with_context(generate()),
            status=status,
            headers=resp_headers,
        )
    except Exception as e:
        return f"Proxy error: {e}", 502


# ─── Bulk download — validate and queue multiple pasted URLs ──────────────────

bulk_store = {}   # job_id -> {status, results: [{url, ok, code, reason, filename}]}

def run_bulk_check(job_id, urls):
    """Validate a list of URLs and store results."""
    r = bulk_store[job_id]
    total = len(urls)
    r["log"] = [f"🔎 Checking {total} URL(s)..."]
    lock = threading.Lock()

    def check(url):
        url = url.strip()
        if not url.startswith("http"):
            url = "https://" + url
        fname = os.path.basename(urlparse(url).path) or "video"
        code, ok, reason = 0, False, "unknown"
        try:
            resp = smart_get(url, timeout=10, extra_headers={"Range": "bytes=0-0"}, retries=2)
            code = resp.status_code
            ok     = code < 400
            reason = "ok" if ok else f"HTTP {code}"
        except Exception as e:
            reason = str(e)[:60]
        with lock:
            r["results"].append({"url": url, "ok": ok, "code": code,
                                 "reason": reason, "filename": fname})
            status = "✅" if ok else "💀"
            r["log"].append(f"   {status} [{code or reason}] {url[:80]}")

    with ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(check, urls))

    r["status"] = "done"
    good = sum(1 for x in r["results"] if x["ok"])
    r["log"].append(f"🏁 Done — {good}/{total} links valid")


@app.route("/bulk_check", methods=["POST"])
def bulk_check():
    import os
    data = request.get_json()
    raw  = data.get("urls", "")
    urls = [u.strip() for u in re.split(r"[\n\r,]+", raw) if u.strip()]
    if not urls:
        return jsonify({"error": "No URLs provided"}), 400

    job_id = str(uuid.uuid4())[:8]
    bulk_store[job_id] = {"status": "running", "results": [], "log": []}
    t = threading.Thread(target=run_bulk_check, args=(job_id, urls), daemon=True)
    t.start()
    return jsonify({"job_id": job_id, "count": len(urls)})

@app.route("/bulk_poll/<job_id>")
def bulk_poll(job_id):
    r = bulk_store.get(job_id)
    if not r:
        return jsonify({"error": "Unknown job"}), 404
    return jsonify(r)

import os  # make sure os is imported for proxy_download


# ─── Fingerprint stats API route ──────────────────────────────────────────────

@app.route("/engine_status")
def engine_status():
    """Return status of all CF bypass engines and Python version."""
    import sys
    pv = sys.version_info
    return jsonify({
        "python":        f"{pv.major}.{pv.minor}.{pv.micro}",
        "python_ok":     pv < (3, 14),
        "nodriver":      NODRIVER_OK,
        "camoufox":      CAMOUFOX_OK,
        "seleniumbase":  SELENIUMBASE_OK,
        "playwright":    PLAYWRIGHT_OK,
        "curl_cffi":     CURL_CFFI_OK,
        "cloudscraper":  CLOUDSCRAPER_OK,
        "httpx":         HTTPX_OK,
        "yt_dlp":        YTDLP_OK,
        "recommended":   ["seleniumbase"] if not SELENIUMBASE_OK else [],
        "install_cmd":   "pip install seleniumbase" if not SELENIUMBASE_OK else "",
        "py314_note":    "seleniumbase works on Python 3.14. nodriver/camoufox need ≤3.13 but are optional.",
    })


@app.route("/fp_stats")
def fp_stats_route():
    """Return per-domain adaptive fingerprint performance data."""
    return jsonify(get_fp_stats_summary())


# ─── AI Video Thumbnail Classifier ───────────────────────────────────────────
# Fetches og:image thumbnails from video pages and sends them to Claude Vision
# to classify: content_type, quality, safety, topics, and a confidence score.

def _fetch_thumbnail_url(page_url: str) -> str | None:
    """Extract thumbnail URL from og:image or twitter:image meta tags."""
    try:
        resp = smart_get(page_url, timeout=8, retries=1)
        if resp.status_code >= 400:
            return None
        soup = BeautifulSoup(resp.text, "lxml")
        for prop in ["og:image", "twitter:image", "og:image:secure_url"]:
            tag = soup.find("meta", property=prop) or soup.find("meta", attrs={"name": prop})
            if tag and tag.get("content"):
                thumb = tag["content"].strip()
                if thumb.startswith("http"):
                    return thumb
        # Fallback: first <img> inside a video player wrapper
        for cls in ["player", "video-thumb", "thumbnail", "poster"]:
            img = soup.find("img", class_=lambda c: c and cls in c.lower())
            if img and img.get("src", "").startswith("http"):
                return img["src"]
    except Exception:
        pass
    return None


def _download_image_b64(url: str) -> tuple | None:
    """Download image and return (base64_data, media_type) or None."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        if r.status_code != 200:
            return None
        ct = r.headers.get("Content-Type", "image/jpeg").split(";")[0].strip()
        if ct not in ("image/jpeg", "image/png", "image/webp", "image/gif"):
            ct = "image/jpeg"
        import base64
        b64 = base64.b64encode(r.content).decode()
        return b64, ct
    except Exception:
        return None


def classify_thumbnail_with_ai(page_url: str, thumb_url: str = None) -> dict:
    if not external_ai_enabled():
        return {"error":"External AI is disabled in local mode"}
    """
    Classify a video thumbnail using Claude Vision API.
    Returns dict with: content_type, quality, safety, topics, confidence, summary.
    """
    if not thumb_url:
        thumb_url = _fetch_thumbnail_url(page_url)
    if not thumb_url:
        return {"error": "No thumbnail found", "page_url": page_url}

    img_data = _download_image_b64(thumb_url)
    if not img_data:
        return {"error": "Failed to download thumbnail", "thumb_url": thumb_url}

    b64, media_type = img_data

    prompt = (
        "Analyze this video thumbnail image and respond ONLY with a JSON object "
        "(no markdown, no explanation) with these exact keys:\n"
        "- content_type: one of [movie, tv_show, animation, music_video, sports, "
        "news, tutorial, gaming, vlog, documentary, short_clip, unknown]\n"
        "- quality: one of [high, medium, low] based on visual quality/production value\n"
        "- safety: one of [safe, questionable, unsafe]\n"
        "- topics: array of up to 5 short topic tags (e.g. [\"action\", \"sci-fi\"])\n"
        "- confidence: float 0.0-1.0 for your classification confidence\n"
        "- summary: one sentence describing what this video is likely about\n"
        "Example: {\"content_type\":\"movie\",\"quality\":\"high\","
        "\"safety\":\"safe\",\"topics\":[\"action\",\"superhero\"],"
        "\"confidence\":0.92,\"summary\":\"A superhero action film thumbnail.\"}"
    )

    try:
        import urllib.request as _urlreq
        payload = _json_mod.dumps({
            "model":      "claude-sonnet-4-20250514",
            "max_tokens": 200,
            "messages":   [{
                "role":    "user",
                "content": [
                    {
                        "type":   "image",
                        "source": {
                            "type":       "base64",
                            "media_type": media_type,
                            "data":       b64,
                        },
                    },
                    {"type": "text", "text": prompt},
                ],
            }],
        }).encode()
        req = _urlreq.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type":      "application/json",
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        with _urlreq.urlopen(req, timeout=20) as resp:
            data = _json_mod.loads(resp.read())
        raw = data["content"][0]["text"].strip()
        raw = re.sub(r"```[a-z]*", "", raw).strip().strip("`").strip()
        result = _json_mod.loads(raw)
        result["thumb_url"] = thumb_url
        result["page_url"]  = page_url
        return result
    except Exception as e:
        return {
            "error":     str(e)[:120],
            "thumb_url": thumb_url,
            "page_url":  page_url,
        }


def classify_links_thumbnails(scan_id: str, links: list, max_classify: int = 10):
    """
    Background task: classify thumbnails for up to max_classify video page URLs.
    Results stored in scan_store[scan_id]["thumbnail_classifications"].
    """
    r = scan_store.get(scan_id)
    if not r:
        return
    r["thumbnail_classifications"] = {}
    r["classifying_thumbnails"] = True
    r["log"].append(f"🖼️  AI thumbnail classifier: analysing up to {max_classify} link(s)...")

    # Only classify page-level URLs (not direct .mp4/.m3u8 CDN links)
    page_links = [u for u in links if not is_video_url(u)][:max_classify]
    if not page_links:
        # Fall back to classifying direct video links via og:image lookup
        page_links = links[:max_classify]

    def classify_one(url):
        result = classify_thumbnail_with_ai(url)
        r["thumbnail_classifications"][url] = result
        if "error" not in result:
            r["log"].append(
                f"🖼️  [{result.get('content_type','?')}] "
                f"{result.get('safety','?')} | "
                f"{', '.join(result.get('topics', [])[:3])} — {url[:60]}"
            )

    with ThreadPoolExecutor(max_workers=4) as ex:
        list(ex.map(classify_one, page_links))

    r["classifying_thumbnails"] = False
    done = len(r["thumbnail_classifications"])
    r["log"].append(f"✅ Thumbnail classification done — {done} page(s) classified.")


@app.route("/classify_thumbnails", methods=["POST"])
def classify_thumbnails_route():
    if not external_ai_enabled():
        return jsonify({"error":"External AI is disabled. Enable RIPPER_ALLOW_EXTERNAL_AI locally to opt in."}), 403
    """
    POST {scan_id, max_classify?}
    Triggers background AI thumbnail classification for an existing scan.
    """
    data        = request.get_json()
    scan_id     = data.get("scan_id", "")
    max_classify = int(data.get("max_classify", 10))
    r = scan_store.get(scan_id)
    if not r:
        return jsonify({"error": "Unknown scan_id"}), 404
    if r.get("classifying_thumbnails"):
        return jsonify({"ok": False, "msg": "Classification already running"})

    links = list(r.get("mp4_links", []))
    if not links:
        return jsonify({"ok": False, "msg": "No links to classify"})

    threading.Thread(
        target=classify_links_thumbnails,
        args=(scan_id, links, max_classify),
        daemon=True,
    ).start()
    return jsonify({"ok": True, "queued": min(len(links), max_classify)})


@app.route("/classify_single", methods=["POST"])
def classify_single_route():
    if not external_ai_enabled():
        return jsonify({"error":"External AI is disabled. Enable RIPPER_ALLOW_EXTERNAL_AI locally to opt in."}), 403
    """
    POST {url, thumb_url?}
    Classify a single URL's thumbnail immediately and return result.
    """
    data      = request.get_json()
    url       = data.get("url", "").strip()
    thumb_url = data.get("thumb_url", "").strip() or None
    if not url:
        return jsonify({"error": "url required"}), 400
    result = classify_thumbnail_with_ai(url, thumb_url=thumb_url)
    return jsonify(result)


# ─── HTML UI ──────────────────────────────────────────────────────────────────
HTML_PAGE = '<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>Source Studio · Media discovery</title>\n<style>\n:root{--bg:#f3f5f7;--card:#fff;--ink:#15202c;--muted:#697686;--line:#e3e8ee;--accent:#d5f16a;--nav:#14202c;--blue:#3059df;--radius:16px}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 Inter,Segoe UI,Arial,sans-serif}button,input,select{font:inherit}button,a{touch-action:manipulation}button{cursor:pointer;border:0;border-radius:9px;padding:10px 15px;background:#eaf0f6;color:var(--ink)}button:disabled{cursor:wait;opacity:.5}button:hover:not(:disabled){filter:brightness(.96)}input,select{border:1px solid var(--line);border-radius:9px;padding:10px;background:white;color:var(--ink);min-width:0}input:focus,select:focus{outline:2px solid #5576e7;outline-offset:2px}a{color:var(--blue)}.app{display:grid;grid-template-columns:222px minmax(0,1fr);min-height:100vh}.sidebar{background:var(--nav);color:#e4ebf1;padding:30px 22px;display:flex;flex-direction:column;gap:35px}.brand{font-weight:750;font-size:20px;letter-spacing:-.8px}.brand i{font-style:normal;background:var(--accent);color:#172126;border-radius:8px;display:inline-grid;place-items:center;width:32px;height:32px;margin-right:8px}.side-label{font-size:10px;letter-spacing:1.6px;color:#8b9aa9;margin-bottom:12px}.nav-item{display:flex;gap:12px;align-items:center;border-radius:10px;padding:12px;background:#263440;color:#f5f7f9}.sidebar .foot{margin-top:auto;font-size:12px;color:#99a7b4}.connection{display:flex;align-items:center;gap:8px}.dot{height:7px;width:7px;background:var(--accent);border-radius:50%;display:inline-block}.main{padding:30px 42px 38px;max-width:1650px;width:100%;margin:auto}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:30px;color:var(--muted);font-size:12px}.badge{border:1px solid var(--line);background:var(--card);padding:6px 11px;border-radius:20px;font-size:11px;color:var(--muted)}.hero{display:flex;justify-content:space-between;align-items:end;margin-bottom:24px}.eyebrow{font-size:11px;letter-spacing:1.4px;color:var(--blue);font-weight:700;text-transform:uppercase}h1{font-size:38px;font-weight:650;letter-spacing:-1.7px;margin:7px 0 8px;line-height:1.15}h2{font-size:16px;margin:0;font-weight:650;letter-spacing:-.3px}p{margin:6px 0;color:var(--muted)}.card{border:1px solid var(--line);background:var(--card);border-radius:var(--radius);box-shadow:0 3px 12px #17283703}.target{padding:24px}.label{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted)}.url-row{display:grid;grid-template-columns:130px minmax(0,1fr) auto auto;gap:10px;margin-top:11px}.url-row input{font-size:15px;padding:13px}.primary{background:var(--ink);color:white;padding:12px 23px}.primary span{color:var(--accent);margin-left:12px}.stop{background:#fff0ed;color:#9f3526}.target-bottom{display:flex;gap:18px;align-items:center;flex-wrap:wrap;margin-top:17px;font-size:12px;color:var(--muted)}.target-bottom label{display:flex;gap:6px;align-items:center}.target-bottom input[type=checkbox]{accent-color:var(--blue)}details>summary{cursor:pointer;color:var(--blue);font-size:12px}.advanced{margin-top:16px;border-top:1px solid var(--line);padding-top:15px}.settings{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:16px}.settings label{display:flex;flex-direction:column;gap:5px;color:var(--muted);font-size:12px}.settings .check{flex-direction:row;align-items:center}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:20px 0}.stat{padding:20px}.stat .value{font-size:29px;font-weight:650;letter-spacing:-1px;margin-top:9px}.stat .hint{font-size:11px;color:var(--muted)}.stat:first-child{background:var(--nav);color:white;border-color:var(--nav)}.stat:first-child .label,.stat:first-child .hint{color:#a4b3c0}.workspace{display:grid;grid-template-columns:minmax(0,1fr) 285px;gap:20px}.results{overflow:hidden;min-height:410px}.panel-head{padding:20px 23px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);gap:10px}.panel-head p{font-size:12px}.tools{display:flex;gap:7px}.tools button{font-size:12px;padding:8px 11px}.filters{padding:14px 22px;display:flex;justify-content:space-between;align-items:center;gap:12px;background:#fcfdfe;border-bottom:1px solid var(--line)}.tabs{display:flex;gap:4px}.tabs button{background:transparent;font-size:12px;padding:7px 10px;white-space:nowrap}.tabs button.active{background:#e9efff;color:var(--blue)}.filters input{max-width:190px;font-size:12px;padding:7px 10px;width:100%}.result-table{overflow:auto;max-height:580px}table{width:100%;border-collapse:collapse;text-align:left;table-layout:fixed}th{font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);font-weight:600;background:#fcfdfe;padding:11px 22px}td{padding:17px 22px;border-top:1px solid #eff2f5;vertical-align:top;font-size:12px}th:nth-child(1){width:52%}th:nth-child(2){width:26%}th:nth-child(3){width:22%}.file-title{font-weight:650;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-bottom:5px}.url-text{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px}.pill{display:inline-block;border-radius:5px;background:#edf1f5;color:#576679;font-size:10px;padding:3px 6px;margin-bottom:5px}.pill.good{background:#edf6d8;color:#4e6925}.pill.warn{background:#fff2df;color:#96641c}.actions{display:flex;gap:6px;flex-wrap:wrap}.actions button,.actions a{font-size:11px;padding:5px 7px;border-radius:5px;text-decoration:none;background:#f0f3f7;border:0;display:inline-block}.empty{padding:70px 25px;text-align:center;color:var(--muted)}.empty-icon{display:grid;place-items:center;margin:0 auto 18px;height:52px;width:52px;border:1px dashed #bdc7d3;border-radius:15px;font-size:22px;color:#5c7288}.empty strong{font-size:16px;font-weight:550;color:#405064}.empty p{font-size:12px;max-width:280px;margin:8px auto}.insights{display:flex;flex-direction:column;gap:16px}.insight{padding:20px}.stage{margin-top:20px;font-size:12px;display:flex;align-items:center;gap:10px;color:var(--muted)}.stage em{display:grid;place-items:center;font-style:normal;font-size:10px;width:23px;height:23px;border:1px solid var(--line);border-radius:50%}.stage.active{color:var(--blue);font-weight:600}.stage.active em{background:#edf1ff;border-color:#c9d4ff}.progress{background:#e9edf2;border-radius:5px;height:5px;margin:20px 0 8px;overflow:hidden}.progress>div{height:100%;background:var(--blue);width:0;transition:width .3s}.coverage{font-size:11px;color:var(--muted)}.note{font-size:12px;border-left:2px solid #d3dfef;padding-left:10px;margin-top:12px;color:var(--muted)}.activity{margin-top:20px;overflow:hidden}.log{padding:15px 22px;max-height:180px;overflow:auto;font:11px/1.9 ui-monospace,Consolas,monospace;color:#68788a;white-space:pre-wrap;overflow-wrap:anywhere}.status{font-size:11px;display:flex;gap:8px;align-items:center}.status.busy .dot{background:#d3a540}.bottom-note{font-size:11px;color:var(--muted);margin-top:18px}.cookie-tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:15px}.cookie-tools button{font-size:12px}.cookie-tools input{max-width:250px;font-size:11px}#toast{position:fixed;bottom:25px;left:50%;transform:translateX(-50%);padding:12px 20px;border-radius:9px;background:var(--ink);color:white;box-shadow:0 4px 22px #0002;z-index:10;display:none}.metric-icon{float:right;color:#98a7b4}.small{font-size:11px;color:var(--muted)}\n@media(min-width:1450px){.workspace{grid-template-columns:minmax(0,1fr) 320px}}@media(max-width:1100px){.app{grid-template-columns:175px minmax(0,1fr)}.sidebar{padding:28px 16px}.main{padding:26px}.workspace{grid-template-columns:minmax(0,1fr)}.insights{display:grid;grid-template-columns:1fr 1fr}.brand{font-size:17px}.brand i{width:26px;height:26px}.filters{flex-wrap:wrap}}@media(max-width:700px){.app{display:block}.sidebar{padding:15px 20px;display:flex;flex-direction:row;justify-content:space-between;align-items:center}.sidebar nav,.sidebar .side-label,.sidebar .foot{display:none}.main{padding:22px 16px}.top{margin-bottom:23px}.hero .badge{display:none}h1{font-size:30px}.url-row{grid-template-columns:110px 1fr}.url-row{grid-template-columns:1fr 1fr}.url-row select,.url-row input{grid-column:1 / -1}.url-row .primary{grid-column:1;white-space:nowrap;padding:12px 8px}.stats{grid-template-columns:repeat(2,1fr);gap:10px}.workspace{gap:14px}.insights{grid-template-columns:1fr}.settings{grid-template-columns:repeat(2,1fr)}.target{padding:18px}.panel-head{flex-wrap:wrap;padding:17px}.filters{padding:12px}.filters input{max-width:none}.tabs{overflow:auto;width:100%}td,th{padding:12px}.hero{margin-bottom:20px}.top .badge{display:none}}\n</style></head><body><div class="app">\n<aside class="sidebar"><div class="brand"><i>↗</i>Source Studio</div><nav><div class="side-label">WORKSPACE</div><div class="nav-item">◉ &nbsp; Media discovery</div><p style="font-size:12px;color:#93a4b3;margin:17px 10px">One workspace for page sources, streams and APIs.</p></nav><div class="foot"><div class="connection"><span class="dot"></span> Local workspace</div><p style="color:#99a7b4;margin-top:10px">Your scans stay on this computer.</p></div></aside>\n<main class="main"><div class="top"><span>Workspace &nbsp; / &nbsp; Discovery</span><span class="badge">WEBSITES &nbsp; · &nbsp; STREAMS &nbsp; · &nbsp; APIs</span></div>\n<div class="hero"><div><div class="eyebrow">Media intelligence</div><h1>Find the source.</h1><p>Trace media across pages, JavaScript players and API responses.</p></div><span class="badge" id="routeBadge">Checking connection…</span></div>\n<section class="card target"><div class="label">Start a discovery</div><form id="scanForm"><div class="url-row"><select id="sourceType" aria-label="Scan source"><option value="website">Website</option><option value="api">API JSON</option></select><input id="ui" aria-label="Target URL" placeholder="https://example.com/watch" required autocomplete="off"><button class="primary" id="sb" type="submit">Discover media <span>↗</span></button><button class="stop" id="xb" type="button" disabled>Stop</button></div>\n<div class="target-bottom"><label><input id="doValidate" type="checkbox" checked> Verify media links</label><label><input id="renderBrowser" type="checkbox" checked> Render JavaScript</label><label><input id="discoverSitemap" type="checkbox" checked> Discover sitemap pages</label><span id="cookieSt">No cookies loaded</span></div>\n<details class="advanced"><summary>Discovery settings &amp; session</summary><div class="settings"><label>Page limit<input id="pageLimit" type="number" min="1" max="1000" value="80"></label><label>Link depth<input id="depth" type="number" min="0" max="8" value="3"></label><label>Parallel requests<input id="concurrency" type="number" min="1" max="6" value="3"></label><label>Time budget (seconds)<input id="timeBudget" type="number" min="20" max="900" value="120"></label><label>Rendered pages<input id="browserLimit" type="number" min="1" max="50" value="8"></label><label>Observe each page (ms)<input id="dwell" type="number" min="300" max="10000" value="1800"></label><label>API page limit<input id="apiMaxPages" type="number" min="1" max="20" value="5"></label><label class="check"><input id="deepJs" type="checkbox"> Deep JS recognition (optional)</label><label class="check"><input id="attemptPlayback" type="checkbox" checked> Attempt muted playback</label><label>Discovery profile<select id="scanMode"><option value="moderate">Balanced</option><option value="quick">Quick</option><option value="deep">Deep</option></select></label></div><div class="cookie-tools"><input id="cookieFile" type="file" accept=".txt" aria-label="Netscape cookie file"><button id="uploadCookies" type="button">Load cookies.txt</button><button id="clearCookies" type="button">Clear cookies</button></div><p class="small">Session cookies retain their domain scope. API authorization and proxies use your local environment settings.</p></details></form></section>\n<div class="stats"><div class="card stat"><span class="metric-icon">↗</span><div class="label">Media candidates</div><div class="value" id="mediaCount">0</div><div class="hint">Unique media and manifest URLs</div></div><div class="card stat"><span class="metric-icon">▧</span><div class="label">Pages inspected</div><div class="value" id="pageCount">0</div><div class="hint" id="browserCount">0 pages rendered</div></div><div class="card stat"><span class="metric-icon">✓</span><div class="label">Verified media</div><div class="value" id="verifiedCount">0</div><div class="hint">Confirmed by response inspection</div></div><div class="card stat"><span class="metric-icon">◷</span><div class="label">Elapsed time</div><div class="value" id="elapsed">0:00</div><div class="hint" id="requestCount">Ready when you are</div></div></div>\n<div class="workspace"><section class="card results"><div class="panel-head"><div><h2>Discovered sources</h2><p>Every result, with the evidence behind it.</p></div><div class="tools"><button id="copyAll">Copy URLs</button><button id="exportJson">Export JSON ↓</button><button id="exportTxt">TXT ↓</button></div></div><div class="filters"><div class="tabs" role="group" aria-label="Result filter"><button class="active" data-filter="all">All sources</button><button data-filter="manifest">Manifests</button><button data-filter="file">Media files</button><button data-filter="browser">Browser only</button><button data-filter="failed">Unverified / failed</button></div><input id="search" placeholder="Filter by URL or type…" aria-label="Search results"></div><div class="result-table" id="streamResults"><div class="empty"><div class="empty-icon">⌁</div><strong>A clearer view of your media.</strong><p>Start a scan to see files, manifests and browser streams with source evidence.</p></div></div></section>\n<aside class="insights"><section class="card insight"><div style="display:flex;justify-content:space-between"><h2>Discovery pipeline</h2><div class="status" id="statusWrap"><span class="dot"></span><span id="st" role="status">IDLE</span></div></div><div class="stage" data-phase="discovering"><em>1</em>Explore pages &amp; APIs</div><div class="stage" data-phase="rendering"><em>2</em>Observe browser streams</div><div class="stage" data-phase="validating"><em>3</em>Verify media responses</div><div class="progress"><div id="progressFill"></div></div><div class="coverage" id="coverage">Coverage follows your page and time limits.</div></section><section class="card insight"><h2>Coverage notes</h2><div id="notes"><div class="note">Manifests describe streams. Segments are fragments. Browser blobs aren’t standalone download links.</div><div class="note">Access-denied pages and DRM signals are reported separately.</div></div></section></aside></div>\n<section class="card activity"><div class="panel-head"><h2>Activity</h2><span class="small" id="activityCount">Waiting for a scan</span></div><div class="log" id="term" role="log">Ready. Start with a website or a JSON API endpoint.</div></section><div class="bottom-note">Source Studio identifies observable media; a scan cannot guarantee every host link or decrypt protected streams.</div></main></div><div id="toast" role="status"></div>\n<script>\nconst $=id=>document.getElementById(id);let sid=null,snapshot=null,tab=\'all\',timer=null,started=0,pollTimer=null,busy=false,lastRender=\'\';\nfunction toast(text){$(\'toast\').textContent=text;$(\'toast\').style.display=\'block\';setTimeout(()=>$(\'toast\').style.display=\'none\',3500)}\nasync function request(url,options){const res=await fetch(url,options);let data;try{data=await res.json()}catch{throw new Error(\'The local server returned an unexpected response.\')}if(!res.ok)throw new Error(data.error||\'Request failed\');return data}\nfunction status(text,active=false){$(\'st\').textContent=text;$(\'statusWrap\').classList.toggle(\'busy\',active)}\nfunction elapsed(){const n=Math.max(0,Math.floor((Date.now()-started)/1000));$(\'elapsed\').textContent=Math.floor(n/60)+\':\'+String(n%60).padStart(2,\'0\')}\nfunction records(){if(!snapshot)return[];const map=new Map();for(const r of snapshot.stream_diagnostics||[]){const key=r.url||r.kind+\':\'+r.mime;if(!map.has(key)||r.confidence===\'response_headers\')map.set(key,r)}for(const url of [...snapshot.mp4_links||[],...snapshot.broken_links||[]])if(!map.has(url))map.set(url,{url,kind:\'media_candidate\',evidence:[\'source extraction\'],file_type:\'unknown\'});return[...map.values()]}\nfunction paint(){const rows=records(),search=$(\'search\').value.toLowerCase(),validation=snapshot?.validation_results||{};const visible=rows.filter(r=>{const v=validation[r.url];const kind=r.kind||\'\';let match=tab===\'all\'||tab===\'manifest\'&&kind.includes(\'manifest\')||tab===\'browser\'&&/blob|mse/.test(kind)||tab===\'file\'&&/file|ranged|api_media|media_candidate/.test(kind)||tab===\'failed\'&&(!v||!v.ok);return match&&JSON.stringify([r.url,kind,r.mime]).toLowerCase().includes(search)});const root=$(\'streamResults\');root.replaceChildren();if(!visible.length){const box=document.createElement(\'div\');box.className=\'empty\';box.textContent=rows.length?\'No sources match this filter.\':busy?\'Discovery is in progress. Sources will appear here.\':\'No media sources collected yet.\';root.append(box);return}const table=document.createElement(\'table\'),head=document.createElement(\'thead\');head.innerHTML=\'<tr><th>Source</th><th>Type / evidence</th><th>Actions</th></tr>\';table.append(head);const body=document.createElement(\'tbody\');for(const r of visible.slice(0,1000)){const v=validation[r.url],tr=document.createElement(\'tr\'),source=document.createElement(\'td\'),title=document.createElement(\'div\'),url=document.createElement(\'div\'),meta=document.createElement(\'td\'),pill=document.createElement(\'span\'),evidence=document.createElement(\'div\'),act=document.createElement(\'td\'),actions=document.createElement(\'div\');title.className=\'file-title\';try{title.textContent=decodeURIComponent(new URL(r.url).pathname.split(\'/\').pop())||new URL(r.url).hostname}catch{title.textContent=\'Browser media buffer\'}title.title=r.url||r.mime||\'\';url.className=\'url-text\';url.textContent=r.url||\'(No standalone URL)\';url.title=r.url||\'\';source.append(title,url);pill.className=\'pill\'+(v?.ok?\' good\':v&&!v.ok?\' warn\':\'\');pill.textContent=v?.ok?\'Verified\':v&&!v.ok?\'Not verified\':(r.kind||\'candidate\').replaceAll(\'_\',\' \');evidence.className=\'small\';evidence.textContent=(r.mime||r.file_type||\'\')+\' · \'+(r.evidence||[]).join(\', \')+(r.quality?\' · \'+r.quality:\'\');meta.append(pill,evidence);actions.className=\'actions\';if(r.url){const copy=document.createElement(\'button\');copy.textContent=\'Copy\';copy.onclick=()=>navigator.clipboard.writeText(r.url).then(()=>toast(\'URL copied\')).catch(()=>toast(\'Clipboard unavailable\'));actions.append(copy);if(/^https?:\\/\\//.test(r.url)){const link=document.createElement(\'a\');link.textContent=\'Open ↗\';link.href=r.url;link.target=\'_blank\';link.rel=\'noopener noreferrer\';actions.append(link);if(v?.ok&&(r.download_candidate||[\'api_media_candidate\',\'media_candidate\'].includes(r.kind))){const dl=document.createElement(\'a\');dl.textContent=\'Download\';dl.href=\'/proxy_download?url=\'+encodeURIComponent(r.url);actions.append(dl)}}}act.append(actions);tr.append(source,meta,act);body.append(tr)}table.append(body);root.append(table)}\nfunction update(data){snapshot=data;const found=new Set(data.mp4_links||[]);$(\'mediaCount\').textContent=found.size;$(\'pageCount\').textContent=data.pages_scraped||0;$(\'browserCount\').textContent=(data.browser_pages||0)+\' pages rendered\';$(\'verifiedCount\').textContent=Object.values(data.validation_results||{}).filter(v=>v.ok).length;$(\'requestCount\').textContent=(data.api_responses||0)+\' API responses · \'+(data.blocked_pages||0)+\' blocked pages\';$(\'coverage\').textContent=(data.queue_size||0)+\' URLs queued · \'+(data.requests_failed||0)+\' request failures\';for(const stage of document.querySelectorAll(\'[data-phase]\'))stage.classList.toggle(\'active\',stage.dataset.phase===data.phase);const logs=data.log||[];$(\'term\').textContent=logs.slice(-180).join(\'\\n\');$(\'term\').scrollTop=$(\'term\').scrollHeight;$(\'activityCount\').textContent=logs.length+\' events\';const notes=[...(data.coverage_notes||[])];if((data.drm_diagnostics||[]).length)notes.push(\'Encrypted media signals observed. Authorized playback may require a license.\');if(!notes.length)notes.push(\'Discovery is bounded by the configured limits. File candidates remain unconfirmed until verified.\');$(\'notes\').replaceChildren(...notes.map(text=>{const n=document.createElement(\'div\');n.className=\'note\';n.textContent=text;return n}));const max=data.limits?.pages||Number($(\'pageLimit\').value);$(\'progressFill\').style.width=Math.min(100,Math.max((data.pages_scraped||0)/max*100,data.phase===\'rendering\'?55:data.phase===\'validating\'?85:0))+\'%\';const fingerprint=JSON.stringify([data.stream_diagnostics,data.mp4_links,data.broken_links,data.validation_results]);if(fingerprint!==lastRender){lastRender=fingerprint;paint()}}\nasync function poll(){if(!sid)return;try{const data=await request(\'/poll/\'+sid);update(data);if([\'done\',\'error\',\'blocked\',\'rate_limited\',\'cancelled\'].includes(data.status)){busy=false;clearInterval(timer);$(\'sb\').disabled=false;$(\'xb\').disabled=true;status({done:\'COMPLETE\',error:\'ERROR\',blocked:\'BLOCKED\',rate_limited:\'RATE LIMITED\',cancelled:\'STOPPED\'}[data.status]);if(data.status===\'done\')$(\'progressFill\').style.width=\'100%\';return}status((data.phase||data.status||\'SCANNING\').toUpperCase(),true);pollTimer=setTimeout(poll,900)}catch(e){toast(e.message);pollTimer=setTimeout(poll,2000)}}\n$(\'scanForm\').addEventListener(\'submit\',async event=>{event.preventDefault();if(busy)return;busy=true;snapshot=null;lastRender=\'\';$(\'sb\').disabled=true;$(\'xb\').disabled=false;status(\'STARTING\',true);started=Date.now();elapsed();timer=setInterval(elapsed,1000);paint();const payload={url:$(\'ui\').value.trim(),source_type:$(\'sourceType\').value,scan_mode:$(\'scanMode\').value,skip_validate:!$(\'doValidate\').checked,depth:Number($(\'depth\').value),page_limit:Number($(\'pageLimit\').value),concurrency:Number($(\'concurrency\').value),time_limit_s:Number($(\'timeBudget\').value),browser_limit:Number($(\'browserLimit\').value),dwell_ms:Number($(\'dwell\').value),api_max_pages:Number($(\'apiMaxPages\').value),deep_js:$(\'deepJs\').checked,attempt_playback:$(\'attemptPlayback\').checked,render_browser:$(\'renderBrowser\').checked,discover_sitemap:$(\'discoverSitemap\').checked};try{const result=await request(\'/start_scan\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify(payload)});sid=result.scan_id;poll()}catch(e){busy=false;clearInterval(timer);$(\'sb\').disabled=false;$(\'xb\').disabled=true;status(\'ERROR\');toast(e.message)}});\n$(\'xb\').onclick=async()=>{if(!sid)return;try{await request(\'/stop_scan/\'+sid,{method:\'POST\'});status(\'STOPPING\',true);$(\'xb\').disabled=true}catch(e){toast(e.message)}};\nfor(const button of document.querySelectorAll(\'[data-filter]\'))button.onclick=()=>{tab=button.dataset.filter;for(const b of document.querySelectorAll(\'[data-filter]\'))b.classList.toggle(\'active\',b===button);paint()};$(\'search\').oninput=paint;\n$(\'copyAll\').onclick=()=>{const urls=[...new Set(records().map(r=>r.url).filter(u=>/^https?:\\/\\//.test(u||\'\')))];if(!urls.length)return toast(\'No URLs to copy\');navigator.clipboard.writeText(urls.join(\'\\n\')).then(()=>toast(urls.length+\' URLs copied\')).catch(()=>toast(\'Clipboard unavailable\'))};\nfor(const [id,format]of[[\'exportJson\',\'json\'],[\'exportTxt\',\'txt\']])$(id).onclick=()=>{if(!sid)return toast(\'Run a scan first\');const link=document.createElement(\'a\');link.href=\'/export_scan/\'+sid+\'?format=\'+format;link.click()};\nasync function cookieStatus(){try{const d=await request(\'/cookie_status\');$(\'cookieSt\').textContent=d.loaded?d.count+\' session cookies loaded\':\'No cookies loaded\'}catch{$(\'cookieSt\').textContent=\'Cookie status unavailable\'}}\n$(\'uploadCookies\').onclick=async()=>{const file=$(\'cookieFile\').files[0];if(!file)return toast(\'Choose a cookies.txt file first\');const form=new FormData();form.append(\'cookies\',file);try{await request(\'/upload_cookies\',{method:\'POST\',body:form});cookieStatus();toast(\'Session cookies loaded\')}catch(e){toast(e.message)}};$(\'clearCookies\').onclick=async()=>{try{await request(\'/clear_cookies\',{method:\'POST\'});cookieStatus()}catch(e){toast(e.message)}};\n$(\'scanMode\').onchange=()=>{const presets={quick:[30,2,60,3,700],moderate:[80,3,120,8,1800],deep:[300,5,300,20,3000]};const p=presets[$(\'scanMode\').value];[\'pageLimit\',\'depth\',\'timeBudget\',\'browserLimit\',\'dwell\'].forEach((id,i)=>$(id).value=p[i])};\n$(\'sourceType\').onchange=()=>{const api=$(\'sourceType\').value===\'api\';$(\'ui\').placeholder=api?\'https://example.com/api/videos\':\'https://example.com/watch\';$(\'renderBrowser\').disabled=api;$(\'discoverSitemap\').disabled=api};\ncookieStatus();request(\'/routing_status\').then(d=>$(\'routeBadge\').textContent=d.configured?\'UPSTREAM PROXY CONFIGURED\':\'DIRECT / SYSTEM ROUTING\').catch(()=>$(\'routeBadge\').textContent=\'CONNECTION STATUS UNAVAILABLE\');\n</script></body></html>\n'

# BEGIN OPTIONAL VIDEO ADDONS
"""Optional video-discovery extensions, embedded verbatim in app.py.

The original engine and endpoints are untouched. Only /addons/start selects this
subclass. Persistence is opt-in; cookies, headers, bodies and query URLs stay out
of its database. Signed URLs remain usable in the current in-memory scan.
"""
import hashlib as _va_hash
import sqlite3 as _va_sql
import csv as _va_csv
import io as _va_io
from pathlib import Path as _VAPath
from dataclasses import replace as _va_replace

try:
    from selectolax.lexbor import LexborHTMLParser as _VAParser
except ImportError:
    _VAParser = None

_VA_LOCK = threading.RLock()
_VA_FIELDS = ('page', 'title', 'description', 'duration', 'thumbnail', 'url', 'kind', 'quality', 'source')


def _va_safe_url(value):
    """Only unsigned HTTP URLs may be stored, never silently alter signed URLs."""
    try:
        p = urlparse(value)
        return value if p.scheme in ('http', 'https') and p.hostname and not (p.query or p.fragment or p.username or p.password) else ''
    except (ValueError, TypeError):
        return ''


class VideoJournal:
    def __init__(self, path=None):
        self.path = str(path or _VAPath(__file__).with_name('video-discovery.sqlite3'))

    @contextmanager
    def db(self):
        with _VA_LOCK:
            db = _va_sql.connect(self.path, timeout=5)
            try:
                db.execute('CREATE TABLE IF NOT EXISTS entries (kind TEXT, id TEXT, updated REAL, data TEXT, PRIMARY KEY(kind,id))')
                db.execute('DELETE FROM entries WHERE updated < ?', (time.time()-7*86400,))
                yield db
                db.commit()
            finally:
                db.close()

    def put(self, kind, key, data):
        with self.db() as db:
            db.execute('INSERT OR REPLACE INTO entries VALUES (?,?,?,?)', (kind, key, time.time(), _json_mod.dumps(data)))
            limit = 5000 if kind == 'page' else 100
            db.execute('DELETE FROM entries WHERE kind=? AND id NOT IN (SELECT id FROM entries WHERE kind=? ORDER BY updated DESC LIMIT ?)', (kind,kind,limit))

    def get(self, kind, key):
        with self.db() as db:
            row = db.execute('SELECT data FROM entries WHERE kind=? AND id=?', (kind,key)).fetchone()
            return _json_mod.loads(row[0]) if row else None

    def items(self, kind):
        with self.db() as db:
            return [{'id':r[0], 'updated':r[1], **_json_mod.loads(r[2])} for r in db.execute('SELECT id,updated,data FROM entries WHERE kind=? ORDER BY updated DESC LIMIT 100', (kind,))]

    def clear(self):
        with self.db() as db:
            db.execute('DELETE FROM entries')


def _va_recipe(value):
    if not isinstance(value, dict):
        raise ValueError('Recipe must be a JSON object')
    result = {}
    for key in ('title', 'description', 'duration', 'thumbnail', 'media', 'next'):
        text = value.get(key, '')
        if not isinstance(text, str) or len(text) > 250:
            raise ValueError('Each recipe selector must be text under 250 characters')
        if text:
            # Validate selectors now, not in the worker.
            BeautifulSoup('<html></html>', 'html.parser').select(text)
            result[key] = text
    return result


class VideoAddonEngine(DiscoveryEngine):
    def __init__(self, scan_id, url, plan, options, resume=None):
        super().__init__(scan_id, url, plan)
        self.scan_id, self.options = scan_id, options
        self.recipe = options.get('recipe', {})
        self.lock = threading.RLock()
        self.clock = time.monotonic()
        self.metadata, self.page_sources = {}, {}
        self.browser_needed = set()
        self.window = min(2, plan.workers)
        self.journal = VideoJournal() if options.get('persist') else None
        self.metrics = {'requests':0, 'static_bytes':0, 'browser_bytes':0,
            'browser_seconds':0, 'parse_seconds':0, 'first_result_seconds':None,
            'unique_sources':0, 'unchanged_pages':0, 'redirects':0,
            'workers':self.window, 'worker_responses':0, 'websocket_messages':0,
            'parser':'Lexbor' if options.get('fast_parser') and _VAParser else 'BeautifulSoup',
            'browser_skipped':0}
        self.r['addon_metrics'] = self.metrics
        self.r['video_records'] = []
        self.r['addon_options'] = options
        self.resume = resume or {}
        for entry in self.resume.get('pending', []):
            self.enqueue(entry[0], entry[1], entry[2])
        self.visited.update(self.resume.get('visited', []))
        for record in self.resume.get('sources', []):
            self.add(record)

    def add(self, record):
        if record and hasattr(self, 'lock'):
            with self.lock:
                super().add(record)
                self.metrics['unique_sources'] = len(self.media)
                if self.media and self.metrics['first_result_seconds'] is None:
                    self.metrics['first_result_seconds'] = round(time.monotonic()-self.clock, 3)
        else:
            super().add(record)

    def fetch(self, url):
        if not self.active():
            return {'url':url, 'skip':True}
        start = time.monotonic()
        try:
            with self.pooled_connection() as session:
                current, seen = url, set()
                for hop in range(11):
                    if not self.active():
                        return {'url':url, 'skip':True}
                    if current in seen:
                        return {'url':url, 'error':'Redirect loop detected (same URL repeated)'}
                    if not self.scope(current):
                        return {'url':url, 'error':'Redirect leaves the selected origin; target retained in browser navigation only'}
                    seen.add(current)
                    with self.lock:
                        self.metrics['requests'] += 1
                    with closing(session.get(current, stream=True, allow_redirects=False,
                            timeout=min(10,max(1,self.deadline-time.monotonic())))) as response:
                        headers, status = dict(response.headers), response.status_code
                        if status in (301,302,303,307,308):
                            location = response.headers.get('Location')
                            if not location:
                                return {'url':url, 'error':'Redirect response has no Location header'}
                            if hop == 10:
                                return {'url':url, 'error':'Redirect chain exceeds the add-on limit of 10 hops'}
                            with self.lock:
                                self.metrics['redirects'] += 1
                            current = normalise_url(location, current)
                            continue
                        result = {'url':current, 'status':status, 'headers':headers, 'text':'', 'elapsed':time.monotonic()-start}
                        if status >= 400:
                            return result
                        record = identify_stream(current, headers, source='response', frame_url=url)
                        if record and record['confidence']=='response_headers':
                            result['record'] = record
                            return result
                        body = bytearray()
                        for chunk in response.iter_content(65536):
                            with self.lock:
                                self.metrics['static_bytes'] += len(chunk)
                            body.extend(chunk)
                            if not self.active():
                                return {'url':url, 'skip':True}
                            if len(body)>2*1024*1024:
                                return {'url':url, 'error':'Page exceeded 2 MiB discovery limit'}
                        result['text'] = body.decode(response.encoding or 'utf-8', errors='replace')
                        result['elapsed'] = time.monotonic()-start
                        # Never cache a response associated with authentication or privacy directives.
                        result['cacheable'] = not (session.cookies or session.headers.get('Authorization') or
                            session.headers.get('Cookie') or response.headers.get('Set-Cookie') or
                            re.search(r'private|no-store', response.headers.get('Cache-Control',''),re.I))
                        return result
        except Exception as exc:
            return {'url':url, 'error':api_failure_message(exc,'video discovery')}

    def _document(self, text):
        if self.options.get('fast_parser') and _VAParser:
            try:
                tree = _VAParser(text)
                # Recipes may use a selector supported only by SoupSieve. Choose
                # the existing parser for the whole document in that case.
                for selector in self.recipe.values(): tree.css(selector)
                return lambda selector: tree.css(selector), lambda node: node.text(), lambda node,key: node.attributes.get(key,'') or ''
            except Exception:
                self.emit('Optional parser failed; using the existing HTML parser.')
        tree = BeautifulSoup(text, 'html.parser')
        return lambda selector: tree.select(selector), lambda node: node.get_text(), lambda node,key: node.get(key,'')

    def consume(self, item, depth, kind):
        url, text = item['url'], item.get('text','')
        if item.get('error'):
            # Context without logging signed query strings.
            self.emit('Page: '+urlunparse((*urlparse(url)[:3], '', '', '')))
            self.browser_needed.add(url)
        if not text or item.get('status',500)>=400 or access_block_reason(text) or kind in ('sitemap','robots'):
            return super().consume(item,depth,kind)
        digest = _va_hash.sha256(text.encode()).hexdigest()
        cache_key = _va_hash.sha256((url+_json_mod.dumps(self.recipe,sort_keys=True)).encode()).hexdigest()
        cacheable = self.journal and item.get('cacheable') and _va_safe_url(url)
        try:
            cached = self.journal.get('page',cache_key) if cacheable and self.options.get('incremental') else None
        except Exception:
            cached = None
        if cached and cached['hash']==digest:
            self.r['pages_scraped'] += 1
            self.metrics['unchanged_pages'] += 1
            for record in cached['sources']:
                self.add(record)
            for link in cached['links']:
                self.enqueue(link[0],depth+link[1],link[2])
            self.metadata[url] = cached['metadata']
            if cached.get('browser_needed'):
                self.browser_needed.add(url)
                self.render_targets.append(url)
            return
        start = time.monotonic()
        before = set(self.media)
        links = []
        def queue(target, offset=1, category='page'):
            full = normalise_url(target,url)
            self.enqueue(full,depth+offset,category)
            links.append([full,offset,category])
        try:
            # API/JS documents stay on the original extraction path.
            if kind != 'page' or '<' not in text or text.lstrip().startswith(('{','[')):
                return super().consume(item,depth,kind)
            select, content, attr = self._document(text)
            self.r['pages_scraped'] += 1
            self.add(item.get('record'))
            self.render_targets.append(url)
            raw = []
            _extract_from_raw(text.replace(r'\u002f','/'),url,raw,[],player_store=self.r['player_store'])
            for value in raw:
                self.add(identify_stream(value,source='page_source',frame_url=url))
            meta = {'page':url,'title':'','description':'','duration':'','thumbnail':''}
            for key, selector in {'title':'meta[property="og:title"]','description':'meta[property="og:description"]',
                    'duration':'meta[property="video:duration"]','thumbnail':'meta[property="og:image"]'}.items():
                nodes=select(self.recipe.get(key,selector))
                if nodes:
                    meta[key]=(attr(nodes[0],'content') or attr(nodes[0],'src') or content(nodes[0]))[:2000]
            if not meta['title']:
                nodes=select('title')
                if nodes: meta['title']=content(nodes[0])[:500]
            for node in select('script[type="application/ld+json"],script[type="application/json"]')[:100]:
                try:
                    payload=_json_mod.loads(content(node))
                    for record in extract_api_media(payload,url): self.add(record)
                    stack=[payload]; count=0
                    while stack and count<3000:
                        value=stack.pop();count+=1
                        if isinstance(value,list): stack.extend(value[:100])
                        elif isinstance(value,dict):
                            if 'VideoObject' in str(value.get('@type','')):
                                for dest,src in [('title','name'),('description','description'),('duration','duration'),('thumbnail','thumbnailUrl')]:
                                    val=value.get(src)
                                    if isinstance(val,str): meta[dest]=val[:2000]
                            stack.extend(v for v in value.values() if isinstance(v,(list,dict)))
                except (ValueError,RecursionError): pass
            self.metadata[url]=meta
            for selector,attribute,offset,category in [('a[href]','href',1,'page'),('iframe[src]','src',1,'page'),('script[src]','src',0,'script')]:
                for node in select(selector)[:1000]:
                    target=normalise_url(attr(node,attribute),url)
                    record=identify_stream(target,source='dom',frame_url=url)
                    if record: self.add(record)
                    else: queue(target,offset,category)
            for node in select(self.recipe.get('media','video[src],video source[src]'))[:200]:
                value=attr(node,'src') or attr(node,'href') or attr(node,'data-src')
                if value:
                    target=normalise_url(value,url)
                    record=identify_stream(target,{'content-type':attr(node,'type')},source='video_recipe',frame_url=url)
                    if record is None and target.startswith(('http://','https://')):
                        record={'url':target,'kind':'api_media_candidate','file_type':'unknown','mime':'','source':'video_recipe',
                            'frame_url':url,'confidence':'candidate','download_candidate':False,'evidence':['video selector']}
                    self.add(record)
            if self.recipe.get('next'):
                for node in select(self.recipe['next'])[:10]:
                    if attr(node,'href'): queue(attr(node,'href'),0)
            for match in re.finditer(r'''(?:fetch|axios\.get)\s*\(\s*["']([^"']+)["']''',text):
                if '/api/' in urlparse(normalise_url(match.group(1),url)).path: queue(match.group(1),0,'api')
            # Only skip rendering a fully static page with actual media sources.
            needs_browser=bool(select('script,iframe')) or not (self.media-before)
            if needs_browser: self.browser_needed.add(url)
            records=[dict(r) for r in self.r['stream_diagnostics'] if r.get('frame_url')==url]
            # Cache only complete, unsigned discoveries; otherwise refetch/reparse next time.
            if cacheable and all(_va_safe_url(r.get('url','')) for r in records) and all(_va_safe_url(v[0]) for v in links):
                safe_meta={**meta,'thumbnail':_va_safe_url(meta.get('thumbnail',''))}
                try:
                    self.journal.put('page',cache_key,{'hash':digest,'sources':records,'links':links,'metadata':safe_meta,'browser_needed':needs_browser})
                except Exception: self.emit('Local cache unavailable; continuing in memory.')
        finally:
            self.metrics['parse_seconds']=round(self.metrics['parse_seconds']+time.monotonic()-start,3)
            self.refresh_records()

    def refresh_records(self):
        records=[]
        for source in self.r['stream_diagnostics'][:5000]:
            if source.get('kind') in ('segment_candidate','mse_buffer','mse_source','browser_blob'): continue
            page=source.get('frame_url','')
            record={**self.metadata.get(page,{'page':page}), **{k:source.get(k,'') for k in ('url','kind','quality','source')}}
            records.append(record)
        self.r['video_records']=records

    def checkpoint(self):
        if not self.journal: return
        try:
            pending=[[v[2],v[3],v[4]] for v in self.frontier if _va_safe_url(v[2])]
            pending.extend([[u,0,'page'] for u in self.browser_needed if _va_safe_url(u) and u not in {v[0] for v in pending}])
            sources=[{k:v for k,v in r.items() if k in ('url','kind','file_type','mime','source','confidence','download_candidate','evidence','quality')}
                for r in self.r['stream_diagnostics'] if _va_safe_url(r.get('url',''))]
            self.journal.put('run',self.scan_id,{'url':_va_safe_url(self.url),'pending':pending,
                'visited':[u for u in self.visited if _va_safe_url(u) and u not in {v[0] for v in pending}],
                'sources':sources,'status':self.r['status']})
        except Exception:
            self.journal=None
            self.emit('Local checkpoint unavailable; scan continues in memory.')

    def discover(self, until=None):
        self.r['phase']='discovering'
        try:
            with ThreadPoolExecutor(max_workers=self.plan.workers) as pool:
                while self.frontier and self.active() and self.r['pages_scraped']<self.plan.pages and (until is None or time.monotonic()<until):
                    batch=[]
                    limit=self.window if self.options.get('adaptive_concurrency') else self.plan.workers
                    while self.frontier and len(batch)<min(limit,self.plan.pages-self.r['pages_scraped']):
                        _,_,url,depth,kind=heapq.heappop(self.frontier)
                        if url not in self.visited:
                            self.visited.add(url)
                            batch.append((url,pool.submit(self.fetch,url),depth,kind))
                    slow=False
                    for url,future,depth,kind in batch:
                        item=future.result()
                        if item.get('skip'):
                            self.visited.discard(url)
                            self.sequence+=1
                            heapq.heappush(self.frontier,(depth*10,self.sequence,url,depth,kind))
                        self.consume(item,depth,kind)
                        slow=slow or bool(item.get('error')) or item.get('status',200)>=400 or item.get('elapsed',0)>2
                        if item.get('status')==429:
                            self.emit('Host rate limit reached; scan stopped. Retry-After: '+str(item.get('headers',{}).get('Retry-After','not supplied'))[:60])
                    if batch:
                        self.window=max(1,self.window//2) if slow else min(self.plan.workers,self.window+1)
                    self.metrics['workers']=self.window
                    self.r['queue_size']=len(self.frontier)
                    self.checkpoint()
        finally: self.close_connections()

    def render(self):
        if not PLAYWRIGHT_OK: return super().render()
        targets=list(dict.fromkeys([self.url]+self.render_targets))
        if self.options.get('adaptive'):
            chosen=[u for u in targets if u in self.browser_needed or u not in self.visited]
            self.metrics['browser_skipped']+=len(targets)-len(chosen)
            targets=chosen
        if not targets: return
        start=time.monotonic()
        self.r['phase']='rendering'
        with sync_playwright() as pw:
            browser=_make_pw_browser(pw,headless=True)
            try:
                context=_make_pw_context(browser,cookies=_get_best_pw_cookies(self.url))
                def response_seen(response):
                    try:
                        if response.status==429: self.r['rate_limited']=True
                        if response.status>=400 or not self.active(): return
                        req=response.request
                        try: frame=req.frame.url
                        except Exception: frame=''
                        worker=bool(getattr(req,'service_worker',None))
                        if worker and not self.options.get('browser_channels'): return
                        if worker: self.metrics['worker_responses']+=1
                        source='worker_response' if worker else 'browser_response'
                        self.add(identify_stream(response.url,response.headers,source,req.resource_type,frame))
                        size=int(response.headers.get('content-length','0'))
                        if 'json' in response.headers.get('content-type','') and 0<size<=512000 and self.r['api_responses']<100:
                            body=response.body()
                            if len(body)<=512000:
                                for record in extract_api_media(_json_mod.loads(body),response.url): self.add(record)
                                self.r['api_responses']+=1
                    except Exception: pass
                context.on('response',response_seen)
                def finished(req):
                    try: self.metrics['browser_bytes']+=max(0,req.sizes()['responseBodySize'])
                    except Exception: pass
                context.on('requestfinished',finished)
                page=context.new_page()
                if self.options.get('browser_channels'):
                    def socket_open(socket):
                        def received(payload):
                            if not self.active() or self.metrics['websocket_messages']>=100 or not isinstance(payload,str) or len(payload)>65536: return
                            self.metrics['websocket_messages']+=1
                            try:
                                for record in extract_api_media(_json_mod.loads(payload),page.url):
                                    record['source']='websocket_json';self.add(record)
                            except (ValueError,RecursionError): pass
                        socket.on('framereceived',received)
                    page.on('websocket',socket_open)
                for target in targets[:self.plan.browser_pages]:
                    if not self.active(): break
                    try:
                        response=page.goto(target,wait_until='domcontentloaded',timeout=min(12000,max(1000,int((self.deadline-time.monotonic())*1000))))
                        if response and response.status in (401,403,429):
                            self.r['blocked_pages']+=1
                            continue
                        if access_block_reason(page.content()):
                            self.r['blocked_pages']+=1
                            continue
                        settled=0;last_count=-1; observation=time.monotonic()
                        while self.active():
                            for frame in list(page.frames):
                                if frame.is_detached(): continue
                                try:
                                    report=frame.evaluate('(play)=>window.__playerDiscovery?.sample(play)||null',self.plan.attempt_playback)
                                    if report:
                                        for player in report['players']:
                                            if player not in self.r['player_store']: self.r['player_store'].append(player)
                                        self.r.setdefault('playback_observations',{})[frame.url]=report['playback']
                                        for source in report['sources']:
                                            for record in extract_api_media({'sources':[{'file':source['url'],'type':source.get('mime','')}]},frame.url):
                                                record['source']='player_adapter:'+source['adapter'];self.add(record)
                                    for doc in frame.evaluate('()=>window.__apiDocuments?.snapshot()||[]'):
                                        for record in extract_api_media(_json_mod.loads(doc['text']),doc['url']): self.add(record)
                                    if self.plan.deep_js:
                                        deep=frame.evaluate(DEEP_RECOGNITION_SCRIPT)
                                        self.r.setdefault('deep_recognition',{})[frame.url]={k:v for k,v in deep.items() if k!='sources'}
                                        for source in deep['sources']:
                                            for record in extract_api_media({'sources':[{'file':source['url'],'type':source.get('mime','')}]},frame.url):
                                                record['source']=source['source'];self.add(record)
                                except Exception: pass
                            for value,base in extract_live_frame_urls(page,VIDEO_EXTRACTION_SCRIPT,[]):
                                self.add(identify_stream(normalise_url(value,base or target),source='rendered_dom',frame_url=base))
                            count=len(self.media)
                            settled=settled+1 if count==last_count else 0;last_count=count
                            elapsed=(time.monotonic()-observation)*1000
                            if elapsed>=self.plan.dwell_ms: break
                            if self.options.get('adaptive') and count and settled>=2 and elapsed>=750: break
                            page.evaluate('window.scrollBy(0,Math.min(innerHeight,900))')
                            page.wait_for_timeout(min(250,max(1,self.plan.dwell_ms-elapsed),max(1,(self.deadline-time.monotonic())*1000)))
                        collect_stream_snapshot(page,self.r['stream_diagnostics'],self.r['log'])
                        for frame in list(page.frames):
                            try:
                                frame.evaluate('()=>window.__playerDiscovery?.finish()')
                                drm=frame.evaluate('()=>window.__drmDiagnostics?.snapshot()||null')
                                if drm and (drm.get('events') or drm.get('keySystems')): self.r['drm_diagnostics'].append({'page':target,**drm})
                            except Exception: pass
                        for href in page.eval_on_selector_all('a[href]','els=>els.slice(0,500).map(e=>e.href)'): self.enqueue(href,1)
                        self.browser_needed.discard(target)
                    except Exception as exc:
                        self.r['requests_failed']+=1
                        self.emit(navigation_error(target,exc))
                    finally: self.r['browser_pages']+=1
            finally: browser.close()
        self.metrics['browser_seconds']=round(time.monotonic()-start,3)
        self.refresh_records()

    def run(self):
        try: super().run()
        finally:
            self.refresh_records()
            self.metrics['elapsed_seconds']=round(time.monotonic()-self.clock,3)
            self.checkpoint()


@app.route('/addons/start',methods=['POST'])
def video_addon_start():
    data=request.get_json(silent=True)
    try:
        if not isinstance(data,dict): raise ValueError('Send a JSON object')
        if data.get('source_type','website')!='website': raise ValueError('Video add-ons use website mode; API mode remains available in the original scanner')
        url=data.get('url','').strip()
        if '://' not in url: url='https://'+url
        _api_origin(url)
        options=data.get('addons',{})
        if not isinstance(options,dict): raise ValueError('Invalid add-on settings')
        opts={key:options.get(key) is True for key in ('adaptive','adaptive_concurrency','fast_parser','persist','incremental','browser_channels')}
        opts['recipe']=_va_recipe(options.get('recipe',{}))
        def number(key,default,low,high): return max(low,min(high,int(data.get(key,default))))
        plan=DiscoveryPlan(pages=number('page_limit',80,1,1000),depth=number('depth',3,0,8),workers=number('concurrency',3,1,6),
            browser_pages=number('browser_limit',8,1,50),dwell_ms=number('dwell_ms',1800,300,10000),seconds=number('time_limit_s',120,20,900),
            validate=not bool(data.get('skip_validate')),sitemap=bool(data.get('discover_sitemap',True)),browser=bool(data.get('render_browser',True)),
            attempt_playback=bool(data.get('attempt_playback',True)),deep_js=bool(data.get('deep_js')))
        resume=None
        if options.get('resume_id'):
            if not opts['persist']: raise ValueError('Enable local history to resume')
            resume=VideoJournal().get('run',str(options['resume_id']))
            if not resume or resume['url']!=url: raise ValueError('Saved scan does not match this URL')
        with _VA_LOCK:
            if sum(r.get('status') in ('running','validating') for r in scan_store.values())>=2:
                return jsonify(error='Two scans are already active'),409
            if len(scan_store)>=50:
                for key,value in list(scan_store.items()):
                    if value.get('status') not in ('running','validating'):
                        del scan_store[key];break
            scan_id=str(uuid.uuid4())[:12]
            scan_store[scan_id]={'status':'running','phase':'discovering','cancel_requested':False,'mp4_links':[],
                'broken_links':[],'validation_results':{},'stream_diagnostics':[],'drm_diagnostics':[],
                'manifest_store':{},'player_store':[],'log':['Optional video discovery add-ons enabled.'],
                'pages_scraped':0,'sitemap_size':0,'source_type':'website'}
            engine=VideoAddonEngine(scan_id,url,plan,opts,resume)
            threading.Thread(target=engine.run,daemon=True).start()
        return jsonify(scan_id=scan_id)
    except Exception as exc:
        return jsonify(error=str(exc)[:200]),400


@app.route('/addons/status/<scan_id>')
def video_addon_status(scan_id):
    result=scan_store.get(scan_id)
    if not result: return jsonify(error='Unknown scan'),404
    return jsonify(metrics=result.get('addon_metrics',{}),records=result.get('video_records',[]))


@app.route('/addons/export/<scan_id>')
def video_addon_export(scan_id):
    from flask import Response
    result=scan_store.get(scan_id)
    if not result: return jsonify(error='Unknown scan'),404
    fields=[k for k in request.args.get('fields',','.join(_VA_FIELDS)).split(',') if k in _VA_FIELDS]
    records=[{k:r.get(k,'') for k in fields} for r in result.get('video_records',[])]
    fmt=request.args.get('format','json')
    if fmt=='json': body,mime=_json_mod.dumps(records,indent=2),'application/json'
    elif fmt=='csv':
        output=_va_io.StringIO(newline='');writer=_va_csv.DictWriter(output,fieldnames=fields);writer.writeheader()
        for record in records:
            writer.writerow({k:("'"+str(v) if str(v).lstrip().startswith(('=','+','-','@')) else v) for k,v in record.items()})
        body,mime=output.getvalue(),'text/csv'
    else: return jsonify(error='Choose CSV or JSON'),400
    return Response(body,mimetype=mime,headers={'Content-Disposition':f'attachment; filename="videos-{scan_id}.{fmt}"'})


@app.route('/addons/history',methods=['GET','DELETE'])
def video_addon_history():
    journal=VideoJournal()
    if request.method=='DELETE': journal.clear();return jsonify(ok=True)
    if not _VAPath(journal.path).exists(): return jsonify(runs=[],recipes=[])
    return jsonify(runs=[{k:r.get(k) for k in ('id','url','updated','status')} for r in journal.items('run')],recipes=journal.items('recipe'))


@app.route('/addons/recipes',methods=['POST'])
def video_addon_recipe_save():
    try:
        data=request.get_json(silent=True) or {}
        origin=_api_origin(data.get('url',''))
        recipe=_va_recipe(data.get('recipe',{}))
        key=_json_mod.dumps(origin)
        VideoJournal().put('recipe',key,{'origin':list(origin),'recipe':recipe})
        return jsonify(ok=True)
    except Exception: return jsonify(error='Provide a valid site URL and CSS selectors'),400


"""Separate, opt-in TeraBox share resolver. Embedded in app.py."""
from http.cookies import SimpleCookie as _TBCookie
from html import escape as _tb_escape
from pathlib import Path as _TBPath
from tempfile import NamedTemporaryFile as _tb_tempfile
from urllib.parse import parse_qs as _tb_query

_TB_PROVIDERS = {
    'iteraplay_com': 'https://iteraplay.com/api/stream',
    'iteraplay_in': 'https://iteraplay.in/api/videos/import',
    'xapiverse': 'https://xapiverse.com/api/terabox',
}
_TB_SLOTS = threading.BoundedSemaphore(2)
_TB_DOMAINS = ('terabox.com','1024terabox.com','terabox.app')
_TB_HOME = 'https://www.1024terabox.com/'
_TB_SESSION_LOCK = threading.Lock()
_TB_ACTIVE_SAVE = None


def _tb_session_path():
    if os.name != 'nt' or not os.environ.get('LOCALAPPDATA'):
        raise OSError('Windows user storage unavailable')
    return _TBPath(os.environ['LOCALAPPDATA']) / 'Source Studio' / 'terabox-session.bin'


def _tb_protect(data, decrypt=False):
    """Use Windows DPAPI with the current user's scope and no system prompts."""
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('pointer', ctypes.c_void_p)]

    buffer = ctypes.create_string_buffer(data)
    incoming = Blob(len(data), ctypes.addressof(buffer))
    outgoing = Blob()
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    operation = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    if not operation(ctypes.byref(incoming), None, None, None, None, 1, ctypes.byref(outgoing)):
        raise ctypes.WinError(ctypes.get_last_error())
    free = ctypes.WinDLL('kernel32').LocalFree
    free.argtypes = [ctypes.c_void_p]
    free.restype = ctypes.c_void_p
    try:
        return ctypes.string_at(outgoing.pointer, outgoing.size)
    finally:
        free(outgoing.pointer)


def _tb_save_session(cookies, user_agent=''):
    path = _tb_session_path()
    payload = {'cookies':cookies,'user_agent':user_agent} if user_agent else cookies
    encrypted = _tb_protect(_json_mod.dumps(payload).encode('utf-8'))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with _tb_tempfile(dir=path.parent, delete=False) as output:
            temporary = _TBPath(output.name)
            output.write(encrypted)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _tb_load_session(with_user_agent=False):
    user_agent = ''
    try:
        payload = _json_mod.loads(_tb_protect(_tb_session_path().read_bytes(), decrypt=True))
        if isinstance(payload,dict):
            user_agent = payload.get('user_agent','')
            payload = payload['cookies']
        cookies = [cookie for cookie in payload if _tb_cookie_domain(cookie['domain'])
                   and (cookie.get('expires', -1) <= 0 or cookie['expires'] > time.time())]
    except FileNotFoundError:
        cookies = []
    return (cookies,user_agent) if with_user_agent else cookies


class _TBInputError(ValueError):
    pass


def _tb_cookie_domain(domain):
    domain=domain.lower().lstrip('.')
    return any(domain==root or domain.endswith('.'+root) for root in _TB_DOMAINS)


def _tb_cookie_matches_host(domain,host):
    domain = domain.lower()
    return host==domain.lstrip('.') or (domain.startswith('.') and host.endswith(domain))


def _tb_cookies(raw,host='terabox.com'):
    """Preserve exported scope; never transplant unrelated-site credentials."""
    if not isinstance(raw,str) or len(raw)>16000:
        raise _TBInputError('Cookie input must be text under 16 KB. Export only TeraBox cookies.')
    raw=raw.strip()
    if not raw:return []
    rows=[]
    if raw.startswith(('[','{')):
        try:
            payload=_json_mod.loads(raw)
            rows=payload.get('cookies',[]) if isinstance(payload,dict) else payload
            if not isinstance(rows,list):raise ValueError()
        except (ValueError,RecursionError):raise _TBInputError('Invalid JSON cookie export.')
    elif '\t' in raw or '\n' in raw:
        for line in raw.splitlines():
            line=line.strip()
            if not line or (line.startswith('#') and not line.startswith('#HttpOnly_')):continue
            parts=line.split('\t')
            if len(parts)>=7 and parts[1].upper() in ('TRUE','FALSE'):
                domain=parts[0].removeprefix('#HttpOnly_')
                rows.append({'domain':domain if parts[1].upper()=='TRUE' else domain.lstrip('.'),
                    'name':parts[5],'value':parts[6],'path':parts[2],
                    'expires':int(parts[4]) if parts[4].isdigit() else -1,
                    'secure':parts[3].upper()=='TRUE','httpOnly':parts[0].startswith('#HttpOnly_')})
            elif len(parts)>=4 and '.' in parts[2]:
                rows.append({'name':parts[0],'value':parts[1],'domain':parts[2],
                    'path':parts[3],'secure':len(parts)>7 and parts[7]=='✓','httpOnly':len(parts)>6 and parts[6]=='✓'})
            else:raise _TBInputError('Unrecognized cookie table. Use JSON, Netscape cookies.txt, or tab-separated browser cookie rows.')
    else:
        if host is None:
            raise _TBInputError('Upload a cookie export that includes the original domains.')
        if '\r' in raw:raise _TBInputError('Invalid Cookie header.')
        jar=_TBCookie()
        try:jar.load(raw)
        except Exception:raise _TBInputError('Invalid Cookie header.')
        if not jar:raise _TBInputError('Use name=value; name2=value2 or a domain-scoped cookie export.')
        rows=[{'name':name,'value':v.value,'domain':host,'path':'/','secure':True} for name,v in jar.items()]
    accepted={}
    for row in rows[:300]:
        if not isinstance(row,dict):raise _TBInputError('Each exported cookie must be an object.')
        domain=row.get('domain','')
        if not isinstance(domain,str) or not _tb_cookie_domain(domain):continue
        domain=domain.lower()
        if row.get('hostOnly') is True:domain=domain.lstrip('.')
        name,value,path=row.get('name'),row.get('value'),row.get('path','/')
        if not all(isinstance(v,str) for v in (name,value,path)) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",name) or any(c in value for c in ('\r','\n','\x00')) or not path.startswith('/'):
            raise _TBInputError('Invalid TeraBox cookie fields.')
        cookie={'name':name,'value':value,'domain':domain,'path':path,
                'secure':row.get('secure',True) is True,'httpOnly':row.get('httpOnly',False) is True}
        same=row.get('sameSite','')
        if isinstance(same,str) and same.lower() in ('strict','lax','none'):
            cookie['sameSite']=same.title()
        expiry=row.get('expirationDate',row.get('expires'))
        if isinstance(expiry,(int,float)) and expiry>0:
            if expiry<=time.time():continue
            cookie['expires']=expiry
        accepted[(domain,path,name)]=cookie
    if not accepted:raise _TBInputError('No usable TeraBox cookies found. Unrelated domains and expired cookies are excluded; export cookies from the actual TeraBox page.')
    return list(accepted.values())


def _tb_sources(payload,base):
    """Extract only recognized media fields, not the entire private API response."""
    found={}; stack=[(payload,'',0)]; nodes=0
    while stack and nodes<10000 and len(found)<250:
        value,field,depth=stack.pop();nodes+=1
        if depth>20: continue
        if isinstance(value,dict):
            for key,child in list(value.items())[:200]:
                if re.search(r'token|cookie|secret|password|authorization|license|drmkey',key,re.I): continue
                label=field if field in ('fast_stream_url','stream_url','quality') else key
                stack.append((child,label,depth+1))
        elif isinstance(value,list):
            stack.extend((child,field,depth+1) for child in value[:250])
        elif isinstance(value,str) and value.startswith(('https://','http://')):
            try:
                _api_origin(value)
            except ValueError: continue
            if field not in ('fast_stream_url','stream_url','fast_dlink','normal_dlink','download_link','url','contentUrl','quality'): continue
            record=identify_stream(value,source='terabox_resolver',frame_url=base)
            if not record and field not in ('url','quality'):
                record={'url':value,'kind':'media_candidate','file_type':'unknown','confidence':'candidate','source':'terabox_resolver'}
            if record:
                record['field']=field;found[value]=record
    return list(found.values())


def _tb_playback_headers(browser_request):
    names = ('user-agent','referer','origin','accept','accept-language','cookie')
    return {key.lower():value for key,value in browser_request.all_headers().items() if key.lower() in names}


def _tb_original_download(page,context):
    """Observe the site's ordinary Download control without saving the file."""
    if not _tb_cookie_domain(urlparse(page.url).hostname or ''):
        return None
    name = re.compile(r'^download(?: (?:video|file))?$',re.I)
    control = (_tb_visible_one(page.get_by_role('button',name=name))
               or _tb_visible_one(page.get_by_role('link',name=name))
               or _tb_visible_one(page.get_by_text(name)))
    if control is None or not control.is_enabled():
        return None
    requests_by_url = {}
    downloads = []

    def observe_request(browser_request):
        if browser_request.method == 'GET' and _tb_media_host(browser_request.url) and len(requests_by_url)<100:
            requests_by_url[browser_request.url] = browser_request

    def observe_download(download):
        filename = download.suggested_filename
        if _tb_media_host(download.url) and re.search(r'\.(?:mp4|mkv|webm|mov|m4v|avi|wmv|flv|mpeg|mpg)$',filename,re.I):
            downloads.append((download.url,filename))

    context.on('request',observe_request)
    page.on('download',observe_download)
    try:
        control.click(timeout=1500)
        for _ in range(8):
            if downloads:
                url,filename = downloads[0]
                browser_request = requests_by_url.get(url)
                if browser_request is not None:
                    return {'url':url,'kind':'video_download','name':filename},_tb_playback_headers(browser_request)
                return None
            page.wait_for_timeout(250)
    except PWTimeout:
        pass
    finally:
        page.remove_listener('download',observe_download)
        context.remove_listener('request',observe_request)
    return None


def _tb_visible_one(locator):
    if locator.count()>12:
        return None
    visible = [item for item in locator.all() if item.is_visible()]
    return visible[0] if len(visible)==1 else None


_TB_FULL_VIDEO_PROMPT = 'Save to TeraBox to watch the full video'
_TB_FULL_VIDEO_SIGN_IN = 'TeraBox asked you to sign in for the full video. This saved session could only access the preview.'


def _tb_login_gate(page):
    return (_tb_cookie_domain(urlparse(page.url).hostname or '')
            and page.locator('.login-dialog').first.is_visible())


def _tb_preview_save_prompt(page, wait_for_preview_end):
    prompt = page.get_by_text(_TB_FULL_VIDEO_PROMPT,exact=True).first
    if prompt.is_visible():
        return True
    if not wait_for_preview_end:
        return False
    # The share player reveals the save prompt only after the preview ends.
    for _ in range(8):
        seeked = page.locator('video').evaluate_all('''videos => {
            const video = videos.find(item => item.getClientRects().length &&
                item.duration >= 29 && item.duration <= 31 && item.seekable.length &&
                item.seekable.end(item.seekable.length - 1) >= item.duration - 1);
            if (!video) return false;
            video.currentTime = Math.min(video.duration, video.seekable.end(video.seekable.length - 1)) - 0.25;
            video.muted = true;
            video.play().catch(() => {});
            return true;
        }''')
        if seeked:
            try:
                prompt.wait_for(state='visible',timeout=5500)
                return True
            except PWTimeout:
                return False
        page.wait_for_timeout(300)
    return False


def _tb_save_preview_and_download(page,context):
    """Follow the provider's save and file controls for one identified video."""
    pattern = re.compile(r'^[^\r\n]{1,240}\.(?:mp4|mkv|webm|mov|m4v|avi|wmv|flv|mpeg|mpg)$',re.I)
    names = {name.strip() for name in page.get_by_text(pattern).all_inner_texts() if pattern.fullmatch(name.strip())}
    if not names:
        title = page.title().strip()
        if pattern.fullmatch(title):
            names.add(title)
    if len(names)!=1:
        return None,'TeraBox did not identify a single video to save.'
    filename = names.pop()
    save = _tb_visible_one(page.get_by_role('button',name='Save',exact=True))
    if save is None:
        save = _tb_visible_one(page.get_by_text('Save',exact=True))
    if save is None:
        save = _tb_visible_one(page.get_by_role('button',name=re.compile(r'^save to terabox$',re.I)))
    if save is None:
        return None,'TeraBox did not show a single Save control for the preview.'
    save.click(timeout=1500)

    success = re.compile(r'^(?:(?:file )?saved(?: to (?:my )?terabox)? successfully|save successful|save success|file saved|saved to my terabox)[.!]?$',re.I)
    account_link = re.compile(r'^(?:view (?:saved )?file|view in terabox|go to (?:my )?terabox|my terabox)$',re.I)
    confirmed = False
    saved = False
    for _ in range(16):
        if _tb_login_gate(page):
            return None,_TB_FULL_VIDEO_SIGN_IN
        if page.get_by_text(success).first.is_visible():
            saved = True
            break
        if not confirmed:
            dialog = _tb_visible_one(page.get_by_role('dialog').filter(has_text=re.compile(r'Save to:\s*My TeraBox',re.I)))
            if dialog is not None:
                confirm = _tb_visible_one(dialog.get_by_role('button',name=re.compile(r'^(?:save|save here|confirm)$',re.I)))
                if confirm is not None:
                    confirm.click(timeout=1500)
                    confirmed = True
        page.wait_for_timeout(250)
    if not saved:
        return None,'The save was requested, but TeraBox did not confirm it. Check your account before trying again.'

    link = _tb_visible_one(page.get_by_role('link',name=account_link))
    if link is None:
        link = _tb_visible_one(page.get_by_role('button',name=account_link))
    if link is None:
        link = _tb_visible_one(page.get_by_text(account_link))
    if link is None:
        return None,'TeraBox confirmed the save. Open My TeraBox to download the file.'
    previous_pages = set(context.pages)
    link.click(timeout=1500)
    for _ in range(16):
        new_pages = [tab for tab in context.pages if tab not in previous_pages and _tb_cookie_domain(urlparse(tab.url).hostname or '')]
        account = new_pages[0] if len(new_pages)==1 else page
        if _tb_cookie_domain(urlparse(account.url).hostname or ''):
            file = _tb_visible_one(account.get_by_text(filename,exact=True))
            if file is not None and (account is not page or not account.get_by_text(_TB_FULL_VIDEO_PROMPT,exact=True).first.is_visible()):
                file.click(timeout=1500)
                account.wait_for_timeout(300)
                original = _tb_original_download(account,context)
                if original and original[0]['name']==filename:
                    return original,'TeraBox saved the video and offered the original file.'
                break
        account.wait_for_timeout(250)
    return None,'TeraBox confirmed the save, but the original download was not captured. Open My TeraBox to download the saved file.'


@isolated_browser_thread
def _tb_direct(share,cookies,interactive=False,save_signal=None,auto_session=False,user_agent='',save_preview_to_account=False):
    if not PLAYWRIGHT_OK: return {'error':'Install Playwright and Chromium to use direct mode.'},503
    save_session = save_signal is not None
    sources={};count=0
    media_seen_at = None
    last_track_at = None
    share_errors = {}
    failed_media_urls = set()
    relay_responses = {}
    with sync_playwright() as pw:
        browser=_make_pw_browser(pw,headless=not interactive)
        try:
            # Fresh context: never inherit another site's cookies or resolver tokens.
            options = {'user_agent':user_agent} if user_agent else {}
            if auto_session:
                options['accept_downloads'] = False
            context=browser.new_context(**options)
            if cookies: context.add_cookies(cookies)
            def observed(response):
                nonlocal count, media_seen_at, last_track_at
                if len(sources)>=250 or response.status>=400: return
                try:
                    parts = urlparse(response.url)
                    trusted_share = (parts.path.startswith(('/share/','/sharing/','/api/share/')) and
                                     (_tb_cookie_domain(parts.hostname or '') or parts.hostname=='dm.1024tera.com'))
                    if 'json' in response.headers.get('content-type','').lower():
                        json_allowed = not interactive or trusted_share or _tb_cookie_domain(parts.hostname or '')
                        if not json_allowed or count>=80:
                            return
                        size = int(response.headers.get('content-length','0'))
                        if not size and trusted_share:
                            size = response.request.sizes().get('responseBodySize',0)
                        if 0<size<=512000:
                            count+=1
                            body=response.body()
                            if len(body)<=512000:
                                payload = _json_mod.loads(body)
                                errno = payload.get('errno') if isinstance(payload,dict) else None
                                if trusted_share and re.fullmatch(r'-?[1-9][0-9]{0,8}',str(errno)):
                                    share_errors[parts.path == '/share/streaming'] = int(errno)
                                    if parts.path == '/share/streaming':
                                        failed_media_urls.add(response.url)
                                        sources.pop(response.url,None)
                                        relay_responses.pop(response.url,None)
                                    return
                                for record in extract_api_media(payload,response.url):
                                    sources.setdefault(record['url'],record)
                        return
                    record=identify_stream(response.url,response.headers,source='terabox_browser')
                    if record:
                        failed_media_urls.discard(response.url)
                        if parts.path == '/share/streaming':
                            stream_type = _tb_query(parts.query).get('type', [''])[0]
                            quality = re.fullmatch(r'M3U8_FLV_\d+_(\d{3,4})', stream_type)
                            if quality:
                                record['quality'] = quality[1] + 'p'
                            elif stream_type.startswith('M3U8_SUBTITLE'):
                                record['kind'] = 'subtitle_track'
                        is_new = record['url'] not in sources
                        sources[record['url']]=record
                        if auto_session and 200<=response.status<300 and record['kind']!='dash_manifest' and _tb_media_host(response.url):
                            relay_responses.setdefault(response.url,response)
                        if auto_session and is_new and record['kind'] in (
                                'hls_manifest','dash_manifest','media_file_candidate','ranged_media','subtitle_track'):
                            try:
                                frame_host = urlparse(response.request.frame.url).hostname or ''
                            except Exception:
                                frame_host = ''
                            if _tb_cookie_domain(frame_host) or _tb_cookie_domain(parts.hostname or ''):
                                last_track_at = time.monotonic()
                                if media_seen_at is None and record['kind'] != 'subtitle_track':
                                    media_seen_at = last_track_at
                except Exception: pass
            if not save_session:
                context.on('response',observed)
            page=context.new_page();page.set_default_timeout(5000)
            navigation_issue = ''
            try:
                response = page.goto(share, wait_until='commit' if interactive or auto_session else 'domcontentloaded',
                                     timeout=12000 if interactive or auto_session else 20000)
            except Exception as exc:
                if not interactive:
                    raise
                if page.is_closed() or not browser.is_connected():
                    return {'sources':list(sources.values())[:250],
                            'message':'The capture window closed during navigation.'},200
                error = str(exc).lower()
                if 'err_name_not_resolved' in error:
                    navigation_issue = 'The browser could not resolve the share hostname.'
                elif 'proxy' in error or 'tunnel' in error:
                    navigation_issue = 'The browser could not reach TeraBox through its proxy.'
                elif 'timeout' in error or 'timed out' in error:
                    navigation_issue = 'The share did not load within 12 seconds.'
                else:
                    navigation_issue = 'The browser could not open the share automatically.'
                response = None
                # Recover in the same cookie context after a failed navigation.
                page.goto('about:blank', timeout=5000)
                page.set_content(
                    '<title>TeraBox capture</title><main style="font:18px system-ui;margin:3rem">'
                    '<h1>Open your TeraBox share</h1>'
                    f'<p>{navigation_issue}</p><p><a href="{_tb_escape(share, quote=True)}">'
                    'Retry opening the share</a></p>'
                    '<p><a href="https://www.1024terabox.com/">Open TeraBox homepage to sign in</a></p>'
                    '<p>After signing in, paste the full share URL into this window’s address bar. '
                    + ('Play the video and the resolver will close this window when it detects media.' if auto_session
                       else 'Play the video, then close this window to see captured links.') + '</p></main>'
                )
            if response and response.status in (401,403,429):
                if not interactive:
                    return {'error':'TeraBox denied access or rate-limited this session.','upstream_status':response.status},502
                navigation_issue = f'TeraBox returned HTTP {response.status} when opening the share.'

            def attach_relay(captures):
                if captures and browser.is_connected():
                    playback_cookies = [cookie for cookie in context.cookies()
                                        if _tb_media_host('https://'+cookie['domain'].lstrip('.'))]
                    _tb_attach_media_relay(sources,captures,playback_cookies)

            download_sign_in = False
            if save_preview_to_account:
                try:
                    page.wait_for_load_state('domcontentloaded',timeout=2000)
                    original = _tb_original_download(page,context)
                    if original:
                        source,headers = original
                        sources = {source['url']:source}
                        attach_relay({source['url']:(headers,None)})
                        return {'sources':[source],'message':'TeraBox offered a direct video download.'},200
                except Exception:
                    pass
                try:
                    download_sign_in = _tb_login_gate(page)
                    if download_sign_in:
                        # Download can open a login overlay over the preview's separate Save control.
                        sources.clear()
                        relay_responses.clear()
                        share_errors.clear()
                        failed_media_urls.clear()
                        media_seen_at = last_track_at = None
                        page.reload(wait_until='domcontentloaded',timeout=8000)
                except Exception:
                    pass

            def collect_dom():
                for value,base in extract_live_frame_urls(page,VIDEO_EXTRACTION_SCRIPT,[]):
                    record=identify_stream(normalise_url(value,base or share),source='terabox_dom',frame_url=base)
                    if record and record['url'] not in failed_media_urls:
                        sources.setdefault(record['url'],record)

            if interactive or auto_session:
                deadline=time.monotonic()+(180 if interactive else 15)
                session_cookies = []
                play_clicked_on = None
                while browser.is_connected() and not page.is_closed() and time.monotonic()<deadline:
                    try:
                        if save_session:
                            session_cookies = [cookie for cookie in context.cookies()
                                               if _tb_cookie_domain(cookie['domain'])]
                            if save_signal.is_set():
                                break
                        page.wait_for_timeout(400 if auto_session else 1000 if save_session else 2000)
                        if not save_session and _tb_cookie_domain(urlparse(page.url).hostname or ''):
                            if auto_session and media_seen_at is None:
                                try:
                                    playing = page.locator('video').evaluate_all('''videos => {
                                        const attempted = window.__sourceStudioTeraPlay ??= new WeakSet();
                                        const video = videos.find(item => item.getClientRects().length &&
                                            (item.currentSrc || item.src || item.querySelector('source[src]')));
                                        if (video?.paused && !attempted.has(video)) {
                                            attempted.add(video);
                                            video.muted = true;
                                            video.play().catch(() => {});
                                        }
                                        return Boolean(video && !video.paused);
                                    }''')
                                    if not playing and play_clicked_on != page.url:
                                        play = page.get_by_role('button', name=re.compile(r'^play(?: video)?$',re.I))
                                        if play.count() == 1 and play.is_visible():
                                            play_clicked_on = page.url
                                            try:
                                                play.click(timeout=800)
                                            except PWTimeout:
                                                play.evaluate('''button => {
                                                    if (button.matches(':disabled,[aria-disabled="true"]')) return;
                                                    const rect = button.getBoundingClientRect();
                                                    const top = document.elementFromPoint(rect.x + rect.width/2, rect.y + rect.height/2);
                                                    if (button.contains(top)) button.click();
                                                }''',timeout=800)
                                except Exception:
                                    # Sign-in and share redirects can replace the document mid-scan.
                                    pass
                            collect_dom()
                        now = time.monotonic()
                        tracks_settled = media_seen_at is not None and (
                            (now-media_seen_at>=1.6 and now-last_track_at>=0.8) or now-media_seen_at>=4)
                        if auto_session and tracks_settled:
                            break
                    except Exception:
                        if page.is_closed() or not browser.is_connected():break
                        raise
                if auto_session and media_seen_at is not None:
                    captures = {}
                    cached_playlists = 0
                    for url, captured in relay_responses.items():
                        try:
                            headers = _tb_playback_headers(captured.request)
                            body = None
                            captures[url] = (headers,body)
                            if sources[url]['kind'] in ('hls_manifest','subtitle_track') and cached_playlists<12:
                                size = int(captured.headers.get('content-length','0')) or captured.request.sizes().get('responseBodySize',0)
                                if 0<size<=512000:
                                    data = captured.body()
                                    if len(data)<=512000:
                                        snapshot,duration = _tb_playlist_snapshot(data)
                                        captures[url] = (headers,snapshot)
                                        if duration is not None and sources[url]['kind']=='hls_manifest':
                                            sources[url]['duration_seconds'] = duration
                                        cached_playlists += 1
                        except Exception:
                            continue
                    measured = [source['duration_seconds'] for source in sources.values()
                                if source.get('duration_seconds') is not None]
                    short_playlist = bool(measured) and max(measured)<=31
                    preview_notice = False
                    try:
                        preview_notice = _tb_preview_save_prompt(page,False)
                    except Exception:
                        pass
                    original = None
                    save_status = ''
                    if (short_playlist or preview_notice) and browser.is_connected() and not page.is_closed():
                        if not download_sign_in:
                            try:
                                original = _tb_original_download(page,context)
                            except Exception:
                                pass
                        if original is None and save_preview_to_account and not preview_notice and short_playlist and max(measured)>=29:
                            try:
                                preview_notice = _tb_preview_save_prompt(page,True)
                            except Exception:
                                pass
                        if original is None and save_preview_to_account and preview_notice:
                            try:
                                if _tb_login_gate(page):
                                    save_status = _TB_FULL_VIDEO_SIGN_IN
                                else:
                                    original,save_status = _tb_save_preview_and_download(page,context)
                            except Exception:
                                save_status = 'The TeraBox save flow did not complete. Check your account before trying again.'
                    if download_sign_in and not original and not save_status:
                        save_status = _TB_FULL_VIDEO_SIGN_IN
                        if original:
                            source,headers = original
                            sources = {source['url']:source,**{url:record for url,record in sources.items() if url!=source['url']}}
                            captures[source['url']] = (headers,None)
                    try:
                        attach_relay(captures)
                    except Exception:
                        pass
                    result = {'sources':list(sources.values())[:250],
                              'message':'Media detected using your saved session.'}
                    if original:
                        result['message'] = save_status or 'TeraBox offered a video file through its Download control.'
                    elif short_playlist or preview_notice:
                        result['message'] = save_status or ('The longest measured playlist is short. No original video download was captured.'
                                             if short_playlist else 'TeraBox shows a full-video prompt. No original video download was captured.')
                        result['full_video_share'] = share
                    return result,200
                if save_session:
                    if not save_signal.is_set() and browser.is_connected() and not page.is_closed():
                        return {'error':'Sign-in timed out. Start again and click Save cookies and close browser after signing in.'},408
                    if not session_cookies:
                        return {'error':'No TeraBox cookies were captured. Sign in before clicking Save cookies and close browser.'},422
                    _tb_save_session(session_cookies)
                    return {'message':'TeraBox cookies saved for this Windows account. Select Use saved TeraBox session for your next share.'},200
                if auto_session:
                    sources = {url: record for url, record in sources.items() if url.startswith(('https://','http://'))}
                    if not sources and not page.is_closed():
                        host = urlparse(page.url).hostname or ''
                        if cookies and _tb_cookie_domain(host) and not any(_tb_cookie_matches_host(cookie['domain'],host) for cookie in cookies):
                            return {'sources':[], 'cookie_host':host, 'full_video_share':share,
                                    'message':f'The share opened on {host}, but no saved cookies match that host. Open the original share and export cookies after playback works there.'},200
                    if share_errors and not sources:
                        errno = share_errors.get(True) or share_errors[False]
                        return {'sources':[], 'upstream_errno':errno,
                                'message':f'TeraBox returned error {errno} while resolving the share.'},200
                message='Observed media candidates. Playback outside this browser session may require the same session.' if sources else 'No media observed before the window closed or the capture expired. Try again and start the video in the TeraBox window.'
                if auto_session and not sources:
                    message = 'TeraBox loaded, but the scan did not observe a playable media URL.'
                    if download_sign_in:
                        message = _TB_FULL_VIDEO_SIGN_IN
                    if browser.is_connected() and not page.is_closed():
                        try:
                            if page.get_by_text(re.compile(r'^(?:please )?(?:sign|log) in to (?:watch|play)\b',re.I)).first.is_visible():
                                message = 'TeraBox is asking for sign-in to play this share. Replace the saved cookies with a fresh export from a session that can play it.'
                            elif page.locator('input[type="password"]').first.is_visible():
                                message = 'TeraBox displayed a password field. The saved cookies alone did not unlock playback.'
                        except Exception:
                            pass
                if not sources and navigation_issue:
                    message=f'{navigation_issue} {message}'
                return {'sources':list(sources.values())[:250],'message':message},200
            page.wait_for_timeout(3500)
            collect_dom()
            return {'sources':list(sources.values())[:250], 'message':'Observed media candidates; playback was not verified.' if sources else 'No media observed. The page may require login, a share password, verification or manual playback. Direct mode does not synthesize private API tokens.'},200
        finally:
            if browser.is_connected():browser.close()


@app.route('/terabox')
def terabox_page():
    return TERABOX_PAGE


@app.route('/terabox/session', methods=['POST', 'DELETE'])
def terabox_session():
    global _TB_ACTIVE_SAVE
    if not _TB_SESSION_LOCK.acquire(blocking=False):
        return jsonify(error='A TeraBox sign-in is already in progress.'),409
    try:
        path = _tb_session_path()
        if request.method == 'DELETE':
            path.unlink(missing_ok=True)
            return jsonify(message='Saved TeraBox session cleared.')
        data = request.get_json(silent=True)
        job_id = data.get('job_id') if isinstance(data,dict) else None
        if not isinstance(job_id,str) or not re.fullmatch(r'[a-f0-9-]{36}',job_id):
            return jsonify(error='Reload the resolver page and start sign-in again.'),400
        if not _TB_SLOTS.acquire(blocking=False):
            return jsonify(error='Two resolutions are already active. Try again shortly.'),429
        try:
            save_signal = threading.Event()
            _TB_ACTIVE_SAVE = (job_id, save_signal)
            result, status = _tb_direct(_TB_HOME, [], interactive=True, save_signal=save_signal)
            return jsonify(result),status
        finally:
            _TB_ACTIVE_SAVE = None
            _TB_SLOTS.release()
    except Exception:
        return jsonify(error='Could not manage the saved TeraBox session. Check Chromium and Windows user storage.'),502
    finally:
        _TB_SESSION_LOCK.release()


@app.route('/terabox/session/finish', methods=['POST'])
def terabox_session_finish():
    data = request.get_json(silent=True)
    active = _TB_ACTIVE_SAVE
    if not active or not isinstance(data,dict) or data.get('job_id') != active[0]:
        return jsonify(error='This sign-in window is no longer active. Start sign-in again.'),409
    active[1].set()
    return jsonify(message='Saving TeraBox cookies and closing the browser…')


@app.route('/terabox/session/import', methods=['POST'])
def terabox_session_import():
    if not _TB_SESSION_LOCK.acquire(blocking=False):
        return jsonify(error='Wait for the current TeraBox scan to finish, then upload again.'),409
    try:
        user_agent = request.headers.get('X-TeraBox-User-Agent','').strip()
        if user_agent and not re.fullmatch(r'[ -~]{1,512}',user_agent):
            return jsonify(error='Enter a single browser User-Agent under 512 characters.'),400
        raw = request.stream.read(16001)
        if len(raw)>16000:
            return jsonify(error='Export only TeraBox cookies, up to 16 KB.'),413
        cookies = _tb_cookies(raw.decode('utf-8-sig'),host=None)
        if not cookies:
            return jsonify(error='The cookie export is empty.'),400
        _tb_save_session(cookies,user_agent)
        return jsonify(message=f'Saved {len(cookies)} TeraBox cookies for future scans.')
    except _TBInputError as exc:
        return jsonify(error=str(exc)),400
    except UnicodeDecodeError:
        return jsonify(error='Use a UTF-8 cookie export.'),400
    except OSError:
        return jsonify(error='Windows could not save the cookie file.'),502
    finally:
        _TB_SESSION_LOCK.release()


@app.route('/terabox/session/user-agent', methods=['POST'])
def terabox_session_user_agent():
    data = request.get_json(silent=True)
    user_agent = data.get('user_agent') if isinstance(data,dict) else None
    if not isinstance(user_agent,str) or not re.fullmatch(r'[ -~]{0,512}',user_agent):
        return jsonify(error='Enter a single User-Agent of up to 512 characters.'),400
    if not _TB_SESSION_LOCK.acquire(blocking=False):
        return jsonify(error='Wait for the current TeraBox scan to finish.'),409
    try:
        cookies = _tb_load_session()
        if not cookies:
            return jsonify(error='Upload a usable TeraBox cookie export first.'),422
        _tb_save_session(cookies,user_agent.strip())
        return jsonify(message='User-Agent updated for your saved TeraBox cookies.')
    except (OSError, ValueError):
        return jsonify(error='Windows could not update the saved TeraBox session.'),502
    finally:
        _TB_SESSION_LOCK.release()


@app.route('/terabox/resolve',methods=['POST'])
def terabox_resolve():
    if request.content_length and request.content_length>24000:
        return jsonify(error='Request too large.'),413
    data=request.get_json(silent=True)
    try:
        if not isinstance(data,dict): raise ValueError('Send a JSON object.')
        share=data.get('url','').strip();p=urlparse(share)
        if p.scheme!='https' or p.hostname not in tuple(host for root in _TB_DOMAINS for host in (root,'www.'+root)) or p.username or p.password or p.port not in (None,443):
            raise ValueError('Use an HTTPS share on terabox.com, 1024terabox.com or terabox.app.')
        if not (p.path.startswith('/s/') or 'surl=' in p.query): raise ValueError('Enter a TeraBox sharing link.')
        mode=data.get('provider','direct')
        if mode not in ('direct',*_TB_PROVIDERS): raise ValueError('Unknown provider.')
        token=data.get('token','');name=data.get('token_name','');location=data.get('token_location','header')
        cookie=data.get('cookies','')
        interactive=data.get('browser_session',False)
        saved_session = data.get('saved_session',False)
        auto_session = data.get('auto_session',False)
        save_preview = data.get('save_preview_to_account',False)
        if not isinstance(save_preview,bool) or (save_preview and (mode!='direct' or auto_session is not True)):
            raise _TBInputError('Saving a preview to your account requires automatic Direct TeraBox mode.')
        if not isinstance(auto_session,bool) or (auto_session and (mode!='direct' or interactive or saved_session or cookie)):
            raise _TBInputError('Automatic session handling is available in Direct TeraBox mode.')
        if not isinstance(saved_session,bool) or (saved_session and (mode != 'direct' or interactive or cookie)):
            raise _TBInputError('Choose the saved session, browser sign-in or imported cookies in Direct TeraBox mode.')
        if not isinstance(interactive,bool) or (interactive and mode!='direct'):
            raise _TBInputError('Browser sign-in is available only in Direct TeraBox mode.')
        if not all(isinstance(v,str) for v in (token,name,cookie,location)): raise ValueError('Credential fields must be text.')
        if len(token)>8000 or '\r' in token or '\n' in token: raise ValueError('Invalid token.')
        if mode=='direct':
            if token: raise ValueError('Direct mode accepts your TeraBox cookies. Resolver tokens belong to their provider.')
            if interactive and cookie:
                raise _TBInputError('Choose browser sign-in or imported cookies.')
            cookies=_tb_cookies(cookie,p.hostname)
        else:
            if cookie: raise ValueError('Do not send TeraBox cookies to a third-party resolver.')
            if mode=='xapiverse': name='xAPIverse-Key';location='header'
            if mode=='xapiverse' and not token: raise ValueError('Enter your xAPIverse API key.')
            if token and (not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,79}',name) or name.lower() in ('host','cookie','content-length','connection','transfer-encoding','origin','referer','url','__proto__','constructor')):
                raise ValueError('Enter the actual token field name; reserved transport fields are not allowed.')
            if location not in ('header','json'): raise ValueError('Choose header or JSON token placement.')
    except _TBInputError as exc:
        return jsonify(error=str(exc)),400
    except (ValueError,TypeError,AttributeError):
        return jsonify(error='Check the HTTPS share URL, provider and credential fields. Use TeraBox cookies only in direct mode; resolver tokens need their exact header or JSON field name.'),400
    if not _TB_SLOTS.acquire(blocking=False): return jsonify(error='Two resolutions are already active. Try again shortly.'),429
    try:
        if mode=='direct':
            if auto_session:
                if not _TB_SESSION_LOCK.acquire(blocking=False):
                    return jsonify(error='A TeraBox session action is already running.'),409
                try:
                    try:
                        cookies,user_agent = _tb_load_session(with_user_agent=True)
                    except Exception:
                        cookies,user_agent = [],''
                    if not cookies:
                        return jsonify(error='No usable saved TeraBox cookies found on this PC.'),422
                    result,status = _tb_direct(share,cookies,auto_session=True,user_agent=user_agent,
                                               save_preview_to_account=save_preview)
                    return jsonify(result),status
                finally:
                    _TB_SESSION_LOCK.release()
            if interactive:
                result,status=_tb_direct(share,[],interactive=True)
                return jsonify(result),status
            if saved_session:
                try:
                    cookies = _tb_load_session()
                except Exception:
                    return jsonify(error='The saved session could not be opened. Sign in and save it again.'),422
                if not cookies:
                    return jsonify(error='No usable TeraBox session is saved. Select Sign in and save session first.'),422
            if saved_session:
                result,status=_tb_direct(share,cookies,interactive=True)
            else:
                result,status=_tb_direct(share,cookies)
            result['cookie_info']={'accepted':len(cookies),'domains':sorted({c['domain'] for c in cookies}),
                'note':'Accepted cookies do not prove a logged-in session. Exported domains are preserved; unrelated domains are excluded.'}
            return jsonify(result),status
        endpoint=_TB_PROVIDERS[mode]
        headers={'Content-Type':'application/json'};body={'url':share}
        if token:
            (headers if location=='header' else body)[name]=token
        # Deliberately do not use get_api_session: imported browser cookies and
        # global authorization settings must never leak into these resolvers.
        with requests.Session() as session:
            session.trust_env=False  # Do not inherit .netrc credentials for a resolver.
            with closing(session.post(endpoint,json=body,headers=headers,allow_redirects=False,stream=True,timeout=(8,30))) as response:
                if 300<=response.status_code<400:
                    return jsonify(error='Resolver redirected. Credentials were not forwarded.',upstream_status=response.status_code),502
                buf=bytearray()
                for chunk in response.iter_content(32768):
                    buf.extend(chunk)
                    if len(buf)>2*1024*1024: return jsonify(error='Resolver response exceeded 2 MiB.'),502
                try: payload=_json_mod.loads(buf)
                except (ValueError,RecursionError): return jsonify(error='Resolver returned a non-JSON response.',upstream_status=response.status_code),502
                # Never reflect upstream text, which might echo a credential.
                if response.status_code>=400 or (isinstance(payload,dict) and (payload.get('error') or payload.get('success') is False or payload.get('status')=='error')):
                    code=payload.get('error') if isinstance(payload,dict) else None
                    message='Resolver could not resolve this share. Check access, credentials and provider availability.'
                    if code=='token_missing': message='Resolver requires a verification token. Supply its exact field name and value from your own valid session; a session ID alone may not satisfy it.'
                    return jsonify(error=message,upstream_status=response.status_code),502
                sources=_tb_sources(payload,share)
                # Guard against a provider reflecting the submitted credential in a URL.
                if token:
                    from urllib.parse import unquote as _tb_unquote
                    sources=[r for r in sources if token not in _tb_unquote(r['url'])]
                return jsonify(sources=sources,message='Media candidates returned; availability and playback are not verified.' if sources else 'Resolver returned no recognized media URLs.',upstream_status=response.status_code)
    except Exception as exc:
        text=str(exc).lower()
        message='Resolution failed. Check the selected provider and session. Credentials and upstream details were not logged.'
        if 'timeout' in text or 'timed out' in text:message='Connection or page loading timed out. A token cannot fix an unreachable host; verify the share opens in your browser.'
        elif 'name_not_resolved' in text or 'nameresolution' in text or 'name resolution' in text:message='DNS lookup failed. Check the host and network connection.'
        return jsonify(error=message),502
    finally: _TB_SLOTS.release()

"""Short-lived local relay for media observed in a TeraBox browser session."""
from secrets import token_urlsafe as _tb_token
from urllib.parse import quote as _tb_quote
from base64 import b64decode as _tb_b64decode
from gzip import decompress as _tb_gunzip
from shutil import which as _tb_which
import subprocess as _tb_subprocess
from tempfile import TemporaryDirectory as _TBTempDirectory
from flask import Response as _TBResponse

_TB_MEDIA = {}
_TB_MEDIA_LOCK = threading.Lock()
_TB_MEDIA_TTL = 600
_TB_MEDIA_LIMIT = 1500
_TB_EXPORT_SLOT = threading.BoundedSemaphore(1)


class _TBPlaylistError(ValueError):
    pass


@app.route('/terabox/player/hls.js')
def terabox_hls_script():
    compressed = _tb_b64decode(_TB_HLS_BUNDLE)
    headers = {'Vary':'Accept-Encoding'}
    if request.accept_encodings['gzip']>0:
        headers['Content-Encoding'] = 'gzip'
        body = compressed
    else:
        body = _tb_gunzip(compressed)
    return _TBResponse(body,mimetype='application/javascript',headers=headers)


def _tb_expire_media(session_id):
    with _TB_MEDIA_LOCK:
        _TB_MEDIA.pop(session_id,None)


def _tb_media_host(url):
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ''
        if (parsed.scheme == 'https' and parsed.port in (None,443) and not (parsed.username or parsed.password)
                and (_tb_cookie_domain(host) or host in ('1024tera.com','v4.freeterabox.com','teraboxcdn.com')
                     or host.endswith(('.1024tera.com','.teraboxcdn.com')))):
            return host
    except ValueError:
        pass
    return ''


def _tb_media_entry(session_id, state, url, headers, playlist=False, body=None, filename=''):
    """Called with the media lock held. Only provider URLs get local handles."""
    if not _tb_media_host(url):
        return ''
    entry = state['urls'].get(url)
    if entry is None:
        if len(state['entries']) >= _TB_MEDIA_LIMIT:
            return ''
        entry = _tb_token(12)
        state['urls'][url] = entry
        state['entries'][entry] = (url,headers,playlist,body,filename)
    return f'/terabox/media/{session_id}/{entry}'


def _tb_attach_media_relay(sources, observed_requests, cookies):
    now = time.monotonic()
    with _TB_MEDIA_LOCK:
        for session_id in list(_TB_MEDIA):
            if _TB_MEDIA[session_id]['expires'] <= now:
                _TB_MEDIA.pop(session_id)['timer'].cancel()
        state = {'expires':now+_TB_MEDIA_TTL,'entries':{},'urls':{},'cookies':cookies,'exports':{}}
        session_id = _tb_token(18)
        for source in sources.values():
            capture = observed_requests.get(source['url'])
            if not capture:
                continue
            headers,body = capture
            playlist = source['kind'] in ('hls_manifest','subtitle_track')
            filename = source.get('name','') if source['kind']=='video_download' else ''
            local = _tb_media_entry(session_id,state,source['url'],headers,playlist,body,filename)
            if local:
                source['replay_url'] = local
                if source['kind']=='hls_manifest':
                    entry = state['urls'][source['url']]
                    state['exports'][entry] = source.get('duration_seconds')
                    source['download_url'] = f'/terabox/download/{session_id}/{entry}'
        if state['entries']:
            if len(_TB_MEDIA)>=8:
                _TB_MEDIA.pop(next(iter(_TB_MEDIA)))['timer'].cancel()
            timer = threading.Timer(_TB_MEDIA_TTL,_tb_expire_media,args=(session_id,))
            timer.daemon = True
            state['timer'] = timer
            _TB_MEDIA[session_id] = state
            timer.start()


def _tb_media_cookie_header(cookies,url):
    parts = urlparse(url)
    path = parts.path or '/'
    pairs = []
    for cookie in sorted(cookies,key=lambda c:len(c.get('path','/')),reverse=True):
        domain = cookie['domain'].lower()
        scope = cookie.get('path','/')
        expires = cookie.get('expires',-1)
        if expires>0 and expires<=time.time():
            continue
        if not _tb_cookie_matches_host(domain,parts.hostname):
            continue
        if path != scope and not path.startswith(scope.rstrip('/')+'/'):
            continue
        pairs.append(f"{cookie['name']}={cookie['value']}")
    return '; '.join(pairs)


def _tb_playlist_snapshot(data):
    """Cache stable playlists and measure the duration of ended media playlists."""
    lines = data.decode('utf-8-sig').splitlines()
    if not lines or lines[0].strip() != '#EXTM3U':
        return None,None
    ended = any(line.strip() == '#EXT-X-ENDLIST' for line in lines)
    if ended:
        durations = re.findall(r'(?m)^#EXTINF:(\d+(?:\.\d+)?)(?=,|\r?$)',data.decode('utf-8-sig'))
        duration = round(sum(map(float,durations)),2) if durations else None
        return data,duration
    if any(line.startswith(('#EXT-X-STREAM-INF:','#EXT-X-I-FRAME-STREAM-INF:')) for line in lines):
        return data,None
    # An unfinished media playlist must be fetched again when the player polls it.
    return None,None


def _tb_rewrite_playlist(body,url,session_id,state,headers):
    try:
        text = body.decode('utf-8-sig')
    except UnicodeDecodeError as exc:
        raise _TBPlaylistError('TeraBox returned a playlist that is not valid UTF-8.') from exc
    if not text.lstrip().startswith('#EXTM3U'):
        raise _TBPlaylistError('TeraBox returned a response without an HLS playlist.')
    child_headers = {key:value for key,value in headers.items() if key not in ('cookie','accept')}

    def register(uri,playlist=False):
        target = urljoin(url,uri)
        if not _tb_media_host(target):
            host = urlparse(target).hostname or ''
            if re.fullmatch(r'[a-z0-9.-]{1,253}',host):
                raise _TBPlaylistError(f'TeraBox playlist references an unsupported media host ({host}).')
            raise _TBPlaylistError('TeraBox playlist contains an unsupported media URL.')
        local = _tb_media_entry(session_id,state,target,child_headers,
                                playlist or urlparse(target).path.lower().endswith('.m3u8'))
        if not local:
            raise _TBPlaylistError('TeraBox playlist exceeds the local relay track limit.')
        return local

    lines = []
    next_is_playlist = False
    with _TB_MEDIA_LOCK:
        for line in text.splitlines():
            line = line.strip()
            if line.startswith('#'):
                if re.search(r'\bURI=(?!")',line):
                    raise _TBPlaylistError('TeraBox playlist contains an invalid URI attribute.')
                if line.startswith('#EXT-X-STREAM-INF:'):
                    next_is_playlist = True
                is_playlist = line.startswith(('#EXT-X-MEDIA:','#EXT-X-I-FRAME-STREAM-INF:'))
                line = re.sub(r'\bURI="([^"\r\n]+)"',lambda match: f'URI="{register(match[1],is_playlist)}"',line)
            elif line:
                line = register(line,next_is_playlist)
                next_is_playlist = False
            lines.append(line)
    return '\n'.join(lines)+'\n'


@app.route('/terabox/download/<session_id>/<entry_id>')
def terabox_download(session_id,entry_id):
    with _TB_MEDIA_LOCK:
        state = _TB_MEDIA.get(session_id)
        if not state or state['expires']<=time.monotonic() or entry_id not in state['exports']:
            return 'This video link has expired. Resolve the TeraBox share again.',404
        duration = state['exports'][entry_id]
    ffmpeg = _tb_which('ffmpeg')
    if not ffmpeg:
        return 'Install FFmpeg to download this stream as MP4.',503
    if not _TB_EXPORT_SLOT.acquire(blocking=False):
        return 'An MP4 download is already being prepared. Try again when it finishes.',409
    directory = None
    media_file = None
    streaming = False
    try:
        directory = _TBTempDirectory(prefix='terabox-export-')
        output = _TBPath(directory.name)/'terabox-video.mp4'
        port = int(request.environ['SERVER_PORT'])
        manifest = f'http://127.0.0.1:{port}/terabox/media/{session_id}/{entry_id}'
        command = [ffmpeg,'-hide_banner','-loglevel','warning','-nostdin',
                   '-progress','pipe:1','-nostats','-protocol_whitelist','http,tcp,crypto',
                   '-allowed_extensions','ALL','-extension_picky','0','-f','hls','-i',manifest,
                   '-map','0:v:0','-map','0:a:0?','-c','copy','-movflags','+faststart',str(output)]
        result = _tb_subprocess.run(command,capture_output=True,timeout=300,
                                    env={**os.environ,'no_proxy':'127.0.0.1','NO_PROXY':'127.0.0.1'},
                                    creationflags=getattr(_tb_subprocess,'CREATE_NO_WINDOW',0))
        missing_segments = re.search(rb'failed to open segment|error when loading|HTTP error [45]\d\d',result.stderr,re.I)
        if result.returncode or missing_segments or not output.is_file() or not output.stat().st_size:
            return 'The stream could not be packaged as MP4. Resolve the share again if its links expired.',502
        elapsed = re.findall(rb'^out_time_us=(\d+)\r?$',result.stdout,re.M)
        if duration is not None and (not elapsed or int(elapsed[-1])/1000000 < duration-2):
            return 'The stream ended before the expected duration. Resolve the share again and retry the download.',502

        media_file = output.open('rb')
        response = _TBResponse(iter(lambda: media_file.read(256*1024),b''),mimetype='video/mp4',
                               headers={'Content-Disposition':'attachment; filename="terabox-video.mp4"',
                                        'Content-Length':str(output.stat().st_size)})
        response.call_on_close(media_file.close)
        response.call_on_close(directory.cleanup)
        streaming = True
        return response
    except _tb_subprocess.TimeoutExpired:
        return 'Preparing the MP4 timed out.',504
    except (OSError, ValueError):
        return 'The local app could not prepare the MP4.',502
    finally:
        if not streaming:
            if media_file is not None:
                media_file.close()
            if directory is not None:
                directory.cleanup()
        _TB_EXPORT_SLOT.release()


@app.route('/terabox/media/<session_id>/<entry_id>')
def terabox_media(session_id,entry_id):
    with _TB_MEDIA_LOCK:
        state = _TB_MEDIA.get(session_id)
        entry = state['entries'].get(entry_id) if state and state['expires']>time.monotonic() else None
    if not entry:
        return 'This media link has expired. Resolve the original TeraBox share again.',404
    url,headers,playlist,body,filename = entry
    session = None
    upstream = None
    streamed = False
    try:
        if body is None:
            session = requests.Session()
            session.trust_env = False
            configure_session(session)
            request_headers = dict(headers)
            request_headers['accept-encoding'] = 'identity'
            if not playlist and request.headers.get('Range'):
                request_headers['range'] = request.headers['Range']
            for _ in range(4):
                if not _tb_media_host(url):
                    return 'TeraBox redirected outside the media relay.',502
                if 'cookie' not in request_headers:
                    cookie = _tb_media_cookie_header(state['cookies'],url)
                    if cookie:
                        request_headers['cookie'] = cookie
                upstream = session.get(url,headers=request_headers,stream=True,allow_redirects=False,timeout=(6,15))
                if not upstream.is_redirect:
                    break
                url = urljoin(url,upstream.headers['Location'])
                upstream.close()
                request_headers.pop('cookie',None)
            if upstream.is_redirect:
                return 'TeraBox exceeded the media redirect limit.',502
            if upstream.status_code>=400:
                return f'TeraBox returned HTTP {upstream.status_code}. Resolve the share again to refresh its media links.',502
            mime = upstream.headers.get('Content-Type','').split(';',1)[0].lower()
            if 'json' in mime or playlist or 'mpegurl' in mime:
                data = bytearray()
                for chunk in upstream.iter_content(16384):
                    data.extend(chunk)
                    if len(data)>512000:
                        return 'TeraBox playlist or error response exceeded the relay limit.',502
                body = bytes(data)
                if 'json' in mime or body.lstrip().startswith(b'{'):
                    try:
                        error = _json_mod.loads(body)
                    except ValueError:
                        return 'TeraBox returned an unreadable JSON error instead of media.',502
                    errno = error.get('errno') if isinstance(error,dict) else None
                    code = f' {errno}' if type(errno) is int else ''
                    return f'TeraBox returned a media error{code}. Resolve the original share again.',502
            else:
                if mime in ('text/html','application/xhtml+xml','image/svg+xml'):
                    return 'TeraBox returned a webpage instead of media.',502
                forwarded = {key:upstream.headers[key] for key in ('Accept-Ranges','Content-Range') if key in upstream.headers}
                if 'Content-Length' in upstream.headers and not upstream.headers.get('Content-Encoding'):
                    forwarded['Content-Length'] = upstream.headers['Content-Length']
                if filename:
                    forwarded['Content-Disposition'] = "attachment; filename*=UTF-8''" + _tb_quote(filename[:240],safe='')
                safe_mime = mime if mime.startswith(('video/','audio/')) or mime=='text/vtt' else 'application/octet-stream'
                result = _TBResponse(upstream.iter_content(65536),status=upstream.status_code,mimetype=safe_mime,headers=forwarded)
                result.call_on_close(session.close)
                result.call_on_close(upstream.close)
                streamed = True
                return result
        rewritten = _tb_rewrite_playlist(body,url,session_id,state,headers)
        return _TBResponse(rewritten,mimetype='application/vnd.apple.mpegurl')
    except _TBPlaylistError as exc:
        return str(exc),502
    except requests.exceptions.ProxyError:
        return 'The local relay could not reach the TeraBox media server through the configured proxy.',502
    except requests.exceptions.SSLError:
        return 'The local relay could not verify the TeraBox media server’s TLS connection.',502
    except requests.exceptions.Timeout:
        return 'The TeraBox media server timed out while the local relay was fetching the stream.',504
    except (requests.RequestException,OSError):
        return 'The local relay lost its connection to the TeraBox media server.',502
    except ValueError:
        return 'TeraBox returned an invalid playlist URL or media response.',502
    finally:
        if not streamed:
            if upstream is not None:
                upstream.close()
            if session is not None:
                session.close()

_TB_HLS_BUNDLE = b'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'

TERABOX_PAGE = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TeraBox · Source Studio</title>\n<style>\n  :root{color-scheme:light;--ink:#172638;--muted:#516274;--line:#dce5eb;--surface:#fff;--primary:#075b59;--soft:#edf7f6}\n  *{box-sizing:border-box}\n  body{margin:0;background:#f5f8fb;color:var(--ink);font:15px/1.55 system-ui,sans-serif}\n  main{max-width:920px;margin:auto;padding:32px 20px 56px}\n  a{color:var(--primary)}\n  .back{font-size:14px;font-weight:650;text-decoration:none}\n  .hero{margin:28px 0 22px}\n  .eyebrow{color:var(--primary);font-size:12px;font-weight:750;letter-spacing:.08em;text-transform:uppercase}\n  h1,h2,p{margin:0}\n  h1{font-size:clamp(30px,5vw,43px);line-height:1.15;letter-spacing:-.04em;margin:6px 0 10px}\n  h2{font-size:17px;letter-spacing:-.01em}\n  .card{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:22px;margin-top:16px;box-shadow:0 4px 14px #183d5510}\n  label{display:block;font-weight:650;margin:0 0 6px}\n  input,button,.button{font:inherit;border-radius:8px;min-height:42px}\n  input{width:100%;min-width:0;border:1px solid #bccbd5;background:white;color:var(--ink);padding:9px 12px}\n  button,.button{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:8px 13px;border:1px solid #c7d5dd;background:white;color:var(--ink);font-weight:650;cursor:pointer;text-decoration:none}\n  button:hover,.button:hover{background:#f0f5f8}\n  .primary{background:var(--primary);border-color:var(--primary);color:white}\n  .primary:hover{background:#074946}\n  .secondary{background:var(--soft);border-color:#c6dfdd;color:#074d4b}\n  button:disabled{opacity:.55;cursor:wait}\n  :is(a,button,input,summary):focus-visible{outline:3px solid #68a5db;outline-offset:3px}\n  .muted,.help{color:var(--muted);font-size:13px}\n  .form-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:9px}\n  .help{margin-top:10px}\n  .settings{border-top:1px solid var(--line);margin-top:17px;padding-top:13px}\n  .settings summary{cursor:pointer;color:var(--primary);font-weight:650}\n  .settings label{margin-top:14px}\n  .settings button{margin-top:8px}\n  .results-header{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:12px}\n  #status{color:var(--muted);white-space:pre-wrap}\n  .source{margin-top:12px;padding:15px;border:1px solid var(--line);border-radius:12px;overflow-wrap:anywhere}\n  .source-main{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px}\n  .source-actions{display:flex;align-items:center;flex-wrap:wrap;gap:8px}\n  .source-details{margin-top:10px;color:var(--muted);font-size:13px}\n  .source-details summary{cursor:pointer;width:max-content;max-width:100%}\n  .source-details p{margin:8px 0}\n  #playerPanel{margin-top:14px}\n  #videoPlayer{display:block;width:100%;max-height:65vh;background:#101820;border-radius:10px}\n  #playerStatus{margin-top:6px}\n  #fullVideoShare{display:inline-block;margin-top:10px}\n  [hidden]{display:none!important}\n  @media(max-width:550px){main{padding:22px 14px 38px}.hero{margin-top:22px}.card{padding:15px}.form-row{grid-template-columns:1fr}.source-actions{width:100%}.results-header{align-items:flex-start}}\n</style></head>\n<body><main>\n<a class="back" href="/">← Source Studio</a>\n<header class="hero">\n  <p class="eyebrow">Media workspace</p>\n  <h1>TeraBox video resolver</h1>\n  <p>Paste a share link to find, play, or download the video with your saved session.</p>\n</header>\n<section class="card" aria-label="Resolve a TeraBox share">\n  <form id="resolveForm" autocomplete="off">\n    <label for="share">TeraBox share URL</label>\n    <div class="form-row">\n      <input id="share" type="url" required placeholder="https://terabox.app/s/…">\n      <button id="submit" class="primary" type="submit">Resolve full video</button>\n    </div>\n    <p class="help">If TeraBox requires it for full access, resolving may save a copy to your account.</p>\n  </form>\n  <details id="cookieSettings" class="settings">\n    <summary>Saved session settings</summary>\n    <label for="userAgent">User-Agent from the browser that can play the share (optional)</label>\n    <input id="userAgent" type="text" maxlength="512" spellcheck="false" placeholder="Copy the User-Agent request header">\n    <button id="saveUserAgent" type="button">Update User-Agent for saved cookies</button>\n    <label for="cookieFile">TeraBox cookie export (JSON, cookies.txt, or TSV)</label>\n    <input id="cookieFile" type="file" accept=".json,.txt,.tsv">\n    <p class="help">Cookies are encrypted on this PC and reused for future shares.</p>\n  </details>\n</section>\n<section class="card" aria-labelledby="resultsHeading">\n  <div class="results-header">\n    <h2 id="resultsHeading">Video results</h2>\n    <button id="copy" type="button" hidden>Copy all links</button>\n  </div>\n  <p id="status" role="status">Paste a share link to get started.</p>\n  <div id="playerPanel" hidden>\n    <video id="videoPlayer" controls playsinline></video>\n    <p id="playerStatus" class="muted"></p>\n  </div>\n  <a id="fullVideoShare" target="_blank" rel="noopener noreferrer" hidden>Open original share for full-video options</a>\n  <div id="results"></div>\n</section>\n</main><script>\nconst $ = id => document.getElementById(id);\nfunction normalizeShareField() {\n    const field = $(\'share\');\n    const value = field.value.trim();\n    field.value = value.replace(/^(?:https?:\\/\\/)?(?:www\\.)?terabox\\.com(?=\\/|[?#]|$)/i, \'https://terabox.app\');\n    return field.value;\n}\n\n$(\'share\').addEventListener(\'paste\', () => setTimeout(normalizeShareField, 0));\n$(\'share\').addEventListener(\'change\', normalizeShareField);\n\nlet links = [];\nlet player = null;\nlet playerLoad = null;\nlet playbackRevision = 0;\n\nfunction resetPlayer() {\n    playbackRevision++;\n    if (player) player.destroy();\n    player = null;\n    const video = $(\'videoPlayer\');\n    video.pause();\n    video.removeAttribute(\'src\');\n    video.load();\n    $(\'playerPanel\').hidden = true;\n}\n\nfunction loadHlsPlayer() {\n    if (!playerLoad) {\n        playerLoad = new Promise((resolve, reject) => {\n            const script = document.createElement(\'script\');\n            script.src = \'/terabox/player/hls.js\';\n            script.onload = resolve;\n            script.onerror = () => {\n                playerLoad = null;\n                script.remove();\n                reject(Error(\'Could not load the local HLS player.\'));\n            };\n            document.head.append(script);\n        });\n    }\n    return playerLoad;\n}\n\nasync function playStream(url) {\n    resetPlayer();\n    const revision = playbackRevision;\n    const video = $(\'videoPlayer\');\n    const status = $(\'playerStatus\');\n    $(\'playerPanel\').hidden = false;\n    status.textContent = \'Loading captured video…\';\n    const start = () => video.play().catch(error => {\n        if (revision === playbackRevision && error.name === \'NotAllowedError\') {\n            status.textContent = \'Press Play in the video controls.\';\n        }\n    });\n    try {\n        await loadHlsPlayer();\n        if (revision !== playbackRevision) return;\n        if (window.Hls?.isSupported()) {\n            const instance = new window.Hls();\n            player = instance;\n            instance.on(window.Hls.Events.ERROR, (_event, data) => {\n                if (data.fatal && player === instance) {\n                    const code = data.response?.code;\n                    status.textContent = code\n                        ? `The media relay returned HTTP ${code}. Resolve the share again if the link expired.`\n                        : \'Playback stopped. \' + data.details;\n                }\n            });\n            instance.on(window.Hls.Events.MANIFEST_PARSED, () => {\n                if (player === instance) start();\n            });\n            instance.loadSource(url);\n            instance.attachMedia(video);\n        } else if (video.canPlayType(\'application/vnd.apple.mpegurl\')) {\n            video.src = url;\n            start();\n        } else {\n            status.textContent = \'This browser cannot play HLS. Open the playlist in an HLS-capable player.\';\n        }\n    } catch (error) {\n        if (revision === playbackRevision) status.textContent = error.message;\n    }\n}\n\n$(\'videoPlayer\').onplaying = () => { $(\'playerStatus\').textContent = \'Playing the captured stream.\'; };\n\nfunction formatDuration(seconds) {\n    const rounded = Math.round(seconds);\n    return Math.floor(rounded / 60) + \':\' + String(rounded % 60).padStart(2, \'0\');\n}\n\nfunction startFileDownload(url, message) {\n    const frame = document.createElement(\'iframe\');\n    frame.hidden = true;\n    frame.title = \'TeraBox video download\';\n    frame.addEventListener(\'load\', () => {\n        const error = frame.contentDocument?.body?.textContent?.trim();\n        if (error) $(\'status\').textContent = error.slice(0, 300);\n    });\n    frame.src = url;\n    $(\'results\').append(frame);\n    $(\'status\').textContent = message;\n}\n\nasync function resolveVideo() {\n    $(\'submit\').disabled = true;\n    $(\'cookieFile\').disabled = true;\n    $(\'copy\').hidden = true;\n    resetPlayer();\n    $(\'fullVideoShare\').hidden = true;\n    $(\'results\').replaceChildren();\n    $(\'status\').textContent = \'Capturing media with your saved TeraBox cookies…\';\n    links = [];\n    try {\n        const response = await fetch(\'/terabox/resolve\', {\n            method: \'POST\',\n            headers: {\'Content-Type\': \'application/json\'},\n            body: JSON.stringify({url: normalizeShareField(), provider: \'direct\', auto_session: true, save_preview_to_account: true})\n        });\n        const result = await response.json();\n        if (!response.ok) {\n            if (response.status === 422 || [401, 403].includes(result.upstream_status)) $(\'cookieSettings\').open = true;\n            throw Error(result.error || \'Resolution failed.\');\n        }\n        let originalDownload = null;\n        for (const source of result.sources || []) {\n            if (!/^https?:\\/\\//.test(source.url || \'\')) continue;\n            links.push(source.url);\n            const card = document.createElement(\'div\');\n            card.className = \'source\';\n            const row = document.createElement(\'div\');\n            row.className = \'source-main\';\n            const actions = document.createElement(\'div\');\n            actions.className = \'source-actions\';\n            const title = document.createElement(\'strong\');\n            const duration = Number.isFinite(source.duration_seconds) ? ` · ${formatDuration(source.duration_seconds)}` : \'\';\n            const label = {hls_manifest: \'Video stream\', subtitle_track: \'Subtitles\', dash_manifest: \'DASH stream\'}[source.kind];\n            title.textContent = source.kind === \'video_download\'\n                ? source.name\n                : (label || \'Media link\') + (source.quality ? \' · \' + source.quality : \'\') + duration;\n            const text = document.createElement(\'p\');\n            text.textContent = source.url;\n            const details = document.createElement(\'details\');\n            details.className = \'source-details\';\n            const summary = document.createElement(\'summary\');\n            summary.textContent = \'Source URL\';\n            details.append(summary, text);\n            const open = document.createElement(\'a\');\n            open.className = \'button\';\n            open.href = source.replay_url || source.url;\n            open.target = \'_blank\';\n            open.rel = \'noopener noreferrer\';\n            open.textContent = source.replay_url ? \'Open with captured session\' : \'Open raw link\';\n            if (source.kind === \'video_download\' && source.replay_url) {\n                open.textContent = \'Download video\';\n                open.classList.add(\'secondary\');\n                originalDownload ??= source.replay_url;\n            }\n            if (source.kind === \'hls_manifest\' && source.replay_url) {\n                const play = document.createElement(\'button\');\n                play.type = \'button\';\n                play.className = \'primary\';\n                play.textContent = \'Play video\';\n                play.onclick = () => playStream(source.replay_url);\n                open.textContent = \'Open playlist\';\n                actions.append(play);\n                if (source.download_url) {\n                    const download = document.createElement(\'a\');\n                    download.className = \'button secondary\';\n                    download.textContent = \'Download MP4\';\n                    download.href = source.download_url;\n                    download.onclick = event => {\n                        event.preventDefault();\n                        startFileDownload(source.download_url, \'Preparing MP4. Your browser will start the download when it’s ready.\');\n                    };\n                    actions.append(download);\n                }\n                details.append(open);\n            } else {\n                actions.append(open);\n            }\n            const copy = document.createElement(\'button\');\n            copy.textContent = \'Copy link\';\n            copy.onclick = () => copyText(source.url);\n            actions.append(copy);\n            row.append(title, actions);\n            card.append(row, details);\n            $(\'results\').append(card);\n        }\n        $(\'status\').textContent = result.message + \' \' + links.length + \' link(s).\';\n        $(\'copy\').hidden = links.length === 0;\n        if (result.cookie_host) $(\'cookieSettings\').open = true;\n        if (result.full_video_share) {\n            $(\'fullVideoShare\').href = result.full_video_share;\n            $(\'fullVideoShare\').textContent = result.cookie_host ? \'Open original share to refresh cookies\' : \'Open original share for full-video options\';\n            $(\'fullVideoShare\').hidden = false;\n        }\n        if (originalDownload) {\n            startFileDownload(originalDownload, result.message + \' Starting the file download…\');\n        }\n    } catch (error) {\n        $(\'status\').textContent = error.message;\n    } finally {\n        $(\'submit\').disabled = false;\n        $(\'cookieFile\').disabled = false;\n    }\n}\n$(\'resolveForm\').onsubmit = event => {\n    event.preventDefault();\n    resolveVideo();\n};\n$(\'saveUserAgent\').onclick = async () => {\n    $(\'saveUserAgent\').disabled = true;\n    try {\n        const response = await fetch(\'/terabox/session/user-agent\', {\n            method: \'POST\', headers: {\'Content-Type\': \'application/json\'},\n            body: JSON.stringify({user_agent: $(\'userAgent\').value.trim()})\n        });\n        const result = await response.json();\n        $(\'status\').textContent = response.ok ? result.message : result.error;\n    } catch (error) {\n        $(\'status\').textContent = error.message;\n    } finally {\n        $(\'saveUserAgent\').disabled = false;\n    }\n};\n$(\'cookieFile\').onchange = async event => {\n    const file = event.target.files[0];\n    if (!file) return;\n    event.target.value = \'\';\n    const headers = {\'Content-Type\': \'text/plain\'};\n    const userAgent = $(\'userAgent\').value.trim();\n    if (userAgent) headers[\'X-TeraBox-User-Agent\'] = userAgent;\n    $(\'cookieFile\').disabled = true;\n    $(\'submit\').disabled = true;\n    try {\n        const response = await fetch(\'/terabox/session/import\', {\n            method: \'POST\', headers, body: file\n        });\n        const result = await response.json();\n        if (!response.ok) throw Error(result.error || \'Cookie upload failed.\');\n        $(\'status\').textContent = result.message;\n        $(\'cookieSettings\').open = false;\n    } catch (error) {\n        $(\'status\').textContent = error.message;\n    } finally {\n        $(\'cookieFile\').disabled = false;\n        $(\'submit\').disabled = false;\n    }\n};\n\nasync function copyText(text) {\n    try {\n        await navigator.clipboard.writeText(text);\n        $(\'status\').textContent = \'Copied.\';\n    } catch {\n        $(\'status\').textContent = \'Clipboard unavailable.\';\n    }\n}\n$(\'copy\').onclick = () => copyText(links.map(url => url + \',\').join(\'\\n\'));\n</script></body></html>\n'

VIDEO_ADDON_UI = '<style>\n.va-panel{margin:18px 0;padding:20px;border:1px solid var(--line);border-radius:16px;background:var(--card)}.va-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(185px,1fr));gap:12px}.va-grid label{display:flex;gap:8px;align-items:center}.va-panel textarea{box-sizing:border-box;width:100%;min-height:95px;border:1px solid var(--line);border-radius:9px;padding:10px;font:13px monospace}.va-metrics{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}.va-metrics span{background:var(--bg);border-radius:8px;padding:9px}.va-records{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px;max-height:420px;overflow:auto}.va-record{padding:14px;background:var(--bg);border-radius:10px;overflow-wrap:anywhere}.va-actions{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}.va-panel select{max-width:100%}.va-note{white-space:pre-wrap;overflow-wrap:anywhere}\n</style>\n<template id="vaTemplate"><section class="va-panel" aria-label="Optional video discovery add-ons">\n<h2>Video discovery add-ons</h2><p class="small">Optional extensions. Leave disabled to use the existing scanner.</p>\n<label><input type="checkbox" id="vaEnabled"> Enable video discovery add-ons</label>\n<details><summary style="margin:12px 0">Add-on settings, recipes &amp; local history</summary>\n<div class="va-grid">\n<label><input type="checkbox" id="vaAdaptive" checked> Adaptive browser use</label>\n<label><input type="checkbox" id="vaConcurrency" checked> Adaptive concurrency</label>\n<label><input type="checkbox" id="vaParser"> Optional Lexbor parser</label>\n<label><input type="checkbox" id="vaChannels" checked> Worker &amp; WebSocket discovery</label>\n<label><input type="checkbox" id="vaPersist"> Save local progress (7 days)</label>\n<label><input type="checkbox" id="vaIncremental"> Reuse unchanged page extraction</label>\n</div>\n<p class="small">Adaptive mode can finish observation early and may miss delayed media; disable it for full configured observation. Local history excludes cookies, headers, page bodies and URLs containing queries. Signed links remain in the current scan only. Unchanged-page reuse still fetches pages to check their contents.</p>\n<label for="vaRecipe">Video recipe (optional JSON of CSS selectors)</label>\n<textarea id="vaRecipe" spellcheck="false" placeholder=\'{"title":"h1","media":"video source","next":"a.next"}\'>{}</textarea>\n<p class="small">Fields: title, description, duration, thumbnail, media, next. Media reads src, href or data-src. Pagination follows links; recipes do not click controls.</p>\n<div class="va-actions"><button type="button" id="vaSaveRecipe">Save recipe locally</button><button type="button" id="vaLoadRecipe">Load site recipe</button><button type="button" id="vaRefreshHistory">Refresh saved scans</button><button type="button" id="vaClear">Clear local history &amp; recipes</button></div>\n<label for="vaResume">Resume saved scan</label> <select id="vaResume"><option value="">Start fresh</option></select>\n<p class="small">Choose the same target URL to resume. Each resumed run gets a fresh time and page budget. Query-bearing targets cannot be resumed from disk.</p>\n</details>\n<div id="vaMetrics" class="va-metrics" aria-live="polite">Performance measurements appear during an add-on scan.</div>\n<p id="vaNote" class="small va-note" role="status"></p>\n<details><summary>Video records &amp; export</summary>\n<div class="va-grid" id="vaFields"></div>\n<div class="va-actions"><button type="button" id="vaCsv">Export video CSV</button><button type="button" id="vaJson">Export video JSON</button></div>\n<div class="va-records" id="vaRecords"></div></details>\n</section></template>\n<script>\n(()=>{\nconst byId=id=>document.getElementById(id);\nconst teraboxLink=document.createElement(\'a\');teraboxLink.href=\'/terabox\';teraboxLink.textContent=\'TeraBox resolver ↗\';teraboxLink.style.display=\'block\';teraboxLink.style.marginTop=\'14px\';document.querySelector(\'.sidebar\')?.append(teraboxLink);\nbyId(\'copyAll\').onclick=()=>{\n const urls=[...new Set(records().map(r=>r.url).filter(u=>/^https?:\\/\\//.test(u||\'\')))];\n if(!urls.length)return toast(\'No URLs to copy\');\n navigator.clipboard.writeText(urls.map(url=>url+\',\').join(\'\\n\'))\n .then(()=>toast(urls.length+\' URLs copied\')).catch(()=>toast(\'Clipboard unavailable\'));\n};\nbyId(\'scanForm\').closest(\'section\').after(byId(\'vaTemplate\').content.cloneNode(true));\nlet addonScan=null,lastRecords=\'\',history={runs:[],recipes:[]};\nconst note=text=>byId(\'vaNote\').textContent=text;\nconst fields=[\'page\',\'title\',\'description\',\'duration\',\'thumbnail\',\'url\',\'kind\',\'quality\',\'source\'];\nfor(const name of fields){const label=document.createElement(\'label\'),input=document.createElement(\'input\');input.type=\'checkbox\';input.checked=true;input.value=name;label.append(input,document.createTextNode(name));byId(\'vaFields\').append(label)}\nfunction recipe(){const value=JSON.parse(byId(\'vaRecipe\').value);if(!value||Array.isArray(value)||typeof value!==\'object\')throw Error(\'Recipe must be a JSON object\');return value}\nasync function refreshHistory(){history=await request(\'/addons/history\');const select=byId(\'vaResume\');select.replaceChildren(new Option(\'Start fresh\',\'\'));for(const run of history.runs){if(run.url)select.add(new Option(run.url+\' · \'+run.status+\' · \'+run.id,run.id))}}\nbyId(\'vaRefreshHistory\').onclick=()=>refreshHistory().catch(e=>note(e.message));\nbyId(\'vaSaveRecipe\').onclick=async()=>{try{await request(\'/addons/recipes\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({url:byId(\'ui\').value,recipe:recipe()})});note(\'Recipe saved locally for this site.\')}catch(e){note(e.message)}};\nbyId(\'vaLoadRecipe\').onclick=async()=>{try{await refreshHistory();const u=new URL(byId(\'ui\').value),port=Number(u.port||(u.protocol===\'https:\'?443:80));const found=history.recipes.find(r=>r.origin[0]===u.protocol.slice(0,-1)&&r.origin[1]===u.hostname&&r.origin[2]===port);if(!found)throw Error(\'No saved recipe for this site\');byId(\'vaRecipe\').value=JSON.stringify(found.recipe,null,2);note(\'Site recipe loaded.\')}catch(e){note(e.message)}};\nbyId(\'vaClear\').onclick=async()=>{try{if(busy)throw Error(\'Stop the active scan before clearing history\');await request(\'/addons/history\',{method:\'DELETE\'});await refreshHistory();note(\'Local scan history, cache and recipes cleared.\')}catch(e){note(e.message)}};\nbyId(\'vaResume\').onchange=()=>{const run=history.runs.find(r=>r.id===byId(\'vaResume\').value);if(run){byId(\'ui\').value=run.url;byId(\'vaPersist\').checked=true;byId(\'vaEnabled\').checked=true}};\nasync function metrics(scan){\n if(addonScan!==scan)return;\n try{const data=await request(\'/addons/status/\'+scan),m=data.metrics;\n const values=[[\'First result\',m.first_result_seconds==null?\'waiting\':m.first_result_seconds+\'s\'],[\'Static requests\',m.requests||0],[\'Static body bytes\',m.static_bytes||0],[\'Browser body bytes\',m.browser_bytes||0],[\'Browser time\',(m.browser_seconds||0)+\'s\'],[\'Parse time\',(m.parse_seconds||0)+\'s\'],[\'Unique sources\',m.unique_sources||0],[\'Reused pages\',m.unchanged_pages||0],[\'Request slots\',m.workers||0],[\'Skipped renders\',m.browser_skipped||0],[\'Worker responses\',m.worker_responses||0],[\'WS messages\',m.websocket_messages||0],[\'Parser\',m.parser||\'\']];\n byId(\'vaMetrics\').replaceChildren(...values.map(([key,value])=>{const span=document.createElement(\'span\');span.textContent=key+\': \'+value;return span}));\n const fingerprint=JSON.stringify(data.records);if(lastRecords!==fingerprint){lastRecords=fingerprint;byId(\'vaRecords\').replaceChildren(...data.records.slice(0,200).map(r=>{const card=document.createElement(\'article\'),title=document.createElement(\'strong\'),body=document.createElement(\'p\');card.className=\'va-record\';title.textContent=r.title||\'Video source\';body.textContent=[r.duration,r.kind,r.quality,r.url].filter(Boolean).join(\' · \');card.append(title,body);return card}))}\n }catch(e){note(e.message)}\n if(addonScan===scan&&busy)setTimeout(()=>metrics(scan),1000);\n else if(addonScan===scan)note(\'Add-on scan finished. Metrics cover discovery traffic; manifest inspection and verification are excluded from byte counts.\');\n}\n// A capture listener handles only explicitly enabled add-on scans. The original\n// submit handler and all its endpoints remain intact for default scans.\nbyId(\'scanForm\').addEventListener(\'submit\',async event=>{\n if(!byId(\'vaEnabled\').checked){addonScan=null;return}\n event.preventDefault();event.stopImmediatePropagation();if(busy)return;\n try{\n if(byId(\'sourceType\').value!==\'website\')throw Error(\'Select Website for video add-ons, or disable add-ons to use API mode.\');\n const payload={url:byId(\'ui\').value.trim(),source_type:\'website\',skip_validate:!byId(\'doValidate\').checked,render_browser:byId(\'renderBrowser\').checked,discover_sitemap:byId(\'discoverSitemap\').checked,attempt_playback:byId(\'attemptPlayback\').checked,deep_js:byId(\'deepJs\').checked};\n for(const[key,id]of Object.entries({depth:\'depth\',page_limit:\'pageLimit\',concurrency:\'concurrency\',time_limit_s:\'timeBudget\',browser_limit:\'browserLimit\',dwell_ms:\'dwell\'}))payload[key]=Number(byId(id).value);\n payload.addons={adaptive:byId(\'vaAdaptive\').checked,adaptive_concurrency:byId(\'vaConcurrency\').checked,fast_parser:byId(\'vaParser\').checked,browser_channels:byId(\'vaChannels\').checked,persist:byId(\'vaPersist\').checked,incremental:byId(\'vaIncremental\').checked,resume_id:byId(\'vaResume\').value,recipe:recipe()};\n busy=true;byId(\'sb\').disabled=true;byId(\'xb\').disabled=true;status(\'STARTING\',true);\n const result=await request(\'/addons/start\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify(payload)});\n clearTimeout(pollTimer);clearInterval(timer);sid=result.scan_id;addonScan=sid;snapshot=null;lastRender=\'\';lastRecords=\'\';started=Date.now();elapsed();timer=setInterval(elapsed,1000);byId(\'xb\').disabled=false;paint();note(\'Add-on scan active. Metrics cover discovery traffic; manifest inspection and verification are not included in byte counts.\');poll();metrics(sid);\n }catch(e){busy=false;byId(\'sb\').disabled=false;byId(\'xb\').disabled=true;status(\'ERROR\');note(e.message)}\n},true);\nfor(const[id,format]of [[\'vaCsv\',\'csv\'],[\'vaJson\',\'json\']])byId(id).onclick=()=>{if(!addonScan)return note(\'Run an add-on scan first\');const selected=[...byId(\'vaFields\').querySelectorAll(\'input:checked\')].map(n=>n.value);if(!selected.length)return note(\'Select at least one export field\');const link=document.createElement(\'a\');link.href=\'/addons/export/\'+addonScan+\'?format=\'+format+\'&fields=\'+encodeURIComponent(selected.join(\',\'));link.click()};\n})();\n</script>\n'
HTML_PAGE = HTML_PAGE.replace("</body>", VIDEO_ADDON_UI + "</body>")
# END OPTIONAL VIDEO ADDONS
if __name__ == "__main__":
    print("Source Studio — http://127.0.0.1:5050")
    app.run(host="127.0.0.1", port=5050, debug=False, use_reloader=False, threaded=True)
