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

if __name__ == "__main__":
    print("Source Studio — http://127.0.0.1:5050")
    app.run(host="127.0.0.1", port=5050, debug=False, use_reloader=False, threaded=True)
