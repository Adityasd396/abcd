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
