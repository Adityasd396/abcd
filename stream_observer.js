(() => {
    if (window.__streamDiagnostics) return;
    const records = new Map();
    function add(kind, url = '', mime = '', evidence = '') {
        const key = kind + ':' + url + ':' + mime;
        if (records.size < 200 || records.has(key))
            records.set(key, {kind, url, mime, evidence});
    }
    Object.defineProperty(window, '__streamDiagnostics', {value:{snapshot() {
        const roots = [document], visited = new Set();
        let budget = 20000;
        while (roots.length && budget > 0) {
            const root = roots.pop();
            if (visited.has(root)) continue;
            visited.add(root);
            const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
            let el;
            while ((el = walker.nextNode()) && budget-- > 0) {
                if (el.shadowRoot) roots.push(el.shadowRoot);
                if (!/^(VIDEO|AUDIO)$/.test(el.tagName)) continue;
                const src = el.currentSrc || el.src || '';
                if (src.startsWith('blob:')) add('browser_blob', src, '', 'media element blob source');
            }
        }
        return [...records.values()];
    }}});
    const create = URL.createObjectURL;
    if (typeof create === 'function') {
        URL.createObjectURL = function(object) {
            const url = create.call(this, object);
            if (typeof MediaSource !== 'undefined' && object instanceof MediaSource)
                add('mse_source', url, '', 'MediaSource object URL');
            else if (typeof Blob !== 'undefined' && object instanceof Blob && /^(video|audio)\//.test(object.type))
                add('browser_blob', url, object.type, 'media Blob object URL');
            return url;
        };
    }
    if (typeof MediaSource !== 'undefined') {
        const original = MediaSource.prototype.addSourceBuffer;
        MediaSource.prototype.addSourceBuffer = function(type) {
            const buffer = original.call(this, type);
            add('mse_buffer', '', String(type).slice(0, 300), 'successful addSourceBuffer');
            return buffer;
        };
    }
})();
