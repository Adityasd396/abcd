(() => {
    if (window.__apiDocuments) return;
    const documents = [];
    const limit = 512000;
    let pending = 0;
    Object.defineProperty(window, '__apiDocuments', {value:{snapshot:()=>documents.slice()}});
    function save(url, text) {
        if (documents.length >= 6 || typeof text !== 'string' || text.length > limit) return;
        try { JSON.parse(text); documents.push({url, text}); } catch (_) {}
    }
    const original = window.fetch;
    window.fetch = function(...args) {
        return original.apply(this, args).then(response => {
            if (!response.ok || !/json/i.test(response.headers.get('content-type') || '') ||
                documents.length + pending >= 6) return response;
            let clone;
            try { clone = response.clone(); } catch (_) { return response; }
            pending++;
            (async () => {
                let reader;
                try {
                    if (!clone.body) return;
                    reader = clone.body.getReader();
                    const chunks = []; let length = 0;
                    while (true) {
                        const part = await reader.read();
                        if (part.done) break;
                        length += part.value.byteLength;
                        if (length > limit) { reader.cancel().catch(()=>{}); return; }
                        chunks.push(part.value);
                    }
                    const bytes = new Uint8Array(length); let offset = 0;
                    for (const chunk of chunks) { bytes.set(chunk,offset); offset += chunk.byteLength; }
                    save(response.url, new TextDecoder().decode(bytes));
                } catch (_) {} finally { pending--; if (reader) reader.releaseLock(); }
            })();
            return response;
        });
    };
    const send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(...args) {
        this.addEventListener('load', () => {
            try {
                if (this.status >= 200 && this.status < 300 && /json/i.test(this.getResponseHeader('content-type') || '') &&
                    (this.responseType === '' || this.responseType === 'text')) save(this.responseURL,this.responseText);
            } catch (_) {}
        }, {once:true});
        return send.apply(this,args);
    };
})();
