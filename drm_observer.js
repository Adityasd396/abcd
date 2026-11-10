(() => {
    if (window.__drmDiagnostics) return;
    const events = [], systems = new Set();
    function record(kind, details = {}) {
        if (events.length < 100) events.push({kind, ...details});
    }
    Object.defineProperty(window, '__drmDiagnostics', {value: {
        snapshot: () => ({keySystems:[...systems], events:events.slice(),
            encryptedMediaObserved:events.some(e => e.kind === 'encrypted')})
    }});
    document.addEventListener('encrypted', event => {
        record('encrypted', {initDataType:String(event.initDataType || '')});
    }, true);
    document.addEventListener('waitingforkey', () => record('waiting-for-key'), true);
    const original = navigator.requestMediaKeySystemAccess;
    if (typeof original === 'function') {
        try {
            navigator.requestMediaKeySystemAccess = function(system, ...args) {
                // Observe only the key-system name. Do not read initialization
                // data, license messages, session IDs or key material.
                if (typeof system === 'string' && systems.size < 20) systems.add(system.slice(0, 200));
                record('key-system-request');
                return original.call(this, system, ...args);
            };
        } catch (_) {}
    }
})();
