const vm = require('node:vm');
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const script = execFileSync('python', ['-c', 'from media_detection import MEDIA_OBSERVER_SCRIPT; print(MEDIA_OBSERVER_SCRIPT)'], {encoding:'utf8'});
const observers = [];
class Element {
    constructor(attrs = {}, tagName = 'VIDEO') { this.attrs = attrs; this.tagName = tagName; }
    getAttribute(name) { return this.attrs[name] || null; }
    attachShadow() { return {}; }
}
class XHR {
    addEventListener(name, callback) { this.callback = callback; }
    send() { return 'sent'; }
    getResponseHeader() { return 'application/dash+xml'; }
}
const response = {url:'https://example.com/opaque', headers:{get: () => 'video/mp4'}};
const document = {baseURI:'https://example.com/', addEventListener(){},
    createTreeWalker() { return {nextNode: () => null}; }};
const context = {document, URL, Element, XMLHttpRequest:XHR, NodeFilter:{SHOW_ELEMENT:1},
    MutationObserver: class { constructor(callback){observers.push(callback);} observe(){} },
    PerformanceObserver: class { observe(){} }, fetch: async () => response};
context.window = context;
vm.createContext(context);
vm.runInContext(script, context);
(async () => {
    assert.equal(await context.fetch('/opaque'), response, 'fetch response preserved');
    const xhr = new context.XMLHttpRequest();
    xhr.responseURL = 'https://example.com/manifest';
    assert.equal(xhr.send(), 'sent'); xhr.callback();
    const node = new Element({src:'/dynamic'});
    observers[0]([{type:'attributes', target:node}]);
    const urls = context.__mediaDiscovery.snapshot().map(x => x.url);
    assert.ok(urls.includes('https://example.com/opaque'));
    assert.ok(urls.includes('https://example.com/manifest'));
    assert.ok(urls.includes('https://example.com/dynamic'));
    vm.runInContext(script, context); // idempotent installation
    assert.equal(context.__mediaDiscovery.snapshot().length, 3);
    console.log('Browser hook simulation passed: fetch, XHR, mutations, idempotence');
})().catch(error => { console.error(error); process.exitCode = 1; });
