const vm = require('node:vm');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const listeners = {};
const sentinel = Promise.resolve('supported');
const context = {
    document:{addEventListener:(name, fn) => listeners[name] = fn},
    navigator:{requestMediaKeySystemAccess:() => sentinel}
};
context.window = context;
vm.createContext(context);
const script = fs.readFileSync('drm_observer.js', 'utf8');
vm.runInContext(script, context);
assert.equal(context.navigator.requestMediaKeySystemAccess('com.example.drm', []), sentinel);
listeners.encrypted({initDataType:'cenc', initData:'not recorded'});
listeners.waitingforkey();
const result = context.__drmDiagnostics.snapshot();
assert.equal(result.encryptedMediaObserved, true);
assert.equal(result.keySystems[0], 'com.example.drm');
assert.ok(!JSON.stringify(result).includes('not recorded'));
vm.runInContext(script, context);
assert.equal(context.__drmDiagnostics.snapshot().events.length, 3);
console.log('DRM diagnostics: events recorded, API behavior preserved, installation idempotent');
