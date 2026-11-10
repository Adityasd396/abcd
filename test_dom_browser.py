"""Real Chromium check using local HTML only; run directly to avoid optional dependency requirements."""
from pathlib import Path
from playwright.sync_api import sync_playwright
import app
from app import identify_stream, merge_stream, collect_stream_snapshot
from app import MEDIA_OBSERVER_SCRIPT


def main():
    script = app.VIDEO_EXTRACTION_SCRIPT
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, timeout=15000)
        try:
            context = app._make_pw_context(browser, headless=True)
            page = context.new_page()
            page.evaluate('(html) => { document.documentElement.innerHTML = html; }', '''<base href="https://example.com/media/">
                <video src="opaque?id=2"></video>
                <div data-config='{"sources":[{"file":"clip.mp4"}]}'></div>
                <script type="application/ld+json">{"@graph":[{"contentUrl":"manifest"}]}</script>
                <template><source src="template.webm"></template>
                <img src="poster.jpg"><a href="javascript:alert(1)">bad</a>
                <div id="host"></div>''')
            page.evaluate('''() => {
                const root = document.querySelector('#host').attachShadow({mode:'open'});
                root.innerHTML = '<video src="shadow.mp4"></video>';
            }''')
            urls = set(page.evaluate(script))
            assert urls == {
                'https://example.com/media/opaque?id=2',
                'https://example.com/media/clip.mp4',
                'https://example.com/media/manifest',
                'https://example.com/media/template.webm',
                'https://example.com/media/shadow.mp4',
            }, urls
            page.evaluate('''() => {
                const video = document.createElement('video');
                video.src = 'late.mp4'; document.body.append(video);
            }''')
            assert 'https://example.com/media/late.mp4' in page.evaluate(script)
            observer = app.DRM_OBSERVER_SCRIPT
            page.evaluate(observer)
            diagnostics = page.evaluate('''() => {
                const event = new Event('encrypted');
                Object.defineProperty(event, 'initDataType', {value:'cenc'});
                document.querySelector('video').dispatchEvent(event);
                return window.__drmDiagnostics.snapshot();
            }''')
            assert diagnostics['encryptedMediaObserved'], diagnostics
            print('Real DOM extraction passed: media, JSON settings, templates, shadow DOM, dynamic insertion')
            print('Real browser DRM event diagnostics passed')
            stream_script = app.STREAM_OBSERVER_SCRIPT
            page.evaluate(stream_script)
            page.evaluate(MEDIA_OBSERVER_SCRIPT)
            store = []
            page.on('response', lambda response: merge_stream(store,
                identify_stream(response.url, response.headers, source='response', frame_url=page.url)))
            page.route('https://example.com/api/stream', lambda route: route.fulfill(
                status=200, content_type='application/vnd.apple.mpegurl',
                headers={'Access-Control-Allow-Origin':'*'}, body='#EXTM3U\n'))
            page.evaluate('''async () => {
                const response = await fetch('https://example.com/api/stream');
                if (!(await response.text()).startsWith('#EXTM3U')) throw new Error('Response changed');
                const mse = new MediaSource();
                const video = document.createElement('video');
                video.src = URL.createObjectURL(mse);
                document.body.append(video);
                window.testMediaSource = mse;
                URL.createObjectURL(new Blob(['sample'], {type:'video/mp4'}));
            }''')
            page.wait_for_function("window.testMediaSource.readyState === 'open'", timeout=3000)
            page.evaluate('''() => {
                const type = 'video/mp4; codecs="avc1.42E01E"';
                if (MediaSource.isTypeSupported(type)) window.testMediaSource.addSourceBuffer(type);
            }''')
            collect_stream_snapshot(page, store, [])
            kinds = {record['kind'] for record in store}
            assert {'hls_manifest', 'mse_source', 'browser_blob'}.issubset(kinds), store
            assert all(not record['download_candidate'] for record in store if record['kind'] in ('mse_source', 'browser_blob'))
            print('Real JS-stream identification passed: extensionless HLS, fetch, MediaSource, media Blob')
        finally:
            browser.close()


if __name__ == '__main__':
    main()
