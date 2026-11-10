"""End-to-end local site/API scan and responsive dashboard verification."""
import json
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import patch
from playwright.sync_api import sync_playwright
import app


class Site(BaseHTTPRequestHandler):
    def do_GET(self):
        pages = {
            '/': ('text/html', '''<h1>Media collection</h1><a href="/watch">Watch</a><script src="/player.js"></script>
                <script>fetch('/dynamic'+'/data').then(r=>r.json());
                window.videojs={getPlayers:()=>({local:{currentSources:()=>[{src:'/adapter'+'-only',type:'video/mp4'}]}})};
                </script>'''),
            '/watch': ('text/html','<video src="/clip.mp4"></video>'),
            '/player.js': ('application/javascript',"fetch('/api/videos').then(r=>r.json());"),
            '/api/videos': ('application/json',json.dumps({'sources':[{'file':'/api-file.mp4'},{'file':'/master.m3u8'}]})),
            '/master.m3u8': ('application/vnd.apple.mpegurl','#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1280000,RESOLUTION=1280x720\nvariant.m3u8\n'),
            '/dynamic/data': ('application/json',json.dumps({'contentUrl':'/browser-only'})),
            '/sitemap.xml': ('application/xml','<urlset><url><loc>/hidden</loc></url></urlset>'),
            '/hidden': ('text/html','<video src="/hidden.webm"></video>')}
        mime, body = pages.get(self.path, ('text/plain','missing'))
        status = 200 if self.path in pages else 404
        body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type',mime)
        if self.path != '/dynamic/data':
            self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass


def main():
    server = ThreadingHTTPServer(('127.0.0.1',0),Site)
    worker = threading.Thread(target=server.serve_forever,daemon=True)
    worker.start()
    base = f'http://127.0.0.1:{server.server_port}'
    client = app.app.test_client()
    try:
        with patch.dict('os.environ', {'RIPPER_PROXY_URL':'','RIPPER_API_HEADERS_JSON':'{}',
                'HTTP_PROXY':'','HTTPS_PROXY':'','ALL_PROXY':'','NO_PROXY':'*'}):
            result = client.post('/start_scan',json={'url':base+'/', 'source_type':'website',
                'skip_validate':True, 'page_limit':20, 'time_limit_s':30, 'browser_limit':2,
                'dwell_ms':300, 'concurrency':2}).json
            scan_id = result['scan_id']
            import time
            end = time.monotonic()+40
            while app.scan_store[scan_id]['status'] in ('running','validating') and time.monotonic()<end:
                time.sleep(.2)
            data = app.scan_store[scan_id]
            expected = {base+'/clip.mp4',base+'/api-file.mp4',base+'/browser-only',base+'/hidden.webm'}
            assert expected.issubset(set(data['mp4_links'])), data
            assert data['status']=='done', data['log']
            assert base+'/adapter-only' in data['mp4_links'], data
            assert 'Video.js' in data['player_store'], data
            assert data['manifest_store'][base+'/master.m3u8']['variants'][0]['resolution']=='720p'
            print('Live discovery passed: sitemap, pages, external JS, API JSON and browser-only API response')
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True,timeout=15000)
                try:
                    page = browser.new_page(viewport={'width':1440,'height':1050}, device_scale_factor=1)
                    errors=[]
                    page.on('pageerror',lambda error:errors.append(str(error)))
                    def route_local(route):
                        request=route.request
                        from urllib.parse import urlparse
                        parsed=urlparse(request.url)
                        result=client.open(parsed.path+('?' + parsed.query if parsed.query else ''),method=request.method,
                            data=request.post_data,content_type='application/json' if request.method=='POST' else None)
                        route.fulfill(status=result.status_code,content_type=result.content_type,body=result.data)
                    page.route('https://studio.test/**',route_local)
                    page.goto('https://studio.test/')
                    page.evaluate('(id) => {sid=id;started=Date.now();poll();}',scan_id)
                    page.wait_for_function("document.querySelector('#st').textContent==='COMPLETE'",timeout=10000)
                    assert 'browser-only' in page.locator('#streamResults').text_content()
                    page.screenshot(path=str(Path('studio-desktop.png').resolve()),full_page=True)
                    page.locator('#search').fill('hidden.webm')
                    assert page.locator('tbody tr').count()==1
                    page.locator('#search').fill('')
                    page.set_viewport_size({'width':390,'height':844})
                    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), 'Mobile overflow'
                    page.screenshot(path=str(Path('studio-mobile.png').resolve()),full_page=True)
                    assert not errors, errors
                    print('Studio UI passed: results, filtering, desktop/mobile layout, no browser errors')
                finally:
                    browser.close()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


if __name__ == '__main__':
    main()
