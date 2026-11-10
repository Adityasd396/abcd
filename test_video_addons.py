import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import app


class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/redirect/'):
            n=int(self.path.rsplit('/',1)[1]);self.send_response(302)
            self.send_header('Location',f'/redirect/{n-1}' if n else '/static');self.end_headers();return
        if self.path=='/loop':
            self.send_response(302);self.send_header('Location','/loop');self.end_headers();return
        if self.path=='/missing-location':
            self.send_response(302);self.end_headers();return
        pages={
            '/static':('text/html','<title>Local video</title><meta property="video:duration" content="42"><video src="/clip.mp4"></video><a class="next" href="/second">Next</a>'),
            '/second':('text/html','<h1>Second video</h1><video src="/second.webm"></video>'),
            '/dynamic':('text/html','''<title>Dynamic</title><script>
                setTimeout(()=>{const f=document.createElement('iframe');f.src='/frame';document.body.append(f)},100);
                fetch('/api'+'/dynamic').then(r=>r.json());
                window.videojs={getPlayers:()=>({one:{currentSources:()=>[{src:'/adapter',type:'video/mp4'}]}})};
                new Worker('/worker.js');
                </script>'''),
            '/frame':('text/html','<video src="/frame.mp4"></video>'),
            '/worker.js':('application/javascript',"fetch('/api/worker').then(r=>r.json())"),
            '/api/worker':('application/json',json.dumps({'contentUrl':'/worker.mp4'})),
            '/api/dynamic':('application/json',json.dumps({'contentUrl':'/dynamic.mp4'})),
        }
        mime,body=pages.get(self.path,('text/plain','missing'))
        self.send_response(200 if self.path in pages else 404)
        self.send_header('Content-Type',mime);self.send_header('Content-Length',str(len(body.encode())))
        self.end_headers();self.wfile.write(body.encode())
    def log_message(self,*args): pass


class AddonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),Fixture)
        threading.Thread(target=cls.server.serve_forever,daemon=True).start()
        cls.base=f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls): cls.server.shutdown();cls.server.server_close()

    def setUp(self):
        self.env=patch.dict('os.environ',{'RIPPER_PROXY_URL':'','RIPPER_API_HEADERS_JSON':'{}','HTTP_PROXY':'','HTTPS_PROXY':'','ALL_PROXY':'','NO_PROXY':'*'})
        self.env.start();self.temp=tempfile.TemporaryDirectory()
        self.journal=app.VideoJournal(Path(self.temp.name)/'test.sqlite3')
        self.jpatch=patch.object(app,'VideoJournal',return_value=self.journal);self.jpatch.start()
        self.client=app.app.test_client();self.ids=[]

    def tearDown(self):
        for key in self.ids: app.scan_store.pop(key,None)
        self.jpatch.stop();self.temp.cleanup();self.env.stop()

    def scan(self,path='/static',addons=None,**kw):
        payload={'url':self.base+path,'skip_validate':True,'render_browser':False,'discover_sitemap':False,
            'page_limit':5,'depth':0,'time_limit_s':20,'addons':addons or {}}
        payload.update(kw)
        res=self.client.post('/addons/start',json=payload)
        self.assertEqual(res.status_code,200,res.json)
        key=res.json['scan_id'];self.ids.append(key)
        end=time.monotonic()+30
        while app.scan_store[key]['status']=='running' and time.monotonic()<end: time.sleep(.05)
        r=app.scan_store[key];self.assertEqual(r['status'],'done',r['log'])
        return key,r

    def test_original_code_unchanged(self):
        text=Path(app.__file__).read_text(encoding='utf-8');a=text.index('# BEGIN OPTIONAL VIDEO ADDONS\n');b=text.index('# END OPTIONAL VIDEO ADDONS\n')+len('# END OPTIONAL VIDEO ADDONS\n')
        self.assertEqual(text[:a]+text[b:],Path('build_support/app_base.py').read_text(encoding='utf-8'))

    def test_metadata_recipe_pagination_export(self):
        key,r=self.scan(addons={'recipe':{'next':'a.next','title':'title,h1'}})
        self.assertIn(self.base+'/second.webm',r['mp4_links'])
        self.assertTrue(any(v.get('duration')=='42' and v.get('title')=='Local video' for v in r['video_records']))
        csv=self.client.get('/addons/export/'+key+'?format=csv&fields=title,url').text
        self.assertTrue(csv.startswith('title,url'));self.assertIn('Local video',csv)
        self.assertGreater(r['addon_metrics']['static_bytes'],0)
        self.assertIsNotNone(r['addon_metrics']['first_result_seconds'])

    def test_redirect_chain_and_loop(self):
        _,r=self.scan('/redirect/6');self.assertIn(self.base+'/clip.mp4',r['mp4_links'])
        self.assertEqual(r['addon_metrics']['redirects'],7)
        _,r=self.scan('/loop');self.assertTrue(any('Redirect loop' in s for s in r['log']))
        self.assertEqual(r['addon_metrics']['requests'],1)
        _,r=self.scan('/missing-location');self.assertTrue(any('no Location' in s for s in r['log']))

    def test_cache_and_resume(self):
        options={'persist':True,'incremental':True}
        key,r=self.scan(addons=options)
        _,second=self.scan(addons=options)
        self.assertEqual(second['addon_metrics']['unchanged_pages'],1)
        self.assertEqual(second['mp4_links'],r['mp4_links'])
        saved=self.journal.get('run',key);saved['pending']=[[self.base+'/second',0,'page']]
        self.journal.put('run',key,saved)
        _,resumed=self.scan(addons={**options,'resume_id':key})
        self.assertIn(self.base+'/second.webm',resumed['mp4_links'])
        self.assertIn(self.base+'/clip.mp4',resumed['mp4_links'])

    def test_privacy_and_validation(self):
        self.assertEqual(app._va_safe_url('https://host/video?token=secret'),'')
        self.assertEqual(app._va_safe_url('https://name:secret@host/video'),'')
        r=self.client.post('/addons/start',json={'url':self.base,'addons':{'recipe':{'media':'['}}})
        self.assertEqual(r.status_code,400)
        self.assertFalse(Path(self.journal.path).exists())

    def test_fast_parser_fallback_and_equivalence(self):
        _,reference=self.scan()
        _,fast=self.scan(addons={'fast_parser':True})
        self.assertEqual(reference['mp4_links'],fast['mp4_links'])
        with patch.object(app,'_VAParser',None):
            _,fallback=self.scan(addons={'fast_parser':True})
        self.assertEqual(fallback['addon_metrics']['parser'],'BeautifulSoup')
        self.assertEqual(reference['video_records'],fallback['video_records'])

    def test_adaptive_static_skips_browser(self):
        _,r=self.scan(addons={'adaptive':True},render_browser=True)
        self.assertEqual(r['browser_pages'],0)
        self.assertEqual(r['addon_metrics']['browser_skipped'],1)

    def test_browser_dynamic_frames_api_player(self):
        _,r=self.scan('/dynamic',addons={'adaptive':True,'browser_channels':True},render_browser=True,dwell_ms=1200,browser_limit=1,deep_js=True)
        for path in ('/dynamic.mp4','/frame.mp4','/adapter','/worker.mp4'):
            self.assertIn(self.base+path,r['mp4_links'],r['log'])
        self.assertIn('Video.js',r['player_store'])
        self.assertGreater(r['addon_metrics']['browser_bytes'],0)

    def test_recipe_roundtrip_and_clear(self):
        r=self.client.post('/addons/recipes',json={'url':self.base,'recipe':{'media':'video'}})
        self.assertEqual(r.status_code,200)
        history=self.client.get('/addons/history').json
        self.assertEqual(history['recipes'][0]['recipe'],{'media':'video'})
        self.client.delete('/addons/history')
        self.assertEqual(self.client.get('/addons/history').json['recipes'],[])

    def test_dashboard_mobile_and_submit(self):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser=pw.chromium.launch(headless=True)
            try:
                page=browser.new_page(viewport={'width':390,'height':844});errors=[]
                page.on('pageerror',lambda e:errors.append(str(e)))
                def route_local(route):
                    req=route.request
                    from urllib.parse import urlsplit
                    u=urlsplit(req.url)
                    r=self.client.open(u.path+('?' + u.query if u.query else ''),method=req.method,data=req.post_data,content_type=req.headers.get('content-type'))
                    route.fulfill(status=r.status_code,body=r.data,headers=dict(r.headers))
                page.route('http://studio.local/**',route_local)
                page.goto('http://studio.local/')
                page.locator('#ui').fill(self.base+'/static')
                page.locator('#vaEnabled').check()
                page.locator('#renderBrowser').uncheck();page.locator('#discoverSitemap').uncheck();page.locator('#doValidate').uncheck()
                page.locator('#sb').click()
                page.wait_for_function("document.getElementById('st').textContent==='COMPLETE'",timeout=30000)
                page.wait_for_function("document.getElementById('vaMetrics').textContent.includes('Unique sources: 1')")
                self.assertFalse(errors,errors)
                self.assertTrue(page.evaluate('document.documentElement.scrollWidth<=innerWidth'))
                page.screenshot(path='video-addons-mobile.png',full_page=True)
                page.set_viewport_size({'width':1440,'height':1050});page.screenshot(path='video-addons-desktop.png',full_page=True)
                self.ids.append(page.evaluate('sid'))
            finally: browser.close()


if __name__=='__main__': unittest.main()
