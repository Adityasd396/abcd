import unittest
from unittest.mock import MagicMock,patch
import app

class TeraBoxTests(unittest.TestCase):
    def setUp(self):
        self.client=app.app.test_client()
        self.data={'url':'https://terabox.com/s/example','provider':'iteraplay_com','token':'private-token','token_name':'x-verification','token_location':'header'}

    def upstream(self,payload,status=200):
        response=MagicMock();response.status_code=status;response.iter_content.return_value=[app._json_mod.dumps(payload).encode()]
        session=MagicMock();session.__enter__.return_value=session;session.post.return_value=response
        return session

    def test_header_scope_and_filtered_result(self):
        s=self.upstream({'status':'success','token':'private-token','list':[{'fast_stream_url':{'720p':'https://cdn.example/video.m3u8'},'download_link':'https://cdn.example/x?secret=private-token'}]})
        with patch.object(app.requests,'Session',return_value=s):r=self.client.post('/terabox/resolve',json=self.data)
        self.assertEqual(r.status_code,200)
        self.assertEqual(len(r.json['sources']),1)
        self.assertNotIn('private-token',r.text)
        args=s.post.call_args
        self.assertEqual(args.args[0],'https://iteraplay.com/api/stream')
        self.assertFalse(args.kwargs['allow_redirects'])
        self.assertEqual(args.kwargs['headers']['x-verification'],'private-token')
        self.assertNotIn('Cookie',args.kwargs['headers'])

    def test_json_token_and_sanitized_failure(self):
        self.data['token_location']='json'
        s=self.upstream({'error':'token_missing','message':'private-token'},400)
        with patch.object(app.requests,'Session',return_value=s):r=self.client.post('/terabox/resolve',json=self.data)
        self.assertEqual(s.post.call_args.kwargs['json']['x-verification'],'private-token')
        self.assertEqual(r.status_code,502);self.assertNotIn('private-token',r.text)

    def test_redirect_never_forwarded(self):
        s=self.upstream({},302)
        with patch.object(app.requests,'Session',return_value=s):r=self.client.post('/terabox/resolve',json=self.data)
        self.assertEqual(r.status_code,502);self.assertEqual(s.post.call_count,1)

    def test_direct_cookie_isolation(self):
        with patch.object(app,'_tb_direct',return_value=({'sources':[]},200)) as direct:
            r=self.client.post('/terabox/resolve',json={'url':self.data['url'],'provider':'direct','cookies':'session=my-session'})
        self.assertEqual(r.status_code,200)
        self.assertEqual(direct.call_args.args[1][0]['domain'],'terabox.com')
        self.assertNotIn('my-session',r.text)
        self.data['cookies']='session=my-session'
        self.assertEqual(self.client.post('/terabox/resolve',json=self.data).status_code,400)

    def test_validation_and_page(self):
        self.data['url']='https://terabox.com.evil.test/s/example'
        self.assertEqual(self.client.post('/terabox/resolve',json=self.data).status_code,400)
        self.assertEqual(self.client.get('/terabox').status_code,200)
        self.assertNotIn('localStorage',self.client.get('/terabox').text)
        self.assertEqual(self.client.post('/terabox/resolve',json={},headers={'Origin':'https://evil.test'}).status_code,403)

    def test_domain_export_filtering(self):
        data=[{'name':'foreign','value':'fixture','domain':'.unrelated.example'},
              {'name':'session','value':'fixture','domain':'.1024terabox.com','path':'/share','secure':True}]
        parsed=app._tb_cookies(app._json_mod.dumps(data))
        self.assertEqual(len(parsed),1)
        self.assertEqual(parsed[0]['domain'],'.1024terabox.com')
        self.assertEqual(parsed[0]['path'],'/share')
        self.assertEqual(app._tb_cookies('session=fixture','www.1024terabox.com')[0]['domain'],'www.1024terabox.com')
        with self.assertRaises(ValueError):app._tb_cookies('[{"name":"x","value":"fixture","domain":"terabox.com.evil.test"}]')

    def test_table_and_netscape(self):
        table='foreign\tfixture\t.google.test\t/\tSession\npreference\t1\t.1024terabox.com\t/\tSession'
        self.assertEqual(len(app._tb_cookies(table)),1)
        netscape='# Netscape HTTP Cookie File\n#HttpOnly_.terabox.com\tTRUE\t/\tTRUE\t0\tsession\tfixture'
        parsed=app._tb_cookies(netscape)
        self.assertTrue(parsed[0]['httpOnly']);self.assertEqual(parsed[0]['domain'],'.terabox.com')

    def test_terabox_share_and_cookie_scope(self):
        for host in ('terabox.app','www.terabox.app','www.1024terabox.com'):
            with patch.object(app,'_tb_direct',return_value=({'sources':[]},200)) as direct:
                response=self.client.post('/terabox/resolve',json={'url':'https://'+host+'/s/example','provider':'direct','cookies':'session=fixture'})
            self.assertEqual(response.status_code,200)
            self.assertEqual(direct.call_args.args[1][0]['domain'],host)
        exported=app._tb_cookies('[{"name":"session","value":"fixture","domain":".terabox.app"}]')
        self.assertEqual(exported[0]['domain'],'.terabox.app')
        self.assertFalse(app._tb_cookie_domain('terabox.app.evil.test'))

    def test_invalid_cookie_error_does_not_echo_secret(self):
        r=self.client.post('/terabox/resolve',json={'url':self.data['url'],'provider':'direct','cookies':'secret-fixture\tbad'})
        self.assertEqual(r.status_code,400);self.assertNotIn('secret-fixture',r.text)
        self.assertIn('cookie',r.json['error'])

    def test_interactive_session_is_direct_and_fresh(self):
        data={'url':'https://terabox.app/s/example','provider':'direct','browser_session':True}
        with patch.object(app,'_tb_direct',return_value=({'sources':[]},200)) as direct:
            response=self.client.post('/terabox/resolve',json=data)
            self.assertEqual(response.status_code,200)
            direct.assert_called_once_with(data['url'],[],interactive=True)
            self.assertEqual(self.client.post('/terabox/resolve',json={**data,'cookies':'session=fixture'}).status_code,400)
            self.assertEqual(self.client.post('/terabox/resolve',json={**data,'provider':'iteraplay_com'}).status_code,400)

    def test_navigation_timeout_leaves_retry_page_in_capture_window(self):
        browser=MagicMock()
        page=browser.new_context.return_value.new_page.return_value
        page.goto.side_effect=[TimeoutError('Navigation timeout'),None]
        page.is_closed.side_effect=[False,False,True]
        page.url='about:blank'
        share='https://terabox.app/s/example?label=a&other=b'
        with patch.object(app,'PLAYWRIGHT_OK',True), patch.object(app,'sync_playwright',create=True), patch.object(app,'_make_pw_browser',return_value=browser):
            result,status=app._tb_direct.__wrapped__(share,[],interactive=True)
        self.assertEqual(status,200)
        self.assertIn('within 12 seconds',result['message'])
        self.assertIn('label=a&amp;other=b',page.set_content.call_args.args[0])
        self.assertIn('https://www.1024terabox.com/',page.set_content.call_args.args[0])
        page.wait_for_timeout.assert_called_once_with(2000)

    def test_saved_session_only_used_for_direct_resolution(self):
        data={'url':'https://terabox.app/s/example','provider':'direct','saved_session':True}
        cookies=[{'name':'session','value':'fixture','domain':'.terabox.app'}]
        with patch.object(app,'_tb_load_session',return_value=cookies) as load, patch.object(app,'_tb_direct',return_value=({'sources':[]},200)) as direct:
            self.assertEqual(self.client.post('/terabox/resolve',json={**data,'provider':'iteraplay_com'}).status_code,400)
            load.assert_not_called()
            response=self.client.post('/terabox/resolve',json=data)
            self.assertEqual(response.status_code,200)
            direct.assert_called_once_with(data['url'],cookies,interactive=True)
            self.assertNotIn('fixture',response.text)

    def test_finish_saves_latest_cookies_and_closes_browser(self):
        browser=MagicMock()
        context=browser.new_context.return_value
        page=context.new_page.return_value
        page.is_closed.return_value=False
        cookie={'name':'session','value':'fixture','domain':'.terabox.app'}
        context.cookies.side_effect=[[],[cookie,{'domain':'.example.test'}]]
        job_id='12345678-1234-4321-8123-123456789abc'
        direct=app._tb_direct.__wrapped__

        def finish_in_resolver():
            with app.app.test_client() as client:
                self.assertEqual(client.post('/terabox/session/finish',json={'job_id':'stale'}).status_code,409)
                self.assertEqual(client.post('/terabox/session/finish',json={'job_id':job_id}).status_code,200)

        page.wait_for_timeout.side_effect=lambda _:finish_in_resolver()
        with patch.object(app,'_tb_session_path'), patch.object(app,'_tb_direct',side_effect=direct), patch.object(app,'PLAYWRIGHT_OK',True), patch.object(app,'sync_playwright',create=True), patch.object(app,'_make_pw_browser',return_value=browser), patch.object(app,'_tb_save_session') as save:
            response=self.client.post('/terabox/session',json={'job_id':job_id})
            self.assertEqual(response.status_code,200,response.text)
            save.assert_called_once_with([cookie])
            browser.close.assert_called_once()
        self.assertEqual(self.client.post('/terabox/session/finish',json={'job_id':job_id}).status_code,409)

    def test_automatic_mode_reuses_cookies_and_finishes_on_media(self):
        browser=MagicMock()
        context=browser.new_context.return_value
        page=context.new_page.return_value
        share='https://www.1024terabox.com/s/example'
        page.url=share
        page.is_closed.return_value=False
        page.goto.return_value.status=200
        page.get_by_text.return_value.first.is_visible.return_value=False
        page.locator.return_value.evaluate_all.return_value=False
        play=page.get_by_role.return_value
        play.count.return_value=1
        play.is_visible.return_value=True
        stored=[{'name':'session','value':'fixture','domain':'.1024terabox.com'}]
        user_agent='Mozilla/5.0 FixtureBrowser/1.0'
        tracks={}
        for milliseconds, stream_type in ((400,'M3U8_SUBTITLE_SRT'),(800,'M3U8_FLV_264_360'),(2400,'M3U8_FLV_264_480')):
            response=MagicMock(status=200,url='https://dm.1024tera.com/share/streaming?type='+stream_type,
                               headers={'content-type':'application/vnd.apple.mpegurl'})
            response.request.frame.url=share
            tracks[milliseconds]=response
        elapsed=0

        def wait(milliseconds):
            nonlocal elapsed
            elapsed+=milliseconds
            if elapsed in tracks and (elapsed==400 or play.click.called):
                context.on.call_args.args[1](tracks[elapsed])

        page.wait_for_timeout.side_effect=wait
        direct=app._tb_direct.__wrapped__
        with patch.object(app,'_tb_direct',side_effect=direct), patch.object(app,'PLAYWRIGHT_OK',True), patch.object(app,'sync_playwright',create=True), patch.object(app,'_make_pw_browser',return_value=browser) as launch, patch.object(app,'extract_live_frame_urls',return_value=[]), patch.object(app.time,'monotonic',side_effect=lambda:elapsed/1000), patch.object(app,'_tb_load_session',return_value=(stored,user_agent)), patch.object(app,'_tb_save_session') as save:
            data={'url':share,'provider':'direct','auto_session':True}
            result=self.client.post('/terabox/resolve',json=data)
            self.assertTrue(launch.call_args.kwargs['headless'])
            browser.new_context.assert_called_once_with(user_agent=user_agent,accept_downloads=False)
            self.assertLess(elapsed,4000)
            context.add_cookies.assert_called_once_with(stored)
            page.locator.return_value.evaluate_all.assert_called_once()
            play.click.assert_called_once_with(timeout=800)
            save.assert_not_called()
            browser.close.assert_called_once()

        self.assertEqual(result.status_code,200,result.text)
        self.assertEqual([item['url'] for item in result.json['sources']],[response.url for response in tracks.values()])
        self.assertEqual([item.get('quality') for item in result.json['sources']],[None,'360p','480p'])
        self.assertEqual(result.json['sources'][0]['kind'],'subtitle_track')

    def test_stream_json_error_is_reported_instead_of_a_media_link(self):
        browser=MagicMock()
        context=browser.new_context.return_value
        page=context.new_page.return_value
        share='https://www.1024terabox.com/s/example'
        stream='https://dm.1024tera.com/share/streaming?type=M3U8_FLV_264_360'
        page.url=share
        page.is_closed.return_value=False
        payload=b'{"errno":31326,"show_msg":"fixture-private-text"}'
        response=MagicMock(status=200,url=stream,headers={'content-type':'application/json'})
        response.request.sizes.return_value={'responseBodySize':len(payload)}
        response.body.return_value=payload
        elapsed=0

        def wait(milliseconds):
            nonlocal elapsed
            elapsed+=milliseconds
            if elapsed==400:
                context.on.call_args.args[1](response)

        page.wait_for_timeout.side_effect=wait
        with patch.object(app,'PLAYWRIGHT_OK',True), patch.object(app,'sync_playwright',create=True), patch.object(app,'_make_pw_browser',return_value=browser), patch.object(app,'extract_live_frame_urls',return_value=[(stream,share)]), patch.object(app.time,'monotonic',side_effect=lambda:elapsed/1000):
            result,status=app._tb_direct.__wrapped__(share,[],auto_session=True)
        self.assertEqual(status,200)
        self.assertEqual(result['upstream_errno'],31326)
        self.assertEqual(result['sources'],[])
        self.assertNotIn('fixture-private-text',result['message'])
        elapsed=0
        page.url='https://www.terabox.app/s/example'
        cookies=[{'name':'session','value':'fixture-private-cookie','domain':'.1024terabox.com'}]
        with patch.object(app,'PLAYWRIGHT_OK',True), patch.object(app,'sync_playwright',create=True), patch.object(app,'_make_pw_browser',return_value=browser), patch.object(app,'extract_live_frame_urls',return_value=[(stream,share)]), patch.object(app.time,'monotonic',side_effect=lambda:elapsed/1000):
            result,status=app._tb_direct.__wrapped__(share,cookies,auto_session=True)
        self.assertEqual(status,200)
        self.assertEqual(result['cookie_host'],'www.terabox.app')
        self.assertEqual(result['full_video_share'],share)
        self.assertNotIn('fixture-private-cookie',result['message'])

    def test_media_relay_reuses_headers_for_manifest_and_segment(self):
        share='https://www.1024terabox.com/s/example'
        root='https://dm.1024tera.com/share/streaming?fixture=1'
        headers={'user-agent':'Fixture Chromium','referer':share,'cookie':'captured=fixture'}
        cookies=[{'name':'segment','value':'fixture','domain':'v4.freeterabox.com','path':'/video/'},
                 {'name':'manifest','value':'fixture','domain':'dm.1024tera.com','path':'/share/'}]
        sources={root:{'url':root,'kind':'hls_manifest'}}
        app._tb_attach_media_relay(sources,{root:(headers,None)},cookies)
        local=sources[root]['replay_url']
        session_id=local.split('/')[3]

        def upstream(url,headers,**options):
            response=MagicMock(is_redirect=False)
            self.assertEqual(headers['user-agent'],'Fixture Chromium')
            self.assertEqual(headers['referer'],share)
            if url==root:
                self.assertEqual(headers['cookie'],'captured=fixture')
                response.status_code=200
                response.headers={'Content-Type':'application/vnd.apple.mpegurl'}
                response.iter_content.return_value=[b'#EXTM3U\n#EXTINF:4,\nhttps://v4.freeterabox.com/video/segment.ts\n']
            else:
                self.assertEqual(url,'https://v4.freeterabox.com/video/segment.ts')
                self.assertEqual(headers['cookie'],'segment=fixture')
                self.assertEqual(headers['range'],'bytes=0-3')
                response.status_code=206
                response.headers={'Content-Type':'video/mp2t','Content-Range':'bytes 0-3/20'}
                response.iter_content.return_value=[b'data']
            return response

        try:
            with patch.object(app.requests,'Session') as requests_session:
                requests_session.return_value.get.side_effect=upstream
                playlist=self.client.get(local)
                self.assertEqual(playlist.status_code,200,playlist.text)
                segment_url=playlist.text.splitlines()[-1]
                self.assertTrue(segment_url.startswith('/terabox/media/'))
                response=self.client.get(segment_url,headers={'Range':'bytes=0-3'},buffered=True)
                self.assertEqual(response.status_code,206,response.text)
                self.assertEqual(response.data,b'data')
        finally:
            app._TB_MEDIA.pop(session_id)['timer'].cancel()

    def test_cached_manifest_rejects_external_urls(self):
        root='https://dm.1024tera.com/share/streaming?fixture=2'
        sources={root:{'url':root,'kind':'hls_manifest'}}
        app._tb_attach_media_relay(sources,{root:({},b'#EXTM3U\nhttps://127.0.0.1/hidden\n')},[])
        local=sources[root]['replay_url']
        try:
            with patch.object(app.requests,'Session') as requests_session:
                response=self.client.get(local)
                self.assertEqual(response.status_code,502)
                self.assertIn('unsupported media host (127.0.0.1)',response.text)
                requests_session.assert_not_called()
        finally:
            app._TB_MEDIA.pop(local.split('/')[3])['timer'].cancel()

    def test_rolling_playlist_is_not_frozen_at_30_seconds(self):
        rolling=b'#EXTM3U\n#EXTINF:12.5,\nfirst.ts\n#EXTINF:17.5,\nsecond.ts\n'
        self.assertEqual(app._tb_playlist_snapshot(rolling),(None,None))
        ended=rolling+b'#EXTINF:100,\nthird.ts\n#EXT-X-ENDLIST\n'
        self.assertEqual(app._tb_playlist_snapshot(ended),(ended,130))

    @unittest.skipUnless(app.os.name=='nt','Windows cookie storage')
    def test_saved_session_encryption_expiry_and_clear(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        cookies=[{'name':'session','value':'fixture-cookie','domain':'.terabox.app','expires':-1},
                 {'name':'old','value':'expired','domain':'.terabox.app','expires':1},
                 {'name':'external','value':'unrelated','domain':'.example.test','expires':-1}]
        with TemporaryDirectory() as folder:
            path=Path(folder)/'session.bin'
            with patch.object(app,'_tb_session_path',return_value=path):
                app._tb_save_session(cookies)
                self.assertNotIn(b'fixture-cookie',path.read_bytes())
                self.assertEqual(app._tb_load_session(),cookies[:1])
                self.assertEqual(self.client.delete('/terabox/session').status_code,200)
                self.assertEqual(app._tb_load_session(),[])

    @unittest.skipUnless(app.os.name=='nt','Windows cookie storage')
    def test_uploaded_cookie_export_is_reusable(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        export=('# Netscape HTTP Cookie File\n.terabox.app\tTRUE\t/\tTRUE\t0\tsession\tfixture-secret\n'
                '.terabox.app\tTRUE\t/\tTRUE\t1\texpired\tfixture\n'
                '.example.test\tTRUE\t/\tTRUE\t0\tforeign\tfixture\n')
        with TemporaryDirectory() as folder, patch.object(app,'_tb_session_path',return_value=Path(folder)/'session.bin') as path:
            user_agent='Mozilla/5.0 FixtureBrowser/1.0'
            response=self.client.post('/terabox/session/import',data=export,content_type='text/plain',
                                      headers={'X-TeraBox-User-Agent':user_agent})
            self.assertEqual(response.status_code,200,response.text)
            self.assertNotIn('fixture-secret',response.text)
            self.assertNotIn(b'fixture-secret',path.return_value.read_bytes())
            cookies=app._tb_load_session()
            self.assertEqual(app._tb_load_session(with_user_agent=True),(cookies,user_agent))
            response=self.client.post('/terabox/session/user-agent',json={'user_agent':'netdisk'})
            self.assertEqual(response.status_code,200,response.text)
            self.assertEqual(app._tb_load_session(with_user_agent=True),(cookies,'netdisk'))
            self.assertEqual([cookie['name'] for cookie in cookies],['session'])
            self.assertEqual(self.client.post('/terabox/session/import',data='session=unknown').status_code,400)
            self.assertEqual(app._tb_load_session(),cookies)

if __name__=='__main__':unittest.main()
