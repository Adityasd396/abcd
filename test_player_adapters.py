"""Real-browser adapters and lazy playback observation with local fixtures."""
from playwright.sync_api import sync_playwright
import app


def main():
    with sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,timeout=15000)
        try:
            context=app._make_pw_context(browser)
            page=context.new_page()
            page.route('https://players.test/**',lambda route:route.fulfill(status=200,content_type='text/html',body='''
                <video id="native"></video><div id="jw" class="jwplayer"></div>
                <script>
                window.videojs={getPlayers:()=>({v:{currentSources:()=>[{src:'/videojs',type:'video/mp4'}]}})};
                window.jwplayer=()=>({getPlaylist:()=>[{sources:[{file:'/jw.m3u8'}],image:'/poster.jpg'}]});
                window.shakaPlayer={getAssetUri:()=>'/shaka.mpd',getVariantTracks:()=>[]};
                window.hls={loadSource(){},attachMedia(){},url:'/hls',levels:[{url:['/level.m3u8']}]};
                window.dashPlayer={getSource:()=>'/dash',getActiveStream:()=>({})};
                const video=document.querySelector('video');
                video.play=function(){window.playCalls=(window.playCalls||0)+1;this.src='/lazy.mp4';this.dispatchEvent(new Event('playing'));return Promise.resolve()};
                video.pause=function(){window.pauseCalls=(window.pauseCalls||0)+1};
                </script>'''))
            page.goto('https://players.test/')
            report=page.evaluate('() => window.__playerDiscovery.sample(false)')
            assert len(report['players'])==5, report
            urls={source['url'] for source in report['sources']}
            assert 'https://players.test/videojs' in urls and 'https://players.test/jw.m3u8' in urls,report
            assert not any('poster.jpg' in url for url in urls)
            assert page.evaluate('window.playCalls || 0')==0
            page.evaluate('() => window.__playerDiscovery.sample(true)')
            report=page.evaluate('() => window.__playerDiscovery.sample(false)')
            assert any(source['url'].endswith('/lazy.mp4') for source in report['sources'])
            assert any(event['event']=='playing' for event in report['playback']), report
            page.evaluate('() => window.__playerDiscovery.finish()')
            assert page.evaluate('document.querySelector("video").muted') is False
            assert page.evaluate('window.pauseCalls')==1
            print('Player adapters passed: five APIs, lazy playback source, event observation, opt-out and cleanup')
        finally:
            browser.close()


if __name__=='__main__':main()

