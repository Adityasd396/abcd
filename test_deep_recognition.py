"""Optional additive JS recognition; test only local browser documents."""
import base64
import json
from playwright.sync_api import sync_playwright
import app


def main():
    with sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,timeout=15000)
        try:
            page=browser.new_page()
            page.route('https://deep.test/**',lambda route:route.fulfill(status=200,content_type='text/html',body='''
                <div id="encoded"></div><div id="shadow"></div>
                <script type="application/json">{"playbackUrl":"/opaque"}</script>
                <meta property="og:video" content="/metadata-stream">
                <template><div data-hls="/template-stream"></div></template>
                <script>window.shouldNotRun=0;</script>'''))
            page.goto('https://deep.test/')
            assert not page.evaluate('Boolean(window.__sourceStudioDeep)'), 'Add-on must be inactive by default'
            encoded=base64.b64encode(json.dumps({'contentUrl':'/encoded.mp4'}).encode()).decode()
            page.evaluate('''value=>{
                document.querySelector('#encoded').setAttribute('data-config',value);
                document.querySelector('#shadow').attachShadow({mode:'open'}).innerHTML='<div data-dash="/shadow-stream"></div>';
                const script=document.createElement('script');script.type='text/plain';
                script.textContent='window.shouldNotRun=99; const media="https:\\\\/\\\\/cdn.test\\\\/escaped.m3u8"';document.body.append(script);
            }''',encoded)
            first=page.evaluate(app.DEEP_RECOGNITION_SCRIPT)
            urls={item['url'] for item in first['sources']}
            assert {'https://deep.test/opaque','https://deep.test/encoded.mp4',
                'https://deep.test/metadata-stream','https://deep.test/template-stream','https://deep.test/shadow-stream'}.issubset(urls),first
            assert 'https://cdn.test/escaped.m3u8' in urls,first
            second=page.evaluate(app.DEEP_RECOGNITION_SCRIPT)
            assert second['configs_parsed']==first['configs_parsed'],'Unchanged config should be cached'
            assert page.evaluate('window.shouldNotRun')==0,'Script text must never execute'
            assert app.DiscoveryPlan().deep_js is False
            print('Deep JS add-on passed: opt-in default, encoded JSON, escaped URLs, shadow DOM, templates, metadata and parse cache')
        finally:browser.close()


if __name__=='__main__':main()
