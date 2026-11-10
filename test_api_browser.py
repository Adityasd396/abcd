"""Local browser UI check with simulated API JSON and Flask test-client routing."""
import json
from urllib.parse import urlparse
from unittest.mock import MagicMock, patch
from playwright.sync_api import sync_playwright
import app
from test_api_scan import response


def main():
    session = MagicMock()
    session.__enter__.return_value = session
    session.get.return_value = response({'sources':[{'file':'https://cdn.example/movie.mp4'}]})
    client = app.app.test_client()
    def route_local(route):
        request = route.request
        path = urlparse(request.url).path
        if path == '/engine_status':
            route.fulfill(status=200, content_type='application/json', body='{}')
            return
        result = client.open(path, method=request.method,
            data=request.post_data, content_type='application/json' if request.method == 'POST' else None)
        route.fulfill(status=result.status_code, content_type=result.content_type, body=result.data)
    with patch.object(app, 'get_api_session', return_value=session), patch.dict(
            'os.environ', {'RIPPER_API_HEADERS_JSON':'{}'}):
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, timeout=15000)
            try:
                page = browser.new_page()
                page.route('https://api-ui.example/**', route_local)
                page.goto('https://api-ui.example/')
                page.locator('#sourceType').select_option('api')
                page.locator('#ui').fill('https://example.com/api')
                page.locator('#doValidate').uncheck()
                page.locator('#sb').click()
                page.wait_for_function("document.querySelector('#st').textContent === 'COMPLETE'", timeout=10000)
                assert 'movie.mp4' in page.locator('#streamResults').text_content(), {
                    'scans':app.scan_store, 'panel':page.locator('#streamResults').text_content()}
                assert 'API page 1' in page.locator('#term').inner_text()
                print('API browser UI passed: scan source, API extraction, result polling, stream panel')
            finally:
                browser.close()


if __name__ == '__main__':
    main()
