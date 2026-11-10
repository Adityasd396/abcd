"""Development source embedded into app.py; not required at runtime."""
from dataclasses import dataclass
import heapq
from contextlib import closing
from contextlib import contextmanager
from xml.etree import ElementTree


@dataclass(frozen=True)
class DiscoveryPlan:
    pages: int = 80
    depth: int = 3
    workers: int = 3
    browser_pages: int = 8
    dwell_ms: int = 1800
    seconds: int = 120
    validate: bool = True
    sitemap: bool = True
    browser: bool = True
    attempt_playback: bool = True
    deep_js: bool = False


class DiscoveryEngine:
    """One bounded frontier, a media registry, and separate render/verify budgets."""
    def __init__(self, scan_id, url, plan):
        self.r = scan_store[scan_id]
        self.url, self.plan = url, plan
        self.deadline = time.monotonic() + plan.seconds
        self.frontier, self.queued, self.visited = [], set(), set()
        self.render_targets, self.media = [], set(self.r['mp4_links'])
        self.sequence = 0
        self.connections=threading.local()
        self.sessions=[]
        self.sessions_lock=threading.Lock()
        self.r.update(phase='discovering', queue_size=0, browser_pages=0,
            requests_failed=0, blocked_pages=0, api_responses=0, started_at=time.time(),
            limits={'pages':plan.pages, 'depth':plan.depth, 'browser_pages':plan.browser_pages,
                    'seconds':plan.seconds}, coverage_notes=[])

    def active(self):
        return not self.r.get('cancel_requested') and not self.r.get('rate_limited') and time.monotonic() < self.deadline

    def emit(self, message):
        self.r['log'].append(message)

    @contextmanager
    def pooled_connection(self):
        session=getattr(self.connections,'session',None)
        if session is None:
            session=get_api_session()
            self.connections.session=session
            with self.sessions_lock:self.sessions.append(session)
        yield session

    def close_connections(self):
        with self.sessions_lock:
            sessions,self.sessions=self.sessions,[]
        for session in sessions:session.close()

    def scope(self, url):
        try:
            return _api_origin(url) == _api_origin(self.url)
        except ValueError:
            return False

    def enqueue(self, url, depth=0, kind='page'):
        url = normalise_url(url, self.url)
        if not self.scope(url) or url in self.queued or depth > self.plan.depth:
            return
        if len(self.queued) >= self.plan.pages * 8:
            return
        path = urlparse(url).path.lower()
        if re.search(r'\.(?:png|jpe?g|gif|svg|css|woff2?|pdf|zip|ico)$', path):
            return
        if any(word in path for word in ('/logout', '/signout', '/delete')):
            return
        priority = depth * 10 - (5 if re.search(r'video|watch|play|episode|stream|/api/', path) else 0)
        self.sequence += 1
        heapq.heappush(self.frontier, (priority, self.sequence, url, depth, kind))
        self.queued.add(url)

    def add(self, record):
        if not record:
            return
        merge_stream(self.r['stream_diagnostics'], record)
        if record['kind'] not in ('segment_candidate', 'browser_blob', 'mse_source', 'mse_buffer'):
            url = record['url']
            if url not in self.media and len(self.media) < 5000:
                self.media.add(url)
                self.r['mp4_links'].append(url)

    def fetch(self, url):
        """Workers own sessions; redirects and decoded body sizes are bounded."""
        if not self.active():
            return {'url':url, 'skip':True}
        try:
            with self.pooled_connection() as session:
                current = url
                for _ in range(5):
                    if not self.scope(current):
                        return {'url':url, 'error':'Cross-origin page redirect skipped'}
                    with closing(session.get(current, stream=True, allow_redirects=False,
                            timeout=min(10, max(1, self.deadline-time.monotonic())))) as response:
                        status, headers = response.status_code, dict(response.headers)
                        if status in (301, 302, 303, 307, 308):
                            current = normalise_url(headers.get('Location', ''), current)
                            continue
                        content_type = response.headers.get('Content-Type', '').lower()
                        record = identify_stream(current, headers, source='response', frame_url=url)
                        # Do not download full media bodies while discovering links.
                        if record and record['confidence'] == 'response_headers':
                            return {'url':current, 'status':status, 'headers':headers, 'record':record, 'text':''}
                        if status >= 400:
                            return {'url':current, 'status':status, 'headers':headers, 'text':''}
                        body = bytearray()
                        for chunk in response.iter_content(65536):
                            if not self.active():
                                return {'url':url, 'skip':True}
                            body.extend(chunk)
                            if len(body) > 2*1024*1024:
                                return {'url':url, 'error':'Page exceeded 2 MiB discovery limit'}
                        return {'url':current, 'status':status, 'headers':headers,
                            'text':body.decode(response.encoding or 'utf-8', errors='replace')}
                return {'url':url, 'error':'Redirect limit reached'}
        except Exception as exc:
            return {'url':url, 'error':api_failure_message(exc, 'page discovery')}

    def consume(self, item, depth, kind):
        if item.get('skip'):
            return
        self.r['pages_scraped'] += 1
        url = item['url']
        if item.get('error'):
            self.r['requests_failed'] += 1
            self.emit(item['error'])
            return
        status = item['status']
        if status in (401, 403, 429):
            self.r['blocked_pages'] += 1
            self.emit(f'HTTP {status}: access unavailable; no repeated retries.')
            if status == 429:
                self.r['rate_limited'] = True
            return
        if status >= 400:
            self.r['requests_failed'] += 1
            return
        self.add(item.get('record'))
        text = item.get('text', '')
        if not text:
            return
        reason = access_block_reason(text)
        if reason:
            self.r['blocked_pages'] += 1
            self.emit(reason)
            return
        try:
            payload = _json_mod.loads(text)
        except (ValueError, RecursionError):
            payload = None
        if payload is not None:
            self.r['api_responses'] += 1
            for record in extract_api_media(payload, url):
                self.add(record)
            following = api_next_url(payload, url, item['headers'].get('Link', ''))
            if following:
                self.enqueue(following, depth, 'api')
        raw_links = []
        _extract_from_raw(text.replace(r'\u002f', '/').replace(r'\u002F', '/'), url,
            raw_links, [], player_store=self.r['player_store'])
        for link in raw_links:
            self.add(identify_stream(link, source='page_source', frame_url=url))
        if kind in ('sitemap', 'robots'):
            if kind == 'robots':
                for match in re.finditer(r'(?im)^sitemap:\s*(https?://\S+)', text):
                    self.enqueue(match.group(1), 0, 'sitemap')
            else:
                try:
                    if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
                        return
                    root = ElementTree.fromstring(text)
                    child_kind = 'sitemap' if root.tag.endswith('sitemapindex') else 'page'
                    for element in root.iter():
                        if element.tag.split('}')[-1] == 'loc' and element.text:
                            self.enqueue(element.text.strip(), 0 if child_kind == 'sitemap' else 1, child_kind)
                            self.r['sitemap_size'] += 1
                except ElementTree.ParseError:
                    pass
            return
        soup = BeautifulSoup(text, 'html.parser')
        if kind == 'page' and '<' in text:
            self.render_targets.append(url)
        for tag in soup.find_all('script', type=re.compile(r'application/(?:ld\+)?json', re.I)):
            try:
                for record in extract_api_media(_json_mod.loads(tag.get_text()), url):
                    self.add(record)
            except (ValueError, RecursionError):
                pass
        for tag in soup.find_all(['a', 'iframe', 'script']):
            target = tag.get('href') if tag.name == 'a' else tag.get('src')
            if target:
                full = normalise_url(target, url)
                record = identify_stream(full, source='dom', frame_url=url)
                if record:
                    self.add(record)
                elif tag.name == 'script':
                    self.enqueue(full, depth, 'script')
                else:
                    self.enqueue(full, depth+1, 'page')
        # Only explicit GET-like API references; never execute arbitrary JS or POSTs.
        for match in re.finditer(r'''(?:fetch|axios\.get)\s*\(\s*["']([^"']+)["']''', text):
            candidate = normalise_url(match.group(1), url)
            if '/api/' in urlparse(candidate).path:
                self.enqueue(candidate, depth, 'api')

    def render(self):
        if not PLAYWRIGHT_OK:
            self.r['coverage_notes'].append('Browser rendering unavailable: install Playwright and Chromium.')
            return
        self.r['phase'] = 'rendering'
        targets = list(dict.fromkeys([self.url] + self.render_targets))[:self.plan.browser_pages]
        with sync_playwright() as pw:
            browser = _make_pw_browser(pw, headless=True)
            try:
                context = _make_pw_context(browser, cookies=_get_best_pw_cookies(self.url))
                def observed(response):
                    if response.status == 429:
                        self.r['rate_limited'] = True
                    if not self.active() or response.status >= 400:
                        return
                    try:
                        request = response.request
                        try:
                            frame = request.frame.url
                        except Exception:
                            frame = ''
                        self.add(identify_stream(response.url, response.headers, 'browser_response', request.resource_type, frame))
                        mime = response.headers.get('content-type', '').lower()
                        size = int(response.headers.get('content-length', '0'))
                        if 'json' in mime and 0 < size <= 512000 and self.r['api_responses'] < 100:
                            body = response.body()
                            if len(body) <= 512000:
                                for record in extract_api_media(_json_mod.loads(body), response.url):
                                    self.add(record)
                                self.r['api_responses'] += 1
                    except Exception:
                        pass
                context.on('response', observed)
                page = context.new_page()
                for target in targets:
                    if not self.active():
                        break
                    if self.scope(target):
                        self.emit(f'Rendering page {self.r["browser_pages"]+1}: observing DOM, APIs and media requests.')
                        try:
                            response = page.goto(target, wait_until='domcontentloaded',
                                timeout=min(12000, max(1000, int((self.deadline-time.monotonic())*1000))))
                            if response and response.status in (401, 403, 429):
                                self.r['blocked_pages'] += 1
                                if response.status == 429:
                                    self.r['rate_limited'] = True
                                continue
                            if access_block_reason(page.content()):
                                self.r['blocked_pages'] += 1
                                continue
                            for _ in range(3):
                                if not self.active():
                                    break
                                page.evaluate('window.scrollBy(0, Math.min(window.innerHeight, 900))')
                                for frame in list(page.frames):
                                    if frame.is_detached():
                                        continue
                                    try:
                                        report=frame.evaluate('(play) => window.__playerDiscovery?.sample(play) || null', self.plan.attempt_playback)
                                        if report:
                                            for player in report['players']:
                                                if player not in self.r['player_store']:
                                                    self.r['player_store'].append(player)
                                            for source in report['sources']:
                                                record=identify_stream(source['url'],{'content-type':source.get('mime','')},
                                                    source='player_adapter:'+source['adapter'],frame_url=frame.url)
                                                if record is None:
                                                    record={'url':source['url'],'kind':'api_media_candidate','file_type':'unknown',
                                                        'mime':source.get('mime',''),'source':'player_adapter','frame_url':frame.url,
                                                        'confidence':'candidate','download_candidate':False,'evidence':[source['adapter']]}
                                                self.add(record)
                                            self.r.setdefault('playback_observations',{})[frame.url]=report['playback']
                                    except Exception:
                                        pass
                                page.wait_for_timeout(min(self.plan.dwell_ms//3, max(1, int((self.deadline-time.monotonic())*1000))))
                            for value, base in extract_live_frame_urls(page, VIDEO_EXTRACTION_SCRIPT, self.r['log']):
                                self.add(identify_stream(normalise_url(value, base or target), source='rendered_dom', frame_url=base))
                            collect_stream_snapshot(page, self.r['stream_diagnostics'], self.r['log'])
                            for frame in list(page.frames):
                                if frame.is_detached():
                                    continue
                                try:
                                    if self.plan.deep_js:
                                        try:
                                            deep=frame.evaluate(DEEP_RECOGNITION_SCRIPT)
                                            self.r.setdefault('deep_recognition',{})[frame.url]={k:v for k,v in deep.items() if k!='sources'}
                                            for source in deep['sources']:
                                                record=identify_stream(source['url'],{'content-type':source.get('mime','')},source=source['source'],frame_url=frame.url)
                                                if record is None:
                                                    record={'url':source['url'],'kind':'api_media_candidate','file_type':'unknown',
                                                        'mime':source.get('mime',''),'source':source['source'],'frame_url':frame.url,
                                                        'confidence':'candidate','download_candidate':False,'evidence':[source['source']]}
                                                record['confidence']='candidate'
                                                self.add(record)
                                        except Exception:
                                            self.emit("Optional deep JS pass unavailable; standard discovery continues.")
                                    final_report=frame.evaluate('() => window.__playerDiscovery?.sample(false) || null')
                                    if final_report:
                                        self.r.setdefault('playback_observations',{})[frame.url]=final_report['playback']
                                        for source in final_report['sources']:
                                            record=identify_stream(source['url'],{'content-type':source.get('mime','')},
                                                source='player_adapter:'+source['adapter'],frame_url=frame.url)
                                            self.add(record)
                                    frame.evaluate('() => window.__playerDiscovery?.finish()')
                                    documents = frame.evaluate('() => window.__apiDocuments?.snapshot() || []')
                                    for document in documents:
                                        for record in extract_api_media(_json_mod.loads(document['text']), document['url']):
                                            self.add(record)
                                    drm = frame.evaluate('() => window.__drmDiagnostics?.snapshot() || null')
                                    if drm and (drm.get('events') or drm.get('keySystems')):
                                        self.r.setdefault('drm_diagnostics', []).append({'page':target, **drm})
                                except Exception:
                                    pass
                            for href in page.eval_on_selector_all('a[href]', 'els => els.slice(0,500).map(e=>e.href)'):
                                self.enqueue(href, 1)
                        except Exception as exc:
                            self.r['requests_failed'] += 1
                            self.emit(navigation_error(target, exc))
                        finally:
                            self.r['browser_pages'] += 1
                    if self.r.get('rate_limited'):
                        break
            finally:
                browser.close()

    def inspect_manifests(self):
        self.r['phase'] = 'manifests'
        manifests = [r for r in self.r['stream_diagnostics'] if r['kind'] in ('hls_manifest','dash_manifest')][:12]
        inspected=set()
        for record in manifests:
            if not self.active() or len(inspected)>=20:
                break
            if record['url'] in inspected:
                continue
            inspected.add(record['url'])
            try:
                with closing(get_api_session()) as session:
                    with closing(session.get(record['url'],stream=True,timeout=min(5,max(1,self.deadline-time.monotonic())))) as response:
                        if response.status_code >= 400:
                            continue
                        body = bytearray()
                        for chunk in response.iter_content(32768):
                            body.extend(chunk)
                            if len(body) > 512000 or not self.active():
                                break
                        if len(body)>512000 or not self.active():
                            continue
                        text=body.decode('utf-8-sig',errors='replace')
                        base=response.url
                if record['kind']=='hls_manifest' and text.lstrip().startswith('#EXTM3U'):
                    ladder=parse_m3u8_manifest(base,text=text)
                    if ladder:
                        self.r['manifest_store'][base]=ladder
                        for variant in ladder.get('variants',[]):
                            candidate=identify_stream(normalise_url(variant['uri'],base),
                                {'content-type':'application/vnd.apple.mpegurl'},source='hls_variant',frame_url=base)
                            if candidate:
                                candidate['quality']=variant.get('resolution', '')
                            self.add(candidate)
                            if candidate and len(manifests)<40:
                                manifests.append(candidate)
                    if M3U8_OK:
                        for rendition in _m3u8_lib.loads(text).media[:40]:
                            if rendition.uri:
                                candidate=identify_stream(normalise_url(rendition.uri,base),
                                    {'content-type':'application/vnd.apple.mpegurl'},source='hls_rendition',frame_url=base)
                                self.add(candidate)
                                if candidate and len(manifests)<40:
                                    manifests.append(candidate)
                    if '#EXT-X-KEY:' in text and 'METHOD=NONE' not in text:
                        self.r.setdefault('drm_diagnostics',[]).append({'page':base,'signal':'HLS encryption declared; not proof of a particular DRM system'})
                elif record['kind']=='dash_manifest' and '<!DOCTYPE' not in text.upper() and '<!ENTITY' not in text.upper():
                    root=ElementTree.fromstring(text)
                    if any(el.tag.split('}')[-1]=='ContentProtection' for el in root.iter()):
                        self.r.setdefault('drm_diagnostics',[]).append({'page':base,'signal':'DASH ContentProtection declared'})
                    self.r['manifest_store'][base]={'type':'DASH','representations':[
                        {key:value for key,value in el.attrib.items() if key in ('id','bandwidth','width','height','codecs','mimeType')}
                        for el in root.iter() if el.tag.split('}')[-1]=='Representation'][:100]}
                    stack=[(root,base,False)]
                    nodes=0
                    while stack and nodes<5000:
                        element,parent,segmented=stack.pop();nodes+=1
                        segmented=segmented or any(child.tag.split('}')[-1] in ('SegmentTemplate','SegmentList','SegmentBase') for child in element)
                        urls=[child.text.strip() for child in element if child.tag.split('}')[-1]=='BaseURL' and child.text]
                        current=normalise_url(urls[0],parent) if urls else parent
                        if element.tag.split('}')[-1]=='Representation' and urls and not segmented:
                            candidate=identify_stream(current,source='dash_representation',frame_url=base)
                            self.add(candidate)
                        stack.extend((child,current,segmented) for child in element if child.tag.split('}')[-1] not in ('BaseURL','SegmentTemplate','SegmentList','SegmentBase'))
            except Exception:
                self.emit('Manifest metadata unavailable; source URL retained.')

    def discover(self, until=None):
        self.r['phase'] = 'discovering'
        with ThreadPoolExecutor(max_workers=self.plan.workers) as pool:
            while self.frontier and self.r['pages_scraped'] < self.plan.pages and self.active() and (until is None or time.monotonic() < until):
                batch = []
                while self.frontier and len(batch) < min(self.plan.workers, self.plan.pages-self.r['pages_scraped']):
                    _, _, url, depth, kind = heapq.heappop(self.frontier)
                    if url not in self.visited:
                        self.visited.add(url)
                        batch.append((pool.submit(self.fetch, url), depth, kind))
                for future, depth, kind in batch:
                    self.consume(future.result(), depth, kind)
                self.r['queue_size'] = len(self.frontier)
                if self.r.get('rate_limited'):
                    break

        self.close_connections()

    def run(self):
        self.enqueue(self.url)
        if self.plan.sitemap:
            origin = urlunparse((*urlparse(self.url)[:2], '', '', '', ''))
            self.enqueue(origin+'/robots.txt', 0, 'robots')
            self.enqueue(origin+'/sitemap.xml', 0, 'sitemap')
        self.emit('Discovery engine v2: bounded page frontier → rendered DOM/API observation → media verification.')
        try:
            if YTDLP_OK and is_streaming_site(self.url) and self.active():
                self.emit('Checking the platform extractor for available media formats.')
                try:
                    options=_make_ytdlp_opts(self.r['log'], get_cookie_file())
                    options.update(socket_timeout=6, retries=0, extractor_retries=0,
                        noplaylist=True, playlistend=10,
                        match_filter=lambda info, **kwargs: None if self.active() else 'Scan budget ended')
                    with yt_dlp.YoutubeDL(options) as extractor:
                        info=extractor.extract_info(self.url,download=False)
                        temporary=[]
                        if info:
                            _process_ytdlp_info(info,self.r['log'],temporary)
                        for url in temporary:
                            self.add(identify_stream(url,source='platform_extractor',frame_url=self.url))
                except Exception:
                    self.emit('Platform extractor unavailable; continuing page and browser discovery.')
            self.discover(time.monotonic() + self.plan.seconds * .45)
            if self.active() and self.plan.browser and not self.r.get('rate_limited'):
                try:
                    self.render()
                except Exception as exc:
                    self.r['coverage_notes'].append('Browser stage unavailable; static/API results retained.')
                    self.emit(navigation_error(self.url, exc))
                self.discover()
            if self.active() and not self.r.get('rate_limited'):
                self.inspect_manifests()
            if self.r.get('cancel_requested'):
                self.r['status'] = 'cancelled'
            elif self.r.get('rate_limited'):
                self.r['status'] = 'rate_limited'
            else:
                if self.active() and self.plan.validate:
                    self.r['phase'] = 'validating'
                    for url in list(self.r['mp4_links'])[:1000]:
                        if not self.active():
                            break
                        _, code, ok, reason = check_link(url, timeout=min(5, max(1,self.deadline-time.monotonic())), verify_video_content=True)
                        self.r['validation_results'][url] = {'code':code, 'ok':ok, 'reason':reason}
                        if not ok:
                            self.r['broken_links'].append(url)
                    self.r['mp4_links'] = [url for url in self.r['mp4_links'] if url not in self.r['broken_links']]
                self.r['status'] = 'cancelled' if self.r.get('cancel_requested') else 'done'
            if self.frontier:
                self.r['coverage_notes'].append(f'{len(self.frontier)} queued URLs remain beyond the configured limits.')
            if time.monotonic() >= self.deadline:
                self.r['coverage_notes'].append('Time budget reached; results collected so far are retained.')
            if self.r['blocked_pages']:
                self.r['coverage_notes'].append('Some pages denied access. Extraction cannot establish complete coverage.')
            self.r['phase'] = 'finished'
            self.emit(f"Finished: {len(self.r['mp4_links'])} media candidates, {self.r['pages_scraped']} responses, {self.r['browser_pages']} rendered pages.")
        except Exception as exc:
            self.r['status'] = 'error'
            self.emit(api_failure_message(exc, self.r['phase']))
        finally:
            self.close_connections()


def run_scan(scan_id, url, max_depth, skip_validate, max_sitemap_urls=5000,
             scan_mode='moderate', url_cap=0, video_only=False):
    r = scan_store[scan_id]
    plan = DiscoveryPlan(pages=r.get('page_limit', url_cap or 80), depth=max_depth,
        workers=r.get('concurrency', 3), browser_pages=r.get('browser_limit', 8),
        dwell_ms=r.get('dwell_ms', 1800), seconds=r['time_limit_s'],
        validate=not skip_validate, sitemap=r.get('discover_sitemap', True),
        browser=r.get('render_browser', True))
    plan = DiscoveryPlan(**{**plan.__dict__, 'attempt_playback':r.get('attempt_playback', True), 'deep_js':r.get('deep_js', False)})
    DiscoveryEngine(scan_id, url, plan).run()
