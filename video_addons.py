"""Optional video-discovery extensions, embedded verbatim in app.py.

The original engine and endpoints are untouched. Only /addons/start selects this
subclass. Persistence is opt-in; cookies, headers, bodies and query URLs stay out
of its database. Signed URLs remain usable in the current in-memory scan.
"""
import hashlib as _va_hash
import sqlite3 as _va_sql
import csv as _va_csv
import io as _va_io
from pathlib import Path as _VAPath
from dataclasses import replace as _va_replace

try:
    from selectolax.lexbor import LexborHTMLParser as _VAParser
except ImportError:
    _VAParser = None

_VA_LOCK = threading.RLock()
_VA_FIELDS = ('page', 'title', 'description', 'duration', 'thumbnail', 'url', 'kind', 'quality', 'source')


def _va_safe_url(value):
    """Only unsigned HTTP URLs may be stored, never silently alter signed URLs."""
    try:
        p = urlparse(value)
        return value if p.scheme in ('http', 'https') and p.hostname and not (p.query or p.fragment or p.username or p.password) else ''
    except (ValueError, TypeError):
        return ''


class VideoJournal:
    def __init__(self, path=None):
        self.path = str(path or _VAPath(__file__).with_name('video-discovery.sqlite3'))

    @contextmanager
    def db(self):
        with _VA_LOCK:
            db = _va_sql.connect(self.path, timeout=5)
            try:
                db.execute('CREATE TABLE IF NOT EXISTS entries (kind TEXT, id TEXT, updated REAL, data TEXT, PRIMARY KEY(kind,id))')
                db.execute('DELETE FROM entries WHERE updated < ?', (time.time()-7*86400,))
                yield db
                db.commit()
            finally:
                db.close()

    def put(self, kind, key, data):
        with self.db() as db:
            db.execute('INSERT OR REPLACE INTO entries VALUES (?,?,?,?)', (kind, key, time.time(), _json_mod.dumps(data)))
            limit = 5000 if kind == 'page' else 100
            db.execute('DELETE FROM entries WHERE kind=? AND id NOT IN (SELECT id FROM entries WHERE kind=? ORDER BY updated DESC LIMIT ?)', (kind,kind,limit))

    def get(self, kind, key):
        with self.db() as db:
            row = db.execute('SELECT data FROM entries WHERE kind=? AND id=?', (kind,key)).fetchone()
            return _json_mod.loads(row[0]) if row else None

    def items(self, kind):
        with self.db() as db:
            return [{'id':r[0], 'updated':r[1], **_json_mod.loads(r[2])} for r in db.execute('SELECT id,updated,data FROM entries WHERE kind=? ORDER BY updated DESC LIMIT 100', (kind,))]

    def clear(self):
        with self.db() as db:
            db.execute('DELETE FROM entries')


def _va_recipe(value):
    if not isinstance(value, dict):
        raise ValueError('Recipe must be a JSON object')
    result = {}
    for key in ('title', 'description', 'duration', 'thumbnail', 'media', 'next'):
        text = value.get(key, '')
        if not isinstance(text, str) or len(text) > 250:
            raise ValueError('Each recipe selector must be text under 250 characters')
        if text:
            # Validate selectors now, not in the worker.
            BeautifulSoup('<html></html>', 'html.parser').select(text)
            result[key] = text
    return result


class VideoAddonEngine(DiscoveryEngine):
    def __init__(self, scan_id, url, plan, options, resume=None):
        super().__init__(scan_id, url, plan)
        self.scan_id, self.options = scan_id, options
        self.recipe = options.get('recipe', {})
        self.lock = threading.RLock()
        self.clock = time.monotonic()
        self.metadata, self.page_sources = {}, {}
        self.browser_needed = set()
        self.window = min(2, plan.workers)
        self.journal = VideoJournal() if options.get('persist') else None
        self.metrics = {'requests':0, 'static_bytes':0, 'browser_bytes':0,
            'browser_seconds':0, 'parse_seconds':0, 'first_result_seconds':None,
            'unique_sources':0, 'unchanged_pages':0, 'redirects':0,
            'workers':self.window, 'worker_responses':0, 'websocket_messages':0,
            'parser':'Lexbor' if options.get('fast_parser') and _VAParser else 'BeautifulSoup',
            'browser_skipped':0}
        self.r['addon_metrics'] = self.metrics
        self.r['video_records'] = []
        self.r['addon_options'] = options
        self.resume = resume or {}
        for entry in self.resume.get('pending', []):
            self.enqueue(entry[0], entry[1], entry[2])
        self.visited.update(self.resume.get('visited', []))
        for record in self.resume.get('sources', []):
            self.add(record)

    def add(self, record):
        if record and hasattr(self, 'lock'):
            with self.lock:
                super().add(record)
                self.metrics['unique_sources'] = len(self.media)
                if self.media and self.metrics['first_result_seconds'] is None:
                    self.metrics['first_result_seconds'] = round(time.monotonic()-self.clock, 3)
        else:
            super().add(record)

    def fetch(self, url):
        if not self.active():
            return {'url':url, 'skip':True}
        start = time.monotonic()
        try:
            with self.pooled_connection() as session:
                current, seen = url, set()
                for hop in range(11):
                    if not self.active():
                        return {'url':url, 'skip':True}
                    if current in seen:
                        return {'url':url, 'error':'Redirect loop detected (same URL repeated)'}
                    if not self.scope(current):
                        return {'url':url, 'error':'Redirect leaves the selected origin; target retained in browser navigation only'}
                    seen.add(current)
                    with self.lock:
                        self.metrics['requests'] += 1
                    with closing(session.get(current, stream=True, allow_redirects=False,
                            timeout=min(10,max(1,self.deadline-time.monotonic())))) as response:
                        headers, status = dict(response.headers), response.status_code
                        if status in (301,302,303,307,308):
                            location = response.headers.get('Location')
                            if not location:
                                return {'url':url, 'error':'Redirect response has no Location header'}
                            if hop == 10:
                                return {'url':url, 'error':'Redirect chain exceeds the add-on limit of 10 hops'}
                            with self.lock:
                                self.metrics['redirects'] += 1
                            current = normalise_url(location, current)
                            continue
                        result = {'url':current, 'status':status, 'headers':headers, 'text':'', 'elapsed':time.monotonic()-start}
                        if status >= 400:
                            return result
                        record = identify_stream(current, headers, source='response', frame_url=url)
                        if record and record['confidence']=='response_headers':
                            result['record'] = record
                            return result
                        body = bytearray()
                        for chunk in response.iter_content(65536):
                            with self.lock:
                                self.metrics['static_bytes'] += len(chunk)
                            body.extend(chunk)
                            if not self.active():
                                return {'url':url, 'skip':True}
                            if len(body)>2*1024*1024:
                                return {'url':url, 'error':'Page exceeded 2 MiB discovery limit'}
                        result['text'] = body.decode(response.encoding or 'utf-8', errors='replace')
                        result['elapsed'] = time.monotonic()-start
                        # Never cache a response associated with authentication or privacy directives.
                        result['cacheable'] = not (session.cookies or session.headers.get('Authorization') or
                            session.headers.get('Cookie') or response.headers.get('Set-Cookie') or
                            re.search(r'private|no-store', response.headers.get('Cache-Control',''),re.I))
                        return result
        except Exception as exc:
            return {'url':url, 'error':api_failure_message(exc,'video discovery')}

    def _document(self, text):
        if self.options.get('fast_parser') and _VAParser:
            try:
                tree = _VAParser(text)
                # Recipes may use a selector supported only by SoupSieve. Choose
                # the existing parser for the whole document in that case.
                for selector in self.recipe.values(): tree.css(selector)
                return lambda selector: tree.css(selector), lambda node: node.text(), lambda node,key: node.attributes.get(key,'') or ''
            except Exception:
                self.emit('Optional parser failed; using the existing HTML parser.')
        tree = BeautifulSoup(text, 'html.parser')
        return lambda selector: tree.select(selector), lambda node: node.get_text(), lambda node,key: node.get(key,'')

    def consume(self, item, depth, kind):
        url, text = item['url'], item.get('text','')
        if item.get('error'):
            # Context without logging signed query strings.
            self.emit('Page: '+urlunparse((*urlparse(url)[:3], '', '', '')))
            self.browser_needed.add(url)
        if not text or item.get('status',500)>=400 or access_block_reason(text) or kind in ('sitemap','robots'):
            return super().consume(item,depth,kind)
        digest = _va_hash.sha256(text.encode()).hexdigest()
        cache_key = _va_hash.sha256((url+_json_mod.dumps(self.recipe,sort_keys=True)).encode()).hexdigest()
        cacheable = self.journal and item.get('cacheable') and _va_safe_url(url)
        try:
            cached = self.journal.get('page',cache_key) if cacheable and self.options.get('incremental') else None
        except Exception:
            cached = None
        if cached and cached['hash']==digest:
            self.r['pages_scraped'] += 1
            self.metrics['unchanged_pages'] += 1
            for record in cached['sources']:
                self.add(record)
            for link in cached['links']:
                self.enqueue(link[0],depth+link[1],link[2])
            self.metadata[url] = cached['metadata']
            if cached.get('browser_needed'):
                self.browser_needed.add(url)
                self.render_targets.append(url)
            return
        start = time.monotonic()
        before = set(self.media)
        links = []
        def queue(target, offset=1, category='page'):
            full = normalise_url(target,url)
            self.enqueue(full,depth+offset,category)
            links.append([full,offset,category])
        try:
            # API/JS documents stay on the original extraction path.
            if kind != 'page' or '<' not in text or text.lstrip().startswith(('{','[')):
                return super().consume(item,depth,kind)
            select, content, attr = self._document(text)
            self.r['pages_scraped'] += 1
            self.add(item.get('record'))
            self.render_targets.append(url)
            raw = []
            _extract_from_raw(text.replace(r'\u002f','/'),url,raw,[],player_store=self.r['player_store'])
            for value in raw:
                self.add(identify_stream(value,source='page_source',frame_url=url))
            meta = {'page':url,'title':'','description':'','duration':'','thumbnail':''}
            for key, selector in {'title':'meta[property="og:title"]','description':'meta[property="og:description"]',
                    'duration':'meta[property="video:duration"]','thumbnail':'meta[property="og:image"]'}.items():
                nodes=select(self.recipe.get(key,selector))
                if nodes:
                    meta[key]=(attr(nodes[0],'content') or attr(nodes[0],'src') or content(nodes[0]))[:2000]
            if not meta['title']:
                nodes=select('title')
                if nodes: meta['title']=content(nodes[0])[:500]
            for node in select('script[type="application/ld+json"],script[type="application/json"]')[:100]:
                try:
                    payload=_json_mod.loads(content(node))
                    for record in extract_api_media(payload,url): self.add(record)
                    stack=[payload]; count=0
                    while stack and count<3000:
                        value=stack.pop();count+=1
                        if isinstance(value,list): stack.extend(value[:100])
                        elif isinstance(value,dict):
                            if 'VideoObject' in str(value.get('@type','')):
                                for dest,src in [('title','name'),('description','description'),('duration','duration'),('thumbnail','thumbnailUrl')]:
                                    val=value.get(src)
                                    if isinstance(val,str): meta[dest]=val[:2000]
                            stack.extend(v for v in value.values() if isinstance(v,(list,dict)))
                except (ValueError,RecursionError): pass
            self.metadata[url]=meta
            for selector,attribute,offset,category in [('a[href]','href',1,'page'),('iframe[src]','src',1,'page'),('script[src]','src',0,'script')]:
                for node in select(selector)[:1000]:
                    target=normalise_url(attr(node,attribute),url)
                    record=identify_stream(target,source='dom',frame_url=url)
                    if record: self.add(record)
                    else: queue(target,offset,category)
            for node in select(self.recipe.get('media','video[src],video source[src]'))[:200]:
                value=attr(node,'src') or attr(node,'href') or attr(node,'data-src')
                if value:
                    target=normalise_url(value,url)
                    record=identify_stream(target,{'content-type':attr(node,'type')},source='video_recipe',frame_url=url)
                    if record is None and target.startswith(('http://','https://')):
                        record={'url':target,'kind':'api_media_candidate','file_type':'unknown','mime':'','source':'video_recipe',
                            'frame_url':url,'confidence':'candidate','download_candidate':False,'evidence':['video selector']}
                    self.add(record)
            if self.recipe.get('next'):
                for node in select(self.recipe['next'])[:10]:
                    if attr(node,'href'): queue(attr(node,'href'),0)
            for match in re.finditer(r'''(?:fetch|axios\.get)\s*\(\s*["']([^"']+)["']''',text):
                if '/api/' in urlparse(normalise_url(match.group(1),url)).path: queue(match.group(1),0,'api')
            # Only skip rendering a fully static page with actual media sources.
            needs_browser=bool(select('script,iframe')) or not (self.media-before)
            if needs_browser: self.browser_needed.add(url)
            records=[dict(r) for r in self.r['stream_diagnostics'] if r.get('frame_url')==url]
            # Cache only complete, unsigned discoveries; otherwise refetch/reparse next time.
            if cacheable and all(_va_safe_url(r.get('url','')) for r in records) and all(_va_safe_url(v[0]) for v in links):
                safe_meta={**meta,'thumbnail':_va_safe_url(meta.get('thumbnail',''))}
                try:
                    self.journal.put('page',cache_key,{'hash':digest,'sources':records,'links':links,'metadata':safe_meta,'browser_needed':needs_browser})
                except Exception: self.emit('Local cache unavailable; continuing in memory.')
        finally:
            self.metrics['parse_seconds']=round(self.metrics['parse_seconds']+time.monotonic()-start,3)
            self.refresh_records()

    def refresh_records(self):
        records=[]
        for source in self.r['stream_diagnostics'][:5000]:
            if source.get('kind') in ('segment_candidate','mse_buffer','mse_source','browser_blob'): continue
            page=source.get('frame_url','')
            record={**self.metadata.get(page,{'page':page}), **{k:source.get(k,'') for k in ('url','kind','quality','source')}}
            records.append(record)
        self.r['video_records']=records

    def checkpoint(self):
        if not self.journal: return
        try:
            pending=[[v[2],v[3],v[4]] for v in self.frontier if _va_safe_url(v[2])]
            pending.extend([[u,0,'page'] for u in self.browser_needed if _va_safe_url(u) and u not in {v[0] for v in pending}])
            sources=[{k:v for k,v in r.items() if k in ('url','kind','file_type','mime','source','confidence','download_candidate','evidence','quality')}
                for r in self.r['stream_diagnostics'] if _va_safe_url(r.get('url',''))]
            self.journal.put('run',self.scan_id,{'url':_va_safe_url(self.url),'pending':pending,
                'visited':[u for u in self.visited if _va_safe_url(u) and u not in {v[0] for v in pending}],
                'sources':sources,'status':self.r['status']})
        except Exception:
            self.journal=None
            self.emit('Local checkpoint unavailable; scan continues in memory.')

    def discover(self, until=None):
        self.r['phase']='discovering'
        try:
            with ThreadPoolExecutor(max_workers=self.plan.workers) as pool:
                while self.frontier and self.active() and self.r['pages_scraped']<self.plan.pages and (until is None or time.monotonic()<until):
                    batch=[]
                    limit=self.window if self.options.get('adaptive_concurrency') else self.plan.workers
                    while self.frontier and len(batch)<min(limit,self.plan.pages-self.r['pages_scraped']):
                        _,_,url,depth,kind=heapq.heappop(self.frontier)
                        if url not in self.visited:
                            self.visited.add(url)
                            batch.append((url,pool.submit(self.fetch,url),depth,kind))
                    slow=False
                    for url,future,depth,kind in batch:
                        item=future.result()
                        if item.get('skip'):
                            self.visited.discard(url)
                            self.sequence+=1
                            heapq.heappush(self.frontier,(depth*10,self.sequence,url,depth,kind))
                        self.consume(item,depth,kind)
                        slow=slow or bool(item.get('error')) or item.get('status',200)>=400 or item.get('elapsed',0)>2
                        if item.get('status')==429:
                            self.emit('Host rate limit reached; scan stopped. Retry-After: '+str(item.get('headers',{}).get('Retry-After','not supplied'))[:60])
                    if batch:
                        self.window=max(1,self.window//2) if slow else min(self.plan.workers,self.window+1)
                    self.metrics['workers']=self.window
                    self.r['queue_size']=len(self.frontier)
                    self.checkpoint()
        finally: self.close_connections()

    def render(self):
        if not PLAYWRIGHT_OK: return super().render()
        targets=list(dict.fromkeys([self.url]+self.render_targets))
        if self.options.get('adaptive'):
            chosen=[u for u in targets if u in self.browser_needed or u not in self.visited]
            self.metrics['browser_skipped']+=len(targets)-len(chosen)
            targets=chosen
        if not targets: return
        start=time.monotonic()
        self.r['phase']='rendering'
        with sync_playwright() as pw:
            browser=_make_pw_browser(pw,headless=True)
            try:
                context=_make_pw_context(browser,cookies=_get_best_pw_cookies(self.url))
                def response_seen(response):
                    try:
                        if response.status==429: self.r['rate_limited']=True
                        if response.status>=400 or not self.active(): return
                        req=response.request
                        try: frame=req.frame.url
                        except Exception: frame=''
                        worker=bool(getattr(req,'service_worker',None))
                        if worker and not self.options.get('browser_channels'): return
                        if worker: self.metrics['worker_responses']+=1
                        source='worker_response' if worker else 'browser_response'
                        self.add(identify_stream(response.url,response.headers,source,req.resource_type,frame))
                        size=int(response.headers.get('content-length','0'))
                        if 'json' in response.headers.get('content-type','') and 0<size<=512000 and self.r['api_responses']<100:
                            body=response.body()
                            if len(body)<=512000:
                                for record in extract_api_media(_json_mod.loads(body),response.url): self.add(record)
                                self.r['api_responses']+=1
                    except Exception: pass
                context.on('response',response_seen)
                def finished(req):
                    try: self.metrics['browser_bytes']+=max(0,req.sizes()['responseBodySize'])
                    except Exception: pass
                context.on('requestfinished',finished)
                page=context.new_page()
                if self.options.get('browser_channels'):
                    def socket_open(socket):
                        def received(payload):
                            if not self.active() or self.metrics['websocket_messages']>=100 or not isinstance(payload,str) or len(payload)>65536: return
                            self.metrics['websocket_messages']+=1
                            try:
                                for record in extract_api_media(_json_mod.loads(payload),page.url):
                                    record['source']='websocket_json';self.add(record)
                            except (ValueError,RecursionError): pass
                        socket.on('framereceived',received)
                    page.on('websocket',socket_open)
                for target in targets[:self.plan.browser_pages]:
                    if not self.active(): break
                    try:
                        response=page.goto(target,wait_until='domcontentloaded',timeout=min(12000,max(1000,int((self.deadline-time.monotonic())*1000))))
                        if response and response.status in (401,403,429):
                            self.r['blocked_pages']+=1
                            continue
                        if access_block_reason(page.content()):
                            self.r['blocked_pages']+=1
                            continue
                        settled=0;last_count=-1; observation=time.monotonic()
                        while self.active():
                            for frame in list(page.frames):
                                if frame.is_detached(): continue
                                try:
                                    report=frame.evaluate('(play)=>window.__playerDiscovery?.sample(play)||null',self.plan.attempt_playback)
                                    if report:
                                        for player in report['players']:
                                            if player not in self.r['player_store']: self.r['player_store'].append(player)
                                        self.r.setdefault('playback_observations',{})[frame.url]=report['playback']
                                        for source in report['sources']:
                                            for record in extract_api_media({'sources':[{'file':source['url'],'type':source.get('mime','')}]},frame.url):
                                                record['source']='player_adapter:'+source['adapter'];self.add(record)
                                    for doc in frame.evaluate('()=>window.__apiDocuments?.snapshot()||[]'):
                                        for record in extract_api_media(_json_mod.loads(doc['text']),doc['url']): self.add(record)
                                    if self.plan.deep_js:
                                        deep=frame.evaluate(DEEP_RECOGNITION_SCRIPT)
                                        self.r.setdefault('deep_recognition',{})[frame.url]={k:v for k,v in deep.items() if k!='sources'}
                                        for source in deep['sources']:
                                            for record in extract_api_media({'sources':[{'file':source['url'],'type':source.get('mime','')}]},frame.url):
                                                record['source']=source['source'];self.add(record)
                                except Exception: pass
                            for value,base in extract_live_frame_urls(page,VIDEO_EXTRACTION_SCRIPT,[]):
                                self.add(identify_stream(normalise_url(value,base or target),source='rendered_dom',frame_url=base))
                            count=len(self.media)
                            settled=settled+1 if count==last_count else 0;last_count=count
                            elapsed=(time.monotonic()-observation)*1000
                            if elapsed>=self.plan.dwell_ms: break
                            if self.options.get('adaptive') and count and settled>=2 and elapsed>=750: break
                            page.evaluate('window.scrollBy(0,Math.min(innerHeight,900))')
                            page.wait_for_timeout(min(250,max(1,self.plan.dwell_ms-elapsed),max(1,(self.deadline-time.monotonic())*1000)))
                        collect_stream_snapshot(page,self.r['stream_diagnostics'],self.r['log'])
                        for frame in list(page.frames):
                            try:
                                frame.evaluate('()=>window.__playerDiscovery?.finish()')
                                drm=frame.evaluate('()=>window.__drmDiagnostics?.snapshot()||null')
                                if drm and (drm.get('events') or drm.get('keySystems')): self.r['drm_diagnostics'].append({'page':target,**drm})
                            except Exception: pass
                        for href in page.eval_on_selector_all('a[href]','els=>els.slice(0,500).map(e=>e.href)'): self.enqueue(href,1)
                        self.browser_needed.discard(target)
                    except Exception as exc:
                        self.r['requests_failed']+=1
                        self.emit(navigation_error(target,exc))
                    finally: self.r['browser_pages']+=1
            finally: browser.close()
        self.metrics['browser_seconds']=round(time.monotonic()-start,3)
        self.refresh_records()

    def run(self):
        try: super().run()
        finally:
            self.refresh_records()
            self.metrics['elapsed_seconds']=round(time.monotonic()-self.clock,3)
            self.checkpoint()


@app.route('/addons/start',methods=['POST'])
def video_addon_start():
    data=request.get_json(silent=True)
    try:
        if not isinstance(data,dict): raise ValueError('Send a JSON object')
        if data.get('source_type','website')!='website': raise ValueError('Video add-ons use website mode; API mode remains available in the original scanner')
        url=data.get('url','').strip()
        if '://' not in url: url='https://'+url
        _api_origin(url)
        options=data.get('addons',{})
        if not isinstance(options,dict): raise ValueError('Invalid add-on settings')
        opts={key:options.get(key) is True for key in ('adaptive','adaptive_concurrency','fast_parser','persist','incremental','browser_channels')}
        opts['recipe']=_va_recipe(options.get('recipe',{}))
        def number(key,default,low,high): return max(low,min(high,int(data.get(key,default))))
        plan=DiscoveryPlan(pages=number('page_limit',80,1,1000),depth=number('depth',3,0,8),workers=number('concurrency',3,1,6),
            browser_pages=number('browser_limit',8,1,50),dwell_ms=number('dwell_ms',1800,300,10000),seconds=number('time_limit_s',120,20,900),
            validate=not bool(data.get('skip_validate')),sitemap=bool(data.get('discover_sitemap',True)),browser=bool(data.get('render_browser',True)),
            attempt_playback=bool(data.get('attempt_playback',True)),deep_js=bool(data.get('deep_js')))
        resume=None
        if options.get('resume_id'):
            if not opts['persist']: raise ValueError('Enable local history to resume')
            resume=VideoJournal().get('run',str(options['resume_id']))
            if not resume or resume['url']!=url: raise ValueError('Saved scan does not match this URL')
        with _VA_LOCK:
            if sum(r.get('status') in ('running','validating') for r in scan_store.values())>=2:
                return jsonify(error='Two scans are already active'),409
            if len(scan_store)>=50:
                for key,value in list(scan_store.items()):
                    if value.get('status') not in ('running','validating'):
                        del scan_store[key];break
            scan_id=str(uuid.uuid4())[:12]
            scan_store[scan_id]={'status':'running','phase':'discovering','cancel_requested':False,'mp4_links':[],
                'broken_links':[],'validation_results':{},'stream_diagnostics':[],'drm_diagnostics':[],
                'manifest_store':{},'player_store':[],'log':['Optional video discovery add-ons enabled.'],
                'pages_scraped':0,'sitemap_size':0,'source_type':'website'}
            engine=VideoAddonEngine(scan_id,url,plan,opts,resume)
            threading.Thread(target=engine.run,daemon=True).start()
        return jsonify(scan_id=scan_id)
    except Exception as exc:
        return jsonify(error=str(exc)[:200]),400


@app.route('/addons/status/<scan_id>')
def video_addon_status(scan_id):
    result=scan_store.get(scan_id)
    if not result: return jsonify(error='Unknown scan'),404
    return jsonify(metrics=result.get('addon_metrics',{}),records=result.get('video_records',[]))


@app.route('/addons/export/<scan_id>')
def video_addon_export(scan_id):
    from flask import Response
    result=scan_store.get(scan_id)
    if not result: return jsonify(error='Unknown scan'),404
    fields=[k for k in request.args.get('fields',','.join(_VA_FIELDS)).split(',') if k in _VA_FIELDS]
    records=[{k:r.get(k,'') for k in fields} for r in result.get('video_records',[])]
    fmt=request.args.get('format','json')
    if fmt=='json': body,mime=_json_mod.dumps(records,indent=2),'application/json'
    elif fmt=='csv':
        output=_va_io.StringIO(newline='');writer=_va_csv.DictWriter(output,fieldnames=fields);writer.writeheader()
        for record in records:
            writer.writerow({k:("'"+str(v) if str(v).lstrip().startswith(('=','+','-','@')) else v) for k,v in record.items()})
        body,mime=output.getvalue(),'text/csv'
    else: return jsonify(error='Choose CSV or JSON'),400
    return Response(body,mimetype=mime,headers={'Content-Disposition':f'attachment; filename="videos-{scan_id}.{fmt}"'})


@app.route('/addons/history',methods=['GET','DELETE'])
def video_addon_history():
    journal=VideoJournal()
    if request.method=='DELETE': journal.clear();return jsonify(ok=True)
    if not _VAPath(journal.path).exists(): return jsonify(runs=[],recipes=[])
    return jsonify(runs=[{k:r.get(k) for k in ('id','url','updated','status')} for r in journal.items('run')],recipes=journal.items('recipe'))


@app.route('/addons/recipes',methods=['POST'])
def video_addon_recipe_save():
    try:
        data=request.get_json(silent=True) or {}
        origin=_api_origin(data.get('url',''))
        recipe=_va_recipe(data.get('recipe',{}))
        key=_json_mod.dumps(origin)
        VideoJournal().put('recipe',key,{'origin':list(origin),'recipe':recipe})
        return jsonify(ok=True)
    except Exception: return jsonify(error='Provide a valid site URL and CSS selectors'),400

