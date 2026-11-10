"""Separate, opt-in TeraBox share resolver. Embedded in app.py."""
from http.cookies import SimpleCookie as _TBCookie
from html import escape as _tb_escape
from pathlib import Path as _TBPath
from tempfile import NamedTemporaryFile as _tb_tempfile
from urllib.parse import parse_qs as _tb_query

_TB_PROVIDERS = {
    'iteraplay_com': 'https://iteraplay.com/api/stream',
    'iteraplay_in': 'https://iteraplay.in/api/videos/import',
    'xapiverse': 'https://xapiverse.com/api/terabox',
}
_TB_SLOTS = threading.BoundedSemaphore(2)
_TB_DOMAINS = ('terabox.com','1024terabox.com','terabox.app')
_TB_HOME = 'https://www.1024terabox.com/'
_TB_SESSION_LOCK = threading.Lock()
_TB_ACTIVE_SAVE = None


def _tb_session_path():
    if os.name != 'nt' or not os.environ.get('LOCALAPPDATA'):
        raise OSError('Windows user storage unavailable')
    return _TBPath(os.environ['LOCALAPPDATA']) / 'Source Studio' / 'terabox-session.bin'


def _tb_protect(data, decrypt=False):
    """Use Windows DPAPI with the current user's scope and no system prompts."""
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('pointer', ctypes.c_void_p)]

    buffer = ctypes.create_string_buffer(data)
    incoming = Blob(len(data), ctypes.addressof(buffer))
    outgoing = Blob()
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    operation = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    if not operation(ctypes.byref(incoming), None, None, None, None, 1, ctypes.byref(outgoing)):
        raise ctypes.WinError(ctypes.get_last_error())
    free = ctypes.WinDLL('kernel32').LocalFree
    free.argtypes = [ctypes.c_void_p]
    free.restype = ctypes.c_void_p
    try:
        return ctypes.string_at(outgoing.pointer, outgoing.size)
    finally:
        free(outgoing.pointer)


def _tb_save_session(cookies, user_agent=''):
    path = _tb_session_path()
    payload = {'cookies':cookies,'user_agent':user_agent} if user_agent else cookies
    encrypted = _tb_protect(_json_mod.dumps(payload).encode('utf-8'))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with _tb_tempfile(dir=path.parent, delete=False) as output:
            temporary = _TBPath(output.name)
            output.write(encrypted)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _tb_load_session(with_user_agent=False):
    user_agent = ''
    try:
        payload = _json_mod.loads(_tb_protect(_tb_session_path().read_bytes(), decrypt=True))
        if isinstance(payload,dict):
            user_agent = payload.get('user_agent','')
            payload = payload['cookies']
        cookies = [cookie for cookie in payload if _tb_cookie_domain(cookie['domain'])
                   and (cookie.get('expires', -1) <= 0 or cookie['expires'] > time.time())]
    except FileNotFoundError:
        cookies = []
    return (cookies,user_agent) if with_user_agent else cookies


class _TBInputError(ValueError):
    pass


def _tb_cookie_domain(domain):
    domain=domain.lower().lstrip('.')
    return any(domain==root or domain.endswith('.'+root) for root in _TB_DOMAINS)


def _tb_cookie_matches_host(domain,host):
    domain = domain.lower()
    return host==domain.lstrip('.') or (domain.startswith('.') and host.endswith(domain))


def _tb_cookies(raw,host='terabox.com'):
    """Preserve exported scope; never transplant unrelated-site credentials."""
    if not isinstance(raw,str) or len(raw)>16000:
        raise _TBInputError('Cookie input must be text under 16 KB. Export only TeraBox cookies.')
    raw=raw.strip()
    if not raw:return []
    rows=[]
    if raw.startswith(('[','{')):
        try:
            payload=_json_mod.loads(raw)
            rows=payload.get('cookies',[]) if isinstance(payload,dict) else payload
            if not isinstance(rows,list):raise ValueError()
        except (ValueError,RecursionError):raise _TBInputError('Invalid JSON cookie export.')
    elif '\t' in raw or '\n' in raw:
        for line in raw.splitlines():
            line=line.strip()
            if not line or (line.startswith('#') and not line.startswith('#HttpOnly_')):continue
            parts=line.split('\t')
            if len(parts)>=7 and parts[1].upper() in ('TRUE','FALSE'):
                domain=parts[0].removeprefix('#HttpOnly_')
                rows.append({'domain':domain if parts[1].upper()=='TRUE' else domain.lstrip('.'),
                    'name':parts[5],'value':parts[6],'path':parts[2],
                    'expires':int(parts[4]) if parts[4].isdigit() else -1,
                    'secure':parts[3].upper()=='TRUE','httpOnly':parts[0].startswith('#HttpOnly_')})
            elif len(parts)>=4 and '.' in parts[2]:
                rows.append({'name':parts[0],'value':parts[1],'domain':parts[2],
                    'path':parts[3],'secure':len(parts)>7 and parts[7]=='✓','httpOnly':len(parts)>6 and parts[6]=='✓'})
            else:raise _TBInputError('Unrecognized cookie table. Use JSON, Netscape cookies.txt, or tab-separated browser cookie rows.')
    else:
        if host is None:
            raise _TBInputError('Upload a cookie export that includes the original domains.')
        if '\r' in raw:raise _TBInputError('Invalid Cookie header.')
        jar=_TBCookie()
        try:jar.load(raw)
        except Exception:raise _TBInputError('Invalid Cookie header.')
        if not jar:raise _TBInputError('Use name=value; name2=value2 or a domain-scoped cookie export.')
        rows=[{'name':name,'value':v.value,'domain':host,'path':'/','secure':True} for name,v in jar.items()]
    accepted={}
    for row in rows[:300]:
        if not isinstance(row,dict):raise _TBInputError('Each exported cookie must be an object.')
        domain=row.get('domain','')
        if not isinstance(domain,str) or not _tb_cookie_domain(domain):continue
        domain=domain.lower()
        if row.get('hostOnly') is True:domain=domain.lstrip('.')
        name,value,path=row.get('name'),row.get('value'),row.get('path','/')
        if not all(isinstance(v,str) for v in (name,value,path)) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",name) or any(c in value for c in ('\r','\n','\x00')) or not path.startswith('/'):
            raise _TBInputError('Invalid TeraBox cookie fields.')
        cookie={'name':name,'value':value,'domain':domain,'path':path,
                'secure':row.get('secure',True) is True,'httpOnly':row.get('httpOnly',False) is True}
        same=row.get('sameSite','')
        if isinstance(same,str) and same.lower() in ('strict','lax','none'):
            cookie['sameSite']=same.title()
        expiry=row.get('expirationDate',row.get('expires'))
        if isinstance(expiry,(int,float)) and expiry>0:
            if expiry<=time.time():continue
            cookie['expires']=expiry
        accepted[(domain,path,name)]=cookie
    if not accepted:raise _TBInputError('No usable TeraBox cookies found. Unrelated domains and expired cookies are excluded; export cookies from the actual TeraBox page.')
    return list(accepted.values())


def _tb_sources(payload,base):
    """Extract only recognized media fields, not the entire private API response."""
    found={}; stack=[(payload,'',0)]; nodes=0
    while stack and nodes<10000 and len(found)<250:
        value,field,depth=stack.pop();nodes+=1
        if depth>20: continue
        if isinstance(value,dict):
            for key,child in list(value.items())[:200]:
                if re.search(r'token|cookie|secret|password|authorization|license|drmkey',key,re.I): continue
                label=field if field in ('fast_stream_url','stream_url','quality') else key
                stack.append((child,label,depth+1))
        elif isinstance(value,list):
            stack.extend((child,field,depth+1) for child in value[:250])
        elif isinstance(value,str) and value.startswith(('https://','http://')):
            try:
                _api_origin(value)
            except ValueError: continue
            if field not in ('fast_stream_url','stream_url','fast_dlink','normal_dlink','download_link','url','contentUrl','quality'): continue
            record=identify_stream(value,source='terabox_resolver',frame_url=base)
            if not record and field not in ('url','quality'):
                record={'url':value,'kind':'media_candidate','file_type':'unknown','confidence':'candidate','source':'terabox_resolver'}
            if record:
                record['field']=field;found[value]=record
    return list(found.values())


def _tb_playback_headers(browser_request):
    names = ('user-agent','referer','origin','accept','accept-language','cookie')
    return {key.lower():value for key,value in browser_request.all_headers().items() if key.lower() in names}


def _tb_original_download(page,context):
    """Observe the site's ordinary Download control without saving the file."""
    if not _tb_cookie_domain(urlparse(page.url).hostname or ''):
        return None
    name = re.compile(r'^download(?: (?:video|file))?$',re.I)
    control = (_tb_visible_one(page.get_by_role('button',name=name))
               or _tb_visible_one(page.get_by_role('link',name=name))
               or _tb_visible_one(page.get_by_text(name)))
    if control is None or not control.is_enabled():
        return None
    requests_by_url = {}
    downloads = []

    def observe_request(browser_request):
        if browser_request.method == 'GET' and _tb_media_host(browser_request.url) and len(requests_by_url)<100:
            requests_by_url[browser_request.url] = browser_request

    def observe_download(download):
        filename = download.suggested_filename
        if _tb_media_host(download.url) and re.search(r'\.(?:mp4|mkv|webm|mov|m4v|avi|wmv|flv|mpeg|mpg)$',filename,re.I):
            downloads.append((download.url,filename))

    context.on('request',observe_request)
    page.on('download',observe_download)
    try:
        control.click(timeout=1500)
        for _ in range(8):
            if downloads:
                url,filename = downloads[0]
                browser_request = requests_by_url.get(url)
                if browser_request is not None:
                    return {'url':url,'kind':'video_download','name':filename},_tb_playback_headers(browser_request)
                return None
            page.wait_for_timeout(250)
    except PWTimeout:
        pass
    finally:
        page.remove_listener('download',observe_download)
        context.remove_listener('request',observe_request)
    return None


def _tb_visible_one(locator):
    if locator.count()>12:
        return None
    visible = [item for item in locator.all() if item.is_visible()]
    return visible[0] if len(visible)==1 else None


_TB_FULL_VIDEO_PROMPT = 'Save to TeraBox to watch the full video'
_TB_FULL_VIDEO_SIGN_IN = 'TeraBox asked you to sign in for the full video. This saved session could only access the preview.'


def _tb_login_gate(page):
    return (_tb_cookie_domain(urlparse(page.url).hostname or '')
            and page.locator('.login-dialog').first.is_visible())


def _tb_preview_save_prompt(page, wait_for_preview_end):
    prompt = page.get_by_text(_TB_FULL_VIDEO_PROMPT,exact=True).first
    if prompt.is_visible():
        return True
    if not wait_for_preview_end:
        return False
    # The share player reveals the save prompt only after the preview ends.
    for _ in range(8):
        seeked = page.locator('video').evaluate_all('''videos => {
            const video = videos.find(item => item.getClientRects().length &&
                item.duration >= 29 && item.duration <= 31 && item.seekable.length &&
                item.seekable.end(item.seekable.length - 1) >= item.duration - 1);
            if (!video) return false;
            video.currentTime = Math.min(video.duration, video.seekable.end(video.seekable.length - 1)) - 0.25;
            video.muted = true;
            video.play().catch(() => {});
            return true;
        }''')
        if seeked:
            try:
                prompt.wait_for(state='visible',timeout=5500)
                return True
            except PWTimeout:
                return False
        page.wait_for_timeout(300)
    return False


def _tb_save_preview_and_download(page,context):
    """Follow the provider's save and file controls for one identified video."""
    pattern = re.compile(r'^[^\r\n]{1,240}\.(?:mp4|mkv|webm|mov|m4v|avi|wmv|flv|mpeg|mpg)$',re.I)
    names = {name.strip() for name in page.get_by_text(pattern).all_inner_texts() if pattern.fullmatch(name.strip())}
    if not names:
        title = page.title().strip()
        if pattern.fullmatch(title):
            names.add(title)
    if len(names)!=1:
        return None,'TeraBox did not identify a single video to save.'
    filename = names.pop()
    save = _tb_visible_one(page.get_by_role('button',name='Save',exact=True))
    if save is None:
        save = _tb_visible_one(page.get_by_text('Save',exact=True))
    if save is None:
        save = _tb_visible_one(page.get_by_role('button',name=re.compile(r'^save to terabox$',re.I)))
    if save is None:
        return None,'TeraBox did not show a single Save control for the preview.'
    save.click(timeout=1500)

    success = re.compile(r'^(?:(?:file )?saved(?: to (?:my )?terabox)? successfully|save successful|save success|file saved|saved to my terabox)[.!]?$',re.I)
    account_link = re.compile(r'^(?:view (?:saved )?file|view in terabox|go to (?:my )?terabox|my terabox)$',re.I)
    confirmed = False
    saved = False
    for _ in range(16):
        if _tb_login_gate(page):
            return None,_TB_FULL_VIDEO_SIGN_IN
        if page.get_by_text(success).first.is_visible():
            saved = True
            break
        if not confirmed:
            dialog = _tb_visible_one(page.get_by_role('dialog').filter(has_text=re.compile(r'Save to:\s*My TeraBox',re.I)))
            if dialog is not None:
                confirm = _tb_visible_one(dialog.get_by_role('button',name=re.compile(r'^(?:save|save here|confirm)$',re.I)))
                if confirm is not None:
                    confirm.click(timeout=1500)
                    confirmed = True
        page.wait_for_timeout(250)
    if not saved:
        return None,'The save was requested, but TeraBox did not confirm it. Check your account before trying again.'

    link = _tb_visible_one(page.get_by_role('link',name=account_link))
    if link is None:
        link = _tb_visible_one(page.get_by_role('button',name=account_link))
    if link is None:
        link = _tb_visible_one(page.get_by_text(account_link))
    if link is None:
        return None,'TeraBox confirmed the save. Open My TeraBox to download the file.'
    previous_pages = set(context.pages)
    link.click(timeout=1500)
    for _ in range(16):
        new_pages = [tab for tab in context.pages if tab not in previous_pages and _tb_cookie_domain(urlparse(tab.url).hostname or '')]
        account = new_pages[0] if len(new_pages)==1 else page
        if _tb_cookie_domain(urlparse(account.url).hostname or ''):
            file = _tb_visible_one(account.get_by_text(filename,exact=True))
            if file is not None and (account is not page or not account.get_by_text(_TB_FULL_VIDEO_PROMPT,exact=True).first.is_visible()):
                file.click(timeout=1500)
                account.wait_for_timeout(300)
                original = _tb_original_download(account,context)
                if original and original[0]['name']==filename:
                    return original,'TeraBox saved the video and offered the original file.'
                break
        account.wait_for_timeout(250)
    return None,'TeraBox confirmed the save, but the original download was not captured. Open My TeraBox to download the saved file.'


@isolated_browser_thread
def _tb_direct(share,cookies,interactive=False,save_signal=None,auto_session=False,user_agent='',save_preview_to_account=False):
    if not PLAYWRIGHT_OK: return {'error':'Install Playwright and Chromium to use direct mode.'},503
    save_session = save_signal is not None
    sources={};count=0
    media_seen_at = None
    last_track_at = None
    share_errors = {}
    failed_media_urls = set()
    relay_responses = {}
    with sync_playwright() as pw:
        browser=_make_pw_browser(pw,headless=not interactive)
        try:
            # Fresh context: never inherit another site's cookies or resolver tokens.
            options = {'user_agent':user_agent} if user_agent else {}
            if auto_session:
                options['accept_downloads'] = False
            context=browser.new_context(**options)
            if cookies: context.add_cookies(cookies)
            def observed(response):
                nonlocal count, media_seen_at, last_track_at
                if len(sources)>=250 or response.status>=400: return
                try:
                    parts = urlparse(response.url)
                    trusted_share = (parts.path.startswith(('/share/','/sharing/','/api/share/')) and
                                     (_tb_cookie_domain(parts.hostname or '') or parts.hostname=='dm.1024tera.com'))
                    if 'json' in response.headers.get('content-type','').lower():
                        json_allowed = not interactive or trusted_share or _tb_cookie_domain(parts.hostname or '')
                        if not json_allowed or count>=80:
                            return
                        size = int(response.headers.get('content-length','0'))
                        if not size and trusted_share:
                            size = response.request.sizes().get('responseBodySize',0)
                        if 0<size<=512000:
                            count+=1
                            body=response.body()
                            if len(body)<=512000:
                                payload = _json_mod.loads(body)
                                errno = payload.get('errno') if isinstance(payload,dict) else None
                                if trusted_share and re.fullmatch(r'-?[1-9][0-9]{0,8}',str(errno)):
                                    share_errors[parts.path == '/share/streaming'] = int(errno)
                                    if parts.path == '/share/streaming':
                                        failed_media_urls.add(response.url)
                                        sources.pop(response.url,None)
                                        relay_responses.pop(response.url,None)
                                    return
                                for record in extract_api_media(payload,response.url):
                                    sources.setdefault(record['url'],record)
                        return
                    record=identify_stream(response.url,response.headers,source='terabox_browser')
                    if record:
                        failed_media_urls.discard(response.url)
                        if parts.path == '/share/streaming':
                            stream_type = _tb_query(parts.query).get('type', [''])[0]
                            quality = re.fullmatch(r'M3U8_FLV_\d+_(\d{3,4})', stream_type)
                            if quality:
                                record['quality'] = quality[1] + 'p'
                            elif stream_type.startswith('M3U8_SUBTITLE'):
                                record['kind'] = 'subtitle_track'
                        is_new = record['url'] not in sources
                        sources[record['url']]=record
                        if auto_session and 200<=response.status<300 and record['kind']!='dash_manifest' and _tb_media_host(response.url):
                            relay_responses.setdefault(response.url,response)
                        if auto_session and is_new and record['kind'] in (
                                'hls_manifest','dash_manifest','media_file_candidate','ranged_media','subtitle_track'):
                            try:
                                frame_host = urlparse(response.request.frame.url).hostname or ''
                            except Exception:
                                frame_host = ''
                            if _tb_cookie_domain(frame_host) or _tb_cookie_domain(parts.hostname or ''):
                                last_track_at = time.monotonic()
                                if media_seen_at is None and record['kind'] != 'subtitle_track':
                                    media_seen_at = last_track_at
                except Exception: pass
            if not save_session:
                context.on('response',observed)
            page=context.new_page();page.set_default_timeout(5000)
            navigation_issue = ''
            try:
                response = page.goto(share, wait_until='commit' if interactive or auto_session else 'domcontentloaded',
                                     timeout=12000 if interactive or auto_session else 20000)
            except Exception as exc:
                if not interactive:
                    raise
                if page.is_closed() or not browser.is_connected():
                    return {'sources':list(sources.values())[:250],
                            'message':'The capture window closed during navigation.'},200
                error = str(exc).lower()
                if 'err_name_not_resolved' in error:
                    navigation_issue = 'The browser could not resolve the share hostname.'
                elif 'proxy' in error or 'tunnel' in error:
                    navigation_issue = 'The browser could not reach TeraBox through its proxy.'
                elif 'timeout' in error or 'timed out' in error:
                    navigation_issue = 'The share did not load within 12 seconds.'
                else:
                    navigation_issue = 'The browser could not open the share automatically.'
                response = None
                # Recover in the same cookie context after a failed navigation.
                page.goto('about:blank', timeout=5000)
                page.set_content(
                    '<title>TeraBox capture</title><main style="font:18px system-ui;margin:3rem">'
                    '<h1>Open your TeraBox share</h1>'
                    f'<p>{navigation_issue}</p><p><a href="{_tb_escape(share, quote=True)}">'
                    'Retry opening the share</a></p>'
                    '<p><a href="https://www.1024terabox.com/">Open TeraBox homepage to sign in</a></p>'
                    '<p>After signing in, paste the full share URL into this window’s address bar. '
                    + ('Play the video and the resolver will close this window when it detects media.' if auto_session
                       else 'Play the video, then close this window to see captured links.') + '</p></main>'
                )
            if response and response.status in (401,403,429):
                if not interactive:
                    return {'error':'TeraBox denied access or rate-limited this session.','upstream_status':response.status},502
                navigation_issue = f'TeraBox returned HTTP {response.status} when opening the share.'

            def attach_relay(captures):
                if captures and browser.is_connected():
                    playback_cookies = [cookie for cookie in context.cookies()
                                        if _tb_media_host('https://'+cookie['domain'].lstrip('.'))]
                    _tb_attach_media_relay(sources,captures,playback_cookies)

            download_sign_in = False
            if save_preview_to_account:
                try:
                    page.wait_for_load_state('domcontentloaded',timeout=2000)
                    original = _tb_original_download(page,context)
                    if original:
                        source,headers = original
                        sources = {source['url']:source}
                        attach_relay({source['url']:(headers,None)})
                        return {'sources':[source],'message':'TeraBox offered a direct video download.'},200
                except Exception:
                    pass
                try:
                    download_sign_in = _tb_login_gate(page)
                    if download_sign_in:
                        # Download can open a login overlay over the preview's separate Save control.
                        sources.clear()
                        relay_responses.clear()
                        share_errors.clear()
                        failed_media_urls.clear()
                        media_seen_at = last_track_at = None
                        page.reload(wait_until='domcontentloaded',timeout=8000)
                except Exception:
                    pass

            def collect_dom():
                for value,base in extract_live_frame_urls(page,VIDEO_EXTRACTION_SCRIPT,[]):
                    record=identify_stream(normalise_url(value,base or share),source='terabox_dom',frame_url=base)
                    if record and record['url'] not in failed_media_urls:
                        sources.setdefault(record['url'],record)

            if interactive or auto_session:
                deadline=time.monotonic()+(180 if interactive else 15)
                session_cookies = []
                play_clicked_on = None
                while browser.is_connected() and not page.is_closed() and time.monotonic()<deadline:
                    try:
                        if save_session:
                            session_cookies = [cookie for cookie in context.cookies()
                                               if _tb_cookie_domain(cookie['domain'])]
                            if save_signal.is_set():
                                break
                        page.wait_for_timeout(400 if auto_session else 1000 if save_session else 2000)
                        if not save_session and _tb_cookie_domain(urlparse(page.url).hostname or ''):
                            if auto_session and media_seen_at is None:
                                try:
                                    playing = page.locator('video').evaluate_all('''videos => {
                                        const attempted = window.__sourceStudioTeraPlay ??= new WeakSet();
                                        const video = videos.find(item => item.getClientRects().length &&
                                            (item.currentSrc || item.src || item.querySelector('source[src]')));
                                        if (video?.paused && !attempted.has(video)) {
                                            attempted.add(video);
                                            video.muted = true;
                                            video.play().catch(() => {});
                                        }
                                        return Boolean(video && !video.paused);
                                    }''')
                                    if not playing and play_clicked_on != page.url:
                                        play = page.get_by_role('button', name=re.compile(r'^play(?: video)?$',re.I))
                                        if play.count() == 1 and play.is_visible():
                                            play_clicked_on = page.url
                                            try:
                                                play.click(timeout=800)
                                            except PWTimeout:
                                                play.evaluate('''button => {
                                                    if (button.matches(':disabled,[aria-disabled="true"]')) return;
                                                    const rect = button.getBoundingClientRect();
                                                    const top = document.elementFromPoint(rect.x + rect.width/2, rect.y + rect.height/2);
                                                    if (button.contains(top)) button.click();
                                                }''',timeout=800)
                                except Exception:
                                    # Sign-in and share redirects can replace the document mid-scan.
                                    pass
                            collect_dom()
                        now = time.monotonic()
                        tracks_settled = media_seen_at is not None and (
                            (now-media_seen_at>=1.6 and now-last_track_at>=0.8) or now-media_seen_at>=4)
                        if auto_session and tracks_settled:
                            break
                    except Exception:
                        if page.is_closed() or not browser.is_connected():break
                        raise
                if auto_session and media_seen_at is not None:
                    captures = {}
                    cached_playlists = 0
                    for url, captured in relay_responses.items():
                        try:
                            headers = _tb_playback_headers(captured.request)
                            body = None
                            captures[url] = (headers,body)
                            if sources[url]['kind'] in ('hls_manifest','subtitle_track') and cached_playlists<12:
                                size = int(captured.headers.get('content-length','0')) or captured.request.sizes().get('responseBodySize',0)
                                if 0<size<=512000:
                                    data = captured.body()
                                    if len(data)<=512000:
                                        snapshot,duration = _tb_playlist_snapshot(data)
                                        captures[url] = (headers,snapshot)
                                        if duration is not None and sources[url]['kind']=='hls_manifest':
                                            sources[url]['duration_seconds'] = duration
                                        cached_playlists += 1
                        except Exception:
                            continue
                    measured = [source['duration_seconds'] for source in sources.values()
                                if source.get('duration_seconds') is not None]
                    short_playlist = bool(measured) and max(measured)<=31
                    preview_notice = False
                    try:
                        preview_notice = _tb_preview_save_prompt(page,False)
                    except Exception:
                        pass
                    original = None
                    save_status = ''
                    if (short_playlist or preview_notice) and browser.is_connected() and not page.is_closed():
                        if not download_sign_in:
                            try:
                                original = _tb_original_download(page,context)
                            except Exception:
                                pass
                        if original is None and save_preview_to_account and not preview_notice and short_playlist and max(measured)>=29:
                            try:
                                preview_notice = _tb_preview_save_prompt(page,True)
                            except Exception:
                                pass
                        if original is None and save_preview_to_account and preview_notice:
                            try:
                                if _tb_login_gate(page):
                                    save_status = _TB_FULL_VIDEO_SIGN_IN
                                else:
                                    original,save_status = _tb_save_preview_and_download(page,context)
                            except Exception:
                                save_status = 'The TeraBox save flow did not complete. Check your account before trying again.'
                    if download_sign_in and not original and not save_status:
                        save_status = _TB_FULL_VIDEO_SIGN_IN
                        if original:
                            source,headers = original
                            sources = {source['url']:source,**{url:record for url,record in sources.items() if url!=source['url']}}
                            captures[source['url']] = (headers,None)
                    try:
                        attach_relay(captures)
                    except Exception:
                        pass
                    result = {'sources':list(sources.values())[:250],
                              'message':'Media detected using your saved session.'}
                    if original:
                        result['message'] = save_status or 'TeraBox offered a video file through its Download control.'
                    elif short_playlist or preview_notice:
                        result['message'] = save_status or ('The longest measured playlist is short. No original video download was captured.'
                                             if short_playlist else 'TeraBox shows a full-video prompt. No original video download was captured.')
                        result['full_video_share'] = share
                    return result,200
                if save_session:
                    if not save_signal.is_set() and browser.is_connected() and not page.is_closed():
                        return {'error':'Sign-in timed out. Start again and click Save cookies and close browser after signing in.'},408
                    if not session_cookies:
                        return {'error':'No TeraBox cookies were captured. Sign in before clicking Save cookies and close browser.'},422
                    _tb_save_session(session_cookies)
                    return {'message':'TeraBox cookies saved for this Windows account. Select Use saved TeraBox session for your next share.'},200
                if auto_session:
                    sources = {url: record for url, record in sources.items() if url.startswith(('https://','http://'))}
                    if not sources and not page.is_closed():
                        host = urlparse(page.url).hostname or ''
                        if cookies and _tb_cookie_domain(host) and not any(_tb_cookie_matches_host(cookie['domain'],host) for cookie in cookies):
                            return {'sources':[], 'cookie_host':host, 'full_video_share':share,
                                    'message':f'The share opened on {host}, but no saved cookies match that host. Open the original share and export cookies after playback works there.'},200
                    if share_errors and not sources:
                        errno = share_errors.get(True) or share_errors[False]
                        return {'sources':[], 'upstream_errno':errno,
                                'message':f'TeraBox returned error {errno} while resolving the share.'},200
                message='Observed media candidates. Playback outside this browser session may require the same session.' if sources else 'No media observed before the window closed or the capture expired. Try again and start the video in the TeraBox window.'
                if auto_session and not sources:
                    message = 'TeraBox loaded, but the scan did not observe a playable media URL.'
                    if download_sign_in:
                        message = _TB_FULL_VIDEO_SIGN_IN
                    if browser.is_connected() and not page.is_closed():
                        try:
                            if page.get_by_text(re.compile(r'^(?:please )?(?:sign|log) in to (?:watch|play)\b',re.I)).first.is_visible():
                                message = 'TeraBox is asking for sign-in to play this share. Replace the saved cookies with a fresh export from a session that can play it.'
                            elif page.locator('input[type="password"]').first.is_visible():
                                message = 'TeraBox displayed a password field. The saved cookies alone did not unlock playback.'
                        except Exception:
                            pass
                if not sources and navigation_issue:
                    message=f'{navigation_issue} {message}'
                return {'sources':list(sources.values())[:250],'message':message},200
            page.wait_for_timeout(3500)
            collect_dom()
            return {'sources':list(sources.values())[:250], 'message':'Observed media candidates; playback was not verified.' if sources else 'No media observed. The page may require login, a share password, verification or manual playback. Direct mode does not synthesize private API tokens.'},200
        finally:
            if browser.is_connected():browser.close()


@app.route('/terabox')
def terabox_page():
    return TERABOX_PAGE


@app.route('/terabox/session', methods=['POST', 'DELETE'])
def terabox_session():
    global _TB_ACTIVE_SAVE
    if not _TB_SESSION_LOCK.acquire(blocking=False):
        return jsonify(error='A TeraBox sign-in is already in progress.'),409
    try:
        path = _tb_session_path()
        if request.method == 'DELETE':
            path.unlink(missing_ok=True)
            return jsonify(message='Saved TeraBox session cleared.')
        data = request.get_json(silent=True)
        job_id = data.get('job_id') if isinstance(data,dict) else None
        if not isinstance(job_id,str) or not re.fullmatch(r'[a-f0-9-]{36}',job_id):
            return jsonify(error='Reload the resolver page and start sign-in again.'),400
        if not _TB_SLOTS.acquire(blocking=False):
            return jsonify(error='Two resolutions are already active. Try again shortly.'),429
        try:
            save_signal = threading.Event()
            _TB_ACTIVE_SAVE = (job_id, save_signal)
            result, status = _tb_direct(_TB_HOME, [], interactive=True, save_signal=save_signal)
            return jsonify(result),status
        finally:
            _TB_ACTIVE_SAVE = None
            _TB_SLOTS.release()
    except Exception:
        return jsonify(error='Could not manage the saved TeraBox session. Check Chromium and Windows user storage.'),502
    finally:
        _TB_SESSION_LOCK.release()


@app.route('/terabox/session/finish', methods=['POST'])
def terabox_session_finish():
    data = request.get_json(silent=True)
    active = _TB_ACTIVE_SAVE
    if not active or not isinstance(data,dict) or data.get('job_id') != active[0]:
        return jsonify(error='This sign-in window is no longer active. Start sign-in again.'),409
    active[1].set()
    return jsonify(message='Saving TeraBox cookies and closing the browser…')


@app.route('/terabox/session/import', methods=['POST'])
def terabox_session_import():
    if not _TB_SESSION_LOCK.acquire(blocking=False):
        return jsonify(error='Wait for the current TeraBox scan to finish, then upload again.'),409
    try:
        user_agent = request.headers.get('X-TeraBox-User-Agent','').strip()
        if user_agent and not re.fullmatch(r'[ -~]{1,512}',user_agent):
            return jsonify(error='Enter a single browser User-Agent under 512 characters.'),400
        raw = request.stream.read(16001)
        if len(raw)>16000:
            return jsonify(error='Export only TeraBox cookies, up to 16 KB.'),413
        cookies = _tb_cookies(raw.decode('utf-8-sig'),host=None)
        if not cookies:
            return jsonify(error='The cookie export is empty.'),400
        _tb_save_session(cookies,user_agent)
        return jsonify(message=f'Saved {len(cookies)} TeraBox cookies for future scans.')
    except _TBInputError as exc:
        return jsonify(error=str(exc)),400
    except UnicodeDecodeError:
        return jsonify(error='Use a UTF-8 cookie export.'),400
    except OSError:
        return jsonify(error='Windows could not save the cookie file.'),502
    finally:
        _TB_SESSION_LOCK.release()


@app.route('/terabox/session/user-agent', methods=['POST'])
def terabox_session_user_agent():
    data = request.get_json(silent=True)
    user_agent = data.get('user_agent') if isinstance(data,dict) else None
    if not isinstance(user_agent,str) or not re.fullmatch(r'[ -~]{0,512}',user_agent):
        return jsonify(error='Enter a single User-Agent of up to 512 characters.'),400
    if not _TB_SESSION_LOCK.acquire(blocking=False):
        return jsonify(error='Wait for the current TeraBox scan to finish.'),409
    try:
        cookies = _tb_load_session()
        if not cookies:
            return jsonify(error='Upload a usable TeraBox cookie export first.'),422
        _tb_save_session(cookies,user_agent.strip())
        return jsonify(message='User-Agent updated for your saved TeraBox cookies.')
    except (OSError, ValueError):
        return jsonify(error='Windows could not update the saved TeraBox session.'),502
    finally:
        _TB_SESSION_LOCK.release()


@app.route('/terabox/resolve',methods=['POST'])
def terabox_resolve():
    if request.content_length and request.content_length>24000:
        return jsonify(error='Request too large.'),413
    data=request.get_json(silent=True)
    try:
        if not isinstance(data,dict): raise ValueError('Send a JSON object.')
        share=data.get('url','').strip();p=urlparse(share)
        if p.scheme!='https' or p.hostname not in tuple(host for root in _TB_DOMAINS for host in (root,'www.'+root)) or p.username or p.password or p.port not in (None,443):
            raise ValueError('Use an HTTPS share on terabox.com, 1024terabox.com or terabox.app.')
        if not (p.path.startswith('/s/') or 'surl=' in p.query): raise ValueError('Enter a TeraBox sharing link.')
        mode=data.get('provider','direct')
        if mode not in ('direct',*_TB_PROVIDERS): raise ValueError('Unknown provider.')
        token=data.get('token','');name=data.get('token_name','');location=data.get('token_location','header')
        cookie=data.get('cookies','')
        interactive=data.get('browser_session',False)
        saved_session = data.get('saved_session',False)
        auto_session = data.get('auto_session',False)
        save_preview = data.get('save_preview_to_account',False)
        if not isinstance(save_preview,bool) or (save_preview and (mode!='direct' or auto_session is not True)):
            raise _TBInputError('Saving a preview to your account requires automatic Direct TeraBox mode.')
        if not isinstance(auto_session,bool) or (auto_session and (mode!='direct' or interactive or saved_session or cookie)):
            raise _TBInputError('Automatic session handling is available in Direct TeraBox mode.')
        if not isinstance(saved_session,bool) or (saved_session and (mode != 'direct' or interactive or cookie)):
            raise _TBInputError('Choose the saved session, browser sign-in or imported cookies in Direct TeraBox mode.')
        if not isinstance(interactive,bool) or (interactive and mode!='direct'):
            raise _TBInputError('Browser sign-in is available only in Direct TeraBox mode.')
        if not all(isinstance(v,str) for v in (token,name,cookie,location)): raise ValueError('Credential fields must be text.')
        if len(token)>8000 or '\r' in token or '\n' in token: raise ValueError('Invalid token.')
        if mode=='direct':
            if token: raise ValueError('Direct mode accepts your TeraBox cookies. Resolver tokens belong to their provider.')
            if interactive and cookie:
                raise _TBInputError('Choose browser sign-in or imported cookies.')
            cookies=_tb_cookies(cookie,p.hostname)
        else:
            if cookie: raise ValueError('Do not send TeraBox cookies to a third-party resolver.')
            if mode=='xapiverse': name='xAPIverse-Key';location='header'
            if mode=='xapiverse' and not token: raise ValueError('Enter your xAPIverse API key.')
            if token and (not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,79}',name) or name.lower() in ('host','cookie','content-length','connection','transfer-encoding','origin','referer','url','__proto__','constructor')):
                raise ValueError('Enter the actual token field name; reserved transport fields are not allowed.')
            if location not in ('header','json'): raise ValueError('Choose header or JSON token placement.')
    except _TBInputError as exc:
        return jsonify(error=str(exc)),400
    except (ValueError,TypeError,AttributeError):
        return jsonify(error='Check the HTTPS share URL, provider and credential fields. Use TeraBox cookies only in direct mode; resolver tokens need their exact header or JSON field name.'),400
    if not _TB_SLOTS.acquire(blocking=False): return jsonify(error='Two resolutions are already active. Try again shortly.'),429
    try:
        if mode=='direct':
            if auto_session:
                if not _TB_SESSION_LOCK.acquire(blocking=False):
                    return jsonify(error='A TeraBox session action is already running.'),409
                try:
                    try:
                        cookies,user_agent = _tb_load_session(with_user_agent=True)
                    except Exception:
                        cookies,user_agent = [],''
                    if not cookies:
                        return jsonify(error='No usable saved TeraBox cookies found on this PC.'),422
                    result,status = _tb_direct(share,cookies,auto_session=True,user_agent=user_agent,
                                               save_preview_to_account=save_preview)
                    return jsonify(result),status
                finally:
                    _TB_SESSION_LOCK.release()
            if interactive:
                result,status=_tb_direct(share,[],interactive=True)
                return jsonify(result),status
            if saved_session:
                try:
                    cookies = _tb_load_session()
                except Exception:
                    return jsonify(error='The saved session could not be opened. Sign in and save it again.'),422
                if not cookies:
                    return jsonify(error='No usable TeraBox session is saved. Select Sign in and save session first.'),422
            if saved_session:
                result,status=_tb_direct(share,cookies,interactive=True)
            else:
                result,status=_tb_direct(share,cookies)
            result['cookie_info']={'accepted':len(cookies),'domains':sorted({c['domain'] for c in cookies}),
                'note':'Accepted cookies do not prove a logged-in session. Exported domains are preserved; unrelated domains are excluded.'}
            return jsonify(result),status
        endpoint=_TB_PROVIDERS[mode]
        headers={'Content-Type':'application/json'};body={'url':share}
        if token:
            (headers if location=='header' else body)[name]=token
        # Deliberately do not use get_api_session: imported browser cookies and
        # global authorization settings must never leak into these resolvers.
        with requests.Session() as session:
            session.trust_env=False  # Do not inherit .netrc credentials for a resolver.
            with closing(session.post(endpoint,json=body,headers=headers,allow_redirects=False,stream=True,timeout=(8,30))) as response:
                if 300<=response.status_code<400:
                    return jsonify(error='Resolver redirected. Credentials were not forwarded.',upstream_status=response.status_code),502
                buf=bytearray()
                for chunk in response.iter_content(32768):
                    buf.extend(chunk)
                    if len(buf)>2*1024*1024: return jsonify(error='Resolver response exceeded 2 MiB.'),502
                try: payload=_json_mod.loads(buf)
                except (ValueError,RecursionError): return jsonify(error='Resolver returned a non-JSON response.',upstream_status=response.status_code),502
                # Never reflect upstream text, which might echo a credential.
                if response.status_code>=400 or (isinstance(payload,dict) and (payload.get('error') or payload.get('success') is False or payload.get('status')=='error')):
                    code=payload.get('error') if isinstance(payload,dict) else None
                    message='Resolver could not resolve this share. Check access, credentials and provider availability.'
                    if code=='token_missing': message='Resolver requires a verification token. Supply its exact field name and value from your own valid session; a session ID alone may not satisfy it.'
                    return jsonify(error=message,upstream_status=response.status_code),502
                sources=_tb_sources(payload,share)
                # Guard against a provider reflecting the submitted credential in a URL.
                if token:
                    from urllib.parse import unquote as _tb_unquote
                    sources=[r for r in sources if token not in _tb_unquote(r['url'])]
                return jsonify(sources=sources,message='Media candidates returned; availability and playback are not verified.' if sources else 'Resolver returned no recognized media URLs.',upstream_status=response.status_code)
    except Exception as exc:
        text=str(exc).lower()
        message='Resolution failed. Check the selected provider and session. Credentials and upstream details were not logged.'
        if 'timeout' in text or 'timed out' in text:message='Connection or page loading timed out. A token cannot fix an unreachable host; verify the share opens in your browser.'
        elif 'name_not_resolved' in text or 'nameresolution' in text or 'name resolution' in text:message='DNS lookup failed. Check the host and network connection.'
        return jsonify(error=message),502
    finally: _TB_SLOTS.release()
