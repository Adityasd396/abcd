"""Short-lived local relay for media observed in a TeraBox browser session."""
from secrets import token_urlsafe as _tb_token
from urllib.parse import quote as _tb_quote
from base64 import b64decode as _tb_b64decode
from gzip import decompress as _tb_gunzip
from shutil import which as _tb_which
import subprocess as _tb_subprocess
from tempfile import TemporaryDirectory as _TBTempDirectory
from flask import Response as _TBResponse

_TB_MEDIA = {}
_TB_MEDIA_LOCK = threading.Lock()
_TB_MEDIA_TTL = 600
_TB_MEDIA_LIMIT = 1500
_TB_EXPORT_SLOT = threading.BoundedSemaphore(1)


class _TBPlaylistError(ValueError):
    pass


@app.route('/terabox/player/hls.js')
def terabox_hls_script():
    compressed = _tb_b64decode(_TB_HLS_BUNDLE)
    headers = {'Vary':'Accept-Encoding'}
    if request.accept_encodings['gzip']>0:
        headers['Content-Encoding'] = 'gzip'
        body = compressed
    else:
        body = _tb_gunzip(compressed)
    return _TBResponse(body,mimetype='application/javascript',headers=headers)


def _tb_expire_media(session_id):
    with _TB_MEDIA_LOCK:
        _TB_MEDIA.pop(session_id,None)


def _tb_media_host(url):
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ''
        if (parsed.scheme == 'https' and parsed.port in (None,443) and not (parsed.username or parsed.password)
                and (_tb_cookie_domain(host) or host in ('1024tera.com','v4.freeterabox.com','teraboxcdn.com')
                     or host.endswith(('.1024tera.com','.teraboxcdn.com')))):
            return host
    except ValueError:
        pass
    return ''


def _tb_media_entry(session_id, state, url, headers, playlist=False, body=None, filename=''):
    """Called with the media lock held. Only provider URLs get local handles."""
    if not _tb_media_host(url):
        return ''
    entry = state['urls'].get(url)
    if entry is None:
        if len(state['entries']) >= _TB_MEDIA_LIMIT:
            return ''
        entry = _tb_token(12)
        state['urls'][url] = entry
        state['entries'][entry] = (url,headers,playlist,body,filename)
    return f'/terabox/media/{session_id}/{entry}'


def _tb_attach_media_relay(sources, observed_requests, cookies):
    now = time.monotonic()
    with _TB_MEDIA_LOCK:
        for session_id in list(_TB_MEDIA):
            if _TB_MEDIA[session_id]['expires'] <= now:
                _TB_MEDIA.pop(session_id)['timer'].cancel()
        state = {'expires':now+_TB_MEDIA_TTL,'entries':{},'urls':{},'cookies':cookies,'exports':{}}
        session_id = _tb_token(18)
        for source in sources.values():
            capture = observed_requests.get(source['url'])
            if not capture:
                continue
            headers,body = capture
            playlist = source['kind'] in ('hls_manifest','subtitle_track')
            filename = source.get('name','') if source['kind']=='video_download' else ''
            local = _tb_media_entry(session_id,state,source['url'],headers,playlist,body,filename)
            if local:
                source['replay_url'] = local
                if source['kind']=='hls_manifest':
                    entry = state['urls'][source['url']]
                    state['exports'][entry] = source.get('duration_seconds')
                    source['download_url'] = f'/terabox/download/{session_id}/{entry}'
        if state['entries']:
            if len(_TB_MEDIA)>=8:
                _TB_MEDIA.pop(next(iter(_TB_MEDIA)))['timer'].cancel()
            timer = threading.Timer(_TB_MEDIA_TTL,_tb_expire_media,args=(session_id,))
            timer.daemon = True
            state['timer'] = timer
            _TB_MEDIA[session_id] = state
            timer.start()


def _tb_media_cookie_header(cookies,url):
    parts = urlparse(url)
    path = parts.path or '/'
    pairs = []
    for cookie in sorted(cookies,key=lambda c:len(c.get('path','/')),reverse=True):
        domain = cookie['domain'].lower()
        scope = cookie.get('path','/')
        expires = cookie.get('expires',-1)
        if expires>0 and expires<=time.time():
            continue
        if not _tb_cookie_matches_host(domain,parts.hostname):
            continue
        if path != scope and not path.startswith(scope.rstrip('/')+'/'):
            continue
        pairs.append(f"{cookie['name']}={cookie['value']}")
    return '; '.join(pairs)


def _tb_playlist_snapshot(data):
    """Cache stable playlists and measure the duration of ended media playlists."""
    lines = data.decode('utf-8-sig').splitlines()
    if not lines or lines[0].strip() != '#EXTM3U':
        return None,None
    ended = any(line.strip() == '#EXT-X-ENDLIST' for line in lines)
    if ended:
        durations = re.findall(r'(?m)^#EXTINF:(\d+(?:\.\d+)?)(?=,|\r?$)',data.decode('utf-8-sig'))
        duration = round(sum(map(float,durations)),2) if durations else None
        return data,duration
    if any(line.startswith(('#EXT-X-STREAM-INF:','#EXT-X-I-FRAME-STREAM-INF:')) for line in lines):
        return data,None
    # An unfinished media playlist must be fetched again when the player polls it.
    return None,None


def _tb_rewrite_playlist(body,url,session_id,state,headers):
    try:
        text = body.decode('utf-8-sig')
    except UnicodeDecodeError as exc:
        raise _TBPlaylistError('TeraBox returned a playlist that is not valid UTF-8.') from exc
    if not text.lstrip().startswith('#EXTM3U'):
        raise _TBPlaylistError('TeraBox returned a response without an HLS playlist.')
    child_headers = {key:value for key,value in headers.items() if key not in ('cookie','accept')}

    def register(uri,playlist=False):
        target = urljoin(url,uri)
        if not _tb_media_host(target):
            host = urlparse(target).hostname or ''
            if re.fullmatch(r'[a-z0-9.-]{1,253}',host):
                raise _TBPlaylistError(f'TeraBox playlist references an unsupported media host ({host}).')
            raise _TBPlaylistError('TeraBox playlist contains an unsupported media URL.')
        local = _tb_media_entry(session_id,state,target,child_headers,
                                playlist or urlparse(target).path.lower().endswith('.m3u8'))
        if not local:
            raise _TBPlaylistError('TeraBox playlist exceeds the local relay track limit.')
        return local

    lines = []
    next_is_playlist = False
    with _TB_MEDIA_LOCK:
        for line in text.splitlines():
            line = line.strip()
            if line.startswith('#'):
                if re.search(r'\bURI=(?!")',line):
                    raise _TBPlaylistError('TeraBox playlist contains an invalid URI attribute.')
                if line.startswith('#EXT-X-STREAM-INF:'):
                    next_is_playlist = True
                is_playlist = line.startswith(('#EXT-X-MEDIA:','#EXT-X-I-FRAME-STREAM-INF:'))
                line = re.sub(r'\bURI="([^"\r\n]+)"',lambda match: f'URI="{register(match[1],is_playlist)}"',line)
            elif line:
                line = register(line,next_is_playlist)
                next_is_playlist = False
            lines.append(line)
    return '\n'.join(lines)+'\n'


@app.route('/terabox/download/<session_id>/<entry_id>')
def terabox_download(session_id,entry_id):
    with _TB_MEDIA_LOCK:
        state = _TB_MEDIA.get(session_id)
        if not state or state['expires']<=time.monotonic() or entry_id not in state['exports']:
            return 'This video link has expired. Resolve the TeraBox share again.',404
        duration = state['exports'][entry_id]
    ffmpeg = _tb_which('ffmpeg')
    if not ffmpeg:
        return 'Install FFmpeg to download this stream as MP4.',503
    if not _TB_EXPORT_SLOT.acquire(blocking=False):
        return 'An MP4 download is already being prepared. Try again when it finishes.',409
    directory = None
    media_file = None
    streaming = False
    try:
        directory = _TBTempDirectory(prefix='terabox-export-')
        output = _TBPath(directory.name)/'terabox-video.mp4'
        port = int(request.environ['SERVER_PORT'])
        manifest = f'http://127.0.0.1:{port}/terabox/media/{session_id}/{entry_id}'
        command = [ffmpeg,'-hide_banner','-loglevel','warning','-nostdin',
                   '-progress','pipe:1','-nostats','-protocol_whitelist','http,tcp,crypto',
                   '-allowed_extensions','ALL','-extension_picky','0','-f','hls','-i',manifest,
                   '-map','0:v:0','-map','0:a:0?','-c','copy','-movflags','+faststart',str(output)]
        result = _tb_subprocess.run(command,capture_output=True,timeout=300,
                                    env={**os.environ,'no_proxy':'127.0.0.1','NO_PROXY':'127.0.0.1'},
                                    creationflags=getattr(_tb_subprocess,'CREATE_NO_WINDOW',0))
        missing_segments = re.search(rb'failed to open segment|error when loading|HTTP error [45]\d\d',result.stderr,re.I)
        if result.returncode or missing_segments or not output.is_file() or not output.stat().st_size:
            return 'The stream could not be packaged as MP4. Resolve the share again if its links expired.',502
        elapsed = re.findall(rb'^out_time_us=(\d+)\r?$',result.stdout,re.M)
        if duration is not None and (not elapsed or int(elapsed[-1])/1000000 < duration-2):
            return 'The stream ended before the expected duration. Resolve the share again and retry the download.',502

        media_file = output.open('rb')
        response = _TBResponse(iter(lambda: media_file.read(256*1024),b''),mimetype='video/mp4',
                               headers={'Content-Disposition':'attachment; filename="terabox-video.mp4"',
                                        'Content-Length':str(output.stat().st_size)})
        response.call_on_close(media_file.close)
        response.call_on_close(directory.cleanup)
        streaming = True
        return response
    except _tb_subprocess.TimeoutExpired:
        return 'Preparing the MP4 timed out.',504
    except (OSError, ValueError):
        return 'The local app could not prepare the MP4.',502
    finally:
        if not streaming:
            if media_file is not None:
                media_file.close()
            if directory is not None:
                directory.cleanup()
        _TB_EXPORT_SLOT.release()


@app.route('/terabox/media/<session_id>/<entry_id>')
def terabox_media(session_id,entry_id):
    with _TB_MEDIA_LOCK:
        state = _TB_MEDIA.get(session_id)
        entry = state['entries'].get(entry_id) if state and state['expires']>time.monotonic() else None
    if not entry:
        return 'This media link has expired. Resolve the original TeraBox share again.',404
    url,headers,playlist,body,filename = entry
    session = None
    upstream = None
    streamed = False
    try:
        if body is None:
            session = requests.Session()
            session.trust_env = False
            configure_session(session)
            request_headers = dict(headers)
            request_headers['accept-encoding'] = 'identity'
            if not playlist and request.headers.get('Range'):
                request_headers['range'] = request.headers['Range']
            for _ in range(4):
                if not _tb_media_host(url):
                    return 'TeraBox redirected outside the media relay.',502
                if 'cookie' not in request_headers:
                    cookie = _tb_media_cookie_header(state['cookies'],url)
                    if cookie:
                        request_headers['cookie'] = cookie
                upstream = session.get(url,headers=request_headers,stream=True,allow_redirects=False,timeout=(6,15))
                if not upstream.is_redirect:
                    break
                url = urljoin(url,upstream.headers['Location'])
                upstream.close()
                request_headers.pop('cookie',None)
            if upstream.is_redirect:
                return 'TeraBox exceeded the media redirect limit.',502
            if upstream.status_code>=400:
                return f'TeraBox returned HTTP {upstream.status_code}. Resolve the share again to refresh its media links.',502
            mime = upstream.headers.get('Content-Type','').split(';',1)[0].lower()
            if 'json' in mime or playlist or 'mpegurl' in mime:
                data = bytearray()
                for chunk in upstream.iter_content(16384):
                    data.extend(chunk)
                    if len(data)>512000:
                        return 'TeraBox playlist or error response exceeded the relay limit.',502
                body = bytes(data)
                if 'json' in mime or body.lstrip().startswith(b'{'):
                    try:
                        error = _json_mod.loads(body)
                    except ValueError:
                        return 'TeraBox returned an unreadable JSON error instead of media.',502
                    errno = error.get('errno') if isinstance(error,dict) else None
                    code = f' {errno}' if type(errno) is int else ''
                    return f'TeraBox returned a media error{code}. Resolve the original share again.',502
            else:
                if mime in ('text/html','application/xhtml+xml','image/svg+xml'):
                    return 'TeraBox returned a webpage instead of media.',502
                forwarded = {key:upstream.headers[key] for key in ('Accept-Ranges','Content-Range') if key in upstream.headers}
                if 'Content-Length' in upstream.headers and not upstream.headers.get('Content-Encoding'):
                    forwarded['Content-Length'] = upstream.headers['Content-Length']
                if filename:
                    forwarded['Content-Disposition'] = "attachment; filename*=UTF-8''" + _tb_quote(filename[:240],safe='')
                safe_mime = mime if mime.startswith(('video/','audio/')) or mime=='text/vtt' else 'application/octet-stream'
                result = _TBResponse(upstream.iter_content(65536),status=upstream.status_code,mimetype=safe_mime,headers=forwarded)
                result.call_on_close(session.close)
                result.call_on_close(upstream.close)
                streamed = True
                return result
        rewritten = _tb_rewrite_playlist(body,url,session_id,state,headers)
        return _TBResponse(rewritten,mimetype='application/vnd.apple.mpegurl')
    except _TBPlaylistError as exc:
        return str(exc),502
    except requests.exceptions.ProxyError:
        return 'The local relay could not reach the TeraBox media server through the configured proxy.',502
    except requests.exceptions.SSLError:
        return 'The local relay could not verify the TeraBox media server’s TLS connection.',502
    except requests.exceptions.Timeout:
        return 'The TeraBox media server timed out while the local relay was fetching the stream.',504
    except (requests.RequestException,OSError):
        return 'The local relay lost its connection to the TeraBox media server.',502
    except ValueError:
        return 'TeraBox returned an invalid playlist URL or media response.',502
    finally:
        if not streamed:
            if upstream is not None:
                upstream.close()
            if session is not None:
                session.close()
