"""Embedded local runtime configuration; standard-library fallbacks supported."""
import gzip
from flask.json.provider import DefaultJSONProvider

try:
    import orjson as _fast_json
except ImportError:
    _fast_json=None


def external_ai_enabled():
    return os.environ.get('RIPPER_ALLOW_EXTERNAL_AI','').strip()=='1'


class LocalJSONProvider(DefaultJSONProvider):
    sort_keys=False
    def dumps(self,obj,**kwargs):
        if _fast_json is None:
            return super().dumps(obj,**kwargs)
        option=_fast_json.OPT_NON_STR_KEYS
        if kwargs.get('indent'):option|=_fast_json.OPT_INDENT_2
        if kwargs.get('sort_keys',self.sort_keys):option|=_fast_json.OPT_SORT_KEYS
        return _fast_json.dumps(obj,default=self.default,option=option).decode('utf-8')

    def loads(self,value,**kwargs):
        if _fast_json is None or kwargs:
            return super().loads(value,**kwargs)
        return _fast_json.loads(value)


def configure_local_runtime(app):
    app.json=LocalJSONProvider(app)
    @app.before_request
    def restrict_browser_origins():
        if urlparse(request.host_url).hostname not in ('localhost','127.0.0.1','::1'):
            return jsonify({'error':'Use the local app address.'}),403
        if request.method in ('POST','PUT','PATCH','DELETE'):
            origin=request.headers.get('Origin')
            if origin and origin!=request.host_url.rstrip('/'):
                return jsonify({'error':'Open this action from the local app.'}),403
    @app.after_request
    def private_compact_responses(response):
        response.headers.pop('Access-Control-Allow-Origin',None)
        response.headers['Cache-Control']='no-store'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['X-Content-Type-Options']='nosniff'
        if (response.mimetype=='application/json' and not response.is_streamed
                and not response.headers.get('Content-Encoding')
                and not response.headers.get('Content-Disposition')):
            response.vary.add('Accept-Encoding')
            if request.accept_encodings['gzip']>0:
                content=response.get_data()
                if len(content)>=4096:
                    compact=gzip.compress(content,compresslevel=1,mtime=0)
                    if len(compact)<len(content):
                        response.set_data(compact)
                        response.headers['Content-Encoding']='gzip'
        return response
