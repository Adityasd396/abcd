"""Explicit upstream routing, configured locally without exposing credentials."""
import os
from urllib.parse import urlparse, unquote


def proxy_url():
    value = os.environ.get('RIPPER_PROXY_URL', '').strip()
    if not value:
        return None
    try:
        parsed = urlparse(value)
        valid = parsed.scheme in ('http', 'https', 'socks5', 'socks5h') and parsed.hostname and parsed.port
    except ValueError:
        valid = False
    if not valid:
        raise ValueError('RIPPER_PROXY_URL must be an HTTP(S) or SOCKS5 URL with a host and port')
    return value


def configure_session(session):
    value = proxy_url()
    if value:
        session.trust_env = False
        session.proxies.update({'http': value, 'https': value})
    return session


def browser_proxy_options():
    value = proxy_url()
    if not value:
        return {}
    parsed = urlparse(value)
    if parsed.scheme.startswith('socks') and (parsed.username or parsed.password):
        raise ValueError('Browser SOCKS5 routing requires a proxy without authentication; use an HTTP proxy for authenticated browser routing')
    host = f'[{parsed.hostname}]' if ':' in parsed.hostname else parsed.hostname
    scheme = 'socks5' if parsed.scheme == 'socks5h' else parsed.scheme
    proxy = {'server': f'{scheme}://{host}:{parsed.port}'}
    if parsed.username:
        proxy['username'] = unquote(parsed.username)
    if parsed.password:
        proxy['password'] = unquote(parsed.password)
    return {'proxy': proxy}


def routing_status():
    return {'configured': bool(proxy_url()), 'mode': 'configured proxy' if proxy_url() else 'default routing'}
