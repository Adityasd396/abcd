"""Keep browser engines and their asyncio state on disposable worker threads."""
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from urllib.parse import urlparse


def isolated_browser_thread(function):
    @wraps(function)
    def run(*args, **kwargs):
        # Never pass live Playwright pages across this boundary. Each decorated
        # function creates, uses and disposes its browser on this same worker.
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix='browser-engine') as pool:
            return pool.submit(function, *args, **kwargs).result()
    return run


def navigation_error(url, error):
    message = str(error)
    if 'ERR_NAME_NOT_RESOLVED' in message or 'NS_ERROR_UNKNOWN_HOST' in message:
        host = urlparse(url).hostname or url
        return f'DNS lookup failed for {host}. Check the website address and your DNS/network connection.'
    return message[:180]


def extract_live_frame_urls(page, script, log):
    """Skip detached frames; retry navigation races once using fresh frames."""
    results = []
    completed = set()
    for attempt in range(2):
        retry = False
        if page.is_closed():
            break
        for frame in list(page.frames):
            if id(frame) in completed or frame.is_detached():
                continue
            try:
                urls = frame.evaluate(script)
                base = frame.url
                if isinstance(urls, list):
                    results.extend((url, base) for url in urls if isinstance(url, str))
                completed.add(id(frame))
            except Exception as exc:
                message = str(exc).lower()
                if frame.is_detached() or 'frame was detached' in message or 'frame has been detached' in message:
                    completed.add(id(frame))
                    retry = True
                elif 'execution context was destroyed' in message or 'cannot find context' in message:
                    retry = True
                elif page.is_closed() or 'target page, context or browser has been closed' in message:
                    return results
                else:
                    completed.add(id(frame))
                    log.append(f"   DOM extraction unavailable: {str(exc)[:120]}")
        if not retry or attempt:
            break
        try:
            page.wait_for_timeout(100)
        except Exception:
            break
    return results
