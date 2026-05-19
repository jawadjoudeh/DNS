import requests
import time
from collections import OrderedDict

_CACHE: OrderedDict = OrderedDict()
_CACHE_TTL = 300
_CACHE_MAX = 5000

PROVIDERS = [
    {"name": "Cloudflare", "url": "https://cloudflare-dns.com/dns-query"},
    {"name": "Google",     "url": "https://dns.google/resolve"},
    {"name": "Quad9",      "url": "https://dns.quad9.net/dns-query"},
]

def resolve(domain, preferred=None):
    now = time.time()
    if domain in _CACHE:
        entry = _CACHE[domain]
        if entry['expires_at'] > now:
            _CACHE.move_to_end(domain)
            return entry['result']
        del _CACHE[domain]

    providers = PROVIDERS
    if preferred:
        key = preferred.lower()
        providers = sorted(PROVIDERS, key=lambda p: 0 if p['name'].lower() == key else 1)
    for provider in providers:
        t0 = time.time()
        try:
            r = requests.get(provider['url'], params={'name': domain, 'type': 'A'},
                             headers={'accept': 'application/dns-json'}, timeout=2)
            if r.status_code == 200:
                answers = r.json().get('Answer', [])
                ip      = answers[0]['data'] if answers else None
                res = {"success": bool(ip), "ip": ip,
                       "provider": provider['name'], "latency_ms": (time.time() - t0) * 1000}
                _CACHE[domain] = {'result': res, 'expires_at': now + _CACHE_TTL}
                if len(_CACHE) > _CACHE_MAX:
                    _CACHE.popitem(last=False)
                return res
        except requests.RequestException:
            continue

    return {"success": False, "ip": None, "provider": None, "latency_ms": 0}
