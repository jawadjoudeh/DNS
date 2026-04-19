import requests
import time

CACHE = {}
CACHE_TTL = 300

PROVIDERS = [
    {"name": "Cloudflare", "url": "https://cloudflare-dns.com/dns-query"},
    {"name": "Google", "url": "https://dns.google/resolve"},
    {"name": "Quad9", "url": "https://dns.quad9.net/dns-query"}
]

def resolve(domain):
    now = time.time()
    if domain in CACHE and CACHE[domain]['expires_at'] > now:
        return CACHE[domain]['result']

    for provider in PROVIDERS:
        start_time = time.time()
        try:
            r = requests.get(provider['url'], params={'name': domain, 'type': 'A'}, headers={'accept': 'application/dns-json'}, timeout=2)
            if r.status_code == 200:
                data = r.json()
                latency = (time.time() - start_time) * 1000
                answers = data.get('Answer', [])
                ip = answers[0]['data'] if answers else None
                res = {
                    "success": bool(ip),
                    "answer": ip,
                    "provider": provider['name'],
                    "latency_ms": latency
                }
                CACHE[domain] = {'result': res, 'expires_at': now + CACHE_TTL}
                return res
        except:
            continue
            
    return {"success": False, "answer": None, "provider": None, "latency_ms": 0}

def check_providers():
    health = {}
    for p in PROVIDERS:
        try:
            r = requests.get(p['url'], params={'name': 'example.com', 'type': 'A'}, headers={'accept': 'application/dns-json'}, timeout=2)
            health[p['name']] = r.status_code == 200
        except:
            health[p['name']] = False
    return health
