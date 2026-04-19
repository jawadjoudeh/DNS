import threading
import requests
import time
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP, send

API_KEY = "YOUR_API_KEY_HERE"
API_URL = "https://YOUR_SERVER_URL/api/classify"
INTERFACE = None
LOG_FILE = "proxy_log.txt"

STOP_EVENT = threading.Event()

def log(msg):
    print(msg)
    with open(LOG_FILE, "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")

def classify_domain(domain):
    headers = {}
    if API_KEY and API_KEY != "YOUR_API_KEY_HERE":
        headers["X-API-Key"] = API_KEY
    try:
        r = requests.post(API_URL, json={"domain": domain}, headers=headers, timeout=2)
        return r.json()
    except Exception as e:
        log(f"WARNING: API unreachable - pass-through for {domain}")
        return {"verdict": "benign", "blocked": False, "confidence": 0.5, "fail_safe": True}

def handle_packet(pkt):
    if pkt.haslayer(DNSQR):
        query = pkt[DNSQR].qname.decode('utf-8').strip('.')
        res = classify_domain(query)
        
        if res.get('blocked'):
            log(f"BLOCKED: {query} (Reason: {res.get('attack_type', 'Malicious')})")
            if pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS):
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                              UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                              DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, rcode=3) # NXDOMAIN
                send(spoofed_pkt, verbose=0)
        else:
            log(f"FORWARDED: {query}")

def start_proxy():
    STOP_EVENT.clear()
    log("Proxy started on port 53...")
    sniff(filter="udp port 53", prn=handle_packet, store=False, stop_filter=lambda p: STOP_EVENT.is_set())

if __name__ == "__main__":
    print("Run as Administrator/root")
    start_proxy()
