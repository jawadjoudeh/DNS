import socket
import sys
import urllib.request
import urllib.parse
import json
import os
import sqlite3

# Pre-configured configurations
API_KEY = "sk-placeholder"
SERVER_URL = "http://127.0.0.1:5000"
BIND_IP = "127.0.0.1"
BIND_PORT = 53

# Auto-detect local API key from database for ease of use in local environment
if API_KEY == "sk-placeholder" or not API_KEY:
    try:
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "users.db")
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            row = conn.execute("SELECT key_value FROM api_keys ORDER BY key_id ASC LIMIT 1").fetchone()
            conn.close()
            if row:
                API_KEY = row[0]
                print(f"Auto-detected local API key: {API_KEY[:12]}...")
    except Exception as e:
        print(f"Failed to auto-detect API key: {e}")

def parse_dns_question(data):
    if len(data) < 12:
        return None, None
    idx = 12
    parts = []
    while idx < len(data):
        length = data[idx]
        if length == 0:
            idx += 1
            break
        parts.append(data[idx+1:idx+1+length].decode('utf-8', errors='ignore'))
        idx += 1 + length
    domain = ".".join(parts)
    return domain, data[:idx+4]

def build_nxdomain_response(query_data, question_section):
    transaction_id = query_data[:2]
    flags = b'\x81\x83'  # NXDOMAIN
    qdcount = b'\x00\x01'
    ancount = b'\x00\x00'
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'
    header = transaction_id + flags + qdcount + ancount + nscount + arcount
    return header + question_section[12:]

def build_a_response(query_data, question_section, ip_str):
    transaction_id = query_data[:2]
    flags = b'\x81\x80'  # NOERROR
    qdcount = b'\x00\x01'
    ancount = b'\x00\x01'
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'
    header = transaction_id + flags + qdcount + ancount + nscount + arcount
    
    name_pointer = b'\xc0\x0c'
    type_a = b'\x00\x01'
    class_in = b'\x00\x01'
    ttl = b'\x00\x00\x01\x2c'
    rdlength = b'\x00\x04'
    try:
        rdata = bytes(int(x) for x in ip_str.split('.'))
    except Exception:
        rdata = b'\x00\x00\x00\x00'
    answer = name_pointer + type_a + class_in + ttl + rdlength + rdata
    return header + question_section[12:] + answer

def check_domain_api(domain):
    url = f"{SERVER_URL}/api/proxy/query"
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
    }
    data = json.dumps({"domain": domain}).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=3.0) as response:
            res = json.loads(response.read().decode('utf-8'))
            return res
    except Exception as e:
        print(f"API Request failed: {e}")
        return None

def start_proxy():
    if not API_KEY or API_KEY == "sk-placeholder":
        print("ERROR: No valid API key found. Please run the server first to generate database or download pre-configured client.")
        sys.exit(1)
        
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((BIND_IP, BIND_PORT))
        print(f"Intelligent DNS Proxy is listening on {BIND_IP}:{BIND_PORT}...")
    except PermissionError:
        print(f"ERROR: Permission denied. Please run as Administrator / root to bind to port {BIND_PORT}.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to bind to {BIND_IP}:{BIND_PORT}: {e}")
        sys.exit(1)
        
    while True:
        try:
            data, addr = sock.recvfrom(512)
            if len(data) < 12:
                continue
            
            domain, question = parse_dns_question(data)
            if not domain:
                continue
                
            print(f"Received query for: {domain}")
            
            res = check_domain_api(domain)
            if res is None:
                print("Fail-safe: API is down. Preserving connectivity (passing through to 8.8.8.8).")
                try:
                    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    upstream.sendto(data, ("8.8.8.8", 53))
                    resp, _ = upstream.recvfrom(512)
                    sock.sendto(resp, addr)
                except Exception as ex:
                    print(f"Upstream resolution failed: {ex}")
                continue
            
            if res.get('blocked'):
                print(f"[BLOCKED] Malicious domain detected by ML: {domain} ({res.get('attack_type', 'DGA')})")
                response_data = build_nxdomain_response(data, question)
            else:
                ip = res.get('resolved_ip')
                if ip:
                    print(f"[ALLOWED] Resolved via DoH: {domain} -> {ip} ({res.get('doh_provider', 'Cloudflare')})")
                    response_data = build_a_response(data, question, ip)
                else:
                    response_data = build_nxdomain_response(data, question)
            
            sock.sendto(response_data, addr)
        except KeyboardInterrupt:
            print("\nShutting down DNS proxy.")
            break
        except Exception as e:
            print(f"Error handling query: {e}")

if __name__ == '__main__':
    start_proxy()
