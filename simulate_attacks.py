import sys
import time
import json
import requests

# Host and port of the Secure DNS Queries server
SERVER_URL = "http://127.0.0.1:5000/api/classify"

# Beautiful ASCII Color codes for printing
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
RESET = "\033[0m"

# 12 Test cases representing Benign (safe) domains, DGA anomalies, and DNS Tunneling exfiltration
TEST_DOMAINS = [
    # ── Benign / Legitimate Domains ──
    {"domain": "google.com", "expected": "Safe", "category": "Benign (Standard)"},
    {"domain": "wikipedia.org", "expected": "Safe", "category": "Benign (Standard)"},
    {"domain": "github.com", "expected": "Safe", "category": "Benign (Standard)"},
    {"domain": "microsoft.com", "expected": "Safe", "category": "Benign (Standard)"},

    # ── DGA (Domain Generation Algorithm) Anomalies ──
    {"domain": "qwertytrewq.xyz", "expected": "Malicious", "category": "DGA Anomaly (High Risk TLD)"},
    {"domain": "xzcvbnmsdfghjkl.pw", "expected": "Malicious", "category": "DGA Anomaly (Keyboard Smash)"},
    {"domain": "1a2b3c4d5e6f7g.click", "expected": "Malicious", "category": "DGA Anomaly (Digit Abuse)"},
    {"domain": "vznmwpqrszxc.xyz", "expected": "Malicious", "category": "DGA Anomaly (Consonants)"},

    # ── DNS Tunneling / Exfiltration (Deterministic Rules) ──
    {"domain": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.tunnel.malicious.net", "expected": "Malicious", "category": "DNS Tunneling (Long Label)"},
    {"domain": "base64payloadherecopyingdata.subdomain.attackerdomain.com", "expected": "Malicious", "category": "DNS Tunneling (Long Label)"},
    {"domain": "exfiltrated-confidential-user-creds-data.attacker.info", "expected": "Malicious", "category": "DNS Tunneling (Long Label)"},
    {"domain": "iodine.exfiltrated.data.payload.malicious.org", "expected": "Malicious", "category": "DNS Tunneling (Multi-subdomain)"}
]

def run_simulation():
    print(f"\n{BOLD}{CYAN}===================================================================={RESET}")
    print(f"{BOLD}{CYAN}            Secure DNS Queries – Security Attack Simulator             {RESET}")
    print(f"{BOLD}{CYAN}===================================================================={RESET}")
    print(f"Target Server API: {SERVER_URL}\n")

    # Check if the server is alive
    try:
        diag_url = "http://127.0.0.1:5000/api/diag"
        resp = requests.get(diag_url, timeout=3)
        if resp.status_code == 200:
            diag_data = resp.json()
            print(f"{GREEN}[+] Connected to Secure DNS Queries server!{RESET}")
            print(f"    Server: {diag_data.get('server')}")
            print(f"    ML Model Loaded: {diag_data.get('model_loaded')}")
            print(f"    Authenticated Session: {diag_data.get('authenticated')}\n")
    except requests.exceptions.ConnectionError:
        print(f"{RED}[!] Error: Cannot connect to server at http://127.0.0.1:5000{RESET}")
        print(f"{YELLOW}[i] Please run 'python app.py' in a separate terminal before running this script.{RESET}\n")
        sys.exit(1)

    print(f"{BOLD}{WHITE}{'Domain Name':<50} | {'Category':<22} | {'Verdict':<9} | {'Latency':<8} | {'Status':<7}{RESET}")
    print("-" * 110)

    success_count = 0
    total_latency = 0.0
    processed_count = 0

    for item in TEST_DOMAINS:
        domain = item["domain"]
        expected = item["expected"]
        category = item["category"]

        start_time = time.perf_counter()
        try:
            res = requests.post(SERVER_URL, json={"domain": domain}, timeout=5)
            latency = (time.perf_counter() - start_time) * 1000
            total_latency += latency
            processed_count += 1

            if res.status_code == 200:
                data = res.json()
                verdict = data.get("prediction", "Unknown")
                blocked = data.get("blocked", False)
                attack_type = data.get("attack_type") or "N/A"
                confidence = data.get("confidence", 0.0) * 100

                # Check if matches expectations
                is_correct = (verdict == expected)
                if is_correct:
                    success_count += 1
                    status_str = f"{GREEN}PASS{RESET}"
                else:
                    status_str = f"{RED}FAIL{RESET}"

                # Formatting output columns
                verdict_color = GREEN if verdict == "Safe" else RED
                verdict_fmt = f"{verdict_color}{verdict:<9}{RESET}"
                latency_fmt = f"{latency:.2f}ms"

                print(f"{domain:<50} | {category:<22} | {verdict_fmt} | {latency_fmt:<8} | {status_str:<7}")
                if verdict == "Malicious":
                    print(f"    {YELLOW}--> Blocked! Reason: {attack_type} (Confidence: {confidence:.1f}%){RESET}")

            else:
                print(f"{domain:<50} | {category:<22} | {RED}API Error{RESET} | --       | {RED}FAIL{RESET}")
        except Exception as e:
            print(f"{domain:<50} | {category:<22} | {RED}Error: {str(e)}{RESET}   | --       | {RED}FAIL{RESET}")

    # Calculate statistics
    avg_latency = total_latency / processed_count if processed_count > 0 else 0
    accuracy = (success_count / processed_count) * 100 if processed_count > 0 else 0

    print(f"\n{BOLD}{CYAN}===================================================================={RESET}")
    print(f"{BOLD}{CYAN}                      SIMULATION RESULTS SUMMARY                    {RESET}")
    print(f"{BOLD}{CYAN}===================================================================={RESET}")
    print(f"  * Total Queries Sent  : {processed_count}")
    print(f"  * Successful Blocks   : {success_count} / {processed_count}")
    
    acc_color = GREEN if accuracy >= 90 else (YELLOW if accuracy >= 70 else RED)
    print(f"  * Detection Accuracy  : {acc_color}{accuracy:.1f}%{RESET}")
    print(f"  * Average Latency     : {GREEN if avg_latency < 20 else YELLOW}{avg_latency:.2f} ms{RESET}")
    print(f"{BOLD}{CYAN}===================================================================={RESET}")

    if accuracy >= 90.0:
        print(f"\n{GREEN}{BOLD}[SUCCESS] Secure DNS Queries successfully identified and blocked simulated threats!{RESET}")
        print(f"    - Benign domains were allowed instantly to guarantee seamless browsing.")
        print(f"    - DGA anomalies were stopped by the machine learning Isolation Forest.")
        print(f"    - DNS Tunneling data leaks were instantly blocked by deterministic heuristics.")
    else:
        print(f"\n{YELLOW}[i] Warning: Some cases did not match. Please verify model thresholds.{RESET}")

if __name__ == "__main__":
    run_simulation()
