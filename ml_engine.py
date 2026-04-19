import os
import glob
import pandas as pd
import numpy as np
import re
from sklearn.ensemble import RandomForestClassifier
import joblib
import threading
import time
import json
import sqlite3

MODEL_PATH = "models/dns_classifier.pkl"
METRICS_PATH = "dns_model_metrics.json"
FEEDBACK_PATH = "data/new_queries.csv"
DATA_DIR = "data"
DNS_DB_PATH = os.environ.get("DB_PATH", "dns_logs.db")

TRAINING_STATUS = {
    "is_training": False,
    "progress": 0,
    "stage": "",
    "last_trained": None,
    "data_source": "",
    "train_samples": 0,
    "accuracy": 0.0,
    "error": None
}

_cache = {}
_threshold = 0.85

def set_threshold(value: int):
    global _threshold
    _threshold = value / 100.0

def calculate_entropy(s):
    p, lns = pd.Series(list(s)).value_counts(normalize=True, dropna=False), float(len(s))
    return -sum(p * np.log2(p))

def extract_features(domain):
    if not isinstance(domain, str):
        return [0]*10
    
    parts = domain.split('.')
    domain_length = len(domain)
    subdomain_count = len(parts) - 2 if len(parts) > 2 else 0
    max_label_length = max([len(p) for p in parts]) if parts else 0
    entropy = calculate_entropy(domain)
    subdomain_entropy = calculate_entropy(''.join(parts[:-2])) if len(parts) > 2 else 0
    
    alpha_chars = sum(c.isalpha() for c in domain)
    num_chars = sum(c.isdigit() for c in domain)
    vowels = sum(c in 'aeiouAEIOU' for c in domain)
    consonants = alpha_chars - vowels
    
    num_ratio = num_chars / domain_length if domain_length > 0 else 0
    vowel_ratio = vowels / domain_length if domain_length > 0 else 0
    consonant_ratio = consonants / domain_length if domain_length > 0 else 0
    
    non_alphanum = len(re.findall(r'[^a-zA-Z0-9\.]', domain))
    non_alphanum_ratio = non_alphanum / domain_length if domain_length > 0 else 0
    
    has_base64 = 1 if re.search(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', domain) else 0
    
    return [
        domain_length, subdomain_count, max_label_length, entropy,
        subdomain_entropy, num_ratio, vowel_ratio, consonant_ratio,
        non_alphanum_ratio, has_base64
    ]

model = None
classes = ["benign", "dga", "tunneling"]

def load():
    global model
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            if os.path.exists(METRICS_PATH):
                with open(METRICS_PATH, "r") as f:
                    metrics = json.load(f)
                    TRAINING_STATUS["accuracy"] = metrics.get("accuracy", 0.0)
                    TRAINING_STATUS["last_trained"] = metrics.get("last_trained")
                    TRAINING_STATUS["train_samples"] = metrics.get("train_samples", 0)
            return True
        except:
            return False
    return False

def get_data_for_training(max_samples=50000):
    X, y = [], []
    def process_folder(folder_name, label):
        path = os.path.join(DATA_DIR, folder_name)
        if not os.path.exists(path): return
        for file in glob.glob(f"{path}/*.csv"):
            try:
                df = pd.read_csv(file, nrows=max_samples, on_bad_lines='skip')
                domains = df.iloc[:, 0].dropna().astype(str).tolist()
                for d in domains:
                    X.append(extract_features(d))
                    y.append(label)
            except Exception as e:
                print(f"Error reading {file}: {e}")

    process_folder("Benign", "benign")
    process_folder("malicious", "dga")
    process_folder("tunneling", "tunneling")
    return X, y

def train_async():
    global model, TRAINING_STATUS
    TRAINING_STATUS["is_training"] = True
    TRAINING_STATUS["progress"] = 10
    TRAINING_STATUS["stage"] = "Loading data"
    TRAINING_STATUS["error"] = None
    
    try:
        X, y = get_data_for_training()
        
        if not X:
            TRAINING_STATUS["error"] = "No data found for training."
            TRAINING_STATUS["is_training"] = False
            return
            
        TRAINING_STATUS["progress"] = 40
        TRAINING_STATUS["stage"] = "Training model"
        TRAINING_STATUS["train_samples"] = len(X)
        
        new_model = RandomForestClassifier(n_estimators=50, max_depth=15, n_jobs=-1, random_state=42)
        new_model.fit(X, y)
        
        TRAINING_STATUS["progress"] = 80
        TRAINING_STATUS["stage"] = "Evaluating"
        
        accuracy = new_model.score(X, y)
        TRAINING_STATUS["accuracy"] = accuracy
        
        os.makedirs("models", exist_ok=True)
        joblib.dump(new_model, MODEL_PATH)
        model = new_model
        
        metrics = {
            "accuracy": accuracy,
            "train_samples": len(X),
            "last_trained": datetime.utcnow().isoformat()
        }
        with open(METRICS_PATH, "w") as f:
            json.dump(metrics, f)
            
        TRAINING_STATUS["last_trained"] = metrics["last_trained"]
        TRAINING_STATUS["progress"] = 100
        TRAINING_STATUS["stage"] = "Completed"
        
    except Exception as e:
        TRAINING_STATUS["error"] = str(e)
    finally:
        TRAINING_STATUS["is_training"] = False

def train():
    if TRAINING_STATUS["is_training"]: return False
    threading.Thread(target=train_async, daemon=True).start()
    return True

from datetime import datetime

def classify(domain):
    if not domain: return {"blocked": False, "prediction": "safe", "confidence": 1.0}
    
    if domain in _cache:
        cached_res, ts = _cache[domain]
        if (time.time() - ts) < 300:
            return cached_res
            
    try:
        conn = sqlite3.connect(DNS_DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT 1 FROM blacklist WHERE domain=?", (domain,))
        is_bl = c.fetchone()
        conn.close()
        if is_bl:
            res = {
                "blocked": True,
                "action": "Blocked",
                "prediction": "Malicious",
                "attack_type": "Manual Blacklist",
                "confidence": 1.0,
                "features": extract_features(domain)
            }
            _cache[domain] = (res, time.time())
            return res
    except:
        pass

    if not model:
        return {"blocked": False, "prediction": "safe", "action": "Allowed", "confidence": 1.0, "features": extract_features(domain)}
        
    features = extract_features(domain)
    proba = model.predict_proba([features])[0]
    
    # Random Forest classes_ ordering handling
    model_classes = list(model.classes_)
    max_class_idx = proba.argmax()
    max_confidence = proba[max_class_idx]
    predicted_class = model_classes[max_class_idx]
    
    blocked = False
    action = "Allowed"
    
    if predicted_class != "benign":
        if max_confidence >= _threshold:
            blocked = True
            action = "Blocked"
        else:
            predicted_class = "benign"
            blocked = False
            action = "Allowed"
            
    attack_type = predicted_class if blocked else None
    
    res = {
        "blocked": blocked,
        "action": action,
        "prediction": "Malicious" if blocked else "Safe",
        "attack_type": attack_type,
        "confidence": float(max_confidence),
        "features": features
    }
    
    _cache[domain] = (res, time.time())
    return res

def start_auto_retrain():
    def loop():
        while True:
            time.sleep(3600)
            try:
                conn = sqlite3.connect(DNS_DB_PATH)
                c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM dns_logs WHERE timestamp >= datetime('now', '-1 hour')")
                recent = c.fetchone()[0]
                conn.close()
                if recent > 500 and not TRAINING_STATUS["is_training"]:
                    train()
            except:
                pass
    threading.Thread(target=loop, daemon=True).start()
