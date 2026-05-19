import os
import re
import json
import math
import time
import logging
import hashlib
import threading
import sqlite3
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import StratifiedShuffleSplit, GroupShuffleSplit, KFold
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

_DIR = os.path.dirname(os.path.abspath(__file__))

# Two separate models — one per classification task
LEXICAL_MODEL_PATH   = os.path.join(_DIR, "models", "lexical_classifier.pkl")
FLOW_MODEL_PATH      = os.path.join(_DIR, "models", "flow_classifier.pkl")
LEXICAL_METRICS_PATH = os.path.join(_DIR, "dns_lexical_metrics.json")
FLOW_METRICS_PATH    = os.path.join(_DIR, "dns_flow_metrics.json")
_LEGACY_MODEL_PATH   = os.path.join(_DIR, "models", "unified_classifier.pkl")

METRICS_PATH = LEXICAL_METRICS_PATH   # backward-compat alias for get_metrics()

DNS_DB_PATH  = os.environ.get("DB_PATH", os.path.join(_DIR, "dns_logs.db"))
_TRANCO_PATH = os.path.join(_DIR, "dns_data", "tranco_GV93K.csv")
_DATA_DIR    = os.path.join(_DIR, "dns_data")

_FEEDBACK_RETRAIN_THRESHOLD = 50
_AUTO_RETRAIN_INTERVAL      = 3600
_CACHE_MAX                  = 10_000
_CACHE_TTL                  = 300
_BLACKLIST_TTL              = 300

# Contamination: the expected fraction of anomalies in the Tranco training corpus.
# "auto" was tested but produced FPR ~16.7% (too aggressive).
# 0.02 (2%) is conservative and keeps FPR around 1.7%.
_CONTAMINATION = 0.02

# ---------------------------------------------------------------------------
# Feature definitions
# ---------------------------------------------------------------------------

# 10 lexical features — used by classify().
# has_long_label is intentionally absent: tunneling is detected by deterministic
# rules before the model is consulted, so encoding it as a feature is redundant.
LEXICAL_FEATURES = [
    "domain_length", "subdomain_count", "max_label_len",
    "entropy", "subdomain_entropy",
    "digit_ratio", "vowel_ratio",
    "char_diversity", "max_consecutive_consonants", "tld_risk",
]

# 29 flow features — used by classify_flow()
FLOW_FEATURES = [
    "Duration", "FlowBytesSent", "FlowSentRate", "FlowBytesReceived", "FlowReceivedRate",
    "PacketLengthVariance", "PacketLengthStandardDeviation", "PacketLengthMean",
    "PacketLengthMedian", "PacketLengthMode", "PacketLengthSkewFromMedian",
    "PacketLengthSkewFromMode", "PacketLengthCoefficientofVariation",
    "PacketTimeVariance", "PacketTimeStandardDeviation", "PacketTimeMean",
    "PacketTimeMedian", "PacketTimeMode", "PacketTimeSkewFromMedian",
    "PacketTimeSkewFromMode", "PacketTimeCoefficientofVariation",
    "ResponseTimeTimeVariance", "ResponseTimeTimeStandardDeviation",
    "ResponseTimeTimeMean", "ResponseTimeTimeMedian", "ResponseTimeTimeMode",
    "ResponseTimeTimeSkewFromMedian", "ResponseTimeTimeSkewFromMode",
    "ResponseTimeTimeCoefficientofVariation",
]

N_LEXICAL = len(LEXICAL_FEATURES)   # 10
N_FLOW    = len(FLOW_FEATURES)      # 29

# TLD risk tiers — based on DGA/malware domain abuse statistics across major threat intel feeds
_HIGH_RISK_TLDS   = frozenset({
    'xyz', 'top', 'click', 'biz', 'info', 'pw', 'cc',
    'tk', 'ml', 'ga', 'cf', 'gq', 'loan', 'win',
})
_MEDIUM_RISK_TLDS = frozenset({
    'online', 'site', 'tech', 'club', 'stream',
    'download', 'racing', 'space',
})
_CONSONANTS = frozenset('bcdfghjklmnpqrstvwxyz')

# ---------------------------------------------------------------------------
# Runtime state
# ---------------------------------------------------------------------------
TRAINING_STATUS = {
    "is_training":    False,
    "progress":       0,
    "stage":          "",
    "last_trained":   None,
    "data_source":    "lexical (Tranco benign) + flow (CIRA-CIC-DoHBrw-2020 L2)",
    "train_samples":  0,
    "accuracy":       0.0,
    "error":          None,
}

_cache      = {}
_cache_lock = threading.Lock()
_threshold  = 0.85

lexical_model = None   # IsolationForest trained on real benign domains only
flow_model    = None   # RandomForestClassifier trained on L2: Benign vs Malicious DoH

_blacklist_cache: set       = set()
_blacklist_lock             = threading.Lock()
_blacklist_last_load: float = 0.0

_last_retrain_count: int = 0

_VALID_DOMAIN_RE = re.compile(
    r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$'
)


def set_threshold(value: float):
    global _threshold
    _threshold = value / 100.0


def get_metrics():
    try:
        with open(METRICS_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


# ---------------------------------------------------------------------------
# Model integrity — SHA-256 verification guards against pickle RCE
# ---------------------------------------------------------------------------

def _hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_model(path):
    hash_path = path + ".sha256"
    if not os.path.exists(hash_path):
        return True
    try:
        with open(hash_path) as f:
            expected = f.read().strip()
        return _hash_file(path) == expected
    except (OSError, ValueError):
        return False


def _save_model_hash(path):
    with open(path + ".sha256", "w") as f:
        f.write(_hash_file(path))


def _atomic_save(model, path):
    """Write to a temp file, keep the previous model as .bak, then atomically swap in the new one."""
    tmp = path + ".tmp"
    joblib.dump(model, tmp)
    if os.path.exists(path):
        os.replace(path, path + ".bak")
    os.replace(tmp, path)
    _save_model_hash(path)


# ---------------------------------------------------------------------------
# Domain normalization
# ---------------------------------------------------------------------------

def _normalize_domain(domain):
    if not isinstance(domain, str):
        return ""
    return domain.lower().rstrip(".")


# ---------------------------------------------------------------------------
# Lexical feature extraction  (returns 10 values)
# ---------------------------------------------------------------------------

def _entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _max_consecutive_consonants(s):
    """Longest run of consonants — high values strongly indicate random DGA."""
    max_run = cur = 0
    for c in s:
        if c in _CONSONANTS:
            cur += 1
            if cur > max_run:
                max_run = cur
        else:
            cur = 0
    return max_run


def _extract_lexical(domain):
    domain = _normalize_domain(domain)
    if not domain:
        return [0.0] * N_LEXICAL
    parts  = domain.split(".")
    tld    = parts[-1] if parts else ""
    body   = domain.replace(".", "")   # all chars excluding dots
    blen   = len(body) or 1
    dlen   = len(domain)

    subdomain_count = max(len(parts) - 2, 0)
    max_label       = max((len(p) for p in parts), default=0)

    # Entropy on body only — dots are non-informative and bias the measurement
    ent      = _entropy(body)
    # Subdomain entropy: entropy of the concatenated subdomain content
    sub_body = "".join(parts[:-2]) if len(parts) > 2 else ""
    sub_ent  = _entropy(sub_body) if sub_body else 0.0

    num            = sum(c.isdigit() for c in body)
    vowels         = sum(c in "aeiou" for c in body)
    char_diversity = len(set(body)) / blen
    max_cc         = float(_max_consecutive_consonants(body))
    tld_risk       = (1.0 if tld in _HIGH_RISK_TLDS
                      else 0.5 if tld in _MEDIUM_RISK_TLDS
                      else 0.0)

    return [
        float(dlen),
        float(subdomain_count),
        float(max_label),
        ent,
        sub_ent,
        num / blen,
        vowels / blen,
        char_diversity,
        max_cc,
        tld_risk,
    ]


def extract_features(domain):
    """Return 10 lexical features for a domain — used by classify()."""
    return _extract_lexical(domain)


# ---------------------------------------------------------------------------
# Tunneling detection — deterministic rules, no model required.
# These thresholds are near-certain: no legitimate FQDN triggers them.
# Rules fire BEFORE the IsolationForest so the model never sees tunnel traffic.
# ---------------------------------------------------------------------------

def _is_tunneling(features):
    domain_len      = features[0]
    subdomain_count = features[1]
    max_label       = features[2]
    ent             = features[3]

    # A single DNS label longer than 24 characters has no legitimate use
    if max_label >= 25:
        return True
    # ≥4 subdomains AND high entropy — classic multi-label exfiltration (iodine-style)
    if subdomain_count >= 4 and ent >= 3.8:
        return True
    # Very long domain with ≥2 subdomains — large payload split across labels
    if domain_len >= 80 and subdomain_count >= 2:
        return True
    return False


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

def _feature_count(model):
    """Return the model's expected input feature count, or None if unknown."""
    for attr in ("n_features_in_", "n_features_"):
        if hasattr(model, attr):
            try:
                return int(getattr(model, attr))
            except Exception:
                pass
    return None


def load():
    global lexical_model, flow_model

    # ── Lexical model ──────────────────────────────────────────────────
    for path in [LEXICAL_MODEL_PATH, _LEGACY_MODEL_PATH]:
        if not os.path.exists(path):
            continue
        if not _verify_model(path):
            logger.error("Hash mismatch — refusing to load %s (possible tampering)", path)
            continue
        try:
            candidate = joblib.load(path)
            # Safety: reject models trained with a different feature set
            n = _feature_count(candidate)
            if n is not None and n != N_LEXICAL:
                logger.warning(
                    "Refusing %s — expects %d features, current extractor produces %d. Retraining required.",
                    os.path.basename(path), n, N_LEXICAL,
                )
                continue
            lexical_model = candidate
            model_type = type(lexical_model).__name__
            try:
                with open(LEXICAL_METRICS_PATH) as f:
                    m = json.load(f)
                TRAINING_STATUS["accuracy"]      = m.get("accuracy", 0.0)
                TRAINING_STATUS["last_trained"]  = m.get("last_trained")
                TRAINING_STATUS["train_samples"] = m.get("train_samples", 0)
            except (OSError, ValueError):
                pass
            logger.info("lexical model loaded from %s (type=%s)", os.path.basename(path), model_type)
            break
        except Exception:
            logger.exception("lexical model load error (%s)", path)

    # ── Flow model ─────────────────────────────────────────────────────
    if os.path.exists(FLOW_MODEL_PATH):
        if not _verify_model(FLOW_MODEL_PATH):
            logger.error("Hash mismatch — refusing to load flow model (possible tampering)")
        else:
            try:
                flow_model = joblib.load(FLOW_MODEL_PATH)
                classes = list(flow_model.classes_) if hasattr(flow_model, "classes_") else []
                logger.info("flow model loaded (classes=%s)", classes)
            except Exception:
                logger.exception("flow model load error (%s)", FLOW_MODEL_PATH)

    return lexical_model is not None


# ---------------------------------------------------------------------------
# Training helpers
# ---------------------------------------------------------------------------

def _load_benign_domains(n=100_000):
    domains = []
    try:
        with open(_TRANCO_PATH, encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) >= 2:
                    d = parts[1].strip().lower()
                    if d:
                        domains.append(d)
                        if len(domains) >= n:
                            break
    except Exception:
        logger.warning("Failed to load benign domains from %s", _TRANCO_PATH)
    return domains


# Columns used to build session group keys — all flows between the same
# IP pair belong to one session and must stay in the same split.
_GROUP_COLS = ["SourceIP", "DestinationIP"]


def _load_flow_csv(path, label, max_rows=None):
    """Load a flow CSV → (X, y, groups) where X has N_FLOW columns.

    *groups* is a string array of IP-pair keys used by GroupShuffleSplit
    to prevent data leakage between train and test sets.
    """
    try:
        use_cols = FLOW_FEATURES + _GROUP_COLS
        chunks = []
        reader = pd.read_csv(
            path, usecols=use_cols,
            on_bad_lines="skip", chunksize=50_000,
        )
        loaded = 0
        for chunk in reader:
            chunk = chunk.dropna(subset=FLOW_FEATURES)
            if max_rows and loaded + len(chunk) > max_rows:
                chunk = chunk.iloc[: max_rows - loaded]
            chunks.append(chunk[use_cols])
            loaded += len(chunk)
            if max_rows and loaded >= max_rows:
                break
        if not chunks:
            return None, None, None
        df     = pd.concat(chunks, ignore_index=True)
        X      = df[FLOW_FEATURES].values.astype(np.float32)
        y      = np.array([label] * len(X))
        groups = (df["SourceIP"].astype(str) + "→" + df["DestinationIP"].astype(str)).values
        return X, y, groups
    except Exception:
        logger.exception("flow CSV error %s", path)
        return None, None, None


def _load_safe_feedback_domains():
    """Return domain names from feedback labeled safe/benign — expands the IsolationForest benign set."""
    domains = []
    seen = set()
    try:
        conn = sqlite3.connect(DNS_DB_PATH)
        try:
            rows = conn.execute(
                "SELECT domain FROM feedback WHERE correct_label IN ('safe', 'benign')"
            ).fetchall()
        finally:
            conn.close()
        for (domain,) in rows:
            domain = _normalize_domain(domain or "")
            if domain and _VALID_DOMAIN_RE.match(domain) and domain not in seen:
                seen.add(domain)
                domains.append(domain)
    except Exception:
        pass
    return domains


# ---------------------------------------------------------------------------
# Training — two separate models trained sequentially
# ---------------------------------------------------------------------------

def train_async():
    global lexical_model, flow_model
    TRAINING_STATUS.update({
        "is_training": True, "progress": 3,
        "stage": "Starting training", "error": None,
    })
    try:
        # ══════════════════════════════════════════════════════════════
        # PART A — LEXICAL CLASSIFIER  (IsolationForest, real data only)
        #
        # Strategy: unsupervised anomaly detection trained exclusively on
        # known-benign Tranco domains + safe user feedback.  No synthetic
        # DGA or tunneling data is ever generated.
        # Tunneling is handled upstream by deterministic rules.
        # ══════════════════════════════════════════════════════════════

        TRAINING_STATUS.update({"stage": "Loading benign domains (Tranco)", "progress": 5})
        benign_raw = _load_benign_domains(100_000)
        if not benign_raw:
            raise RuntimeError(f"Tranco list not found: {_TRANCO_PATH}")

        TRAINING_STATUS.update({"stage": "Loading safe feedback domains", "progress": 10})
        fb_safe = _load_safe_feedback_domains()
        if fb_safe:
            benign_raw.extend(fb_safe)
            logger.info("Added %d safe feedback domains to benign training set", len(fb_safe))

        TRAINING_STATUS.update({"stage": "Extracting lexical features", "progress": 14})
        X_lex = np.array([_extract_lexical(d) for d in benign_raw], dtype=np.float32)

        # ── 5-fold cross-validation to measure FPR reliably ──────────
        TRAINING_STATUS.update({"stage": "Cross-validating IsolationForest (5 folds)…", "progress": 18})
        kf = KFold(n_splits=5, shuffle=True, random_state=42)
        fold_fprs = []
        fold_means = []
        for fold_i, (tr_idx, te_idx) in enumerate(kf.split(X_lex), 1):
            fold_clf = Pipeline([
                ("scaler", StandardScaler()),
                ("iforest", IsolationForest(
                    n_estimators=200,
                    contamination=_CONTAMINATION,
                    random_state=42,
                    n_jobs=-1,
                )),
            ])
            fold_clf.fit(X_lex[tr_idx])
            scores = fold_clf.decision_function(X_lex[te_idx])
            fold_fprs.append(float((scores < 0).mean()))
            fold_means.append(float(scores.mean()))
            logger.info("  Fold %d/%d — FPR=%.2f%%", fold_i, 5, fold_fprs[-1] * 100)

        cv_fpr  = float(np.mean(fold_fprs))
        cv_mean = float(np.mean(fold_means))
        logger.info(
            "Lexical IsolationForest CV — mean FPR: %.2f%%  mean score: %.3f",
            cv_fpr * 100, cv_mean,
        )

        # ── Train final model on ALL data ─────────────────────────────
        TRAINING_STATUS.update({"stage": "Training final IsolationForest…", "progress": 30})
        clf_lex = Pipeline([
            ("scaler", StandardScaler()),
            ("iforest", IsolationForest(
                n_estimators=200,
                contamination=_CONTAMINATION,
                random_state=42,
                n_jobs=-1,
            )),
        ])
        clf_lex.fit(X_lex)

        fpr_benign = cv_fpr
        mean_score = cv_mean

        now = datetime.now(timezone.utc).isoformat()
        os.makedirs(os.path.dirname(LEXICAL_MODEL_PATH), exist_ok=True)
        _atomic_save(clf_lex, LEXICAL_MODEL_PATH)
        lexical_model = clf_lex
        with _cache_lock:
            _cache.clear()

        lex_metrics = {
            "model_type":                 "IsolationForest + StandardScaler",
            "evaluation":                 "5-fold cross-validation",
            "false_positive_rate_benign": round(fpr_benign, 4),
            "mean_score_benign":          round(mean_score, 4),
            "fold_fprs":                  [round(f, 4) for f in fold_fprs],
            # accuracy = how often benign domains correctly pass through
            "accuracy":                   round(1.0 - fpr_benign, 4),
            "contamination":              str(_CONTAMINATION),
            "n_estimators":               200,
            "train_samples":              len(X_lex),
            "feedback_safe_domains":      len(fb_safe),
            "last_trained":               now,
            "n_features":                 N_LEXICAL,
            "feature_names":              LEXICAL_FEATURES,
        }
        with open(LEXICAL_METRICS_PATH, "w") as f:
            json.dump(lex_metrics, f, indent=2)

        TRAINING_STATUS.update({
            "accuracy":      1.0 - fpr_benign,
            "train_samples": len(X_lex),
            "last_trained":  now,
        })

        # ══════════════════════════════════════════════════════════════
        # PART B — FLOW CLASSIFIER  (RandomForest, CIRA-CIC-DoHBrw-2020 L2)
        #
        # Uses ONLY l2-benign + l2-malicious — the correct L2 task split.
        # l1-nondoh is EXCLUDED: it is standard HTTPS traffic (not DoH),
        # and its dramatically different byte/timing statistics would corrupt
        # the Benign class, making the task artificially easy and masking the
        # true Benign-DoH vs Malicious-DoH decision boundary.
        # ══════════════════════════════════════════════════════════════

        flow_sources = [
            (os.path.join(_DATA_DIR, "l2-benign.csv"),    "Benign",    None),
            (os.path.join(_DATA_DIR, "l2-malicious.csv"), "Malicious", None),
        ]

        flow_Xs, flow_ys, flow_groups = [], [], []
        for i, (path, label, cap) in enumerate(flow_sources):
            TRAINING_STATUS.update({
                "stage":    f"Loading flow data: {os.path.basename(path)}",
                "progress": 50 + i * 10,
            })
            if not os.path.exists(path):
                logger.warning("Missing flow file: %s — skipping", path)
                continue
            X_f, y_f, g_f = _load_flow_csv(path, label, max_rows=cap)
            if X_f is not None:
                flow_Xs.append(X_f)
                flow_ys.append(y_f)
                flow_groups.append(g_f)
                logger.info("Flow %s (%s): %d rows", label, os.path.basename(path), len(X_f))

        if flow_Xs:
            TRAINING_STATUS.update({"stage": "Preparing flow data…", "progress": 68})
            X_flow = np.vstack(flow_Xs)
            y_flow = np.concatenate(flow_ys)
            g_flow = np.concatenate(flow_groups)

            benign_count    = int((y_flow == "Benign").sum())
            malicious_count = int((y_flow == "Malicious").sum())
            n_groups        = len(np.unique(g_flow))
            logger.info(
                "Flow dataset — Benign:%d  Malicious:%d  imbalance 1:%.1f  IP-pair groups:%d",
                benign_count, malicious_count, malicious_count / max(benign_count, 1), n_groups,
            )

            # ── Session-aware split: all flows from the same IP pair stay
            #    in the same partition → prevents data leakage ──────────
            gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
            tr2, te2 = next(gss.split(X_flow, y_flow, groups=g_flow))
            X_ftr, X_fte = X_flow[tr2], X_flow[te2]
            y_ftr, y_fte = y_flow[tr2], y_flow[te2]

            # ── SMOTE: oversample the minority class (Benign) to balance
            #    the training set instead of relying only on class_weight ─
            TRAINING_STATUS.update({"stage": "Balancing flow data (SMOTE)…", "progress": 72})
            try:
                from imblearn.over_sampling import SMOTE
                smote = SMOTE(random_state=42)
                X_ftr, y_ftr = smote.fit_resample(X_ftr, y_ftr)
                logger.info("SMOTE applied — resampled train: Benign:%d  Malicious:%d",
                            int((y_ftr == "Benign").sum()), int((y_ftr == "Malicious").sum()))
            except ImportError:
                logger.warning("imbalanced-learn not installed — falling back to class_weight only")

            TRAINING_STATUS.update({"stage": "Training flow classifier…", "progress": 78})
            clf_flow = RandomForestClassifier(
                n_estimators=150, n_jobs=-1,
                random_state=42, oob_score=True,
                class_weight="balanced",
            )
            clf_flow.fit(X_ftr, y_ftr)

            TRAINING_STATUS.update({"stage": "Evaluating flow classifier…", "progress": 90})
            y_pred_flow = clf_flow.predict(X_fte)
            acc_flow    = clf_flow.score(X_fte, y_fte)
            oob_flow    = round(float(clf_flow.oob_score_), 4)
            cm_flow     = confusion_matrix(y_fte, y_pred_flow, labels=clf_flow.classes_).tolist()

            _atomic_save(clf_flow, FLOW_MODEL_PATH)
            flow_model = clf_flow

            flow_metrics = {
                "accuracy":            acc_flow,
                "oob_score":           oob_flow,
                "precision":           precision_score(y_fte, y_pred_flow, average="weighted", zero_division=0),
                "recall":              recall_score(y_fte, y_pred_flow, average="weighted", zero_division=0),
                "f1":                  f1_score(y_fte, y_pred_flow, average="weighted", zero_division=0),
                "train_samples":       len(X_ftr),
                "test_samples":        len(X_fte),
                "benign_train":        benign_count,
                "malicious_train":     malicious_count,
                "last_trained":        now,
                "classes":             list(clf_flow.classes_),
                "confusion_matrix":    cm_flow,
                "feature_importances": dict(zip(
                    FLOW_FEATURES,
                    [round(float(v), 6) for v in clf_flow.feature_importances_],
                )),
                "n_features":          N_FLOW,
            }
            with open(FLOW_METRICS_PATH, "w") as f:
                json.dump(flow_metrics, f, indent=2)

            logger.info("Flow model — accuracy=%.2f%%  oob=%.2f%%  classes=%s",
                        acc_flow * 100, oob_flow * 100, list(clf_flow.classes_))
        else:
            logger.warning("No flow CSV files found — flow classifier not trained")

        TRAINING_STATUS.update({"progress": 100, "stage": "Completed"})

    except Exception as e:
        TRAINING_STATUS["error"] = str(e)
        logger.exception("Training failed")
    finally:
        TRAINING_STATUS["is_training"] = False


def train():
    if TRAINING_STATUS["is_training"]:
        return False
    threading.Thread(target=train_async, daemon=True).start()
    return True


# ---------------------------------------------------------------------------
# Blacklist — in-memory cache, case-normalised, wildcard-aware
# ---------------------------------------------------------------------------

def _reload_blacklist():
    global _blacklist_cache, _blacklist_last_load
    try:
        conn = sqlite3.connect(DNS_DB_PATH)
        try:
            rows = conn.execute("SELECT domain FROM blacklist").fetchall()
        finally:
            conn.close()
        with _blacklist_lock:
            _blacklist_cache = {r[0].lower().rstrip(".") for r in rows if r[0]}
            _blacklist_last_load = time.time()
    except Exception:
        with _blacklist_lock:
            _blacklist_last_load = time.time()


def _blacklisted(domain):
    if time.time() - _blacklist_last_load > _BLACKLIST_TTL:
        _reload_blacklist()
    parts = domain.split(".")
    with _blacklist_lock:
        if domain in _blacklist_cache:
            return True
        for i in range(1, len(parts) - 1):
            if f"*.{'.'.join(parts[i:])}" in _blacklist_cache:
                return True
        return False


# ---------------------------------------------------------------------------
# Classification cache — bounded, TTL-based, thread-safe
# ---------------------------------------------------------------------------

def _cache_get(domain):
    with _cache_lock:
        entry = _cache.get(domain)
        if entry is None:
            return None
        res, ts = entry
        if time.time() - ts < _CACHE_TTL:
            return res
        del _cache[domain]
        return None


def _cache_set(domain, res):
    with _cache_lock:
        if len(_cache) >= _CACHE_MAX:
            cutoff  = time.time() - _CACHE_TTL
            expired = [k for k, (_, ts) in _cache.items() if ts < cutoff]
            for k in expired:
                del _cache[k]
            if len(_cache) >= _CACHE_MAX:
                for k in list(_cache.keys())[:_CACHE_MAX // 2]:
                    del _cache[k]
        _cache[domain] = (res, time.time())


# ---------------------------------------------------------------------------
# Result builders
# ---------------------------------------------------------------------------

def _make_result(blocked, attack_type, confidence, features):
    return {
        "blocked":     blocked,
        "action":      "Blocked" if blocked else "Allowed",
        "prediction":  "Malicious" if blocked else "Safe",
        "attack_type": attack_type,
        "confidence":  float(confidence),
        "features":    features,
    }


def _make_flow_result(blocked, predicted, confidence):
    return {
        "blocked":    blocked,
        "action":     "Blocked" if blocked else "Allowed",
        "prediction": predicted,
        "confidence": float(confidence),
    }


# ---------------------------------------------------------------------------
# Domain classification — deterministic rules → IsolationForest
# ---------------------------------------------------------------------------

def classify(domain):
    if not domain:
        return _make_result(False, None, 1.0, [0.0] * N_LEXICAL)

    domain = _normalize_domain(domain)

    # Blacklist checked BEFORE cache — newly blocked domains take effect immediately
    if _blacklisted(domain):
        features = extract_features(domain)
        res = _make_result(True, "Manual Blacklist", 1.0, features)
        _cache_set(domain, res)
        return res

    cached = _cache_get(domain)
    if cached is not None:
        return cached

    features = extract_features(domain)

    # Tunneling rules fire before the model — these thresholds are near-certain
    if _is_tunneling(features):
        res = _make_result(True, "Tunneling", 1.0, features)
        _cache_set(domain, res)
        return res

    # DGA: IsolationForest anomaly detection (or legacy RandomForest)
    current_model = lexical_model
    if current_model is None:
        res = _make_result(False, None, 0.5, features)
        _cache_set(domain, res)
        return res

    # Branch on actual model type — RandomForest doesn't have decision_function,
    # IsolationForest doesn't have predict_proba. Pick the right path FIRST.
    if hasattr(current_model, "predict_proba"):
        # Legacy RandomForestClassifier path
        proba       = current_model.predict_proba([features])[0]
        classes     = list(current_model.classes_)
        idx         = int(proba.argmax())
        confidence  = float(proba[idx])
        predicted   = classes[idx]
        blocked     = predicted != "Benign" and confidence >= _threshold
        attack_type = predicted if blocked else None
    else:
        # IsolationForest anomaly score → sigmoid-mapped anomaly probability.
        # Multiplier 5 gives useful separation across the typical [-0.6, +0.6] range:
        #   score = +0.3 → anomaly_prob ≈ 0.18 (clearly benign)
        #   score =  0.0 → anomaly_prob = 0.50
        #   score = -0.4 → anomaly_prob ≈ 0.88 (blocked at default 0.85 threshold)
        score        = float(current_model.decision_function([features])[0])
        anomaly_prob = 1.0 / (1.0 + math.exp(score * 5))
        blocked      = anomaly_prob >= _threshold
        attack_type  = "DGA" if blocked else None
        confidence   = anomaly_prob if blocked else 1.0 - anomaly_prob

    res = _make_result(blocked, attack_type, confidence, features)
    _cache_set(domain, res)
    return res


# ---------------------------------------------------------------------------
# Flow classification — uses flow_model (29 features)
# Called when network-level DoH flow statistics are available
# ---------------------------------------------------------------------------

def classify_flow(flow_features):
    """Classify a DoH network flow as Benign or Malicious.

    Args:
        flow_features: dict {feature_name: value} or list/array of 29 values
                       in FLOW_FEATURES order.
    Returns:
        dict with blocked, action, prediction, confidence keys.
    """
    current_model = flow_model
    if current_model is None:
        return _make_flow_result(False, "Unknown", 0.0)

    if isinstance(flow_features, dict):
        vec = [float(flow_features.get(f, 0.0)) for f in FLOW_FEATURES]
    else:
        vec = [float(v) for v in flow_features]

    proba      = current_model.predict_proba([vec])[0]
    classes    = list(current_model.classes_)
    idx        = int(proba.argmax())
    confidence = proba[idx]
    predicted  = classes[idx]

    blocked = predicted != "Benign" and confidence >= _threshold
    return _make_flow_result(blocked, predicted, confidence)


# ---------------------------------------------------------------------------
# Auto-retrain loop — fires only when NEW feedback crosses the threshold
# ---------------------------------------------------------------------------

def start_auto_retrain():
    def loop():
        global _last_retrain_count
        while True:
            time.sleep(_AUTO_RETRAIN_INTERVAL)
            try:
                conn = sqlite3.connect(DNS_DB_PATH)
                try:
                    count = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
                finally:
                    conn.close()
                new_entries = count - _last_retrain_count
                if new_entries >= _FEEDBACK_RETRAIN_THRESHOLD and not TRAINING_STATUS["is_training"]:
                    _last_retrain_count = count
                    train()
            except Exception:
                logger.exception("Auto-retrain check failed")
    threading.Thread(target=loop, daemon=True).start()
