# ===============================
# predictLinks.py – Test 10 random URLs
# ===============================

import pandas as pd
import joblib
import re, math
from urllib.parse import urlparse
from datetime import datetime
import shelve, whois
import random

# -------------------------------
# 1️⃣ Load models & feature columns
# -------------------------------
stacking_model = joblib.load(r"D:\QRusaderTrainedModel\models\stacking_model.pkl")
le = joblib.load(r"D:\QRusaderTrainedModel\models\label_encoder.pkl")
feature_columns = joblib.load(r"D:\QRusaderTrainedModel\models\feature_columns.pkl")

# -------------------------------
# 2️⃣ Load dataset (must include 'url' and 'label')
# -------------------------------
features_df = pd.read_csv(r"D:\QRusaderTrainedModel\src\url_features_enhanced.csv")  # replace with your actual dataset path

# -------------------------------
# 3️⃣ WHOIS caching
# -------------------------------
CACHE_FILE = r"D:\QRusaderTrainedModel\zQRScanner\whois_cache.db"

def get_whois_safe(domain):
    with shelve.open(CACHE_FILE) as cache:
        if domain in cache:
            return cache[domain].get("has_whois", 0), cache[domain].get("domain_age_days", None)
        try:
            w = whois.whois(domain)
            if not hasattr(w, "creation_date") or not w.creation_date:
                has_dns, age_days = 0, None
            else:
                has_dns = 1
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                age_days = (datetime.now() - creation_date).days
        except Exception:
            has_dns, age_days = 0, None
        cache[domain] = {"has_whois": has_dns, "domain_age_days": age_days}
        return has_dns, age_days

# -------------------------------
# 4️⃣ Helper functions
# -------------------------------
def has_ip(url): return 1 if re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", url) else 0
def is_shortened(url):
    shortening_services = ["bit.ly","tinyurl","goo.gl","t.co","ow.ly","shorte.st","cutt.ly"]
    return 1 if any(s in url for s in shortening_services) else 0
def shannon_entropy(data):
    if not data: return 0
    prob = [float(data.count(c))/len(data) for c in set(data)]
    return -sum(p*math.log2(p) for p in prob)
suspicious_keywords = ["secure","account","login","update","free","bonus",
                       "ebayisapi","banking","confirm","signin","verification"]
def contains_suspicious_word(url): return sum(word in url.lower() for word in suspicious_keywords)
suspicious_ext = [".exe",".bat",".com",".msi",".cmd",".scr",".zip",".rar",".7z",".tar",".gz",
                  ".js",".vbs",".jar",".ps1",".wsf",".doc",".docm",".xls",".xlsm",".ppt",".pptm",".apk"]
def has_suspicious_ext(url): return 1 if any(url.lower().endswith(ext) for ext in suspicious_ext) else 0

# -------------------------------
# 5️⃣ Feature extraction
# -------------------------------
def extract_features(url):
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    domain = parsed.netloc or parsed.path
    path, query = parsed.path, parsed.query

    has_dns, domain_age_days = get_whois_safe(domain)
    domain_age_bin = 0
    if domain_age_days is not None:
        if domain_age_days < 30: domain_age_bin = 1
        elif domain_age_days < 365: domain_age_bin = 2
        else: domain_age_bin = 3

    total_special_char = sum(url.count(c) for c in ['@','?','-','=','.','!','#','$','&','~','*','%','+','^','_'])
    special_char_ratio = total_special_char / max(1, len(url))
    subdomain_count = max(domain.count(".") - 1, 0)
    path_depth = path.count('/')
    query_param_amp_count = query.count('&') + (1 if query else 0)
    tld = domain.split('.')[-1]
    tld_length = len(tld)
    numeric_tld = 1 if any(c.isdigit() for c in tld) else 0
    subdomain_ratio = subdomain_count / max(1, len(domain))
    digit_letter_ratio = sum(c.isdigit() for c in url) / max(1, sum(c.isalpha() for c in url))
    url_upper_ratio = sum(1 for c in url if c.isupper()) / max(1, len(url))
    url_encoded_ratio = url.count('%') / max(1, len(url))
    repeated_char_count = sum(url.count(c*2) for c in set(url))
    path_token_count = len([t for t in path.split('/') if t])
    query_token_count = len([q for q in query.split('&') if q])
    suspicious_word_count = contains_suspicious_word(url)

    return {
        "url": url,
        "domain": domain,
        "url_length": len(url),
        "Shortining_Service": is_shortened(url),
        "having_ip_address": has_ip(url),
        "subdomain_count": subdomain_count,
        "subdomain_ratio": subdomain_ratio,
        "path_depth": path_depth,
        "path_length": len(path),
        "query_length": len(query),
        "param_count": query.count("="),
        "query_param_amp_count": query_param_amp_count,
        "digit_letter_ratio": digit_letter_ratio,
        "entropy": shannon_entropy(url),
        "total_special_char": total_special_char,
        "special_char_ratio": special_char_ratio,
        "risky_tld": 1 if tld in ["zip","xyz","top","club","info"] else 0,
        "tld_length": tld_length,
        "numeric_tld": numeric_tld,
        "has_suspicious_ext": has_suspicious_ext(url),
        "suspicious_word_count": suspicious_word_count,
        "url_upper_ratio": url_upper_ratio,
        "url_encoded_ratio": url_encoded_ratio,
        "repeated_char_count": repeated_char_count,
        "path_token_count": path_token_count,
        "query_token_count": query_token_count,
        "has_whois": has_dns,
        "domain_age_days": domain_age_days,
        "domain_age_bin": domain_age_bin
    }

# -------------------------------
# 6️⃣ Predict 50 random URLs
# -------------------------------
sample_df = features_df.sample(n=10, random_state=42)

print("\n🔎 Predicting 10 random URLs:\n")

for idx, row in sample_df.iterrows():
    url = row["url"]
    true_label = row["label"]

    feats = extract_features(url)
    feats_df = pd.DataFrame([feats])[feature_columns].fillna(0).infer_objects()

    pred_encoded = stacking_model.predict(feats_df)[0]
    pred_label = le.inverse_transform([pred_encoded])[0]

    prob_malicious = stacking_model.predict_proba(feats_df)[0][le.transform(['malicious'])[0]]

    print(f"URL: {url}")
    print(f"   True Label: {true_label} | Predicted Label: {pred_label} | Malicious Probability: {prob_malicious*100:.2f}%\n")
