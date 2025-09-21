# ===============================
# Real-Time QR Scanner + URL Risk Detection
# ===============================

import cv2
from pyzbar.pyzbar import decode
import pandas as pd
import joblib
from urllib.parse import urlparse, urlunparse
import math
import re

# -------------------------------
# 1️⃣ Load Random Forest model & metadata
# -------------------------------
model_dir = r"D:\QRusaderTrainedModel\zzznewTrainingModel\saved_models"
rf = joblib.load(f"{model_dir}/random_forest_model.pkl")
le = joblib.load(f"{model_dir}/label_encoder.pkl")
feature_columns = joblib.load(f"{model_dir}/feature_columns.pkl")

CACHE_FILE = "whois_cache.db"

# -------------------------------
# 2️⃣ Helper functions
# -------------------------------
def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    path = parsed.path or "/"
    return urlunparse((parsed.scheme.lower(), domain, path, parsed.params, parsed.query, parsed.fragment))

def shannon_entropy(data):
    if not data:
        return 0
    prob = [float(data.count(c))/len(data) for c in set(data)]
    return -sum(p*math.log2(p) for p in prob)

shortening_services = ["bit.ly","tinyurl","goo.gl","t.co","ow.ly","shorte.st","cutt.ly"]
suspicious_keywords = ["secure","account","login","update","free","bonus","ebayisapi",
                       "banking","confirm","signin","verification"]

def is_shortened(url): return int(any(s in url for s in shortening_services))
def has_ip(url): return int(bool(re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", url)))
def contains_suspicious_word(url): return sum(word in url.lower() for word in suspicious_keywords)

def get_whois_safe(domain):
    import shelve
    with shelve.open(CACHE_FILE) as cache:
        if domain in cache:
            return cache[domain]["has_whois"], cache[domain]["domain_age_days"]
        return 0, 0

# -------------------------------
# 3️⃣ Feature extraction for prediction
# -------------------------------
def extract_features_for_prediction(url):
    url_norm = normalize_url(url)
    parsed = urlparse(url_norm)
    domain = parsed.netloc
    path = parsed.path or "/"

    has_whois, domain_age_days = get_whois_safe(domain)
    total_special_char = sum(url_norm.count(c) for c in ['@','?','-','=','.','!','#','$','&','~','*','%','+','^','_'])
    path_tokens = [t for t in path.split('/') if t]

    return {
        "url_length": len(url_norm),
        "Shortining_Service": is_shortened(url_norm),
        "having_ip_address": has_ip(url_norm),
        "subdomain_count": max(domain.count(".")-1,0),
        "subdomain_ratio": max(domain.count(".")-1,0)/max(1,len(domain)),
        "path_depth": path.count('/'),
        "path_length": len(path),
        "param_count": parsed.query.count("="),
        "digit_letter_ratio": sum(c.isdigit() for c in url_norm)/max(1,sum(c.isalpha() for c in url_norm)),
        "domain_entropy": shannon_entropy(domain),
        "path_entropy": shannon_entropy(path),
        "total_special_char": total_special_char,
        "special_char_ratio": total_special_char/max(1,len(url_norm)),
        "risky_tld": int(domain.split('.')[-1] in ["zip","xyz","top","club","info"]),
        "tld_length": len(domain.split('.')[-1]),
        "suspicious_word_count": contains_suspicious_word(url_norm),
        "url_upper_ratio": sum(1 for c in url_norm if c.isupper())/max(1,len(url_norm)),
        "repeated_char_count": sum(url_norm.count(c*2) for c in set(url_norm)),
        "path_token_count": len(path_tokens),
        "unique_bigrams": len(set(["_".join(path_tokens[i:i+2]) for i in range(len(path_tokens)-1)])),
        "unique_trigrams": len(set(["_".join(path_tokens[i:i+3]) for i in range(len(path_tokens)-2)])),
        "has_whois": has_whois,
        "domain_age_days": domain_age_days
    }

# -------------------------------
# 4️⃣ Predict URL risk
# -------------------------------
def predict_url_risk(url):
    features = extract_features_for_prediction(url)
    X = pd.DataFrame([features])[feature_columns].fillna(0)
    
    pred_encoded = rf.predict(X)[0]
    pred_label = le.inverse_transform([pred_encoded])[0]
    pred_probs = rf.predict_proba(X)[0]
    
    prob_safe = pred_probs[le.transform(['safe'])[0]]
    prob_malicious = pred_probs[le.transform(['malicious'])[0]]
    
    if prob_malicious <= 0.4:
        risk = "Safe"
    elif prob_malicious <= 0.7:
        risk = "Medium"
    else:
        risk = "High"
    
    return {
        "url": url,
        "predicted_label": pred_label,
        "prob_safe": prob_safe,
        "prob_malicious": prob_malicious,
        "risk_level": risk
    }

# -------------------------------
# 5️⃣ Start real-time webcam scanning (fixed)
# -------------------------------
def live_qr_scan():
    cap = cv2.VideoCapture(0)
    scanned_urls = set()
    
    print("🔹 Press 'q' to quit the scanner.")
    
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        
        decoded_objects = decode(frame)
        for obj in decoded_objects:
            try:
                url = obj.data.decode("utf-8")
            except:
                url = str(obj.data)  # fallback if decode fails
            
            if url not in scanned_urls:
                scanned_urls.add(url)
                result = predict_url_risk(url)
                print("\n🔹 Scanned URL:")
                print(f"  URL: {result['url']}")
                print(f"  Label: {result['predicted_label']}")
                print(f"  Risk Level: {result['risk_level']}")
                print(f"  Prob Malicious: {result['prob_malicious']:.2f}")

                # Draw rectangle & text on the frame
                pts = obj.polygon
                if len(pts) > 4:
                    hull = cv2.convexHull(np.array([pt for pt in pts], dtype=np.float32))
                    hull = list(map(tuple, np.squeeze(hull)))
                else:
                    hull = pts
                n = len(hull)
                for j in range(0, n):
                    cv2.line(frame, hull[j], hull[(j + 1) % n], (0,255,0), 2)

                cv2.putText(frame, f"{result['risk_level']}", (obj.rect.left, obj.rect.top - 10),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0,0,255), 2)
        
        cv2.imshow("QR Scanner", frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break
    
    cap.release()
    cv2.destroyAllWindows()


# -------------------------------
# 6️⃣ Run live QR scanner
# -------------------------------
if __name__ == "__main__":
    live_qr_scan()
