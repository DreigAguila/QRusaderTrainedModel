import cv2
from pyzbar.pyzbar import decode
import pandas as pd
import joblib
import re, math
from urllib.parse import urlparse
from datetime import datetime

# -------------------------------
# Load stacking model and label encoder
# -------------------------------
stacking_model = joblib.load(r"D:\QRusaderTrainedModel\models\stacking_model.pkl")
le = joblib.load(r"D:\QRusaderTrainedModel\models\label_encoder.pkl")
feature_columns = joblib.load(r"D:\QRusaderTrainedModel\models\feature_columns.pkl")

# -------------------------------
# Feature extraction 
# -------------------------------
def shannon_entropy(data):
    if not data:
        return 0
    prob = [float(data.count(c))/len(data) for c in set(data)]
    return -sum(p*math.log2(p) for p in prob)

def has_ip(url):
    return 1 if re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", url) else 0

def is_shortened(url):
    shortening_services = ["bit.ly","tinyurl","goo.gl","t.co","ow.ly","shorte.st","cutt.ly"]
    return 1 if any(s in url for s in shortening_services) else 0

suspicious_keywords = ["secure","account","login","update","free","bonus",
                       "ebayisapi","banking","confirm","signin","verification"]

def contains_suspicious_word(url):
    return sum(word in url.lower() for word in suspicious_keywords)

def has_suspicious_ext(url):
    suspicious_ext = [
        ".exe", ".bat", ".com", ".msi", ".cmd", ".scr",
        ".zip", ".rar", ".7z", ".tar", ".gz",
        ".js", ".vbs", ".jar", ".ps1", ".wsf",
        ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
        ".apk"
    ]
    return 1 if any(url.lower().endswith(ext) for ext in suspicious_ext) else 0

# -------------------------------
# Main Feature Extraction
# -------------------------------
def extract_features(url):
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    domain = parsed.netloc or parsed.path
    path = parsed.path
    query = parsed.query

    # URL structural features
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

    # Advanced URL features
    url_upper_ratio = sum(1 for c in url if c.isupper()) / max(1, len(url))
    url_encoded_ratio = url.count('%') / max(1, len(url))
    repeated_char_count = sum(url.count(c*2) for c in set(url))
    path_token_count = len([t for t in path.split('/') if t])
    query_token_count = len([q for q in query.split('&') if q])
    suspicious_word_count = contains_suspicious_word(url)

    # WHOIS placeholders
    has_whois = 0
    domain_age_days = 0
    domain_age_bin = 0

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
        "has_whois": has_whois,
        "domain_age_days": domain_age_days,
        "domain_age_bin": domain_age_bin
    }
    

# -------------------------------
# QR Scanner with prediction
# -------------------------------
def scan_qr_from_camera():
    cap = cv2.VideoCapture(0)
    print("🎥 Press 'q' to quit the camera scanner")

    scanned_urls = set()  # Avoid duplicate predictions

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                continue

            for qr in decode(frame):
                url = qr.data.decode('utf-8')
                if url not in scanned_urls:
                    scanned_urls.add(url)
                    feats = extract_features(url)
                    feats_df = pd.DataFrame([feats])[feature_columns].fillna(0).infer_objects()
                    
                    # Prediction
                    pred_encoded = stacking_model.predict(feats_df)[0]
                    pred_label = le.inverse_transform([pred_encoded])[0]
                    prob_malicious = stacking_model.predict_proba(feats_df)[0][le.transform(['malicious'])[0]]

                    print(f"\n🔗 URL: {url}")
                    print(f"   Predicted Label: {pred_label}")
                    print(f"   Malicious Probability: {prob_malicious*100:.2f}%")

            cv2.imshow("QR Scanner", frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break

    finally:
        cap.release()
        cv2.destroyAllWindows()
        print("\n✅ Camera scanner closed")

# Example usage
scan_qr_from_camera()