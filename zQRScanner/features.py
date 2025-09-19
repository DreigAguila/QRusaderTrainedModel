# features.py
import re
import math
from urllib.parse import urlparse
from datetime import datetime
import whois

# -------------------------------
# Suspicious keywords and extensions
# -------------------------------
SUSPICIOUS_KEYWORDS = [
    "secure","account","login","update","free","bonus",
    "ebayisapi","banking","confirm","signin","verification"
]

SUSPICIOUS_EXT = [
    ".exe", ".bat", ".cmd", ".msi", ".scr",
    ".js", ".vbs", ".wsf", ".ps1", ".jar", ".hta",
    ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z",
    ".tar", ".gz", ".apk", ".pif", ".lnk", ".iso", ".img"
    ]

SHORTENING_SERVICES = ["bit.ly","tinyurl","goo.gl","t.co","ow.ly","shorte.st","cutt.ly"]

# -------------------------------
# Helper functions
# -------------------------------
def shannon_entropy(data: str) -> float:
    if not data:
        return 0
    prob = [float(data.count(c))/len(data) for c in set(data)]
    return -sum(p * math.log2(p) for p in prob)

def has_ip(url: str) -> int:
    return int(bool(re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", url)))

def is_shortened(url: str) -> int:
    return int(any(s in url for s in SHORTENING_SERVICES))

def contains_suspicious_word(url: str) -> int:
    return sum(word in url.lower() for word in SUSPICIOUS_KEYWORDS)

def has_suspicious_ext(url: str) -> int:
    return int(any(url.lower().endswith(ext) for ext in SUSPICIOUS_EXT))

def get_whois_info(domain: str):
    try:
        w = whois.whois(domain)
        has_whois = int(bool(w))
        if hasattr(w, "creation_date") and w.creation_date:
            creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            age_days = (datetime.now() - creation_date).days
        else:
            age_days = 0
    except:
        has_whois = 0
        age_days = 0
    return has_whois, age_days

# -------------------------------
# Main feature extraction function
# -------------------------------
def extract_features(url: str) -> dict:
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    domain = parsed.netloc or parsed.path
    path = parsed.path
    query = parsed.query

    # Domain-level WHOIS
    has_whois, domain_age_days = get_whois_info(domain)
    domain_age_bin = 0
    if domain_age_days:
        if domain_age_days < 30:
            domain_age_bin = 1
        elif domain_age_days < 365:
            domain_age_bin = 2
        else:
            domain_age_bin = 3

    # URL-level features
    total_special_char = sum(url.count(c) for c in ['@','?','-','=','.','!','#','$','&','~','*','%','+','^','_'])
    special_char_ratio = total_special_char / max(1, len(url))
    subdomain_count = max(domain.count(".") - 1, 0)
    path_depth = path.count('/')
    query_param_amp_count = query.count('&') + (1 if query else 0)
    tld = domain.split('.')[-1]
    tld_length = len(tld)
    numeric_tld = int(any(c.isdigit() for c in tld))
    subdomain_ratio = subdomain_count / max(1, len(domain))
    digit_letter_ratio = sum(c.isdigit() for c in url) / max(1, sum(c.isalpha() for c in url))

    # Advanced URL features
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
        "risky_tld": int(tld in ["zip","xyz","top","club","info"]),
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
