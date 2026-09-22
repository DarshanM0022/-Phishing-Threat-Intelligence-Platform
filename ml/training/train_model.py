import os
import json
import random
import numpy as np
from backend.app.detectors.url_features import url_extractor
from backend.app.ml.tree_model import PureRandomForest

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "hyphen_count",
    "slash_count",
    "special_char_count",
    "subdomain_count",
    "is_https",
    "has_ip_hostname",
    "has_at_symbol",
    "has_double_slash_path",
    "uses_punycode",
    "is_shortened_url",
    "suspicious_tld",
    "has_hex_encoding",
    "has_brand_in_subdomain",
    "digit_ratio",
    "hostname_digit_ratio",
    "hostname_entropy",
    "url_entropy",
    "keyword_count",
    "has_login_keyword",
    "has_verify_keyword",
    "has_secure_keyword",
    "has_billing_keyword",
]

def generate_synthetic_dataset():
    random.seed(42)
    np.random.seed(42)

    benign_domains = [
        "google.com", "github.com", "microsoft.com", "amazon.com", "wikipedia.org",
        "stackoverflow.com", "reddit.com", "nytimes.com", "apple.com", "netflix.com",
        "harvard.edu", "mit.edu", "cdc.gov", "nasa.gov", "mozilla.org",
        "cloudflare.com", "digitalocean.com", "linkedin.com", "cnn.com", "bbc.co.uk",
        "stripe.com", "salesforce.com", "dropbox.com", "spotify.com", "adobe.com"
    ]
    
    benign_paths = [
        "", "/about", "/docs/api/v1/overview", "/contact", "/products/hardware",
        "/search?q=cybersecurity+defense", "/articles/2026/09/security-brief",
        "/releases/latest", "/settings/profile", "/dashboard/analytics",
        "/help/faq", "/terms-of-service", "/privacy-policy", "/blog/engineering"
    ]

    phishing_brands = ["paypal", "apple-id", "chase-bank", "wells-fargo", "netflix-login", "microsoft365", "binance", "coinbase"]
    phishing_keywords = ["verify-account", "security-alert", "login-auth", "wallet-restore", "billing-update", "confirm-identity"]
    suspicious_tlds = ["xyz", "top", "tk", "click", "buzz", "icu", "work", "live"]
    shorteners = ["bit.ly", "tinyurl.com", "cutt.ly"]

    urls = []
    labels = []

    # 1. Benign Samples (Label 0)
    for _ in range(600):
        domain = random.choice(benign_domains)
        path = random.choice(benign_paths)
        scheme = "https://" if random.random() > 0.05 else "http://"
        urls.append(f"{scheme}{domain}{path}")
        labels.append(0)

    # 2. Malicious Phishing Samples (Label 1)
    for _ in range(600):
        strategy = random.choice(["brand_subdomain", "ip_address", "punycode", "urgent_path", "tld_abuse", "shortened", "basic_auth"])
        
        if strategy == "brand_subdomain":
            brand = random.choice(phishing_brands)
            kw = random.choice(phishing_keywords)
            tld = random.choice(["com", "net", "org", "xyz"])
            url = f"https://{brand}.{kw}-service.attacker-{random.randint(10,99)}.{tld}/login?token={random.randint(10000,99999)}"
        elif strategy == "ip_address":
            ip = f"{random.randint(11,200)}.{random.randint(1,250)}.{random.randint(1,250)}.{random.randint(1,250)}"
            url = f"http://{ip}/secure/login/account-verification.php"
        elif strategy == "punycode":
            url = f"https://xn--pypal-4ve.com/signin/webapps/verify-account"
        elif strategy == "urgent_path":
            tld = random.choice(suspicious_tlds)
            url = f"http://account-recovery-{random.randint(100,999)}.{tld}/banking/verify/login.html?redirect=auth"
        elif strategy == "tld_abuse":
            tld = random.choice(suspicious_tlds)
            url = f"https://apple-support-notice.{tld}/verification/auth?user_id=1284"
        elif strategy == "shortened":
            short = random.choice(shorteners)
            url = f"https://{short}/{random.choice(['secure-bank', 'verify24', 'login99', 'x9ab2'])}"
        elif strategy == "basic_auth":
            url = f"https://chase.com:secure@attacker-redirect-{random.randint(10,99)}.com/login"
        else:
            url = f"http://urgent-verification-gateway.xyz/login"
            
        urls.append(url)
        labels.append(1)

    return urls, labels

def train_and_evaluate():
    print("[*] Generating synthetic dataset for URL phishing detection...")
    urls, labels = generate_synthetic_dataset()
    print(f"[*] Total dataset size: {len(urls)} samples (Balanced)")

    print("[*] Extracting 27 quantitative features per sample...")
    X_rows = []
    for u in urls:
        ext = url_extractor.extract_features(u)
        feat_dict = ext["features"]
        row = [feat_dict[fn] for fn in FEATURE_NAMES]
        X_rows.append(row)

    X = np.array(X_rows, dtype=float)
    y = np.array(labels, dtype=int)

    # Train / Test split (80% train, 20% test)
    indices = np.arange(len(y))
    np.random.shuffle(indices)
    split = int(0.8 * len(y))
    train_idx, test_idx = indices[:split], indices[split:]

    X_train, y_train = X[train_idx], y[train_idx]
    X_test, y_test = X[test_idx], y[test_idx]

    print(f"[*] Training Pure-NumPy Random Forest (40 trees, max_depth=7)...")
    rf = PureRandomForest(n_estimators=40, max_depth=7, min_samples_split=4)
    rf.fit(X_train, y_train)

    # Inference & Metrics
    probs = rf.predict_proba(X_test)
    y_pred = (probs[:, 1] >= 0.5).astype(int)
    y_prob = probs[:, 1]

    tp = int(np.sum((y_pred == 1) & (y_test == 1)))
    fp = int(np.sum((y_pred == 1) & (y_test == 0)))
    tn = int(np.sum((y_pred == 0) & (y_test == 0)))
    fn = int(np.sum((y_pred == 0) & (y_test == 1)))

    acc = (tp + tn) / max(1, len(y_test))
    prec = tp / max(1, (tp + fp))
    rec = tp / max(1, (tp + fn))
    f1 = 2 * (prec * rec) / max(1e-6, (prec + rec))
    fpr = fp / max(1, (fp + tn))
    fnr = fn / max(1, (fn + tp))

    print("\n" + "="*50)
    print("      PHISHGUARD AI MODEL EVALUATION METRICS       ")
    print("="*50)
    print(f"Accuracy:                  {acc * 100:.2f}%")
    print(f"Precision:                 {prec * 100:.2f}%")
    print(f"Recall:                    {rec * 100:.2f}%")
    print(f"F1 Score:                  {f1:.4f}")
    print(f"False Positive Rate (FPR): {fpr * 100:.2f}%")
    print(f"False Negative Rate (FNR): {fnr * 100:.2f}%")
    print(f"Confusion Matrix: [TN: {tn}, FP: {fp}, FN: {fn}, TP: {tp}]")
    print("="*50)

    # Save model and metrics
    os.makedirs("ml/models", exist_ok=True)
    os.makedirs("ml/evaluation", exist_ok=True)

    metrics = {
        "model_type": "PureRandomForest",
        "estimators": 40,
        "max_depth": 7,
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "false_negative_rate": round(float(fnr), 4),
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp
        }
    }

    model_path = "ml/models/rf_phishing_v1.json"
    metrics_path = "ml/evaluation/metrics.json"

    with open(model_path, "w") as f:
        json.dump(rf.to_dict(), f)

    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"[+] Model JSON saved to: {model_path}")
    print(f"[+] Metrics JSON saved to: {metrics_path}")
    return metrics

if __name__ == "__main__":
    train_and_evaluate()
