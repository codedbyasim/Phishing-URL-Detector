import re
from urllib.parse import urlparse

# CRITICAL: This list MUST match the columns used to train the ML model
FEATURE_NAMES = [
    'url_length', 
    'has_at_symbol', 
    'has_hyphen', 
    'is_https', 
    'digit_count', 
    'is_ip_address'
]

def extract_features(url):
    """
    Extracts the defined set of numerical features from a given URL string.
    These features must be in the exact order specified by FEATURE_NAMES.
    
    Args:
        url (str): The URL string to analyze.
        
    Returns:
        list: A list of numerical feature values.
    """
    
    # 1. Parse the URL to access components easily
    try:
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc
    except:
        # Fallback if parsing fails (treat components as empty)
        netloc = url
    
    # --- Feature Extraction ---

    # F1: URL Length (Integer)
    url_length = len(url)
    
    # F2: Presence of @ Symbol (Binary: 1=Yes, 0=No)
    has_at_symbol = 1 if '@' in url else 0
    
    # F3: Presence of Hyphen in Hostname (Binary: 1=Yes, 0=No)
    # Checks for '-' in the domain/subdomain part
    has_hyphen = 1 if '-' in netloc else 0
    
    # F4: Whether HTTPS is used (Binary: 1=Yes, 0=No)
    # Note: In the CSV data (NoHttps=0 for HTTPS), this feature is inverted 
    # for the ML training to match the desired logical meaning (is_https=1 for HTTPS).
    is_https = 1 if parsed_url.scheme == 'https' else 0

    # F5: Count of Digits (Integer)
    digit_count = sum(c.isdigit() for c in url)
    
    # F6: If Domain Looks Like IP Address (Binary: 1=Yes, 0=No)
    # Checks for basic IPv4 structure in the netloc (host)
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    is_ip_address = 1 if re.match(ip_pattern, netloc.split(':')[0]) else 0
    
    # --- Assemble and Return Feature List ---
    
    features = [
        url_length, 
        has_at_symbol, 
        has_hyphen, 
        is_https, 
        digit_count, 
        is_ip_address
    ]
    
    return features

if __name__ == '__main__':
    # Example usage for testing the extractor
    test_urls = {
        "https://www.google.com/": "Safe",
        "http://192.168.1.1/login": "IP Address",
        "https://secure-login.com@phish.net/": "@ Symbol",
        "http://update-secure-login-portal.co/verify.html": "Hyphenated"
    }

    print("--- Testing Feature Extraction ---")
    print(f"{'URL':<40} | {'@':<2} | {'-':<2} | {'HTTPS':<5} | {'Digits':<6} | {'IP':<2} | {'Length':<6}")
    print("-" * 75)
    
    for url, desc in test_urls.items():
        features = extract_features(url)
        f_map = dict(zip(FEATURE_NAMES, features))
        
        print(
            f"{url[:38]+'...':<40} | {f_map['has_at_symbol']:<2} | {f_map['has_hyphen']:<2} | "
            f"{f_map['is_https']:<5} | {f_map['digit_count']:<6} | {f_map['is_ip_address']:<2} | "
            f"{f_map['url_length']:<6}"
        )
