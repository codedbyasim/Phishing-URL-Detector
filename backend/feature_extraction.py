import re
from urllib.parse import urlparse

# --- Feature Extraction Functions ---

def get_url_length(url):
    """(1) UrlLength: Length of the URL."""
    return len(url)

def get_num_dots(url):
    """(2) NumDots: Number of dots in the URL."""
    return url.count('.')

def get_subdomain_level(url):
    """(3) SubdomainLevel: Number of subdomains (counted by dots in hostname - 1)."""
    try:
        host = urlparse(url).netloc
        if not host:
            return 0
        # Count dots in hostname. Subtract 1 for the TLD dot (e.g., google.com has 1 dot, level 0)
        # However, many datasets count level 1 for one subdomain (e.g., mail.google.com -> level 1)
        # We will use the common definition: total dots - 1
        return host.count('.') - 1 if host.count('.') > 0 else 0
    except:
        return 0

def get_path_level(url):
    """(4) PathLevel: Number of directories/slashes in the path."""
    try:
        path = urlparse(url).path
        if not path or path == '/':
            return 0
        return path.count('/')
    except:
        return 0

def get_symbol_counts(url):
    """
    (5-10) Symbol counts based on common phishing features.
    NumDash, NumDashInHostname, AtSymbol, TildeSymbol, NumUnderscore, NumPercent.
    """
    parsed_url = urlparse(url)
    host = parsed_url.netloc
    
    features = {
        'NumDash': url.count('-'),
        'NumDashInHostname': host.count('-'),
        'AtSymbol': 1 if '@' in url else 0,
        'TildeSymbol': 1 if '~' in url else 0,
        'NumUnderscore': url.count('_'),
        'NumPercent': url.count('%'),
    }
    return features

def get_query_and_fragment_info(url):
    """
    (11-13) Information about query components, ampersands, and hash fragments.
    NumQueryComponents, NumAmpersand, NumHash.
    """
    parsed_url = urlparse(url)
    query = parsed_url.query
    
    num_query_components = 0
    if query:
        # Simple count of key=value pairs separated by '&'
        num_query_components = len(query.split('&'))
        
    features = {
        'NumQueryComponents': num_query_components,
        'NumAmpersand': query.count('&'),
        'NumHash': 1 if parsed_url.fragment else 0,
    }
    return features

def get_num_numeric_chars(url):
    """(14) NumNumericChars: Count of digits (0-9) in the whole URL."""
    return sum(c.isdigit() for c in url)

def check_https(url):
    """(15) NoHttps: 1 if the scheme is NOT HTTPS, 0 otherwise."""
    return 1 if urlparse(url).scheme != 'https' else 0

def check_random_string(url):
    """(16) RandomString: A simple heuristic for random looking strings (0 or 1)."""
    # This is a highly complex feature to replicate accurately. 
    # Since the original dataset's logic is proprietary, we provide a placeholder.
    # We will use a simple check for very long, non-dictionary-word path segments.
    parsed_url = urlparse(url)
    path_segments = parsed_url.path.split('/')
    for segment in path_segments:
        if len(segment) > 15 and not re.search(r'\d', segment): # Long segment without numbers (could be random characters)
             return 1
    return 0

def check_ip_address(url):
    """(17) IpAddress: 1 if the hostname is an IP address, 0 otherwise."""
    host = urlparse(url).netloc
    # Simple regex to check for standard IPv4 format
    return 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host) else 0

def check_domain_in_subdomains(url):
    """(18) DomainInSubdomains: Presence of the TLD-level domain name inside the subdomain."""
    try:
        host = urlparse(url).netloc
        domain_parts = host.split('.')
        if len(domain_parts) >= 3:
            # Simple check: if the name before the TLD appears in the subdomains
            base_domain = domain_parts[-2]
            subdomains = domain_parts[:-2]
            return 1 if base_domain in subdomains else 0
        return 0
    except:
        return 0

def check_domain_in_paths(url):
    """(19) DomainInPaths: Presence of the TLD-level domain name inside the path."""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        path = parsed_url.path
        
        # Simple extraction of the base domain name (e.g., 'google' from 'www.google.com')
        domain_parts = host.split('.')
        base_domain = domain_parts[-2] if len(domain_parts) >= 2 else host
        
        return 1 if base_domain in path else 0
    except:
        return 0

def check_https_in_hostname(url):
    """(20) HttpsInHostname: 1 if 'https' is present in the hostname as a string."""
    host = urlparse(url).netloc
    return 1 if 'https' in host.lower() else 0

def get_hostname_length(url):
    """(21) HostnameLength: Length of the hostname component."""
    return len(urlparse(url).netloc)

def get_path_length(url):
    """(22) PathLength: Length of the path component."""
    return len(urlparse(url).path)

def get_query_length(url):
    """(23) QueryLength: Length of the query string component."""
    return len(urlparse(url).query)

def get_double_slash_in_path(url):
    """(24) DoubleSlashInPath: 1 if '//' appears in the path, 0 otherwise."""
    return 1 if '//' in urlparse(url).path else 0

def get_num_sensitive_words(url):
    """(25) NumSensitiveWords: Count of common sensitive words (login, banking, paypal, etc.) in the URL."""
    sensitive_words = ['login', 'verify', 'update', 'account', 'bank', 'secure', 'paypal', 'amazon', 'ebay', 'signin']
    url_lower = url.lower()
    return sum(url_lower.count(word) for word in sensitive_words)

def check_embedded_brand_name(url):
    """(26) EmbeddedBrandName: Heuristic for brand name spoofing (e.g., 'microsoft' in path)."""
    # Since we cannot replicate the full list, we check for a brand name 
    # followed by a dash or dot, or in the path/subdomain, not just the main domain.
    common_brands = ['paypal', 'google', 'amazon', 'microsoft', 'apple']
    url_parts = re.split(r'[/.-]', url.lower())
    
    for brand in common_brands:
        if brand in url_parts:
            # Check if the brand appears *outside* the primary domain name component
            host = urlparse(url).netloc
            if brand not in host and brand in url.lower():
                return 1
    return 0

# --- Placeholders for Advanced RT Features (Requires Document/External Analysis) ---
# NOTE: The remaining 22 features (27 to 48) in your dataset rely on analyzing the *content* # of the webpage (e.g., number of external hyperlinks, form actions, favicons, etc.) 
# or external resources (like Whois data). 
# Since this API only receives the URL string, we must return a constant, 
# non-zero value for these features to match the training data's structure.
# Returning 0 might throw off the model if the real values are often non-zero. 
# A value of -1 is often used to denote "feature not applicable" or "cannot extract" 
# in some ML contexts, which is a safer placeholder than 0 or an average.

# Features that usually require content analysis (Placeholders: -1)
# 27: PctExtHyperlinks, 28: PctExtResourceUrls, 29: ExtFavicon, 30: InsecureForms
# 31: RelativeFormAction, 32: ExtFormAction, 33: AbnormalFormAction
# 34: PctNullSelfRedirectHyperlinks, 35: FrequentDomainNameMismatch
# 36: FakeLinkInStatusBar, 37: RightClickDisabled, 38: PopUpWindow
# 39: SubmitInfoToEmail, 40: IframeOrFrame, 41: MissingTitle, 42: ImagesOnlyInForm

PLACEHOLDER_VALUE = -1 # Using -1 as a neutral placeholder for page-content-based features

def get_content_based_features():
    """Generates placeholders for features requiring page content analysis (27-42)."""
    
    # Names match the columns in your Phishing_Legitimate_full.csv
    features = {
        'PctExtHyperlinks': PLACEHOLDER_VALUE, 
        'PctExtResourceUrls': PLACEHOLDER_VALUE,
        'ExtFavicon': PLACEHOLDER_VALUE,
        'InsecureForms': PLACEHOLDER_VALUE,
        'RelativeFormAction': PLACEHOLDER_VALUE,
        'ExtFormAction': PLACEHOLDER_VALUE,
        'AbnormalFormAction': PLACEHOLDER_VALUE,
        'PctNullSelfRedirectHyperlinks': PLACEHOLDER_VALUE,
        'FrequentDomainNameMismatch': PLACEHOLDER_VALUE,
        'FakeLinkInStatusBar': PLACEHOLDER_VALUE,
        'RightClickDisabled': PLACEHOLDER_VALUE,
        'PopUpWindow': PLACEHOLDER_VALUE,
        'SubmitInfoToEmail': PLACEHOLDER_VALUE,
        'IframeOrFrame': PLACEHOLDER_VALUE,
        'MissingTitle': PLACEHOLDER_VALUE,
        'ImagesOnlyInForm': PLACEHOLDER_VALUE,
    }
    return features

def get_realtime_features():
    """Generates placeholders for "Real-Time" features (43-48) requiring content or external data."""
    
    # Names match the columns in your Phishing_Legitimate_full.csv
    features = {
        'SubdomainLevelRT': PLACEHOLDER_VALUE,
        'UrlLengthRT': PLACEHOLDER_VALUE,
        'PctExtResourceUrlsRT': PLACEHOLDER_VALUE,
        'AbnormalExtFormActionR': PLACEHOLDER_VALUE,
        'ExtMetaScriptLinkRT': PLACEHOLDER_VALUE,
        'PctExtNullSelfRedirectHyperlinksRT': PLACEHOLDER_VALUE,
    }
    return features


# --- Main Feature Extraction Function ---

def extract_features_from_url(url):
    """
    Extracts all 48 features required by the ML model from a single URL string.
    
    Returns:
        dict: A dictionary mapping feature names (matching the CSV headers) 
              to their extracted or placeholder values.
    """
    
    # 1. Initialize master features dictionary
    features = {}

    # 2. Add simple structural features (1-4, 14, 15, 21-24)
    features['UrlLength'] = get_url_length(url)
    features['NumDots'] = get_num_dots(url)
    features['SubdomainLevel'] = get_subdomain_level(url)
    features['PathLevel'] = get_path_level(url)
    features['NumNumericChars'] = get_num_numeric_chars(url)
    features['NoHttps'] = check_https(url)
    features['HostnameLength'] = get_hostname_length(url)
    features['PathLength'] = get_path_length(url)
    features['QueryLength'] = get_query_length(url)
    features['DoubleSlashInPath'] = get_double_slash_in_path(url)
    
    # 3. Add symbol-based features (5-10)
    features.update(get_symbol_counts(url))
    
    # 4. Add query/fragment features (11-13)
    features.update(get_query_and_fragment_info(url))

    # 5. Add complex structural checks (16-20, 25, 26)
    features['RandomString'] = check_random_string(url)
    features['IpAddress'] = check_ip_address(url)
    features['DomainInSubdomains'] = check_domain_in_subdomains(url)
    features['DomainInPaths'] = check_domain_in_paths(url)
    features['HttpsInHostname'] = check_https_in_hostname(url)
    features['NumSensitiveWords'] = get_num_sensitive_words(url)
    features['EmbeddedBrandName'] = check_embedded_brand_name(url)
    
    # 6. Add PLACEHOLDERS for page-content-based features (27-48)
    # The model expects these features, so they must be present, even if we can't 
    # calculate them from the URL string alone.
    features.update(get_content_based_features())
    features.update(get_realtime_features())
    
    # Verification (should always be 48 features)
    if len(features) != 48:
        print(f"WARNING: Feature extraction resulted in {len(features)} features, expected 48.")
        
    return features

# Example usage (for local testing):
if __name__ == '__main__':
    test_url_safe = "https://www.google.com/search?q=test&ie=UTF-8"
    test_url_phish = "http://paypal-secure-login.com@phishing.net/update/account.html"
    
    print("--- Safe URL Features ---")
    safe_features = extract_features_from_url(test_url_safe)
    for name, value in safe_features.items():
        if value != -1:
             print(f"{name}: {value}")
             
    print("\n--- Phishing URL Features ---")
    phish_features = extract_features_from_url(test_url_phish)
    for name, value in phish_features.items():
        if value != -1:
             print(f"{name}: {value}")
