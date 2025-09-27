import requests
import json

# The URL of the Flask API endpoint
API_URL = "http://127.0.0.1:5000/predict"

def test_url(url, description):
    """
    Sends a POST request to the API with a URL and prints the result.
    """
    print(f"\n--- Testing: {description} ---")
    payload = {"url": url}
    
    try:
        response = requests.post(API_URL, json=payload, timeout=5)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        
        result = response.json()
        print(f"URL: {url}")
        print(f"API Response: {result.get('prediction', 'N/A')}")
        print(f"Reason: {result.get('reason', 'N/A')}")
        
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to API (Is app.py running?): {e}")

if __name__ == '__main__':
    print("Starting API tests. Ensure 'app.py' is running in another terminal window.")
    
    # Case 1: Likely Safe URL (short, HTTPS, no special chars)
    test_url(
        "https://www.google.com/search?q=safe", 
        "Safe URL (Short, HTTPS)"
    )
    
    # Case 2: Phishing URL - Regex Heuristic Trigger (@ symbol)
    test_url(
        "http://security-login.com@realbank.com/login", 
        "Phishing (Uses @ symbol - Heuristic)"
    )

    # Case 3: Phishing URL - Regex Heuristic Trigger (IP address)
    test_url(
        "http://123.45.67.89/login.html", 
        "Phishing (Uses IP in domain - Heuristic)"
    )
    
    # Case 4: Phishing URL - Regex Heuristic Trigger (Length)
    test_url(
        "http://login-security-update-important-verification-for-your-account.net/login.php?" + 
        "user_id=1234567890&session_token=ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", 
        "Phishing (Very Long URL - Heuristic)"
    )
    
    # Case 5: ML Prediction Test (Depends on synthetic data, likely Phishing)
    test_url(
        "http://update-secure-login-portal.co/verify.html", 
        "Suspicious (ML model test)"
    )
