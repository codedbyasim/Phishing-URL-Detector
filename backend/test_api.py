import requests
import json

# Define the URL for the Flask API's prediction endpoint
API_URL = "http://127.0.0.1:5000/predict"

def test_url(url):
    """
    Sends a single URL to the Flask API and prints the response.
    """
    payload = {"url": url}
    headers = {"Content-Type": "application/json"}
    
    try:
        # Send the POST request to the API
        response = requests.post(API_URL, headers=headers, data=json.dumps(payload))
        response.raise_for_status() # Raise an exception for HTTP error codes
        
        # Parse the JSON response
        data = response.json()
        
        # Extract and print the relevant prediction fields
        prediction = data.get("prediction", "N/A")
        reason = data.get("reason", "No reason provided")
        
        phishing_proba = data.get("phishing_proba")
        proba_str = f" (P={phishing_proba})" if phishing_proba else ""
        
        print(f"URL: {url}")
        print(f" -> RESULT: {prediction.upper()}{proba_str}")
        print(f" -> REASON: {reason}\n")
        
    except requests.exceptions.ConnectionError:
        print("--------------------------------------------------")
        print(f"ERROR: Could not connect to the API at {API_URL}.")
        print("Please ensure your Flask app ('python backend/app.py') is running.")
        print("--------------------------------------------------\n")
        return
    except Exception as e:
        print(f"An unexpected error occurred for URL {url}: {e}")
        print(f"Full response status: {response.status_code if 'response' in locals() else 'N/A'}")
        print(f"Full response content: {response.text if 'response' in locals() else 'N/A'}\n")


if __name__ == "__main__":
    
    # List of test URLs to check
    test_cases = [
        # SAFE URLs
        "https://www.google.com",
        "https://github.com/microsoft/vscode",
        "http://blog.openai.com/latest-models",
        
        # PHISHING URLs (Rule-Based Checks)
        # 1. Long URL check (length > 75)
        "http://safe-bank-login-secure.com/dashboard/settings/user/profile/update/long/path/to/phishing/page/verylongurlfortesting.php",
        # 2. '@' symbol check
        "https://secure-login.com@phishing-site.net/login.html",
        # 3. IP address check
        "http://192.168.1.1/admin-login.html",

        # ML-Relevant Suspicious URLs (may rely on the trained model)
        "https://paypal-verify-account.web.app",
        "http://www.amazon-support.online/update",
    ]

    print("--- Running Phishing Detector API Tests ---")
    
    # Run the tests
    for case in test_cases:
        test_url(case)

    print("--- Testing Complete ---")
