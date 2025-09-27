import os
import re
from flask import Flask, request, jsonify
from joblib import load
import pandas as pd # Import pandas for structured prediction input

# Import feature extraction logic
# We also need the FEATURE_NAMES list from feature_extraction.py
from feature_extraction import extract_features, FEATURE_NAMES 

# --- Configuration ---
app = Flask(__name__)
MODEL_PATH = "backend/models/phishing_model.pkl"
MODEL = None # Placeholder for the loaded model

# --- Initialization (Model Loading) ---

# Load the model immediately upon startup, outside of any request handling function.
# This ensures it is ready when the server starts listening.
print(f"Attempting to load ML model from {MODEL_PATH}...")
if os.path.exists(MODEL_PATH):
    try:
        MODEL = load(MODEL_PATH)
        print("Successfully loaded ML model.")
    except Exception as e:
        print(f"Error loading model: {e}")
        print("Please ensure the model file exists and train_model.py ran successfully.")
        MODEL = None
else:
    print(f"Model file not found at {MODEL_PATH}. Please run train_model.py first.")


# --- Heuristics (Regex Checks) ---

def run_security_heuristics(url):
    """
    Applies regex-based security checks to flag suspicious URLs immediately.
    
    Returns:
        bool: True if suspicious (phishing), False otherwise.
    """
    
    # Heuristic 1: Presence of @ symbol
    # The '@' symbol often redirects the user to a different location, disguising the true address.
    if '@' in url:
        print(f"Heuristic Alert: URL contains '@' symbol.")
        return True
        
    # Heuristic 2: IP address in the domain part
    # Phishers frequently use direct IP addresses instead of registered domain names.
    # We reuse the check from feature_extraction, but parse the host only.
    # Pattern: d.d.d.d (basic IPv4 check)
    try:
        from urllib.parse import urlparse
        # Ensure we check the netloc without the scheme
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc.split(':')[0]
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, netloc):
            print(f"Heuristic Alert: Domain is an IP address: {netloc}")
            return True
    except:
        pass # Ignore parsing errors for heuristics
        
    # Heuristic 3: Excessive URL length
    # Very long URLs are often a sign of phishing, as they can contain excessive data.
    if len(url) > 75:
        print(f"Heuristic Alert: URL length ({len(url)}) exceeds 75 characters.")
        return True
        
    return False

# --- API Endpoint ---

@app.route('/predict', methods=['POST'])
def predict():
    """
    Accepts a URL, runs heuristics, and uses the ML model for a final prediction.
    """
    
    # 1. Check if model is loaded
    if MODEL is None:
        return jsonify({"error": "ML Model not loaded. Please check server logs for file path or training errors."}), 500

    # 2. Get data from request
    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return jsonify({"error": "Invalid input. Please provide a JSON object with a 'url' key."}), 400
        
    url = data['url'].strip()
    
    # 3. Part 3: Apply Regex Heuristics
    if run_security_heuristics(url):
        return jsonify({"prediction": "phishing", "reason": "Heuristics (Regex) Flag"}), 200
        
    # 4. Part 1 & 2: ML Prediction
    try:
        # Extract features (uses the same features the model was trained on)
        features_list = extract_features(url)
        
        # FIX: Wrap the single sample into a Pandas DataFrame with the expected feature names
        # to suppress the scikit-learn UserWarning and ensure robustness.
        features_df = pd.DataFrame([features_list], columns=FEATURE_NAMES)
        
        # Predict the label (0 or 1)
        prediction_label = MODEL.predict(features_df)[0]
        
        # Map label to readable string
        prediction_result = "phishing" if prediction_label == 1 else "safe"
        
        return jsonify({"prediction": prediction_result, "reason": "ML Model Prediction"}), 200
        
    except Exception as e:
        # Log the detailed error for debugging purposes
        import traceback
        traceback.print_exc()
        
        return jsonify({"error": f"An error occurred during ML prediction: {str(e)}"}), 500

if __name__ == '__main__':
    # When run directly, app.run() will start the server. 
    # The model is already loaded above.
    app.run(debug=True, port=5000)
