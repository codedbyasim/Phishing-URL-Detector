from flask import Flask, request, jsonify
from joblib import load
from urllib.parse import urlparse # IMPORTANT: Add urlparse import here
import os
import json
import pandas as pd
import numpy as np

# Assuming feature_extraction is in the same directory structure
from feature_extraction import extract_features_from_url 

app = Flask(__name__)

# --- Configuration ---
MODEL_DIR = 'backend/models' 
MODEL_FILENAME = 'phishing_model.pkl'
FEATURES_FILENAME = 'feature_metadata.json'
MODEL_FULL_PATH = os.path.join(MODEL_DIR, MODEL_FILENAME)
FEATURES_FULL_PATH = os.path.join(MODEL_DIR, FEATURES_FILENAME)

# --- Global Variables for ML Model and Features ---
model = None
feature_names = None
ML_THRESHOLD = 0.58 # ADJUSTED: Lowered threshold to 0.58 to catch the 'amazon-support.online' False Negative.

def load_ml_resources():
    """Loads the trained model and the feature list upon API startup."""
    global model, feature_names
    
    # 1. Load the Model
    try:
        model = load(MODEL_FULL_PATH)
        print(f"ML Model loaded successfully from {MODEL_FULL_PATH}.")
    except Exception as e:
        print(f"ERROR: Failed to load ML model from {MODEL_FULL_PATH}. Ensure train_model.py was run.")
        print(f"Details: {e}")
        model = None
        
    # 2. Load the Feature Metadata
    try:
        with open(FEATURES_FULL_PATH, 'r') as f:
            feature_names = json.load(f)
        print(f"Feature list loaded successfully. Total features: {len(feature_names)}")
    except Exception as e:
        print(f"ERROR: Failed to load feature metadata from {FEATURES_FULL_PATH}. Ensure train_model.py was run.")
        print(f"Details: {e}")
        feature_names = None

# --- Prediction Functions ---

def rule_based_check(url):
    """
    Performs fast, high-confidence checks based on classic phishing indicators.
    Returns (True, reason) if phishing, or (False, None) otherwise.
    """
    # 1. Check for the '@' symbol (used to embed credentials or confuse users)
    if '@' in url:
        return True, "Rule-Based (Contains '@' symbol for obfuscation)"
    
    # 2. Check for long URL (Rule based on original project requirements)
    if len(url) > 75:
        return True, "Rule-Based (URL is excessively long)"
        
    # 3. Check for IP address in the hostname (malicious sites often use raw IPs)
    import re
    # We need to import urlparse inside or pass it in, but since we use it globally,
    # let's just make sure it's imported at the top.
    host = urlparse(url).netloc
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        return True, "Rule-Based (Hostname is an IP address)"
        
    return False, None

def ml_based_prediction(url):
    """
    Extracts features from the URL and uses the ML model for prediction.
    Returns prediction ('safe' or 'phishing') and probability.
    """
    if not model or not feature_names:
        return 'error', 0.0, "ML model or feature metadata not loaded."

    # 1. Extract raw features using the imported script
    # This returns a dictionary of feature names and values (e.g., {'UrlLength': 42, ...})
    raw_features = extract_features_from_url(url)
    
    # 2. Create the feature vector in the EXACT ORDER the model expects
    # We use the feature_names list loaded from the JSON
    try:
        # Create a list of feature values in the correct order
        feature_vector = [raw_features[name] for name in feature_names]
        
        # Convert to a DataFrame row for prediction
        X_predict = pd.DataFrame([feature_vector], columns=feature_names)
    except KeyError as e:
        # This handles cases where a feature expected by the model is missing 
        # from the extraction logic (should not happen if feature_extraction.py is complete)
        return 'error', 0.0, f"Missing feature required by model: {e}"

    # 3. Predict probability for class 1 (phishing)
    # prediction_proba returns [[P(class 0), P(class 1)]]
    phishing_proba = model.predict_proba(X_predict)[0][1]
    
    # 4. Apply the adjusted threshold
    if phishing_proba >= ML_THRESHOLD:
        prediction = 'phishing'
    else:
        prediction = 'safe'
        
    return prediction, float(phishing_proba), "ML Model Prediction"

# --- Flask Routes ---

@app.route('/predict', methods=['POST'])
def predict():
    """API endpoint to receive a URL and return a prediction."""
    
    # Ensure request body is JSON
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400
    
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "Missing 'url' field in request"}), 400
    
    # --- Step 1: Rule-Based Check (Fast and High-Confidence) ---
    is_phishing, reason = rule_based_check(url)
    
    if is_phishing:
        # If any rule is triggered, return PHISHING immediately
        response = {
            "prediction": "phishing",
            "reason": reason,
            "phishing_proba": None # No ML proba needed for rule-based detection
        }
        return jsonify(response)
        
    # --- Step 2: ML-Based Prediction ---
    prediction, proba, reason = ml_based_prediction(url)
    
    if prediction == 'error':
        return jsonify({"error": reason}), 500
        
    response = {
        "prediction": prediction,
        "reason": reason,
        # Convert NumPy float to standard Python float for JSON serialization
        "phishing_proba": round(proba, 4)
    }
    return jsonify(response)

# --- Startup ---
if __name__ == '__main__':
    # Load ML resources before starting the server
    load_ml_resources()
    if model and feature_names:
        # Only run the server if resources were successfully loaded
        app.run(debug=True)
    else:
        print("\nFATAL: Server startup failed due to missing ML resources.")
        print("Please resolve the errors above and ensure 'train_model.py' ran successfully.")
