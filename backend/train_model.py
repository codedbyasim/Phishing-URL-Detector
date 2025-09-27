import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from joblib import dump

# NOTE: The feature_extraction module is still required for the Flask API
# to process NEW, un-seen URLs for prediction.
from feature_extraction import FEATURE_NAMES

# Define the path for the uploaded dataset
DATASET_PATH = "G:\\Phishing-URL-Detector\\backend\\Dataset\\Phishing_Legitimate_full.csv"

# --- Training and Saving Script ---

def train_and_save_model(model_path="backend/models/phishing_model.pkl"):
    """
    Loads data from the provided CSV, trains the classifier, and saves the model.
    """
    print(f"Attempting to load dataset from: {DATASET_PATH}")
    
    if not os.path.exists(DATASET_PATH):
        print(f"Error: Dataset not found at {DATASET_PATH}.")
        print("Please ensure 'Phishing_Legitimate_full.csv' is in the current directory.")
        return

    try:
        df = pd.read_csv(DATASET_PATH)
        print(f"Dataset loaded successfully. Total rows: {len(df)}")
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return

    # Map the required features from the CSV column names to the expected model features.
    # We will use the features closest to the original request:
    # - url_length (UrlLength)
    # - has_at_symbol (AtSymbol)
    # - has_hyphen (NumDashInHostname)
    # - is_https (Inverse of NoHttps, where 1=NoHttps, so 1-NoHttps = 1=Https)
    # - digit_count (NumNumericChars)
    # - is_ip_address (IpAddress)
    
    csv_feature_mapping = {
        'UrlLength': 'url_length',
        'AtSymbol': 'has_at_symbol',
        'NumDashInHostname': 'has_hyphen',
        'NumNumericChars': 'digit_count',
        'IpAddress': 'is_ip_address'
    }

    # Prepare features (X)
    X_cols = list(csv_feature_mapping.keys())
    
    # Add 'NoHttps' specifically for the 'is_https' feature calculation
    X_cols.append('NoHttps') 
    
    X = df[X_cols].copy()

    # Apply transformations needed to match feature definition:
    # 1. 'is_https': The 'NoHttps' column is 1 if it's HTTP, 0 if it's HTTPS. 
    #    We need 'is_https' where 1=HTTPS, so we calculate 1 - NoHttps.
    X['is_https'] = 1 - X['NoHttps']
    X.drop('NoHttps', axis=1, inplace=True)
    
    # Rename columns to match the EXPECTED FEATURE_NAMES list order (defined in feature_extraction.py)
    X.rename(columns=csv_feature_mapping, inplace=True)
    
    # Reorder columns to ensure consistency with the feature extraction order
    X = X[FEATURE_NAMES]
    
    # Prepare target variable (y)
    # The target column is CLASS_LABEL (0: legitimate, 1: phishing)
    y = df['CLASS_LABEL']
    
    # Check for consistency
    print(f"Features used for training: {list(X.columns)}")
    
    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Total training samples: {len(X_train)}")
    print(f"Total testing samples: {len(X_test)}")
    
    # Initialize and train the classifier
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    print("Training RandomForestClassifier...")
    model.fit(X_train, y_train)
    
    # Evaluate the model
    accuracy = model.score(X_test, y_test)
    print(f"Model trained successfully. Test Accuracy: {accuracy:.4f}")
    
    # Ensure the models directory exists
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    # Save the trained model using joblib
    dump(model, model_path)
    print(f"Trained model successfully saved to: {model_path}")

if __name__ == "__main__":
    train_and_save_model()
