import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from joblib import dump
import os
import sys
import json # New import for saving feature list

# NOTE: Since the new user-provided dataset ('Phishing_Legitimate_full.csv') 
# already contains pre-calculated features, we will skip the feature extraction 
# loop and use the columns directly. The original feature_extraction.py is 
# now only necessary for the Flask API to process new, single URLs.

# --- Configuration ---
# Update this path to your uploaded filedata/Phishing_Legitimate_full.csv
DATASET_PATH = r'G:\Phishing-URL-Detector\backend\data\Phishing_Legitimate_full.csv' 
MODEL_DIR = 'models'
MODEL_FILENAME = 'phishing_model.pkl'
FEATURES_FILENAME = 'feature_metadata.json' # New file for feature names

# Create the model directory if it doesn't exist
os.makedirs(os.path.join('backend', MODEL_DIR), exist_ok=True)
MODEL_FULL_PATH = os.path.join('backend', MODEL_DIR, MODEL_FILENAME)
FEATURES_FULL_PATH = os.path.join('backend', MODEL_DIR, FEATURES_FILENAME) # Full path for new file

def train_and_save_model():
    """
    Loads pre-processed data from the CSV, trains a RandomForest model, 
    and saves the model and the feature list to a .pkl and .json file, respectively.
    """
    print(f"Loading data from {DATASET_PATH}...")
    try:
        # Load the CSV file
        df = pd.read_csv(DATASET_PATH)

        # The 'id' column and the target column should be excluded from features (X)
        # The target variable is identified as 'CLASS_LABEL' from the CSV header.
        
        # Define features (X) by dropping non-feature columns
        # We drop 'id' and the target column 'CLASS_LABEL'
        X = df.drop(columns=['id', 'CLASS_LABEL']) 
        
        # Define target variable (y)
        y = df['CLASS_LABEL']
        
        # Check if the feature set is empty
        if X.empty:
            print("ERROR: Feature matrix (X) is empty after dropping columns. Check CSV content.")
            return

    except FileNotFoundError:
        print(f"FATAL ERROR: The file {DATASET_PATH} was not found.")
        sys.exit(1)
    except KeyError as e:
        print(f"FATAL ERROR: Required column missing. Check if 'CLASS_LABEL' exists. Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred during data loading: {e}")
        sys.exit(1)
        
    print(f"Dataset loaded. Total samples: {len(df)}")
    print(f"Number of features being used: {X.shape[1]}")

    # --- Feature List Saving (NEW) ---
    feature_list = X.columns.tolist()
    print(f"Saving {len(feature_list)} feature names to {FEATURES_FULL_PATH}...")
    with open(FEATURES_FULL_PATH, 'w') as f:
        json.dump(feature_list, f, indent=4)
    
    # --- Training ---
    print("Training RandomForestClassifier...")
    
    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Initialize and train the model
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate the model (Optional, but good practice)
    accuracy = model.score(X_test, y_test)
    print(f"Model trained successfully. Test Accuracy: {accuracy:.4f}")

    # --- Save Model ---
    print(f"Saving model to {MODEL_FULL_PATH}...")
    dump(model, MODEL_FULL_PATH)
    print("Model saved successfully. You can now run 'python backend/app.py'")

if __name__ == '__main__':
    train_and_save_model()
