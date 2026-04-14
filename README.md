# Phishing URL Detector: Full-Stack ML Security

A complete, full-stack solution to detect potentially malicious phishing URLs in real time.  
This project uses a trained **Random Forest** machine learning model hosted on a **Flask API**, along with a lightweight **Chrome Extension** for instant security feedback.

---

##  Features

- ✅ **Real-time Analysis**  
  Instantly checks the current tab’s URL when the user clicks the extension icon.

- 🧠 **Machine Learning Backend**  
  Uses a trained **RandomForest** classifier to analyze URL features (length, subdomains, symbols, etc.).

- 🧩 **Feature Engineering**  
  Core feature extraction handled via `feature_extraction.py`.

- 🔐 **Cross-Origin API Support**  
  Secure communication between the Chrome Extension and Flask backend.

- 💡 **Lightweight Frontend**  
  Simple, non-intrusive Chrome Extension built with **Manifest V3**.

---

## 🛠️ Technology Stack

| Component        | Technology                        | Purpose                                      |
|------------------|-----------------------------------|----------------------------------------------|
| Machine Learning | Python, Scikit-learn (RandomForest) | Training, feature extraction, predictions    |
| Backend API      | Flask                             | REST API serving model predictions           |
| Frontend         | Chrome Extension (Manifest V3)    | UI + background requests                     |
| Model Storage    | Pickle (.pkl)                     | Saving the trained ML model                  |

---

## 📂 Project Structure

```

phishing-url-detector/
│
├── backend/                 
│   ├── data/
│   │   └── phishing_dataset.csv     
│   ├── models/
│   │   └── phishing_model.pkl        
│   ├── train_model.py                
│   ├── feature_extraction.py         
│   ├── app.py                        
│   └── requirements.txt              
│
└── extension/                
├── manifest.json        
├── background.js       
├── popup.html         
├── popup.js             
├── style.css           
└── icons/            

````

---

## 🚀 Setup & Installation

### ✅ 1. Backend (Flask + ML Model)

```bash
cd backend
````

**Create a virtual environment (recommended):**

```bash
python3 -m venv venv
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

**Install dependencies:**

```bash
pip install -r requirements.txt
```

**Train the model:**

```bash
python train_model.py
```

This will:

* Load the dataset
* Extract features
* Train the RandomForest model
* Save it to `backend/models/phishing_model.pkl`

**Run the API:**

```bash
python app.py
```

You should see:

```
Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
```

---

### ✅ 2. Chrome Extension Setup

**Add icons**
Make sure these files exist under `extension/icons/`:

* `icon16.png`
* `icon48.png`
* `icon128.png`

**Load in Chrome/Edge:**

1. Open `chrome://extensions` or `edge://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `extension/` folder

The extension icon should now appear in your browser toolbar.

---

## 💡 Usage

1. Start the Flask API:

   ```bash
   python app.py
   ```

2. Open any website (e.g., `https://google.com` or a test phishing URL).

3. Click the **Phishing URL Detector** extension icon.

4. The popup will display the prediction based on your local ML model.

| Verdict  | Indicator | Meaning                                              |
| -------- | --------- | ---------------------------------------------------- |
| SAFE     | ✅ Green   | URL is predicted to be legitimate                    |
| PHISHING | ⚠️ Red    | URL shows characteristics commonly found in phishing |
