# Phishing URL Detector

![Project Icon](extension/icons/icon128.png)

> A full-stack demo that detects potentially malicious phishing URLs in real time. It uses a RandomForest model served by a Flask API and a lightweight Chrome extension that checks the current tab URL.

---

## 🔎 What this project does

This repo contains a complete end-to-end demo for detecting phishing URLs. The user installs and runs the backend (Python + Flask) locally. The Chrome extension calls the backend to evaluate the currently open tab URL and shows a clear safe / suspicious status in the popup.

This project is ideal for learning feature engineering for URLs, building a small ML pipeline, and connecting a browser extension to a Python API.

---

## Features

* Fast URL feature extraction (length, tokens, dot counts, IP-in-host tests, suspicious words, etc.)
* RandomForest classifier trained on a demo dataset
* Flask API with a single `/predict` endpoint (POST)
* Chrome Extension (Manifest V3) that checks the active tab URL in real time
* Clear popup UI with safety status and explanation

---

## Repo structure

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
│   ├── test_api.py
│   └── requirements.txt
│
├── extension/
│   ├── manifest.json
│   ├── background.js
│   ├── popup.html
│   ├── popup.js
│   ├── style.css
│   └── icons/
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
│
├── .gitignore
├── README.md
└── LICENSE
```

---

## Quick start

### 1) Backend (Python + Flask)

1. Open a terminal and go to the backend folder:

```bash
cd backend
```

2. Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Train the model (this reads `data/phishing_dataset.csv`, extracts features, trains RandomForest, and saves the model to `models/phishing_model.pkl`):

```bash
python train_model.py
```

5. Run the Flask API (default: [http://127.0.0.1:5000](http://127.0.0.1:5000)):

```bash
python app.py
```

Keep the API running while you use the extension.

---

### 2) Chrome Extension (Manifest V3)

1. Create three placeholder icons and place them at `extension/icons/icon16.png`, `icon48.png`, and `icon128.png`.

2. Open Chrome or Edge and go to `chrome://extensions` or `edge://extensions`.

3. Enable Developer mode.

4. Click **Load unpacked** and select the `extension/` folder.

5. The extension icon should appear in the toolbar. Visit any site and click the icon. The popup will show the prediction returned by your backend.

---

## API specification

**POST /predict**

Request JSON

```json
{
  "url": "https://example.com/path?query=1"
}
```

Response JSON

```json
{
  "prediction": "malicious",      // or "benign"
  "probability": 0.93,            // model confidence
  "explanation": {
    "feature_scores": {"url_length": 1, "num_dots": 0, ...},
    "reasons": ["suspicious keyword: login", "long hostname"]
  }
}
```

A simple `test_api.py` script is included to exercise the endpoint.

---

## How the ML side works (short)

* `feature_extraction.py` contains functions that transform a raw URL into numeric features the model understands. Examples:

  * URL length and number of path segments
  * Hostname token counts and presence of IP addresses
  * Number of dots and hyphens
  * Presence of suspicious words like `login`, `secure`, `verify`, etc.
  * Ratio of digits/letters

* `train_model.py` loads `data/phishing_dataset.csv`, applies the feature extractor, trains a `RandomForestClassifier`, evaluates it on a holdout set, prints key metrics, and saves the trained model to `models/phishing_model.pkl`.

* `app.py` loads the saved model at startup and exposes `/predict` to receive a URL, run the extractor, and return the prediction and a compact explanation.

---

## Tips to improve accuracy

* Use more labeled data and balance classes.
* Try feature selection or using more advanced models like XGBoost or LightGBM.
* Add heuristic signals such as WHOIS age, SSL certificate checks, or domain registration country.
* Collect real-world false positives and false negatives and add them to the training set.

---

## Security and privacy notes

* This demo sends URLs from your browser to a local API. Do not run this against private or internal URLs you cannot share. If you deploy remotely, use HTTPS and authentication.
* The model is for educational/demo purposes only. Do not rely on it as your sole phishing defense.

---

## Development notes

* If you change features, re-run `python train_model.py` to re-create `models/phishing_model.pkl`.
* To add more UI details to the extension, update `popup.html`, `popup.js`, and `style.css`. Keep the extension logic in `background.js` minimal; let `popup.js` handle rendering.

---

## Example curl (quick test)

```bash
curl -X POST http://127.0.0.1:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url":"http://192.168.1.2/verify-login"}'
```

---

## Contributing

If you want to contribute:

1. Fork the repo
2. Create a feature branch
3. Add tests and documentation
4. Open a pull request describing the change

---

## License

This project is open source. See the `LICENSE` file for details.

* Produce a polished popup design and matching icons.
* Create a `deploy/` folder with a Dockerfile for the backend.
