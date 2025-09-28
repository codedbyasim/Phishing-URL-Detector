const API_ENDPOINT = "http://127.0.0.1:5000/predict"; // Local Flask API endpoint

// -------------------------------------------------------------
// EVENT LISTENER (Passive Check on URL change/load complete)
// This is used for passive updates only.
// -------------------------------------------------------------
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    // Only proceed if the URL has finished loading (or is about to finish)
    if (changeInfo.status === 'complete' || changeInfo.url) {
        // We only want to analyze HTTP/HTTPS links
        if (tab.url && (tab.url.startsWith('http://') || tab.url.startsWith('https://'))) {
            // Send the URL to the Flask backend for prediction
            const prediction = await checkUrl(tab.url);
            
            // Store the result in local storage so the popup can read it
            chrome.storage.local.set({ 
                lastPrediction: prediction.prediction, 
                phishingProba: prediction.phishing_proba 
            });
        } else {
            // Clear storage if not a web page
            chrome.storage.local.set({ lastPrediction: 'safe', phishingProba: null });
        }
    }
});

// -------------------------------------------------------------
// CORE API CALL FUNCTION
// -------------------------------------------------------------
async function checkUrl(url) {
    try {
        const response = await fetch(API_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        return data;

    } catch (error) {
        console.error("Error calling Phishing API:", error);
        // Default safe result if API is unreachable or fails
        return { prediction: 'error', phishing_proba: null };
    }
}

// -------------------------------------------------------------
// MESSAGE HANDLER (New: Allows popup.js to request a fresh check)
// -------------------------------------------------------------
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "requestFreshCheck" && request.url) {
        // Perform a new prediction check
        checkUrl(request.url).then(prediction => {
            // Store the new result in storage (optional, but good practice)
            chrome.storage.local.set({ 
                lastPrediction: prediction.prediction, 
                phishingProba: prediction.phishing_proba 
            });
            // Send the result back to the popup immediately
            sendResponse({ status: "success", prediction: prediction.prediction, proba: prediction.phishing_proba });
        }).catch(error => {
            console.error("Fresh check failed:", error);
            sendResponse({ status: "error", message: error.message });
        });
        
        // Return true to indicate that sendResponse will be called asynchronously
        return true; 
    }
});
