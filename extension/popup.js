document.addEventListener('DOMContentLoaded', () => {
    // UI elements
    const statusText = document.getElementById('status-text');
    const statusContainer = document.getElementById('status-container');
    const probaText = document.getElementById('proba-text');
    const loadingSpinner = document.getElementById('loading-spinner');

    /**
     * Updates the popup UI based on the prediction result.
     * @param {string} prediction 'safe', 'phishing', 'error', or 'unknown'.
     * @param {number|null} proba The phishing probability (0-1).
     * @param {string} reason Optional text explaining the prediction source.
     */
    function updateUI(prediction, proba, reason) {
        loadingSpinner.classList.add('hidden');
        statusContainer.classList.remove('hidden');

        let color = '#3498db'; // Default blue for checking/unknown
        let text = 'CHECKING...';
        let probaDisplay = '';
        let reasonDisplay = reason || '';

        if (prediction === 'phishing') {
            color = '#e74c3c'; // Red
            text = 'PHISHING ALERT';
            // Display probability only if available
            probaDisplay = proba !== null ? `(P = ${Math.round(proba * 10000) / 100}%)` : 'Rule-Based';
        } else if (prediction === 'safe') {
            color = '#2ecc71'; // Green
            text = 'SAFE';
            probaDisplay = proba !== null ? `(P = ${Math.round(proba * 10000) / 100}%)` : '';
        } else if (prediction === 'error') {
            color = '#f39c12'; // Orange
            text = 'API ERROR';
            reasonDisplay = 'Could not reach Flask API.';
        } else {
            color = '#95a5a6'; // Gray
            text = 'NOT A WEB PAGE';
            reasonDisplay = 'Analysis skipped for file:// or chrome:// pages.';
        }

        statusContainer.style.backgroundColor = color;
        statusText.textContent = text;
        probaText.textContent = probaDisplay;
        
        // Use the reason text area for displaying detailed reason/error
        document.getElementById('reason-text').textContent = reasonDisplay;
    }

    /**
     * Gets the active tab's URL and initiates a fresh check via the background script.
     */
    function requestActiveTabCheck() {
        // Show loading state immediately
        loadingSpinner.classList.remove('hidden');
        statusContainer.classList.add('hidden');

        // 1. Get the current active tab's URL
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            const currentTab = tabs[0];
            const url = currentTab.url;

            // Check if URL is valid for analysis
            if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
                updateUI('unknown', null);
                return;
            }

            // 2. Send a message to background.js to perform a NEW check
            chrome.runtime.sendMessage({ action: "requestFreshCheck", url: url }, function(response) {
                if (chrome.runtime.lastError) {
                    // This often happens if the background script is not running or the extension was just reloaded
                    console.error("Error communicating with background script:", chrome.runtime.lastError.message);
                    updateUI('error', null, 'Failed to connect to background worker.');
                    return;
                }

                if (response && response.status === "success") {
                    // 3. Update UI with the fresh result
                    // Note: The API response contains 'reason', but we only pass prediction and proba here.
                    // The reason text will be populated with the probability or status.
                    updateUI(response.prediction, response.proba, response.reason || (response.proba !== null ? 'ML Prediction' : 'Rule-Based'));
                } else {
                    console.error("Background script returned an error or no response.", response);
                    updateUI('error', null, 'Prediction failed or invalid response.');
                }
            });
        });
    }

    // Start the process when the popup loads
    requestActiveTabCheck();
});
