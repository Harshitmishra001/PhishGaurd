document.addEventListener("DOMContentLoaded", function() {
    let statusText = document.getElementById("status");
    let reportButton = document.getElementById("report");

    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
        let currentUrl = tabs[0].url;
        console.log("Checking URL:", currentUrl); // Debugging log

        chrome.runtime.sendMessage({ action: "check_url", url: currentUrl }, function(response) {
            console.log("API Response:", response); // Debugging log

            if (response.safe) {
                statusText.textContent = "Safe ✅";
                statusText.classList.add("safe");
            } else {
                statusText.textContent = "Phishing Detected! ❌";
                statusText.classList.add("phishing");
            }
        });
    });
    if (!chrome.downloads) {
        console.error("chrome.downloads API is not available.");
        statusText.innerHTML = `<p>⚠️ Downloads API not available.</p>`;
        return;
    }
    chrome.downloads.search({}, function(downloads) {
        downloads.forEach(download => {
            if (download.state === "in_progress") {
                statusText.innerHTML += `<p>🔄 Downloading: ${download.filename}</p>`;
            } else if (download.state === "interrupted") {
                statusText.innerHTML += `<p>⚠️ Warning: Suspicious file blocked - ${download.filename}</p>`;
            }
        });
    });
    reportButton.addEventListener("click", function() {
        alert("Thank you for reporting. We will review this link.");
    });
});