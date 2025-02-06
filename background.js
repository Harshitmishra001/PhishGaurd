const API_KEY = "AIzaSyA3FXyV9-M8Tmdl0-3MXLo7c9LjGnfCu0k";
const API_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "check_url") {
        let url = message.url;

        let requestBody = {
            client: { clientId: "phishguard", clientVersion: "1.0" },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                platformTypes: ["WINDOWS", "LINUX", "ANDROID"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url: url }]
            }
        };

        fetch(API_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(requestBody)
            })
            .then(response => response.json())
            .then(data => {
                if (data.matches) {
                    console.log("Phishing detected!", data);
                    sendResponse({ safe: false });
                } else {
                    console.log("Safe site:", url);
                    sendResponse({ safe: true });
                }
            })
            .catch(error => {
                console.error("API request failed:", error);
                sendResponse({ safe: true }); // Default to safe if API fails
            });

        return true; // Keeps the message channel open for async response
    }
});
// Monitor downloads
chrome.downloads.onCreated.addListener(downloadItem => {
    let fileUrl = downloadItem.finalUrl;
    let fileName = downloadItem.filename;

    // Check only risky file types
    const riskyExtensions = [".exe", ".zip", ".msi", ".bat", ".dll", ".scr", ".js"];
    let isRisky = riskyExtensions.some(ext => fileName.toLowerCase().endsWith(ext));

    if (isRisky) {
        console.log("Checking risky file:", fileUrl);

        let requestBody = {
            client: { clientId: "phishguard", clientVersion: "1.0" },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION"],
                platformTypes: ["WINDOWS", "LINUX", "ANDROID"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url: fileUrl }]
            }
        };

        fetch(API_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(requestBody)
            })
            .then(response => response.json())
            .then(data => {
                if (data.matches) {
                    console.log("Malicious download detected!", data);
                    chrome.downloads.cancel(downloadItem.id); // Cancel download
                    alert("⚠️ Warning! This file may be malicious.");
                } else {
                    console.log("Download seems safe:", fileUrl);
                }
            })
            .catch(error => {
                console.error("Safe Browsing API failed:", error);
            });
    }
});