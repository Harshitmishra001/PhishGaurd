const GOOGLE_API_KEY = "AIzaSyA3FXyV9-M8Tmdl0-3MXLo7c9LjGnfCu0k";
const VT_API_KEY = "23e5dc864830882098ed10052f4801ef9cb929fbd872fd8a770d1583fb25a19b";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "check_url" && message.url) {
        checkGoogleSafeBrowsing(message.url, googleResult => {
            checkVirusTotalURL(message.url, vtResult => {
                sendResponse({ googleResult, vtResult });
            });
        });
        return true; // Indicates that the response will be sent asynchronously
    }
});

// Listen for downloads
chrome.downloads.onCreated.addListener(downloadItem => {
    console.log("Download started:", downloadItem.filename);

    // Get file extension
    const riskyExtensions = [".exe", ".zip", ".msi", ".apk", ".bat", ".dll", ".scr", ".js"];
    let isRisky = riskyExtensions.some(ext => downloadItem.filename.toLowerCase().endsWith(ext));

    if (isRisky) {
        console.log("Potentially risky file detected:", downloadItem.filename);

        // First check with VirusTotal (faster hash lookup)
        checkVirusTotalFile(downloadItem.finalUrl, downloadItem.id);
    }
});

// Function to check URL with Google Safe Browsing
function checkGoogleSafeBrowsing(url, callback) {
    const API_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`;

    let requestBody = {
        client: { clientId: "phishguard", clientVersion: "1.0" },
        threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            platformTypes: ["ANY_PLATFORM"],
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
            callback(data.matches ? "⚠️ Unsafe (Google Safe Browsing)" : "✅ Safe (Google)");
        })
        .catch(error => {
            console.error("Google Safe Browsing API error:", error);
            callback("❓ Unknown (Google Error)");
        });
}

// Function to check URL with VirusTotal
function checkVirusTotalURL(url, callback) {
    fetch(`https://www.virustotal.com/api/v3/urls`, {
            method: "POST",
            headers: { "x-apikey": VT_API_KEY, "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        })
        .then(response => response.json())
        .then(data => {
            let id = data.data.id;
            return fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, {
                headers: { "x-apikey": VT_API_KEY }
            });
        })
        .then(response => response.json())
        .then(result => {
            let maliciousCount = result.data.attributes.stats.malicious;
            callback(maliciousCount > 0 ? `⚠️ Unsafe (VirusTotal: ${maliciousCount} reports)` : "✅ Safe (VirusTotal)");
        })
        .catch(error => {
            console.error("VirusTotal API error:", error);
            callback("❓ Unknown (VirusTotal Error)");
        });
}

// Function to check file hash with VirusTotal
function checkVirusTotalFile(fileUrl, downloadId) {
    fetch(`https://www.virustotal.com/api/v3/files/${fileUrl}`, {
            headers: { "x-apikey": VT_API_KEY }
        })
        .then(response => response.json())
        .then(data => {
            let malicious = data.data.attributes.last_analysis_stats.malicious;
            if (malicious > 0) {
                chrome.downloads.cancel(downloadId); // Cancel the download
                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "icon.png",
                    title: "⚠️ Malicious File Detected",
                    message: `This file is flagged as unsafe (${malicious} detections)`
                });
            }
        })
        .catch(error => {
            console.error("VirusTotal File Check Error:", error);
        });
}

// Context Menu to Scan URLs
chrome.contextMenus.create({
    id: "scanURL",
    title: "Scan URL with PhishGuard",
    contexts: ["link"]
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === "scanURL") {
        let url = info.linkUrl;
        checkGoogleSafeBrowsing(url, googleResult => {
            checkVirusTotalURL(url, vtResult => {
                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "icon.png",
                    title: "PhishGuard Scan Result",
                    message: `Google: ${googleResult}\nVirusTotal: ${vtResult}`
                });
            });
        });
    }
});