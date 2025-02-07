const GOOGLE_API_KEY = "AIzaSyA3FXyV9-M8Tmdl0-3MXLo7c9LjGnfCu0k";
const VT_API_KEY = "23e5dc864830882098ed10052f4801ef9cb929fbd872fd8a770d1583fb25a19b";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "check_url" && message.url) {
        checkGoogleSafeBrowsing(message.url, googleResult => {
            checkVirusTotalURL(message.url, vtResult => {
                checkLocalDatabase(message.url, localResult => {
                    sendResponse({ googleResult, vtResult, localResult });
                });
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
            if (data.matches && data.matches.length > 0) {
                callback("⚠️ Unsafe (Google Safe Browsing)");
            } else {
                callback("✅ Safe (Google)");
            }
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
            let malicious = data.data && data.data.attributes && data.data.attributes.last_analysis_stats ? data.data.attributes.last_analysis_stats.malicious : 0;
            if (malicious > 0) {
                chrome.downloads.cancel(downloadId); // Cancel the download
                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "icon.png",
                    title: "⚠️ Malicious File Detected",
                    message: `This file is flagged as unsafe (${malicious} detections)`
                });
                alert(`⚠️ Malicious File Detected: This file is flagged as unsafe (${malicious} detections)`);
            }
        })
        .catch(error => {
            console.error("VirusTotal File Check Error:", error);
        });
}

// Function to initialize the database
function initDatabase() {
    return new Promise((resolve, reject) => {
        let request = indexedDB.open("PhishGuardDB", 1);

        request.onupgradeneeded = function(event) {
            let db = event.target.result;
            if (!db.objectStoreNames.contains("reportedUrls")) {
                db.createObjectStore("reportedUrls", { keyPath: "url" });
            }
        };

        request.onsuccess = function(event) {
            resolve(event.target.result);
        };

        request.onerror = function(event) {
            reject("Database error: " + event.target.errorCode);
        };
    });
}

// Function to add a reported URL to the database
function addReportedUrl(url, reason) {
    initDatabase().then(db => {
        let transaction = db.transaction(["reportedUrls"], "readwrite");
        let store = transaction.objectStore("reportedUrls");
        let report = { url: url, reason: reason, timestamp: new Date().toISOString() };
        store.put(report);
    }).catch(error => {
        console.error("Error adding reported URL:", error);
    });
}

// Function to check URL in local database
function checkLocalDatabase(url, callback) {
    initDatabase().then(db => {
        let transaction = db.transaction(["reportedUrls"], "readonly");
        let store = transaction.objectStore("reportedUrls");
        let request = store.get(url);

        request.onsuccess = function(event) {
            if (event.target.result) {
                callback("⚠️ Reported as Phishing");
            } else {
                callback("✅ Not Reported");
            }
        };

        request.onerror = function(event) {
            console.error("Database error:", event.target.errorCode);
            callback("❓ Unknown (Database Error)");
        };
    }).catch(error => {
        console.error("Error checking local database:", error);
        callback("❓ Unknown (Database Error)");
    });
}

// Context Menu to Scan URLs
chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "scanURL",
        title: "Scan URL with PhishGuard",
        contexts: ["link"]
    });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === "scanURL") {
        let url = info.linkUrl;
        checkGoogleSafeBrowsing(url, googleResult => {
            checkVirusTotalURL(url, vtResult => {
                checkLocalDatabase(url, localResult => {
                    chrome.notifications.create({
                        type: "basic",
                        iconUrl: "icon.png",
                        title: "PhishGuard Scan Result",
                        message: `Google: ${googleResult}\nVirusTotal: ${vtResult}\nLocal Database: ${localResult}`
                    });
                });
            });
        });
    }
});