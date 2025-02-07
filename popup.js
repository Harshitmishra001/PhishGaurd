document.addEventListener("DOMContentLoaded", function() {
    let statusText = document.getElementById("status");
    let reportButton = document.getElementById("report");
    let scanButton = document.getElementById("scanButton");
    let urlInput = document.getElementById("urlInput");
    let resultText = document.getElementById("resultText");
    let blockedFilesList = document.getElementById("blockedFilesList");

    // Ensure elements exist before attaching event listeners
    if (!statusText || !reportButton || !scanButton || !urlInput || !resultText || !blockedFilesList) {
        console.error("Some elements are missing from popup.html.");
        return;
    }

    // ✅ Scan Current Tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
        let currentUrl = tabs[0] ? tabs[0].url : null;
        if (!currentUrl) return;

        console.log("Checking URL:", currentUrl);

        chrome.runtime.sendMessage({ action: "check_url", url: currentUrl }, function(response) {
            console.log("API Response:", response);

            if (response && response.googleResult && response.vtResult) {
                statusText.textContent = `Google: ${response.googleResult}\nVirusTotal: ${response.vtResult}`;
                statusText.classList.add(response.googleResult.includes("Safe") && response.vtResult.includes("Safe") ? "safe" : "phishing");
            } else {
                statusText.textContent = "Error checking URL.";
            }
        });
    });

    // ✅ Scan Downloads
    if (chrome.downloads) {
        chrome.downloads.search({}, function(downloads) {
            downloads.forEach(download => {
                if (download.state === "in_progress") {
                    statusText.innerHTML += `<p>🔄 Downloading: ${download.filename}</p>`;
                } else if (download.state === "interrupted") {
                    statusText.innerHTML += `<p>⚠️ Warning: Suspicious file blocked - ${download.filename}</p>`;
                }
            });
        });
    } else {
        console.error("chrome.downloads API is not available.");
        statusText.innerHTML = `<p>⚠️ Downloads API not available.</p>`;
    }

    // ✅ Report Button Click
    reportButton.addEventListener("click", function() {
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            let currentUrl = tabs[0] ? tabs[0].url : null;
            if (!currentUrl) return;

            addReportedUrl(currentUrl, "User reported");
            alert("Thank you for reporting. We will review this link.");
        });
    });

    // ✅ Manual URL Scan (User Input)
    scanButton.addEventListener("click", function() {
        let url = urlInput.value.trim();
        if (url === "") {
            resultText.innerHTML = "❌ Please enter a URL.";
            return;
        }

        checkGoogleSafeBrowsing(url, googleResult => {
            checkVirusTotalURL(url, vtResult => {
                checkLocalDatabase(url, localResult => {
                    resultText.innerHTML = `🔍 Scan Results:<br>
                    Google: ${googleResult}<br>
                    VirusTotal: ${vtResult}<br>
                    Local Database: ${localResult}`;
                });
            });
        });
    });

    // ✅ Display Blocked Files History
    displayBlockedFilesHistory();
});

// ✅ Google Safe Browsing API Call
function checkGoogleSafeBrowsing(url, callback) {
    const apiKey = "AIzaSyA3FXyV9-M8Tmdl0-3MXLo7c9LjGnfCu0k";
    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

    let requestBody = {
        client: { clientId: "PhishGuard", clientVersion: "1.0" },
        threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: url }]
        }
    };

    fetch(apiUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(requestBody)
        })
        .then(response => response.json())
        .then(data => {
            if (data.matches && data.matches.length > 0) {
                callback("⚠️ Phishing Detected!");
                alert("Phishing Detected in the URL");
            } else {
                callback("✅ Safe");
            }
        })
        .catch(error => {
            console.error("Safe Browsing API error:", error);
            callback("❌ Error checking URL.");
        });
}

// ✅ VirusTotal API Call
function checkVirusTotalURL(url, callback) {
    const apiKey = "23e5dc864830882098ed10052f4801ef9cb929fbd872fd8a770d1583fb25a19b";
    const apiUrl = `https://www.virustotal.com/api/v3/urls`;

    fetch(apiUrl, {
            method: "POST",
            headers: {
                "x-apikey": apiKey,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: `url=${encodeURIComponent(url)}`
        })
        .then(response => response.json())
        .then(data => {
            let analysisId = data.data ? data.data.id : null;
            if (!analysisId) {
                callback("❌ Error submitting URL.");
                return;
            }

            // Check scan results
            setTimeout(() => {
                fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                        headers: { "x-apikey": apiKey }
                    })
                    .then(response => response.json())
                    .then(result => {
                        let maliciousCount = result.data && result.data.attributes && result.data.attributes.stats ? result.data.attributes.stats.malicious || 0 : 0;
                        callback(maliciousCount > 0 ? `⚠️ ${maliciousCount} engines flagged this URL!` : "✅ Safe");
                    })
                    .catch(error => {
                        console.error("VirusTotal API error:", error);
                        callback("❌ Error checking URL.");
                    });
            }, 5000);
        })
        .catch(error => {
            console.error("VirusTotal API error:", error);
            callback("❌ Error submitting URL.");
        });
}

// ✅ Local Database Check
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

// Function to initialize the database
function initDatabase() {
    return new Promise((resolve, reject) => {
        let request = indexedDB.open("PhishGuardDB", 2); // Increment version to 2

        request.onupgradeneeded = function(event) {
            let db = event.target.result;
            if (!db.objectStoreNames.contains("reportedUrls")) {
                db.createObjectStore("reportedUrls", { keyPath: "url" });
            }
            if (!db.objectStoreNames.contains("blockedFiles")) {
                db.createObjectStore("blockedFiles", { keyPath: "id", autoIncrement: true });
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

// Function to display blocked files history
function displayBlockedFilesHistory() {
    initDatabase().then(db => {
        let transaction = db.transaction(["blockedFiles"], "readonly");
        let store = transaction.objectStore("blockedFiles");
        let request = store.getAll();

        request.onsuccess = function(event) {
            let blockedFiles = event.target.result;
            let blockedFilesList = document.getElementById("blockedFilesList");
            blockedFilesList.innerHTML = "";

            if (blockedFiles.length > 0) {
                blockedFiles.forEach(file => {
                    let listItem = document.createElement("li");
                    listItem.textContent = `URL: ${file.fileUrl}, Malicious Count: ${file.maliciousCount}, Timestamp: ${file.timestamp}`;
                    blockedFilesList.appendChild(listItem);
                });
            } else {
                blockedFilesList.innerHTML = "<li>No blocked files found.</li>";
            }
        };

        request.onerror = function(event) {
            console.error("Error retrieving blocked files:", event.target.errorCode);
        };
    }).catch(error => {
        console.error("Error displaying blocked files history:", error);
    });
}