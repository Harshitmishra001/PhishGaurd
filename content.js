chrome.runtime.sendMessage({ action: "check_url", url: window.location.href }, function(response) {
    if (response && (response.googleResult.includes("Unsafe") || response.vtResult.includes("Unsafe") || response.localResult.includes("Phishing"))) {
        window.location.href = chrome.runtime.getURL("blocked.html");
    }
});