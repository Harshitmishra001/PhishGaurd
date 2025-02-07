chrome.runtime.sendMessage({ action: "check_url", url: window.location.href }, function(response) {
    if (response && response.googleResult && response.googleResult.includes("Unsafe")) {
        alert("⚠️ Warning: This site may be unsafe!\n" + response.googleResult);
    }
});