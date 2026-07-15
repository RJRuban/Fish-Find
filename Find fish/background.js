// Simple list of suspicious indicators
const suspiciousKeywords = ["secure-login", "verify-account", "update-password"];
const lookalikes = [/paypa1/i, /g00gle/i, /microsoft-support/i];

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only run the check when the page URL is fully updated
  if (changeInfo.status === "complete" && tab.url) {
    try {
      const urlObj = new URL(tab.url);
      const hostname = urlObj.hostname.toLowerCase();
      let isSuspicious = false;
      let reason = "";

      // 1. Check lookalike domains
      for (const pattern of lookalikes) {
        if (pattern.test(hostname)) {
          isSuspicious = true;
          reason = `Domain looks suspiciously similar to a trusted brand: "${hostname}"`;
          break;
        }
      }

      // 2. Check suspicious keywords in the URL path/query
      if (!isSuspicious) {
        for (const keyword of suspiciousKeywords) {
          if (tab.url.toLowerCase().includes(keyword)) {
            isSuspicious = true;
            reason = `URL contains highly suspicious keywords: "${keyword}"`;
            break;
          }
        }
      }

      // If flagged, trigger a warning notification
      if (isSuspicious) {
        chrome.notifications.create({
          type: "basic",
          iconUrl: "fish.jpg", // Ensure you have an icon.png in your folder, or use a placeholder
          title: "⚠️ Potential Phishing Warning!",
          message: reason,
          priority: 2
        });
      }
    } catch (e) {
      console.error("Error parsing URL:", e);
    }
  }
});