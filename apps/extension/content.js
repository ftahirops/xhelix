// xhelix Browser Bridge — content script.
//
// Runs in every page at document_start. Captures the Referer
// chain and any window.opener relationship the background-page
// webNavigation API can't see, then forwards to the service
// worker.
//
// Kept minimal: this script must not slow page load. No fetch
// hooks, no DOM mutation observers, no synchronous I/O.

(function () {
  if (window.__xhelix_bridge_loaded) return;
  window.__xhelix_bridge_loaded = true;

  const payload = {
    kind: "page_meta",
    url: location.href,
    referrer: document.referrer || "",
    opener: window.opener ? "yes" : "no",
  };

  // chrome.runtime.sendMessage doesn't reach a native-messaging
  // port directly — we deliver via a runtime message to the
  // background service worker which has the port.
  try {
    chrome.runtime.sendMessage(payload);
  } catch (_) {
    // Extension context may already be gone (page reload race).
  }
})();
