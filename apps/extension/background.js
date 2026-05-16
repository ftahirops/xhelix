// xhelix Browser Bridge — background service worker.
//
// Reports tab → URL events to a native messaging host that proxies
// them to the xhelix daemon's LocalAPI. The daemon then attaches
// (tab, URL, referrer) metadata to the next outbound TCP connect
// from the browser pid, closing the "which tab caused this
// request" attribution gap.
//
// Wire shape (one JSON per native-messaging frame):
//
//   { kind: "tab_nav", tabId, url, referrer, ts }
//   { kind: "tab_focus", tabId, url, ts }
//   { kind: "tab_remove", tabId, ts }

const NATIVE_HOST = "io.xhelix.bridge";
const QUEUE_FLUSH_MS = 200;
const QUEUE_MAX = 256;

let port = null;
let queue = [];

function connect() {
  try {
    port = chrome.runtime.connectNative(NATIVE_HOST);
    port.onDisconnect.addListener(() => {
      console.warn("xhelix: native host disconnected; will retry");
      port = null;
      setTimeout(connect, 5000);
    });
  } catch (err) {
    console.warn("xhelix: connectNative failed", err);
    setTimeout(connect, 5000);
  }
}

function send(msg) {
  msg.ts = Date.now();
  queue.push(msg);
  if (queue.length > QUEUE_MAX) {
    queue = queue.slice(-QUEUE_MAX);
  }
}

function flush() {
  if (!port || queue.length === 0) return;
  const batch = queue;
  queue = [];
  try {
    port.postMessage({ kind: "batch", events: batch });
  } catch (err) {
    console.warn("xhelix: postMessage failed", err);
    // Re-queue (bounded)
    queue = batch.concat(queue).slice(-QUEUE_MAX);
  }
}

setInterval(flush, QUEUE_FLUSH_MS);
connect();

// Navigation events
chrome.webNavigation.onCommitted.addListener((details) => {
  send({
    kind: "tab_nav",
    tabId: details.tabId,
    url: details.url,
    transition: details.transitionType,
  });
});

// Tab activation (focus change)
chrome.tabs.onActivated.addListener(async (info) => {
  try {
    const tab = await chrome.tabs.get(info.tabId);
    send({ kind: "tab_focus", tabId: info.tabId, url: tab.url || "" });
  } catch (_) {
    // tab might have closed between activation and lookup
  }
});

// Tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  send({ kind: "tab_remove", tabId });
});
