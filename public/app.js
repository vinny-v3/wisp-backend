import { BareMuxConnection } from "/baremux/index.mjs";

const { ScramjetController } = $scramjetLoadController();

const scramjet = new ScramjetController({
  prefix: "/scramjet/",
  files: {
    wasm: "/scram/scramjet.wasm.wasm",
    all: "/scram/scramjet.all.js",
    sync: "/scram/scramjet.sync.js",
  },
});

const status = document.getElementById("status");
const input = document.getElementById("url");
const form = document.getElementById("form");

(async () => {
  try {
    await scramjet.init();
    await navigator.serviceWorker.register("/sw.js", { scope: "/" });
    await navigator.serviceWorker.ready;

    // Point the Epoxy transport at our own Wisp endpoint.
    const wispUrl = (location.protocol === "https:" ? "wss" : "ws") + "://" + location.host + "/wisp/";
    const connection = new BareMuxConnection("/baremux/worker.js");
    await connection.setTransport("/epoxy/index.mjs", [{ wisp: wispUrl }]);

    const frame = scramjet.createFrame();
    document.getElementById("frame-container").appendChild(frame.frame);
    frame.addEventListener("urlchange", (e) => (input.value = e.url));

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      frame.go(normalize(input.value.trim()));
    });
    status.textContent = "Ready";
  } catch (err) {
    console.error(err);
    status.textContent = "Setup failed: " + err.message;
  }
})();

// Turn user input into a URL, falling back to a search query.
function normalize(value) {
  if (/^https?:\/\//i.test(value)) return value;
  if (/^[^\s]+\.[^\s]{2,}$/.test(value)) return "https://" + value;
  return "https://duckduckgo.com/?q=" + encodeURIComponent(value);
}
