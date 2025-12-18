// static/tick.js
function startTicker(sessionId, windowSec, showQR) {
  console.log("Ticker running", { sessionId });

  function updateCount() {
    fetch(`/live_count/${sessionId}`, { cache: "no-store" })
      .then(r => r.json())
      .then(data => {
        const el = document.getElementById('count');
        if (el) el.textContent = data.count;
      })
      .catch(() => {});
  }

  updateCount();
  setInterval(updateCount, 5000);
}