import { App } from "@modelcontextprotocol/ext-apps";

const app = new App({ name: "message-status-card", version: "1" });
const root = document.getElementById("root");

app.ontoolresult = (result) => {
  const row = result.structuredContent?.data;
  if (!root || !row) return;
  root.textContent = `${row.status} · sent ${row.sent_at} · delivered ${row.delivered_at || "pending"}`;
};

void app.connect();
