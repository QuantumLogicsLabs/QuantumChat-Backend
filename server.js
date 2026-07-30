import "dotenv/config";
import http from "http";
import { Server } from "socket.io";
import { createApp } from "./src/app.js";
import { connectDB } from "./src/config/db.js";
import { attachSocket } from "./src/socket/index.js";
import { runExpiryJobs } from "./src/jobs/expireMessages.js";
import FriendRequest from "./src/models/FriendRequest.js";

async function main() {
  await connectDB();
  await FriendRequest.syncIndexes();

  const app = createApp();
  const server = http.createServer(app);
  const allowedOrigins = String(process.env.CLIENT_URL || 'http://localhost:5173')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

  const io = new Server(server, {
    cors: { origin: allowedOrigins },
  });
  attachSocket(io);
  app.set("io", io);

  const EXPIRY_INTERVAL_MS = 60_000;
  setInterval(() => {
    runExpiryJobs(io).catch((err) => console.error("Expiry job failed:", err.message));
  }, EXPIRY_INTERVAL_MS);
  setTimeout(() => {
    runExpiryJobs(io).catch((err) => console.error("Expiry job failed:", err.message));
  }, 5_000);

  const port = process.env.PORT || 5000;
  server.listen(port, () =>
    console.log(`QuantumChat backend listening on port ${port}`),
  );
}

main().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});