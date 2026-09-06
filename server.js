import "dotenv/config";
import http from "http";
import { Server } from "socket.io";
import { createApp } from "./src/app.js";
import { connectDB } from "./src/config/db.js";
import { allowedOrigins } from "./src/config/corsOrigins.js";
import { runBirthdayNotifications } from "./src/jobs/birthdayNotifications.js";
import { runExpiryJobs } from "./src/jobs/expireMessages.js";
import { runStoryPublishJobs } from "./src/jobs/publishScheduledStories.js";
import FriendRequest from "./src/models/FriendRequest.js";
import { attachSocket } from "./src/socket/index.js";

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
    cors: {
      origin: (origin, callback) => {
        // Native mobile clients often omit Origin; allow that in dev.
        if (!origin || allowedOrigins.includes(origin) || process.env.NODE_ENV !== "production") {
          callback(null, true);
        } else {
          callback(null, false);
        }
      },
    },
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

  const STORY_PUBLISH_INTERVAL_MS = 30_000;
  setInterval(() => {
    runStoryPublishJobs(io).catch((err) => console.error("Story publish job failed:", err.message));
  }, STORY_PUBLISH_INTERVAL_MS);
  setTimeout(() => {
    runStoryPublishJobs(io).catch((err) => console.error("Story publish job failed:", err.message));
  }, 8_000);

  const BIRTHDAY_CHECK_INTERVAL_MS = 60_000; // must stay <= the job's 1-minute window
  setInterval(() => {
    runBirthdayNotifications().catch((err) => console.error("Birthday notification job failed:", err.message));
  }, BIRTHDAY_CHECK_INTERVAL_MS);

  const port = process.env.PORT || 5000;
  server.listen(port, () =>
    console.log(`QuantumChat backend listening on port ${port}`),
  );
}

main().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});