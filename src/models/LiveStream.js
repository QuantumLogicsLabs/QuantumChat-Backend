import mongoose from 'mongoose';

export const LIVE_AUDIENCE_TYPES = ['friends', 'group', 'custom'];
export const LIVE_RECORDING_DECISIONS = ['none', 'pending', 'saved', 'discarded'];
export const LIVE_TITLE_MAX = 100;
export const LIVE_HEARTBEAT_STALE_MS = 45_000;
// Keep ended streams around for a week so "X was live" history and the
// host's recording decision can still be read, then let Mongo drop them.
const ENDED_STREAM_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Metadata for one live broadcast. The video, audio, comments and reactions
 * never touch the server — they travel host <-> viewer over WebRTC (media
 * tracks + data channels), with signaling relayed as X5 sealed envelopes.
 * This document only exists so the server can enforce who may join, list
 * "live now" for the audience, send go-live notifications, and count viewers.
 *
 * `title` is the one piece of user-authored text stored here, and it is
 * server-visible (like a group name) — the go-live UI says so.
 */
const viewerSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    joinedAt: { type: Date, default: Date.now },
  },
  { _id: false }
);

const liveStreamSchema = new mongoose.Schema(
  {
    host: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    title: { type: String, trim: true, maxlength: LIVE_TITLE_MAX, default: '' },
    audience: {
      type: { type: String, enum: LIVE_AUDIENCE_TYPES, default: 'friends' },
      group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group', default: null },
      // 'custom' only: the friends explicitly picked by the host.
      users: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
      // 'friends' / 'group': people the host chose to hide the stream from.
      hiddenFrom: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    },
    // Contacts the host invited mid-stream; admitted even if outside `audience`.
    invited: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    // Viewers the host removed — they can't rejoin this stream.
    removed: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    status: { type: String, enum: ['live', 'ended'], default: 'live', index: true },
    endReason: { type: String, enum: ['host', 'timeout', 'replaced', null], default: null },
    startedAt: { type: Date, default: Date.now },
    endedAt: { type: Date, default: null },
    lastHeartbeatAt: { type: Date, default: Date.now },
    // Currently admitted viewers. Live signaling is only relayed between the
    // host and someone in this list.
    viewers: { type: [viewerSchema], default: [] },
    peakViewers: { type: Number, default: 0 },
    totalViewers: { type: Number, default: 0 },
    // The recording itself stays on the host's device; this only records
    // what the host decided to do with it.
    recording: {
      enabled: { type: Boolean, default: false },
      decision: { type: String, enum: LIVE_RECORDING_DECISIONS, default: 'none' },
    },
    expiresAt: { type: Date, default: null },
  },
  { timestamps: true }
);

liveStreamSchema.index({ status: 1, lastHeartbeatAt: 1 });
liveStreamSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0, sparse: true });

liveStreamSchema.methods.hasViewer = function hasViewer(userId) {
  return (this.viewers || []).some((v) => String(v.user) === String(userId));
};

liveStreamSchema.methods.markEnded = function markEnded(reason) {
  this.status = 'ended';
  this.endReason = reason;
  this.endedAt = new Date();
  this.viewers = [];
  this.expiresAt = new Date(Date.now() + ENDED_STREAM_TTL_MS);
  if (this.recording?.enabled && this.recording.decision === 'none') {
    this.recording.decision = 'pending';
  }
};

export { ENDED_STREAM_TTL_MS };

export default mongoose.model('LiveStream', liveStreamSchema);
