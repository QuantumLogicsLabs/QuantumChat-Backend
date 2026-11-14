import mongoose from 'mongoose';

const NOTIFICATION_TYPES = [
  'FRIEND_REQUEST',
  'FRIEND_REQUEST_ACCEPTED',
  'MESSAGE_REACTION',
  'NEW_MESSAGE',
  'GROUP_MENTION',
  'STORY_MENTION',
  'STORY_REPLY',
  'GROUP_EVENT',
  'MISSED_CALL',
  'LIVE_STARTED',
];

const ENTITY_TYPES = ['friend_request', 'message', 'group', 'story', 'call', 'live'];

const notificationSchema = new mongoose.Schema(
  {
    // Who sees this notification. Every query in notificationService.js is
    // scoped by this field — that's the entire privacy boundary: a user
    // can never fetch a row where they aren't the recipient.
    recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    // Who caused it (reacted, requested, mentioned you, etc). Null for
    // system-generated events with no single actor.
    actor: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    type: { type: String, enum: NOTIFICATION_TYPES, required: true },
    entityType: { type: String, enum: ENTITY_TYPES, required: true },
    // Mixed rather than strict ObjectId: a missed call's "entity" is a
    // client-generated callId string (CallSignal.callId), not a Mongo
    // document id, so this has to accept either shape.
    entityId: { type: mongoose.Schema.Types.Mixed, required: true },
    // Type-specific, non-sensitive extras for rendering (e.g. { mentionType:
    // 'hidden' } for a story mention, { groupId } for a group event,
    // { conversationKey, count } for new messages). Never put
    // message/story plaintext here — this collection has no encryption
    // of its own.
    metadata: { type: mongoose.Schema.Types.Mixed, default: undefined },
    readAt: { type: Date, default: null },
    // Optional TTL — e.g. tied to a story's expiry, so a notification about
    // a since-expired story cleans itself up. Left null, it lives forever.
    expiresAt: { type: Date, default: null },
  },
  { timestamps: true }
);

notificationSchema.index({ recipient: 1, createdAt: -1 });
notificationSchema.index({ recipient: 1, readAt: 1 });
// TTL cleanup: Mongo deletes a doc once its expiresAt has passed. A null
// expiresAt is simply never picked up, so this is safe for rows that
// should live forever.
notificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0, sparse: true });

notificationSchema.methods.toPublicJSON = function toPublicJSON() {
  return {
    id: this._id,
    actor: this.actor?._id || this.actor || null,
    type: this.type,
    entityType: this.entityType,
    entityId: this.entityId,
    metadata: this.metadata || {},
    read: Boolean(this.readAt),
    readAt: this.readAt,
    createdAt: this.createdAt,
  };
};

export default mongoose.model('Notification', notificationSchema);