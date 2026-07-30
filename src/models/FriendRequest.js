import mongoose from 'mongoose';

const friendRequestSchema = new mongoose.Schema(
  {
    from: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    to: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    status: {
      type: String,
      enum: ['pending', 'accepted', 'declined'],
      default: 'pending',
      index: true,
    },
  },
  { timestamps: true }
);

// Prevent duplicate pending requests in the same direction
friendRequestSchema.index(
  { from: 1, to: 1 },
  { unique: true, partialFilterExpression: { status: 'pending' } }
);

export default mongoose.model('FriendRequest', friendRequestSchema, 'friendrequests');