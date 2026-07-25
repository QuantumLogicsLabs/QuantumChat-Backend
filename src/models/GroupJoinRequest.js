import mongoose from 'mongoose';

const groupJoinRequestSchema = new mongoose.Schema(
  {
    group: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Group',
      required: true,
      index: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    status: {
      type: String,
      enum: ['pending', 'accepted', 'rejected'],
      default: 'pending',
      index: true,
    },
  },
  { timestamps: true }
);

groupJoinRequestSchema.index({ group: 1, user: 1 }, { unique: true });

export default mongoose.model('GroupJoinRequest', groupJoinRequestSchema, 'group_join_requests');
