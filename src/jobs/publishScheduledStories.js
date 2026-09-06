import Story from '../models/Story.js';

/**
 * Publish scheduled stories whose publishAt has arrived.
 * Emits story:new for each newly published story.
 */
export async function publishDueStories(io) {
  const now = new Date();
  const due = await Story.find({
    status: 'scheduled',
    publishAt: { $lte: now },
  })
    .limit(50)
    .populate('user', 'username avatarPath');

  if (!due.length) return 0;

  let published = 0;
  for (const story of due) {
    const ttl = story.ttlMs || Story.ttlMs;
    story.status = 'published';
    story.expiresAt = new Date(now.getTime() + ttl);
    if (!story.publishAt) story.publishAt = now;
    await story.save();
    published += 1;

    if (!io) continue;
    const owner = story.user;
    io.emit('story:new', {
      ...story.toPublicJSON(),
      user: {
        id: owner?._id || story.user,
        username: owner?.username || 'User',
        hasAvatar: Boolean(owner?.avatarPath),
      },
    });
  }

  return published;
}

export async function runStoryPublishJobs(io) {
  try {
    return await publishDueStories(io);
  } catch (err) {
    console.error('publishDueStories failed:', err.message);
    return 0;
  }
}
