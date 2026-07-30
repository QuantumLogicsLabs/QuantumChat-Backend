/**
 * Clear Mongo blob metadata that still points at removed local uploads/ paths.
 * Old /tmp and uploads/ files cannot be recovered — this removes broken records
 * (or clears avatar/photo fields) so the app stops 404ing.
 *
 * Usage:
 *   node scripts/fix-local-blob-records.js           # dry run
 *   node scripts/fix-local-blob-records.js --yes     # apply
 */
import 'dotenv/config';
import mongoose from 'mongoose';
import { connectDB } from '../src/config/db.js';
import Attachment from '../src/models/Attachment.js';
import User from '../src/models/User.js';
import Group from '../src/models/Group.js';
import Story from '../src/models/Story.js';
import Message from '../src/models/Message.js';

const confirmed = process.argv.includes('--yes');

/** Local disk keys used before Google Drive (relative paths / file extensions). */
export function looksLikeLocalBlobKey(key) {
  if (!key || typeof key !== 'string') return false;
  if (key.includes('/') || key.includes('\\')) return true;
  if (/^(avatars|groups|stories)([/\\]|$)/i.test(key)) return true;
  if (/\.(enc|jpg|jpeg|png|webp|gif|mp4|webm|mov|mp3|ogg|wav|m4a)$/i.test(key)) return true;
  // bare uuid.enc style without slash
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\./i.test(key)) return true;
  return false;
}

function isLocalProvider(provider) {
  return !provider || provider === 'local';
}

async function main() {
  await connectDB();
  console.log(`Connected: ${mongoose.connection.host}/${mongoose.connection.name}\n`);

  const attachments = await Attachment.find({}).select(
    'storagePath forSenderStoragePath storageProvider filename'
  );
  const localAttachments = attachments.filter(
    (a) =>
      looksLikeLocalBlobKey(a.storagePath) ||
      looksLikeLocalBlobKey(a.forSenderStoragePath) ||
      isLocalProvider(a.storageProvider)
  );

  const users = await User.find({ avatarPath: { $ne: null } }).select(
    'username avatarPath avatarStorageProvider'
  );
  const localAvatars = users.filter(
    (u) => looksLikeLocalBlobKey(u.avatarPath) || isLocalProvider(u.avatarStorageProvider)
  );

  const groups = await Group.find({ photoPath: { $ne: null } }).select(
    'name photoPath photoStorageProvider'
  );
  const localPhotos = groups.filter(
    (g) => looksLikeLocalBlobKey(g.photoPath) || isLocalProvider(g.photoStorageProvider)
  );

  const stories = await Story.find({}).select('storagePath storageProvider filename');
  const localStories = stories.filter(
    (s) => looksLikeLocalBlobKey(s.storagePath) || isLocalProvider(s.storageProvider)
  );

  console.log('Orphan / local-path records:');
  console.log(`  attachments: ${localAttachments.length}`);
  console.log(`  user avatars: ${localAvatars.length}`);
  console.log(`  group photos: ${localPhotos.length}`);
  console.log(`  stories:      ${localStories.length}`);
  if (localAttachments[0]) {
    console.log('  sample attachment:', localAttachments[0].storagePath);
  }
  if (localAvatars[0]) {
    console.log('  sample avatar:', localAvatars[0].username, localAvatars[0].avatarPath);
  }

  if (!confirmed) {
    console.log('\nDry run — nothing changed. Re-run with --yes to apply.');
    await mongoose.disconnect();
    process.exit(0);
  }

  console.log('\nApplying…');

  let messagesUnlinked = 0;
  for (const att of localAttachments) {
    const res = await Message.updateMany(
      { attachment: att._id },
      { $unset: { attachment: 1 } }
    );
    messagesUnlinked += res.modifiedCount || 0;
    await Attachment.deleteOne({ _id: att._id });
  }
  console.log(`  deleted attachments: ${localAttachments.length} (unlinked from ${messagesUnlinked} messages)`);

  for (const u of localAvatars) {
    u.avatarPath = null;
    u.avatarStorageProvider = null;
    u.avatarMimeType = null;
    await u.save();
  }
  console.log(`  cleared avatars: ${localAvatars.length}`);

  for (const g of localPhotos) {
    g.photoPath = null;
    g.photoStorageProvider = null;
    g.photoMimeType = null;
    await g.save();
  }
  console.log(`  cleared group photos: ${localPhotos.length}`);

  for (const s of localStories) {
    await Story.deleteOne({ _id: s._id });
  }
  console.log(`  deleted stories: ${localStories.length}`);

  console.log('\nDone. New uploads will use Google Drive file ids.');
  await mongoose.disconnect();
  process.exit(0);
}

main().catch((err) => {
  console.error('FAILED:', err.message);
  process.exit(1);
});
