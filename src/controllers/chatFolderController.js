import { toObjectId } from '../utils/toObjectId.js';

/**
 * User-defined chat folders. A folder is a named list of conversation keys
 * owned by one user; it only changes how that user's own chat list is
 * filtered, so nothing here touches other users, groups or messages.
 */

export const MAX_CHAT_FOLDERS = 10;
export const MAX_FOLDER_NAME = 24;
export const MAX_CHATS_PER_FOLDER = 500;

const CONVERSATION_KEY_RE = /^(dm|group):[0-9a-f]{24}$/i;

function folderList(user) {
  return user.toSelfJSON().chatFolders;
}

function cleanName(raw) {
  const name = typeof raw === 'string' ? raw.replace(/\s+/g, ' ').trim() : '';
  if (!name) return { error: 'Folder name is required' };
  if (name.length > MAX_FOLDER_NAME) {
    return { error: `Folder name must be ${MAX_FOLDER_NAME} characters or fewer` };
  }
  return { name };
}

function nameTaken(user, name, exceptId) {
  const lower = name.toLowerCase();
  return (user.chatFolders || []).some(
    (f) => f.name.toLowerCase() === lower && String(f._id) !== String(exceptId || '')
  );
}

function cleanKeys(raw) {
  if (raw == null) return { keys: [] };
  if (!Array.isArray(raw)) return { error: 'conversationKeys must be an array' };
  const keys = [...new Set(raw.map((k) => String(k).toLowerCase()))];
  if (keys.some((k) => !CONVERSATION_KEY_RE.test(k))) {
    return { error: 'Invalid conversation key' };
  }
  if (keys.length > MAX_CHATS_PER_FOLDER) {
    return { error: `A folder can hold at most ${MAX_CHATS_PER_FOLDER} chats` };
  }
  return { keys };
}

function findFolder(user, folderId) {
  const id = toObjectId(folderId);
  if (!id) return null;
  return (user.chatFolders || []).find((f) => String(f._id) === String(id)) || null;
}

export async function listChatFolders(req, res) {
  res.json({ success: true, data: folderList(req.user) });
}

export async function createChatFolder(req, res) {
  try {
    const user = req.user;
    if ((user.chatFolders || []).length >= MAX_CHAT_FOLDERS) {
      return res.status(400).json({ success: false, error: `You can have up to ${MAX_CHAT_FOLDERS} folders` });
    }
    const { name, error: nameError } = cleanName(req.body?.name);
    if (nameError) return res.status(400).json({ success: false, error: nameError });
    if (nameTaken(user, name)) {
      return res.status(409).json({ success: false, error: 'You already have a folder with that name' });
    }
    const { keys, error: keysError } = cleanKeys(req.body?.conversationKeys);
    if (keysError) return res.status(400).json({ success: false, error: keysError });

    user.chatFolders.push({ name, conversationKeys: keys });
    await user.save();
    const created = user.chatFolders[user.chatFolders.length - 1];
    res.status(201).json({ success: true, data: folderList(user), folderId: String(created._id) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function updateChatFolder(req, res) {
  try {
    const user = req.user;
    const folder = findFolder(user, req.params.folderId);
    if (!folder) return res.status(404).json({ success: false, error: 'Folder not found' });

    if (req.body?.name !== undefined) {
      const { name, error } = cleanName(req.body.name);
      if (error) return res.status(400).json({ success: false, error });
      if (nameTaken(user, name, folder._id)) {
        return res.status(409).json({ success: false, error: 'You already have a folder with that name' });
      }
      folder.name = name;
    }
    if (req.body?.conversationKeys !== undefined) {
      const { keys, error } = cleanKeys(req.body.conversationKeys);
      if (error) return res.status(400).json({ success: false, error });
      folder.conversationKeys = keys;
    }

    await user.save();
    res.json({ success: true, data: folderList(user) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

/** Add or remove a single chat — used by the per-chat "Add to folder" menu. */
export async function setChatFolderMembership(req, res) {
  try {
    const user = req.user;
    const folder = findFolder(user, req.params.folderId);
    if (!folder) return res.status(404).json({ success: false, error: 'Folder not found' });

    const key = String(req.body?.conversationKey || '').toLowerCase();
    if (!CONVERSATION_KEY_RE.test(key)) {
      return res.status(400).json({ success: false, error: 'Invalid conversation key' });
    }
    const included = req.body?.included !== false;
    const current = (folder.conversationKeys || []).map(String);

    if (included && !current.includes(key)) {
      if (current.length >= MAX_CHATS_PER_FOLDER) {
        return res.status(400).json({ success: false, error: `A folder can hold at most ${MAX_CHATS_PER_FOLDER} chats` });
      }
      folder.conversationKeys = [...current, key];
    } else if (!included && current.includes(key)) {
      folder.conversationKeys = current.filter((k) => k !== key);
    }

    await user.save();
    res.json({ success: true, data: folderList(user) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function deleteChatFolder(req, res) {
  try {
    const user = req.user;
    const folder = findFolder(user, req.params.folderId);
    if (!folder) return res.status(404).json({ success: false, error: 'Folder not found' });
    user.chatFolders = user.chatFolders.filter((f) => String(f._id) !== String(folder._id));
    await user.save();
    res.json({ success: true, data: folderList(user) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}
