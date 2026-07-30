import mongoose from 'mongoose';
import Attachment from '../models/Attachment.js';
import Group from '../models/Group.js';
import { getStorage, newObjectName } from '../middleware/upload.js';
import { areUsersBlocked } from './userController.js';

const HEX_64 = /^[0-9a-f]{64}$/i;

async function putBuffer(file, objectName, userId) {
  const storage = getStorage();
  const stored = await storage.put(
    file.buffer,
    objectName,
    file.mimetype || 'application/octet-stream',
    String(userId)
  );
  return stored;
}

async function deleteKey(key) {
  if (!key) return;
  try {
    await getStorage().delete(key);
  } catch {
    // best-effort
  }
}

export async function uploadAttachment(req, res) {
  const recipientFile = req.files?.file?.[0] || req.file;
  const senderFile = req.files?.senderFile?.[0];
  /** @type {string[]} */
  const uploadedKeys = [];

  try {
    if (!recipientFile?.buffer) {
      return res.status(400).json({ success: false, error: 'file is required' });
    }

    const {
      recipientId,
      groupId,
      secretboxNonce,
      nonce,
      ephemeralPublicKey,
      targetPublicKey,
      forSenderNonce,
      forSenderEphemeralPublicKey,
      forSenderTargetPublicKey,
    } = req.body;

    if (groupId) {
      if (!mongoose.isValidObjectId(groupId)) {
        return res.status(400).json({ success: false, error: 'Valid groupId is required' });
      }
      if (!secretboxNonce || typeof secretboxNonce !== 'string') {
        return res.status(400).json({ success: false, error: 'secretboxNonce is required for group files' });
      }
      const group = await Group.findById(groupId);
      if (!group || !group.isMember(req.user._id)) {
        return res.status(403).json({ success: false, error: 'Not a group member' });
      }

      const recipientStored = await putBuffer(recipientFile, newObjectName('', '.enc'), req.user._id);
      uploadedKeys.push(recipientStored.key);

      const attachment = await Attachment.create({
        owner: req.user._id,
        group: groupId,
        filename: recipientFile.originalname,
        mimetype: recipientFile.mimetype || 'application/octet-stream',
        size: recipientFile.size,
        storagePath: recipientStored.key,
        storageProvider: recipientStored.provider,
        encryption: 'secretbox',
        secretboxNonce,
      });

      return res.status(201).json({
        success: true,
        data: {
          id: attachment._id,
          filename: attachment.filename,
          mimetype: attachment.mimetype,
          size: attachment.size,
          encryption: 'secretbox',
          secretboxNonce: attachment.secretboxNonce,
          group: groupId,
        },
      });
    }

    if (!recipientId || !mongoose.isValidObjectId(recipientId)) {
      return res.status(400).json({ success: false, error: 'Valid recipientId is required' });
    }
    if (!nonce || !HEX_64.test(ephemeralPublicKey || '') || !HEX_64.test(targetPublicKey || '')) {
      return res.status(400).json({
        success: false,
        error: 'nonce, ephemeralPublicKey and targetPublicKey are required',
      });
    }

    const hasSenderCopy = Boolean(senderFile?.buffer);
    if (hasSenderCopy) {
      if (
        !forSenderNonce ||
        !HEX_64.test(forSenderEphemeralPublicKey || '') ||
        !HEX_64.test(forSenderTargetPublicKey || '')
      ) {
        return res.status(400).json({
          success: false,
          error: 'forSenderNonce, forSenderEphemeralPublicKey and forSenderTargetPublicKey are required with senderFile',
        });
      }
    }

    if (await areUsersBlocked(req.user._id, recipientId)) {
      return res.status(403).json({ success: false, error: 'Cannot send attachments to a blocked user' });
    }

    const recipientStored = await putBuffer(recipientFile, newObjectName('', '.enc'), req.user._id);
    uploadedKeys.push(recipientStored.key);

    let senderStored;
    if (hasSenderCopy) {
      senderStored = await putBuffer(senderFile, newObjectName('', '.enc'), req.user._id);
      uploadedKeys.push(senderStored.key);
    }

    const attachment = await Attachment.create({
      owner: req.user._id,
      recipient: recipientId,
      filename: recipientFile.originalname,
      mimetype: recipientFile.mimetype || 'application/octet-stream',
      size: recipientFile.size,
      storagePath: recipientStored.key,
      storageProvider: recipientStored.provider,
      nonce,
      ephemeralPublicKey: ephemeralPublicKey.toLowerCase(),
      targetPublicKey: targetPublicKey.toLowerCase(),
      encryption: 'sealed',
      ...(hasSenderCopy
        ? {
            forSenderStoragePath: senderStored.key,
            forSenderNonce,
            forSenderEphemeralPublicKey: forSenderEphemeralPublicKey.toLowerCase(),
            forSenderTargetPublicKey: forSenderTargetPublicKey.toLowerCase(),
          }
        : {}),
    });

    res.status(201).json({
      success: true,
      data: {
        id: attachment._id,
        filename: attachment.filename,
        mimetype: attachment.mimetype,
        size: attachment.size,
      },
    });
  } catch (err) {
    await Promise.all(uploadedKeys.map((key) => deleteKey(key)));
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function downloadAttachment(req, res) {
  try {
    const attachment = await Attachment.findById(req.params.id);
    if (!attachment) {
      return res.status(404).json({ success: false, error: 'Attachment not found' });
    }

    const userId = req.user._id.toString();
    const isOwner = attachment.owner.toString() === userId;

    if (attachment.group) {
      const group = await Group.findById(attachment.group);
      if (!group || !group.isMember(req.user._id)) {
        return res.status(403).json({ success: false, error: 'Not authorized to access this attachment' });
      }
      const bytes = await getStorage().read(attachment.storagePath);
      res.setHeader('Content-Type', 'application/octet-stream');
      return res.send(bytes);
    }

    const isRecipient = attachment.recipient?.toString() === userId;
    if (!isOwner && !isRecipient) {
      return res.status(403).json({ success: false, error: 'Not authorized to access this attachment' });
    }

    const storagePath =
      isOwner && attachment.forSenderStoragePath ? attachment.forSenderStoragePath : attachment.storagePath;

    const bytes = await getStorage().read(storagePath);
    res.setHeader('Content-Type', 'application/octet-stream');
    return res.send(bytes);
  } catch (err) {
    if (!res.headersSent) {
      res.status(404).json({ success: false, error: 'Encrypted file not found' });
    }
  }
}
