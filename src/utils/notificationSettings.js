export const DEFAULT_NOTIFICATION_SETTINGS = {
  messageNotifications: 'all',
  statusNotifications: 'all',
  statusNotificationsSelectedFriends: [],
  soundEnabled: true,
  soundVolume: 80,
  messagePreview: 'full',
  vibration: 'on',
  doNotDisturb: { enabled: false, startTime: '22:00', endTime: '07:00', allowedContacts: [] },
  groupNotifications: 'all',
  liveNotifications: true,
  callNotifications: {
    voiceCallEnabled: true,
    videoCallEnabled: true,
    vibrateOnCall: true,
    missedCallReminders: true,
  },
  mediaSettings: { autoDownloadImages: true, autoDownloadVideos: false, wifiOnly: true },
  badgeCount: 'show',
  webNotifications: { enabled: true, soundOnWeb: true, syncReadAcrossDevices: true },
  priority: 'normal',
};

export function normalizeNotificationSettings(raw) {
  const src =
    raw && typeof raw.toObject === 'function'
      ? raw.toObject()
      : raw && typeof raw === 'object'
        ? raw
        : {};
  return {
    ...DEFAULT_NOTIFICATION_SETTINGS,
    ...src,
    // Legacy name for 'selected' (see the pre-validate hook in User.js).
    statusNotifications:
      src.statusNotifications === 'favorites_only'
        ? 'selected'
        : src.statusNotifications || DEFAULT_NOTIFICATION_SETTINGS.statusNotifications,
    statusNotificationsSelectedFriends: Array.isArray(src.statusNotificationsSelectedFriends)
      ? src.statusNotificationsSelectedFriends.map((id) => String(id._id || id))
      : [],
    doNotDisturb: {
      ...DEFAULT_NOTIFICATION_SETTINGS.doNotDisturb,
      ...(src.doNotDisturb || {}),
      allowedContacts: Array.isArray(src.doNotDisturb?.allowedContacts)
        ? src.doNotDisturb.allowedContacts.map((id) => String(id._id || id))
        : [],
    },
    callNotifications: {
      ...DEFAULT_NOTIFICATION_SETTINGS.callNotifications,
      ...(src.callNotifications || {}),
    },
    mediaSettings: {
      ...DEFAULT_NOTIFICATION_SETTINGS.mediaSettings,
      ...(src.mediaSettings || {}),
    },
    webNotifications: {
      ...DEFAULT_NOTIFICATION_SETTINGS.webNotifications,
      ...(src.webNotifications || {}),
    },
  };
}
