/** Allow only http(s) URLs for rendered links. */
export function isSafeHttpUrl(raw) {
  if (!raw || typeof raw !== 'string') return false;
  try {
    const url = new URL(raw, 'https://example.invalid');
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}
