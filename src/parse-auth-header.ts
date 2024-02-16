export function parseAuthHeader(headerValue: string) {
  if (typeof headerValue !== 'string') {
    return null;
  }
  const matches = headerValue.match(/(\S+)\s+(\S+)/);
  return matches && { scheme: matches[1], value: matches[2] };
}
