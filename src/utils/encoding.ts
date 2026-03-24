const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Encode a UTF-8 string to bytes. */
export function toBytes(str: string): Uint8Array {
  return encoder.encode(str);
}

/** Decode bytes to a UTF-8 string. */
export function fromBytes(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** Encode bytes as hex string. */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Decode hex string to bytes. */
export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Encode bytes as base64 string. */
export function toBase64(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (b) => String.fromCodePoint(b)).join('');
  return btoa(binString);
}

/** Decode base64 string to bytes. */
export function fromBase64(b64: string): Uint8Array {
  const binString = atob(b64);
  return Uint8Array.from(binString, (c) => c.codePointAt(0)!);
}
