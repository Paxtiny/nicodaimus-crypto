/**
 * Zero all bytes in a Uint8Array. Best-effort defense-in-depth
 * in JavaScript (no guarantee the GC hasn't copied the buffer).
 */
export function shred(buf: Uint8Array): void {
  buf.fill(0);
}

/** Shred multiple buffers. */
export function shredAll(...bufs: Uint8Array[]): void {
  for (const buf of bufs) {
    shred(buf);
  }
}
