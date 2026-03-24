import { describe, it, expect } from 'vitest';
import { shred, shredAll } from './shred.js';

describe('shred', () => {
  it('zeros a buffer', () => {
    const buf = new Uint8Array([1, 2, 3, 4, 5]);
    shred(buf);
    expect(buf).toEqual(new Uint8Array(5));
  });

  it('shredAll zeros multiple buffers', () => {
    const a = new Uint8Array([10, 20]);
    const b = new Uint8Array([30, 40, 50]);
    shredAll(a, b);
    expect(a).toEqual(new Uint8Array(2));
    expect(b).toEqual(new Uint8Array(3));
  });
});
