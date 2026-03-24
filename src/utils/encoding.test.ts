import { describe, it, expect } from 'vitest';
import { toBytes, fromBytes, toHex, fromHex, toBase64, fromBase64 } from './encoding.js';

describe('encoding', () => {
  it('toBytes/fromBytes roundtrip', () => {
    const str = 'hello nicodAImus';
    expect(fromBytes(toBytes(str))).toBe(str);
  });

  it('toHex/fromHex roundtrip', () => {
    const bytes = new Uint8Array([0x00, 0x0a, 0xff, 0xde, 0xad]);
    expect(toHex(bytes)).toBe('000affDEAD'.toLowerCase());
    expect(fromHex(toHex(bytes))).toEqual(bytes);
  });

  it('toHex produces lowercase hex', () => {
    expect(toHex(new Uint8Array([0xab, 0xcd]))).toBe('abcd');
  });

  it('fromHex handles uppercase', () => {
    expect(fromHex('ABCD')).toEqual(new Uint8Array([0xab, 0xcd]));
  });

  it('toBase64/fromBase64 roundtrip', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5, 255, 254, 253]);
    expect(fromBase64(toBase64(bytes))).toEqual(bytes);
  });

  it('handles empty input', () => {
    expect(toHex(new Uint8Array([]))).toBe('');
    expect(fromHex('')).toEqual(new Uint8Array([]));
    expect(fromBytes(toBytes(''))).toBe('');
  });

  it('handles unicode', () => {
    const emoji = 'Privacy first! 🔒';
    expect(fromBytes(toBytes(emoji))).toBe(emoji);
  });
});
