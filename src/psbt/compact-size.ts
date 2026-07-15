export class CompactSizeError extends Error {
  override readonly name = "CompactSizeError";
}

function requireBytes(buffer: Buffer, offset: number, count: number): void {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset + count > buffer.length) {
    throw new CompactSizeError("Truncated CompactSize integer");
  }
}

export interface CompactSizeValue {
  value: number;
  nextOffset: number;
}

export function readCompactSize(buffer: Buffer, offset: number): CompactSizeValue {
  requireBytes(buffer, offset, 1);
  const prefix = buffer[offset] as number;
  if (prefix < 0xfd) {
    return { value: prefix, nextOffset: offset + 1 };
  }

  if (prefix === 0xfd) {
    requireBytes(buffer, offset + 1, 2);
    const value = buffer.readUInt16LE(offset + 1);
    if (value < 0xfd) {
      throw new CompactSizeError("Non-minimal CompactSize integer");
    }
    return { value, nextOffset: offset + 3 };
  }

  if (prefix === 0xfe) {
    requireBytes(buffer, offset + 1, 4);
    const value = buffer.readUInt32LE(offset + 1);
    if (value <= 0xffff) {
      throw new CompactSizeError("Non-minimal CompactSize integer");
    }
    return { value, nextOffset: offset + 5 };
  }

  requireBytes(buffer, offset + 1, 8);
  const value = buffer.readBigUInt64LE(offset + 1);
  if (value <= 0xffff_ffffn) {
    throw new CompactSizeError("Non-minimal CompactSize integer");
  }
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new CompactSizeError("CompactSize integer exceeds the safe range");
  }
  return { value: Number(value), nextOffset: offset + 9 };
}
