import { createHash } from "node:crypto";
import { CompactSizeError, type CompactSizeValue, readCompactSize } from "./compact-size.js";

interface Subtree {
  readonly depth: number;
  readonly hash: Buffer;
}

function taggedHash(tag: string, value: Buffer): Buffer {
  const tagHash = createHash("sha256").update(tag).digest();
  return createHash("sha256").update(tagHash).update(tagHash).update(value).digest();
}

function tapBranch(left: Buffer, right: Buffer): Buffer {
  const [first, second] = Buffer.compare(left, right) <= 0 ? [left, right] : [right, left];
  return taggedHash("TapBranch", Buffer.concat([first, second]));
}

function invalidTree(message: string): never {
  throw new TypeError(`Invalid BIP371 Taproot tree: ${message}`);
}

export function taprootTreeMerkleRoot(tree: Buffer): string {
  if (tree.byteLength === 0) invalidTree("tree is empty");

  const stack: Subtree[] = [];
  let offset = 0;
  while (offset < tree.byteLength) {
    if (offset + 2 > tree.byteLength) invalidTree("leaf header is truncated");
    const depth = tree[offset] as number;
    const leafVersion = tree[offset + 1] as number;
    if (depth > 128) invalidTree("leaf depth exceeds 128");
    if ((leafVersion & 1) !== 0 || leafVersion === 0x50) {
      invalidTree("leaf version is invalid");
    }

    const compactSizeOffset = offset + 2;
    let scriptLength: CompactSizeValue;
    try {
      scriptLength = readCompactSize(tree, compactSizeOffset);
    } catch (error) {
      if (error instanceof CompactSizeError) {
        invalidTree("script length is invalid");
      }
      throw error;
    }
    const scriptEnd = scriptLength.nextOffset + scriptLength.value;
    if (scriptEnd > tree.byteLength) invalidTree("leaf script is truncated");
    const leaf = Buffer.concat([
      Buffer.from([leafVersion]),
      tree.subarray(compactSizeOffset, scriptEnd),
    ]);
    stack.push({ depth, hash: taggedHash("TapLeaf", leaf) });
    offset = scriptEnd;

    while (stack.length >= 2 && stack[stack.length - 1]?.depth === stack[stack.length - 2]?.depth) {
      const right = stack.pop() as Subtree;
      const left = stack.pop() as Subtree;
      if (left.depth === 0) invalidTree("tree has multiple roots");
      stack.push({
        depth: left.depth - 1,
        hash: tapBranch(left.hash, right.hash),
      });
    }
  }

  if (stack.length !== 1 || stack[0]?.depth !== 0) {
    invalidTree("leaves do not encode one binary tree");
  }
  return (stack[0] as Subtree).hash.toString("hex");
}
