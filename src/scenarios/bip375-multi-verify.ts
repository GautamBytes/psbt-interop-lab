import { validateBip375ReferencePsbt } from "../psbt/bip375-validator.js";
import { diffPsbtDocuments } from "../psbt/diff.js";
import { type PsbtDocument, type PsbtDocumentMap, parsePsbtDocument } from "../psbt/document.js";
import { applyPsbtMutations, type PsbtMutationRecipe } from "../psbt/mutation.js";

export const MULTI_KEYS = [
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
] as const;
const mapAt = (doc: PsbtDocument, kind: "input" | "output", index: number) =>
  doc.maps.find(({ location }) => location.kind === kind && location.index === index);
const entry = (map: PsbtDocumentMap | undefined, type: number) =>
  map?.entries.find(({ keyType }) => keyType === type);

function orderedTemplate(template: string, reverse: boolean, shuffle: boolean): PsbtDocument {
  const doc = parsePsbtDocument(template);
  if (!reverse && !shuffle) return doc;
  const mutations: PsbtMutationRecipe[] = [];
  for (const kind of ["input", "output"] as const) {
    if ((kind === "input" && !reverse) || (kind === "output" && !shuffle)) continue;
    const maps = doc.maps.filter((m) => m.location.kind === kind);
    for (const map of maps)
      for (const e of map.entries)
        mutations.push({
          kind: "delete-entry",
          location: map.location,
          keyType: e.keyType,
          keyDataHex: e.keyData.toString("hex"),
        });
    for (const [index, map] of [...maps].reverse().entries())
      for (const e of map.entries)
        mutations.push({
          kind: "set-entry",
          location: { kind, index },
          keyType: e.keyType,
          keyDataHex: e.keyData.toString("hex"),
          valueHex: e.value.toString("hex"),
        });
  }
  return parsePsbtDocument(applyPsbtMutations(template, mutations));
}

export function verifyMultiSender(
  template: string,
  signed: string,
  mode: string,
  reverse: boolean,
  shuffle = false,
): boolean {
  try {
    if (mode !== "global" && mode !== "per-input") return false;
    const before = orderedTemplate(template, reverse, shuffle),
      after = parsePsbtDocument(signed);
    if (
      [before, after].some(
        (doc) => doc.psbtVersion !== 2 || doc.inputCount !== 2 || ![2, 3].includes(doc.outputCount),
      )
    )
      return false;
    if (before.outputCount !== after.outputCount || (shuffle && before.outputCount !== 3))
      return false;
    const recipients = before.outputCount === 3 ? (shuffle ? [1, 2] : [0, 1]) : [0];
    const global = after.maps.find((m) => m.location.kind === "global");
    if (
      entry(global, 6)?.value.toString("hex") !== "00" ||
      recipients.some(
        (i) =>
          entry(mapAt(after, "output", i), 9)?.value.toString("hex") !==
          MULTI_KEYS[1] + MULTI_KEYS[0],
      )
    )
      return false;
    const expected = new Set(["input:0:2", "input:1:2", ...recipients.map((i) => `output:${i}:9`)]);
    if (mode === "global") {
      expected.add("global:7");
      expected.add("global:8");
    } else
      for (const i of [0, 1]) {
        expected.add(`input:${i}:29`);
        expected.add(`input:${i}:30`);
      }
    for (const index of [0, 1]) {
      const key = MULTI_KEYS[reverse ? 1 - index : index];
      const sig = entry(mapAt(after, "input", index), 2);
      if (!sig || sig.keyData.toString("hex") !== key || sig.value.at(-1) !== 1) return false;
    }
    const diff = diffPsbtDocuments(before, after);
    for (const added of diff.added) {
      const { location, keyType } = added;
      if (location.kind === "global" && keyType === 6) continue;
      if (location.kind === "input" && keyType === 6) {
        const key = MULTI_KEYS[reverse ? 1 - location.index : location.index];
        const origin = mapAt(after, "input", location.index)?.entries.find(
          (e) => e.completeKeySha256 === added.completeKeySha256,
        );
        if (
          origin &&
          origin.keyData.toString("hex") === key &&
          origin.value.toString("hex") === "00000000"
        )
          continue;
      }
      const id =
        location.kind === "global"
          ? `global:${keyType}`
          : `${location.kind}:${location.index}:${keyType}`;
      if (!expected.delete(id)) return false;
    }
    return (
      expected.size === 0 &&
      diff.removed.length === 0 &&
      recipients.every((index) =>
        diff.changed.some(
          ({ location, keyType }) =>
            location.kind === "output" && location.index === index && keyType === 4,
        ),
      ) &&
      diff.changed.every(
        ({ location, keyType }) =>
          (location.kind === "output" && recipients.includes(location.index) && keyType === 4) ||
          (location.kind === "global" && keyType === 6),
      ) &&
      validateBip375ReferencePsbt(signed).valid
    );
  } catch {
    return false;
  }
}

export function verifyMultiWitnesses(signed: string, finalized: string): boolean {
  try {
    const before = parsePsbtDocument(signed),
      after = parsePsbtDocument(finalized);
    if (before.inputCount !== 2 || after.inputCount !== 2) return false;
    return [0, 1].every((index) => {
      const input = mapAt(before, "input", index),
        finalInput = mapAt(after, "input", index);
      const signatures = input?.entries.filter(({ keyType }) => keyType === 2);
      const signature = signatures?.[0];
      if (
        signatures?.length !== 1 ||
        !signature ||
        signature.value.length < 9 ||
        signature.value.length > 73 ||
        signature.value.at(-1) !== 1 ||
        signature.keyData.length !== 33
      )
        return false;
      const expected = Buffer.concat([
        Buffer.from([2, signature.value.length]),
        signature.value,
        Buffer.from([33]),
        signature.keyData,
      ]);
      return (
        entry(finalInput, 8)?.value.equals(expected) === true &&
        !finalInput?.entries.some(({ keyType }) => keyType === 2 || keyType === 7)
      );
    });
  } catch {
    return false;
  }
}
