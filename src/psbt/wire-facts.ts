import { PsbtDocumentError, type PsbtDocumentLimits, parsePsbtDocument } from "./document.js";

export class PsbtWireError extends Error {
  override readonly name = "PsbtWireError";
}

export interface PsbtWireLimits extends PsbtDocumentLimits {}

export interface PsbtEntryFacts {
  keyType: number;
  keyDataBytes: number;
  valueBytes: number;
}

export interface PsbtMapFacts {
  kind: "global" | "input" | "output";
  index: number;
  entryCount: number;
  entries: PsbtEntryFacts[];
}

export interface PsbtWireFacts {
  format: "psbt";
  psbtVersion: number;
  byteLength: number;
  sha256: string;
  inputCount: number;
  outputCount: number;
  mapCount: number;
  maps: PsbtMapFacts[];
}

export function extractWireFacts(encoded: string, limits: PsbtWireLimits = {}): PsbtWireFacts {
  try {
    const document = parsePsbtDocument(encoded, limits);
    return {
      format: "psbt",
      psbtVersion: document.psbtVersion,
      byteLength: document.byteLength,
      sha256: document.sha256,
      inputCount: document.inputCount,
      outputCount: document.outputCount,
      mapCount: document.mapCount,
      maps: document.maps.map((map) => ({
        kind: map.location.kind,
        index: map.location.kind === "global" ? 0 : map.location.index,
        entryCount: map.entries.length,
        entries: map.entries.map((entry) => ({
          keyType: entry.keyType,
          keyDataBytes: entry.keyData.byteLength,
          valueBytes: entry.valueBytes,
        })),
      })),
    };
  } catch (error) {
    if (error instanceof PsbtDocumentError) {
      throw new PsbtWireError(error.message);
    }
    throw error;
  }
}
