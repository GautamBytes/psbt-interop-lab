export interface LocalParseFixture {
  readonly id: string;
  readonly title: string;
  readonly source: string;
  readonly psbtVersion: 0 | 2;
  readonly psbt: string;
  readonly sha256: string;
}

export const LOCAL_PARSE_FIXTURES: readonly LocalParseFixture[] = [
  {
    id: "bip174-minimal-v0",
    title: "Minimal unsigned PSBTv0",
    source: "BIP174 public test fixture",
    psbtVersion: 0,
    psbt: "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA=",
    sha256: "1c8e14a4d2f70496b46bb9df06f72a8c938b378b7160cf4806336bf24ba89130",
  },
  {
    id: "bip370-valid-01-v2",
    title: "Required-fields-only PSBTv2",
    source: "BIP370 valid vector 1 mirrored by rust-psbt v0.3.0",
    psbtVersion: 2,
    psbt: "cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA==",
    sha256: "eadcaa4b78f52e1be8ee499c956df26f976aa793e02f62e361cbbe5f53cf9c92",
  },
];
