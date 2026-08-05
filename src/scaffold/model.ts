export interface AdapterInitOptions {
  readonly directory: string;
  readonly name: string;
  readonly template: string;
  readonly cwd: string;
}

export interface GeneratedFile {
  readonly path: string;
  readonly contents: string;
}

export interface AdapterTemplate {
  readonly id: "typescript";
  readonly displayName: "TypeScript";
  readonly directory: URL;
}

export interface AdapterInitResult {
  readonly template: "typescript";
  readonly directory: string;
  readonly files: readonly string[];
}
