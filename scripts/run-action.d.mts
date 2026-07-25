export interface ActionConfiguration {
  readonly workspace: string;
  readonly adapterManifest: string;
  readonly artifacts: string;
  readonly packageSpec: string;
  readonly junit: string;
  readonly sarif: string;
  readonly build: boolean;
}

export function actionConfiguration(
  environment?: Readonly<Record<string, string | undefined>>,
): ActionConfiguration;

export function buildMatrixArguments(configuration: {
  readonly adapterManifest: string;
  readonly artifacts: string;
  readonly junit: string;
  readonly sarif: string;
  readonly build: boolean;
}): string[];

export function runAction(
  environment?: Readonly<Record<string, string | undefined>>,
): Promise<void>;
