import packageMetadata from "../../package.json";

export const releaseFacts = {
  version: packageMetadata.version,
  scenarioCount: 51,
  walkthroughScenarioCount: 47,
  integrationStackCount: 9,
  replayCheckpointCount: 91,
} as const;
