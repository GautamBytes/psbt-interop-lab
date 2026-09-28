import packageMetadata from "../../package.json";

export const releaseFacts = {
  version: packageMetadata.version,
  walkthroughVersion: "0.10.0",
  scenarioCount: 59,
  sourceScenarioCount: 59,
  walkthroughScenarioCount: 52,
  integrationStackCount: 9,
  replayCheckpointCount: 101,
  compatibilityFindingCount: 3,
} as const;
