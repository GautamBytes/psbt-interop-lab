import packageMetadata from "../../package.json";

export const releaseFacts = {
  version: packageMetadata.version,
  walkthroughVersion: "0.11.0",
  scenarioCount: 59,
  sourceScenarioCount: 59,
  walkthroughScenarioCount: 59,
  integrationStackCount: 9,
  replayCheckpointCount: 179,
  compatibilityFindingCount: 3,
} as const;
