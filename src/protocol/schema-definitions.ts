import {
  ADAPTER_PROTOCOL,
  adapterOperations,
  adapterRoles,
  adapterScriptTypes,
  adapterStatuses,
} from "./types.js";

const safeIdentifierPattern = "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$";
const adapterScriptOperations = adapterOperations.filter(
  (operation) => operation !== "hello" && operation !== "native-parse",
);

export const requestSchema = {
  type: "object",
  additionalProperties: false,
  required: ["protocol", "id", "operation", "payload"],
  properties: {
    protocol: { type: "string", const: ADAPTER_PROTOCOL },
    id: { type: "string", pattern: safeIdentifierPattern },
    operation: { type: "string", enum: [...adapterOperations] },
    payload: {
      type: "object",
      required: [],
      additionalProperties: true,
    },
  },
} as const satisfies Record<string, unknown>;

const implementationSchema = {
  type: "object",
  additionalProperties: false,
  required: ["name", "version", "artifactDigest"],
  properties: {
    name: { type: "string", minLength: 1, maxLength: 128 },
    version: { type: "string", minLength: 1, maxLength: 128 },
    artifactDigest: {
      type: "string",
      pattern: "^sha256:[0-9a-f]{64}$",
    },
    sourceRevision: { type: "string", minLength: 1, maxLength: 256 },
  },
} as const;

export const responseSchema = {
  type: "object",
  additionalProperties: false,
  required: ["protocol", "id", "status", "implementation"],
  properties: {
    protocol: { type: "string", const: ADAPTER_PROTOCOL },
    id: { type: "string", pattern: safeIdentifierPattern },
    status: { type: "string", enum: [...adapterStatuses] },
    implementation: implementationSchema,
    output: {
      type: "object",
      required: [],
      additionalProperties: true,
    },
    error: {
      type: "object",
      additionalProperties: false,
      required: ["class", "message"],
      properties: {
        class: { type: "string", minLength: 1, maxLength: 128 },
        message: { type: "string", minLength: 1, maxLength: 2048 },
        retryable: { type: "boolean" },
      },
    },
  },
  oneOf: [
    {
      properties: {
        status: { const: "ok" },
        output: {
          type: "object",
          required: [],
          additionalProperties: true,
        },
        error: false,
      },
      required: ["output"],
    },
    {
      properties: {
        status: {
          enum: ["unsupported", "rejected", "crashed", "timeout"],
        },
        error: {
          type: "object",
          additionalProperties: false,
          required: ["class", "message"],
          properties: {
            class: { type: "string", minLength: 1, maxLength: 128 },
            message: { type: "string", minLength: 1, maxLength: 2048 },
            retryable: { type: "boolean" },
          },
        },
        output: false,
      },
      required: ["error"],
    },
  ],
} as const;

export const helloCapabilitiesSchema = {
  type: "object",
  additionalProperties: false,
  required: ["operations", "roles", "psbtVersions", "scriptTypes"],
  properties: {
    operations: {
      type: "array",
      minItems: 1,
      maxItems: adapterOperations.length,
      uniqueItems: true,
      items: { type: "string", enum: [...adapterOperations] },
    },
    roles: {
      type: "array",
      minItems: 1,
      maxItems: adapterRoles.length,
      uniqueItems: true,
      items: { type: "string", enum: [...adapterRoles] },
    },
    psbtVersions: {
      type: "array",
      minItems: 1,
      maxItems: 2,
      uniqueItems: true,
      items: { type: "integer", enum: [0, 2] },
    },
    scriptTypes: {
      type: "array",
      minItems: 1,
      maxItems: adapterScriptTypes.length,
      uniqueItems: true,
      items: { type: "string", enum: [...adapterScriptTypes] },
    },
    operationScriptTypes: {
      type: "object",
      additionalProperties: false,
      required: [],
      properties: Object.fromEntries(
        adapterScriptOperations.map((operation) => [
          operation,
          {
            type: "array",
            maxItems: adapterScriptTypes.length,
            uniqueItems: true,
            items: { type: "string", enum: [...adapterScriptTypes] },
          },
        ]),
      ),
    },
    features: {
      type: "array",
      maxItems: 64,
      uniqueItems: true,
      items: { type: "string", pattern: safeIdentifierPattern },
    },
  },
} as const satisfies Record<string, unknown>;
