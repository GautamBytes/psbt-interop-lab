import { Ajv, type ErrorObject, type JSONSchemaType } from "ajv";
import {
  ADAPTER_PROTOCOL,
  type AdapterHelloCapabilities,
  type AdapterRequest,
  type AdapterResponse,
  adapterOperations,
  adapterRoles,
  adapterScriptTypes,
  adapterStatuses,
  type ValidationResult,
} from "./types.js";

const safeIdentifierPattern = "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$";

const requestSchema: JSONSchemaType<AdapterRequest> = {
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
};

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

const responseSchema = {
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

const helloCapabilitiesSchema = {
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
      properties: {
        inspect: {
          type: "array",
          maxItems: adapterScriptTypes.length,
          uniqueItems: true,
          items: { type: "string", enum: [...adapterScriptTypes] },
        },
        roundtrip: {
          type: "array",
          maxItems: adapterScriptTypes.length,
          uniqueItems: true,
          items: { type: "string", enum: [...adapterScriptTypes] },
        },
        sign: {
          type: "array",
          maxItems: adapterScriptTypes.length,
          uniqueItems: true,
          items: { type: "string", enum: [...adapterScriptTypes] },
        },
        combine: {
          type: "array",
          maxItems: adapterScriptTypes.length,
          uniqueItems: true,
          items: { type: "string", enum: [...adapterScriptTypes] },
        },
        finalize: {
          type: "array",
          maxItems: adapterScriptTypes.length,
          uniqueItems: true,
          items: { type: "string", enum: [...adapterScriptTypes] },
        },
        "finalize-inputs": {
          type: "array",
          maxItems: adapterScriptTypes.length,
          uniqueItems: true,
          items: { type: "string", enum: [...adapterScriptTypes] },
        },
      },
    },
    features: {
      type: "array",
      maxItems: 64,
      uniqueItems: true,
      items: { type: "string", pattern: safeIdentifierPattern },
    },
  },
} as const;

const ajv = new Ajv({ allErrors: true, strict: true });
const validateRequest = ajv.compile(requestSchema);
const validateResponse = ajv.compile<AdapterResponse>(responseSchema);
const validateHelloCapabilities = ajv.compile<AdapterHelloCapabilities>(helloCapabilitiesSchema);

function describeErrors(errors: ErrorObject[] | null | undefined): string[] {
  return (errors ?? []).map((error) => {
    const location = error.instancePath || "/";
    return `${location} ${error.message ?? "is invalid"}`;
  });
}

export function validateAdapterRequest(value: unknown): ValidationResult {
  return validateRequest(value)
    ? { ok: true }
    : { ok: false, errors: describeErrors(validateRequest.errors) };
}

export function validateAdapterResponse(value: unknown): ValidationResult {
  return validateResponse(value)
    ? { ok: true }
    : { ok: false, errors: describeErrors(validateResponse.errors) };
}

export function parseAdapterHelloCapabilities(value: unknown): AdapterHelloCapabilities {
  if (!validateHelloCapabilities(value)) {
    const errors = describeErrors(validateHelloCapabilities.errors).join("; ");
    throw new Error(`Invalid adapter hello capabilities: ${errors}`);
  }
  const capabilities: AdapterHelloCapabilities = {
    operations: [...value.operations],
    roles: [...value.roles],
    psbtVersions: [...value.psbtVersions],
    scriptTypes: [...value.scriptTypes],
    ...(value.operationScriptTypes === undefined
      ? {}
      : {
          operationScriptTypes: Object.fromEntries(
            Object.entries(value.operationScriptTypes).map(([operation, scriptTypes]) => [
              operation,
              [...scriptTypes],
            ]),
          ),
        }),
    ...(value.features === undefined ? {} : { features: [...value.features] }),
  };
  for (const [operation, scriptTypes] of Object.entries(capabilities.operationScriptTypes ?? {})) {
    if (!capabilities.operations.includes(operation as (typeof capabilities.operations)[number])) {
      throw new Error(
        `Invalid adapter hello capabilities: operationScriptTypes declares unsupported operation ${operation}`,
      );
    }
    for (const scriptType of scriptTypes ?? []) {
      if (!capabilities.scriptTypes.includes(scriptType)) {
        throw new Error(
          `Invalid adapter hello capabilities: ${operation} declares undeclared script type ${scriptType}`,
        );
      }
    }
  }
  return capabilities;
}
