import { Ajv, type ErrorObject, type JSONSchemaType } from "ajv";
import {
  ADAPTER_PROTOCOL,
  type AdapterRequest,
  type AdapterResponse,
  adapterOperations,
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

const ajv = new Ajv({ allErrors: true, strict: true });
const validateRequest = ajv.compile(requestSchema);
const validateResponse = ajv.compile<AdapterResponse>(responseSchema);

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
