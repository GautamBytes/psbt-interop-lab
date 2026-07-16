import {
  validateAdapterHelloCapabilities as generatedValidateHelloCapabilities,
  validateAdapterRequest as generatedValidateRequest,
  validateAdapterResponse as generatedValidateResponse,
} from "../generated/validators.js";
import type {
  AdapterHelloCapabilities,
  AdapterRequest,
  AdapterResponse,
  ValidationResult,
} from "./types.js";

interface GeneratedValidationError {
  readonly instancePath: string;
  readonly message?: string;
}

interface GeneratedValidator<T> {
  (value: unknown): value is T;
  readonly errors?: readonly GeneratedValidationError[] | null;
}

const validateRequest = generatedValidateRequest as GeneratedValidator<AdapterRequest>;
const validateResponse = generatedValidateResponse as GeneratedValidator<AdapterResponse>;
const validateHelloCapabilities =
  generatedValidateHelloCapabilities as GeneratedValidator<AdapterHelloCapabilities>;

function describeErrors(errors: readonly GeneratedValidationError[] | null | undefined): string[] {
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
