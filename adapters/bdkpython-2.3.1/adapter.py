import base64
import hashlib
import importlib.metadata
import json
import os
import re
import sys

from bdkpython import Psbt


PROTOCOL = "psbt-lab.adapter/0.2"
MAX_LINE_BYTES = 4 * 1024 * 1024
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def implementation(digest):
    return {
        "name": "bdkpython",
        "version": importlib.metadata.version("bdkpython"),
        "artifactDigest": digest,
        "sourceRevision": "bdk-ffi-v2.3.1",
    }


def success(request_id, digest, output):
    return {
        "protocol": PROTOCOL,
        "id": request_id,
        "status": "ok",
        "implementation": implementation(digest),
        "output": output,
    }


def failure(request_id, digest, status, error_class, message):
    return {
        "protocol": PROTOCOL,
        "id": request_id,
        "status": status,
        "implementation": implementation(digest),
        "error": {
            "class": error_class,
            "message": message,
            "retryable": False,
        },
    }


def valid_request(value):
    if not isinstance(value, dict) or set(value) != {
        "protocol",
        "id",
        "operation",
        "payload",
    }:
        return False
    return (
        value.get("protocol") == PROTOCOL
        and isinstance(value.get("id"), str)
        and SAFE_ID.fullmatch(value["id"]) is not None
        and isinstance(value.get("operation"), str)
        and isinstance(value.get("payload"), dict)
    )


def parse_psbt(payload, fields):
    if set(payload) != set(fields) or not isinstance(payload.get("psbt"), str):
        raise ValueError("invalid_payload")
    encoded = payload["psbt"]
    if len(encoded) > MAX_LINE_BYTES:
        raise ValueError("too_large")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        raise ValueError("invalid_psbt") from None
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise ValueError("invalid_psbt")
    try:
        return raw, Psbt(encoded)
    except Exception:
        raise ValueError("invalid_psbt") from None


def classify_finalize_errors(errors):
    indices = []
    missing_witness_script = False
    for error in errors or []:
        reason = getattr(error, "reason", "")
        index = getattr(error, "index", None)
        if isinstance(index, int) and index >= 0:
            indices.append(index)
        if isinstance(reason, str) and "missing witness script" in reason.lower():
            missing_witness_script = True

    input_label = ", ".join(str(index) for index in sorted(set(indices))) or "unknown"
    if missing_witness_script:
        return (
            "finalize.missing_witness_script",
            "BDK Python 2.3.1 retried an already-finalized input and reported "
            f"missing witness-script metadata at input {input_label}",
        )
    return (
        "finalize.input_error",
        f"BDK Python 2.3.1 could not finalize input {input_label}",
    )


def handle_request(value, digest):
    fallback_id = (
        value.get("id")
        if isinstance(value, dict)
        and isinstance(value.get("id"), str)
        and SAFE_ID.fullmatch(value["id"])
        else "invalid-1"
    )
    if not valid_request(value):
        return failure(
            fallback_id,
            digest,
            "rejected",
            "protocol.invalid_request",
            "Request does not match the adapter protocol",
        )

    request_id = value["id"]
    operation = value["operation"]
    payload = value["payload"]

    if operation == "hello":
        if payload:
            return failure(
                request_id,
                digest,
                "rejected",
                "protocol.invalid_payload",
                "hello expects an empty payload",
            )
        return success(
            request_id,
            digest,
            {
                "operations": ["hello", "native-parse", "inspect", "roundtrip", "finalize"],
                "roles": ["parser", "finalizer"],
                "psbtVersions": [0],
                "scriptTypes": ["p2wsh"],
                "operationScriptTypes": {
                    "inspect": ["p2wsh"],
                    "roundtrip": ["p2wsh"],
                    "finalize": ["p2wsh"],
                },
                "features": ["historical-regression.bdk-wallet-488"],
            },
        )

    if operation == "native-parse":
        try:
            _, psbt = parse_psbt(payload, ["psbt"])
        except ValueError as error:
            error_class = (
                "protocol.invalid_payload"
                if str(error) == "invalid_payload"
                else "psbt.native_parse_failed"
            )
            return failure(
                request_id,
                digest,
                "rejected",
                error_class,
                "BDK rejected the PSBT",
            )
        return success(
            request_id,
            digest,
            {
                "nativeParser": "bdkpython",
                "inputs": len(psbt.input()),
                "outputs": len(psbt.output()),
            },
        )

    if operation in ("inspect", "roundtrip"):
        try:
            raw, psbt = parse_psbt(payload, ["psbt"])
        except ValueError as error:
            error_class = (
                "protocol.invalid_payload"
                if str(error) == "invalid_payload"
                else "psbt.parse_failed"
            )
            return failure(
                request_id,
                digest,
                "rejected",
                error_class,
                "Payload must contain one valid base64 PSBT",
            )
        if operation == "inspect":
            return success(
                request_id,
                digest,
                {"inputs": len(psbt.input()), "outputs": len(psbt.output())},
            )
        serialized = psbt.serialize()
        return success(
            request_id,
            digest,
            {
                "psbt": serialized,
                "byteIdentical": base64.b64decode(serialized) == raw,
                "psbtVersion": 0,
            },
        )

    if operation == "finalize":
        if (
            set(payload) != {"psbt", "network", "fixtureId"}
            or payload.get("network") != "regtest"
            or payload.get("fixtureId") != "bdk-finalize-regression"
        ):
            return failure(
                request_id,
                digest,
                "rejected",
                "protocol.invalid_payload",
                "finalize accepts only the controlled regtest regression fixture",
            )
        try:
            _, psbt = parse_psbt(payload, ["psbt", "network", "fixtureId"])
            result = psbt.finalize()
        except ValueError:
            return failure(
                request_id,
                digest,
                "rejected",
                "psbt.parse_failed",
                "Payload does not contain a valid PSBT",
            )
        except Exception:
            return failure(
                request_id,
                digest,
                "crashed",
                "adapter.unexpected_failure",
                "BDK Python finalization raised an unexpected internal error",
            )

        if result.could_finalize:
            return success(
                request_id,
                digest,
                {"psbt": result.psbt.serialize(), "couldFinalize": True},
            )
        error_class, message = classify_finalize_errors(result.errors)
        return failure(request_id, digest, "rejected", error_class, message)

    return failure(
        request_id,
        digest,
        "unsupported",
        "operation.unsupported",
        "Operation is not implemented by the frozen BDK adapter",
    )


def artifact_digest():
    with open(os.path.abspath(__file__), "rb") as source:
        return "sha256:" + hashlib.sha256(source.read()).hexdigest()


def main():
    digest = artifact_digest()
    while True:
        line = sys.stdin.buffer.readline(MAX_LINE_BYTES + 2)
        if not line:
            return 0
        if len(line) > MAX_LINE_BYTES + 1 or not line.endswith(b"\n"):
            return 2
        try:
            request = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            response = failure(
                "invalid-1",
                digest,
                "rejected",
                "protocol.invalid_json",
                "Request line is not valid JSON",
            )
        else:
            response = handle_request(request, digest)
        encoded = json.dumps(response, separators=(",", ":"), ensure_ascii=True)
        sys.stdout.write(encoded + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    raise SystemExit(main())
