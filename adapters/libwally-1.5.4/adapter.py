import base64
import hashlib
import hmac
import json
import os
import re
import sys

import wallycore as wally


PROTOCOL = "psbt-lab.adapter/0.2"
LIBWALLY_VERSION = "1.5.4"
SOURCE_REVISION = (
    "libwally-core-release_1.5.4@c5591834b3ae4ee4c7db9e537a9c19104ab4bf0c"
)
MAX_LINE_BYTES = 4 * 1024 * 1024
MAX_FIXTURE_COMMITMENTS_BYTES = 4 * 1024
MAX_COMBINE_PSBT = 16
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SAFE_COMMITMENT = re.compile(r"^sha256:[0-9a-f]{64}$")
ALLOWED_FIXTURES = {
    "p2wpkh",
    "intent-rich-p2wpkh",
    "p2wsh-2-of-3",
}

PUBKEY_1 = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
PUBKEY_2 = bytes.fromhex(
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)
PUBKEY_3 = bytes.fromhex(
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
)
PRIVATE_KEY_1 = bytes.fromhex("00" * 31 + "01")
PRIVATE_KEY_2 = bytes.fromhex("00" * 31 + "02")
P2WPKH_SCRIPT = b"\x00\x14" + hashlib.new(
    "ripemd160", hashlib.sha256(PUBKEY_1).digest()
).digest()
MULTISIG_SCRIPT = (
    b"\x52\x21"
    + PUBKEY_1
    + b"\x21"
    + PUBKEY_2
    + b"\x21"
    + PUBKEY_3
    + b"\x53\xae"
)
P2WSH_SCRIPT = b"\x00\x20" + hashlib.sha256(MULTISIG_SCRIPT).digest()


class PayloadError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def implementation(digest):
    return {
        "name": "libwally-core",
        "version": LIBWALLY_VERSION,
        "artifactDigest": digest,
        "sourceRevision": SOURCE_REVISION,
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


def is_record(value):
    return isinstance(value, dict)


def exact_fields(value, fields):
    return is_record(value) and set(value) == set(fields)


def valid_request(value):
    return (
        exact_fields(value, ("protocol", "id", "operation", "payload"))
        and value.get("protocol") == PROTOCOL
        and isinstance(value.get("id"), str)
        and SAFE_ID.fullmatch(value["id"]) is not None
        and isinstance(value.get("operation"), str)
        and is_record(value.get("payload"))
    )


def fallback_request_id(value):
    if (
        is_record(value)
        and isinstance(value.get("id"), str)
        and SAFE_ID.fullmatch(value["id"]) is not None
    ):
        return value["id"]
    return "invalid-1"


def parse_fixture_commitments(raw):
    if raw is None:
        return {}
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_FIXTURE_COMMITMENTS_BYTES:
        raise ValueError("invalid fixture commitments")
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("invalid fixture commitments") from error
    if not is_record(parsed) or not parsed or len(parsed) > len(ALLOWED_FIXTURES):
        raise ValueError("invalid fixture commitments")
    for fixture_id, commitment in parsed.items():
        if (
            fixture_id not in ALLOWED_FIXTURES
            or not isinstance(commitment, str)
            or SAFE_COMMITMENT.fullmatch(commitment) is None
        ):
            raise ValueError("invalid fixture commitments")
    return parsed


def parse_encoded_psbt(encoded):
    if not isinstance(encoded, str) or len(encoded) > MAX_LINE_BYTES:
        raise PayloadError("invalid_psbt")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError, UnicodeEncodeError):
        raise PayloadError("invalid_psbt") from None
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise PayloadError("invalid_psbt")
    try:
        psbt = wally.psbt_from_base64(encoded, wally.WALLY_PSBT_PARSE_FLAG_STRICT)
    except Exception:
        raise PayloadError("invalid_psbt") from None
    return raw, psbt


def parse_psbt_payload(payload, fields=("psbt",)):
    if not exact_fields(payload, fields) or not isinstance(payload.get("psbt"), str):
        raise PayloadError("invalid_payload")
    return parse_encoded_psbt(payload["psbt"])


def serialize_psbt(psbt):
    return wally.psbt_to_base64(psbt, 0)


def unsigned_transaction(psbt):
    return wally.psbt_extract(psbt, wally.WALLY_PSBT_EXTRACT_NON_FINAL)


def display_hash(raw_hash):
    return bytes(raw_hash)[::-1].hex()


def transaction_identity(psbt):
    tx = unsigned_transaction(psbt)
    unsigned_bytes = bytes(wally.tx_to_bytes(tx, 0))
    return {
        "transactionId": display_hash(wally.tx_get_txid(tx)),
        "unsignedTxSha256": "sha256:" + hashlib.sha256(unsigned_bytes).hexdigest(),
        "bip370UniqueId": display_hash(
            wally.psbt_get_id(psbt, wally.WALLY_PSBT_ID_AS_V2)
        ),
    }


def modifiable_flags(psbt):
    if wally.psbt_get_version(psbt) != 2:
        return None
    return wally.psbt_get_tx_modifiable_flags(psbt)


def finalized_input_count(psbt):
    return sum(
        1
        for index in range(wally.psbt_get_num_inputs(psbt))
        if wally.psbt_is_input_finalized(psbt, index)
    )


def partial_signature_input_count(psbt):
    return sum(
        1
        for index in range(wally.psbt_get_num_inputs(psbt))
        if wally.psbt_get_input_signatures_size(psbt, index) > 0
    )


def inspect_output(psbt):
    output = {
        "psbtVersion": wally.psbt_get_version(psbt),
        "inputs": wally.psbt_get_num_inputs(psbt),
        "outputs": wally.psbt_get_num_outputs(psbt),
        "finalizedInputs": finalized_input_count(psbt),
        "partialSignatureInputs": partial_signature_input_count(psbt),
        **transaction_identity(psbt),
    }
    flags = modifiable_flags(psbt)
    if flags is not None:
        output["transactionModifiableFlags"] = flags
    return output


def fixture_payload(payload):
    if not exact_fields(payload, ("psbt", "network", "fixtureId")):
        raise PayloadError("invalid_payload")
    if (
        payload.get("network") != "regtest"
        or payload.get("fixtureId") not in ALLOWED_FIXTURES
    ):
        raise PayloadError("invalid_payload")
    _, psbt = parse_psbt_payload(payload, ("psbt", "network", "fixtureId"))
    return psbt, payload["fixtureId"]


def verify_fixture_commitment(psbt, fixture_id, commitments):
    expected = commitments.get(fixture_id)
    if expected is None:
        raise PayloadError("commitment_missing")
    actual = transaction_identity(psbt)["unsignedTxSha256"]
    if not hmac.compare_digest(expected, actual):
        raise PayloadError("commitment_mismatch")


def validate_fixture_scope(psbt, fixture_id):
    if wally.psbt_is_elements(psbt):
        raise PayloadError("fixture_scope")
    if wally.psbt_get_num_inputs(psbt) != 1:
        raise PayloadError("fixture_scope")
    witness_utxo = wally.psbt_get_input_witness_utxo(psbt, 0)
    if witness_utxo is None:
        raise PayloadError("fixture_scope")
    funding_script = bytes(wally.tx_output_get_script(witness_utxo))
    redeem_script = wally.psbt_get_input_redeem_script(psbt, 0)
    witness_script = wally.psbt_get_input_witness_script(psbt, 0)
    sighash = wally.psbt_get_input_sighash(psbt, 0)
    if redeem_script not in (None, b"") or sighash not in (0, wally.WALLY_SIGHASH_ALL):
        raise PayloadError("fixture_scope")

    if fixture_id in ("p2wpkh", "intent-rich-p2wpkh"):
        if funding_script != P2WPKH_SCRIPT or witness_script not in (None, b""):
            raise PayloadError("fixture_scope")
        return PRIVATE_KEY_1, PUBKEY_1
    if funding_script != P2WSH_SCRIPT or bytes(witness_script or b"") != MULTISIG_SCRIPT:
        raise PayloadError("fixture_scope")
    return PRIVATE_KEY_2, PUBKEY_2


def sign_with_temporary_keypath(psbt, private_key, public_key):
    signing_psbt = wally.psbt_clone(psbt, 0)
    keypaths = wally.map_keypath_public_key_init(1)
    wally.map_keypath_add(keypaths, public_key, b"\x00" * 4, [0])
    wally.psbt_set_input_keypaths(signing_psbt, 0, keypaths)
    wally.psbt_sign(signing_psbt, private_key, 0)
    position = wally.psbt_find_input_signature(signing_psbt, 0, public_key)
    if not position:
        return False
    signature = wally.psbt_get_input_signature(signing_psbt, 0, position - 1)
    wally.psbt_add_input_signature(psbt, 0, public_key, signature)
    return True


def parse_error_response(request_id, digest, error, native_class="psbt.parse_failed"):
    if error.code == "invalid_payload":
        return failure(
            request_id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "Operation payload does not match the adapter protocol",
        )
    return failure(
        request_id,
        digest,
        "rejected",
        native_class,
        "libwally rejected the PSBT",
    )


def fixture_error_response(request_id, digest, error):
    if error.code == "commitment_missing":
        return failure(
            request_id,
            digest,
            "rejected",
            "adapter.fixture_commitments_missing",
            "The run did not authorize this fixture",
        )
    if error.code == "commitment_mismatch":
        return failure(
            request_id,
            digest,
            "rejected",
            "policy.fixture_commitment_mismatch",
            "PSBT does not match the run-scoped fixture commitment",
        )
    if error.code == "fixture_scope":
        return failure(
            request_id,
            digest,
            "rejected",
            "policy.fixture_scope_rejected",
            "PSBT is outside the authorized fixture script scope",
        )
    return parse_error_response(request_id, digest, error)


def hello(request_id, digest, payload):
    if payload:
        return failure(
            request_id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "hello expects an empty payload",
        )
    operation_script_types = {
        operation: ["p2wpkh", "p2wsh"]
        for operation in (
            "inspect",
            "roundtrip",
            "sign",
            "combine",
            "finalize",
            "extract",
            "convert",
        )
    }
    return success(
        request_id,
        digest,
        {
            "operations": [
                "hello",
                "native-parse",
                "inspect",
                "roundtrip",
                "sign",
                "combine",
                "finalize",
                "extract",
                "convert",
            ],
            "roles": ["parser", "signer", "combiner", "finalizer", "extractor"],
            "psbtVersions": [0, 2],
            "scriptTypes": ["p2wpkh", "p2wsh"],
            "operationScriptTypes": operation_script_types,
            "features": [
                "fixture-commitment-sha256",
                "bip370-unique-id",
                "unsigned-tx-sha256",
                "psbt-v0-v2-conversion",
                "network-free",
            ],
        },
    )


def native_parse(request_id, digest, payload):
    try:
        _, psbt = parse_psbt_payload(payload)
    except PayloadError as error:
        return parse_error_response(request_id, digest, error, "psbt.native_parse_failed")
    return success(
        request_id,
        digest,
        {
            "nativeParser": "libwally-core",
            "psbtVersion": wally.psbt_get_version(psbt),
            "inputs": wally.psbt_get_num_inputs(psbt),
            "outputs": wally.psbt_get_num_outputs(psbt),
        },
    )


def inspect(request_id, digest, payload):
    try:
        _, psbt = parse_psbt_payload(payload)
        output = inspect_output(psbt)
    except PayloadError as error:
        return parse_error_response(request_id, digest, error)
    except Exception:
        return failure(
            request_id,
            digest,
            "rejected",
            "psbt.identity_failed",
            "libwally could not determine PSBT transaction identity",
        )
    return success(request_id, digest, output)


def roundtrip(request_id, digest, payload):
    try:
        raw, psbt = parse_psbt_payload(payload)
    except PayloadError as error:
        return parse_error_response(request_id, digest, error)
    encoded = serialize_psbt(psbt)
    return success(
        request_id,
        digest,
        {
            "psbt": encoded,
            "byteIdentical": base64.b64decode(encoded) == raw,
            "psbtVersion": wally.psbt_get_version(psbt),
        },
    )


def sign(request_id, digest, payload, commitments):
    try:
        psbt, fixture_id = fixture_payload(payload)
        verify_fixture_commitment(psbt, fixture_id, commitments)
        private_key, public_key = validate_fixture_scope(psbt, fixture_id)
        before = [
            wally.psbt_get_input_signatures_size(psbt, index)
            for index in range(wally.psbt_get_num_inputs(psbt))
        ]
        sign_with_temporary_keypath(psbt, private_key, public_key)
        after = [
            wally.psbt_get_input_signatures_size(psbt, index)
            for index in range(wally.psbt_get_num_inputs(psbt))
        ]
    except PayloadError as error:
        return fixture_error_response(request_id, digest, error)
    except Exception:
        return failure(
            request_id,
            digest,
            "rejected",
            "signing.failed",
            "libwally could not sign the authorized PSBT",
        )

    signed_inputs = [index for index, counts in enumerate(zip(before, after)) if counts[1] > counts[0]]
    signatures_added = sum(after) - sum(before)
    if signatures_added <= 0:
        return failure(
            request_id,
            digest,
            "rejected",
            "signing.no_matching_input",
            "The authorized key did not match a PSBT input",
        )
    output = {
        "psbt": serialize_psbt(psbt),
        "signedInputs": signed_inputs,
        "signaturesAdded": signatures_added,
        **transaction_identity(psbt),
    }
    flags = modifiable_flags(psbt)
    if flags is not None:
        output["transactionModifiableFlags"] = flags
    return success(request_id, digest, output)


def combine(request_id, digest, payload):
    if not exact_fields(payload, ("psbts",)):
        return failure(
            request_id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "combine expects only a psbts array",
        )
    encoded_psbts = payload.get("psbts")
    if (
        not isinstance(encoded_psbts, list)
        or not 2 <= len(encoded_psbts) <= MAX_COMBINE_PSBT
        or any(not isinstance(encoded, str) for encoded in encoded_psbts)
    ):
        return failure(
            request_id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "psbts must contain between two and sixteen PSBT strings",
        )
    try:
        psbts = [parse_encoded_psbt(encoded)[1] for encoded in encoded_psbts]
        identities = [transaction_identity(psbt) for psbt in psbts]
    except PayloadError as error:
        return parse_error_response(request_id, digest, error)
    except Exception:
        return failure(
            request_id,
            digest,
            "rejected",
            "psbt.identity_failed",
            "libwally could not determine combined PSBT transaction identity",
        )

    expected_intent = identities[0]["unsignedTxSha256"]
    if any(identity["unsignedTxSha256"] != expected_intent for identity in identities[1:]):
        return failure(
            request_id,
            digest,
            "rejected",
            "combine.transaction_intent_mismatch",
            "PSBT sources do not describe the same unsigned transaction intent",
        )
    try:
        combined = wally.psbt_clone(psbts[0], 0)
        for source in psbts[1:]:
            wally.psbt_combine(combined, source)
    except Exception:
        return failure(
            request_id,
            digest,
            "rejected",
            "combine.incompatible_psbts",
            "libwally could not combine the PSBT sources",
        )
    output = {
        "psbt": serialize_psbt(combined),
        "combinedPsbtCount": len(psbts),
        "partialSignatureInputs": partial_signature_input_count(combined),
        **transaction_identity(combined),
    }
    flags = modifiable_flags(combined)
    if flags is not None:
        output["transactionModifiableFlags"] = flags
    return success(request_id, digest, output)


def finalize(request_id, digest, payload, commitments):
    try:
        psbt, fixture_id = fixture_payload(payload)
        verify_fixture_commitment(psbt, fixture_id, commitments)
        validate_fixture_scope(psbt, fixture_id)
        before = transaction_identity(psbt)
        wally.psbt_finalize(psbt, 0)
        if not wally.psbt_is_finalized(psbt):
            return failure(
                request_id,
                digest,
                "rejected",
                "finalize.incomplete",
                "PSBT does not contain enough valid signatures to finalize",
            )
        after = transaction_identity(psbt)
        if before["unsignedTxSha256"] != after["unsignedTxSha256"]:
            return failure(
                request_id,
                digest,
                "crashed",
                "finalize.transaction_intent_changed",
                "Native finalization changed the unsigned transaction intent",
            )
    except PayloadError as error:
        return fixture_error_response(request_id, digest, error)
    except Exception:
        return failure(
            request_id,
            digest,
            "rejected",
            "finalize.failed",
            "libwally could not finalize the authorized PSBT",
        )
    return success(
        request_id,
        digest,
        {
            "psbt": serialize_psbt(psbt),
            "finalized": True,
            "finalizedInputs": finalized_input_count(psbt),
            **after,
        },
    )


def extract(request_id, digest, payload):
    try:
        _, psbt = parse_psbt_payload(payload)
        identity = transaction_identity(psbt)
        if not wally.psbt_is_finalized(psbt):
            return failure(
                request_id,
                digest,
                "rejected",
                "extract.not_finalized",
                "PSBT must be fully finalized before extraction",
            )
        tx = wally.psbt_extract(psbt, wally.WALLY_PSBT_EXTRACT_FINAL)
        transaction = bytes(
            wally.tx_to_bytes(tx, wally.WALLY_TX_FLAG_USE_WITNESS)
        )
    except PayloadError as error:
        return parse_error_response(request_id, digest, error)
    except Exception:
        return failure(
            request_id,
            digest,
            "rejected",
            "extract.failed",
            "libwally could not extract the finalized transaction",
        )
    witness_hash = hashlib.sha256(hashlib.sha256(transaction).digest()).digest()
    return success(
        request_id,
        digest,
        {
            "transaction": transaction.hex(),
            "transactionId": display_hash(wally.tx_get_txid(tx)),
            "witnessTransactionId": display_hash(witness_hash),
            "bip370UniqueId": identity["bip370UniqueId"],
            "unsignedTxSha256": identity["unsignedTxSha256"],
        },
    )


def convert(request_id, digest, payload):
    if (
        not exact_fields(payload, ("psbt", "targetVersion"))
        or payload.get("targetVersion") not in (0, 2)
        or isinstance(payload.get("targetVersion"), bool)
    ):
        return failure(
            request_id,
            digest,
            "rejected",
            "protocol.invalid_payload",
            "convert expects a psbt and targetVersion 0 or 2",
        )
    try:
        _, psbt = parse_psbt_payload(payload, ("psbt", "targetVersion"))
        source_version = wally.psbt_get_version(psbt)
        before = transaction_identity(psbt)
        wally.psbt_set_version(psbt, 0, payload["targetVersion"])
        after = transaction_identity(psbt)
    except PayloadError as error:
        return parse_error_response(request_id, digest, error)
    except Exception:
        return failure(
            request_id,
            digest,
            "rejected",
            "conversion.failed",
            "libwally could not convert the PSBT version",
        )
    if before["unsignedTxSha256"] != after["unsignedTxSha256"]:
        return failure(
            request_id,
            digest,
            "crashed",
            "conversion.transaction_intent_changed",
            "Native conversion changed the unsigned transaction intent",
        )
    output = {
        "psbt": serialize_psbt(psbt),
        "sourceVersion": source_version,
        "psbtVersion": wally.psbt_get_version(psbt),
        **after,
    }
    flags = modifiable_flags(psbt)
    if flags is not None:
        output["transactionModifiableFlags"] = flags
    return success(request_id, digest, output)


def handle_request(value, digest, commitments=None):
    request_id = fallback_request_id(value)
    if not valid_request(value):
        return failure(
            request_id,
            digest,
            "rejected",
            "protocol.invalid_request",
            "Request does not match the adapter protocol",
        )
    commitments = commitments or {}
    operation = value["operation"]
    payload = value["payload"]
    request_id = value["id"]

    if operation == "hello":
        return hello(request_id, digest, payload)
    if operation == "native-parse":
        return native_parse(request_id, digest, payload)
    if operation == "inspect":
        return inspect(request_id, digest, payload)
    if operation == "roundtrip":
        return roundtrip(request_id, digest, payload)
    if operation == "sign":
        return sign(request_id, digest, payload, commitments)
    if operation == "combine":
        return combine(request_id, digest, payload)
    if operation == "finalize":
        return finalize(request_id, digest, payload, commitments)
    if operation == "extract":
        return extract(request_id, digest, payload)
    if operation == "convert":
        return convert(request_id, digest, payload)
    return failure(
        request_id,
        digest,
        "unsupported",
        "operation.unsupported",
        "Operation is not implemented by the pinned libwally adapter",
    )


def artifact_digest():
    with open(os.path.abspath(__file__), "rb") as source:
        return "sha256:" + hashlib.sha256(source.read()).hexdigest()


def main():
    try:
        commitments = parse_fixture_commitments(
            os.environ.get("PSBT_LAB_FIXTURE_COMMITMENTS")
        )
    except ValueError:
        return 2
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
            try:
                response = handle_request(request, digest, commitments)
            except Exception:
                response = failure(
                    fallback_request_id(request),
                    digest,
                    "crashed",
                    "adapter.unexpected_failure",
                    "libwally adapter encountered an unexpected internal failure",
                )
        encoded = json.dumps(response, separators=(",", ":"), ensure_ascii=True)
        sys.stdout.write(encoded + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    raise SystemExit(main())
