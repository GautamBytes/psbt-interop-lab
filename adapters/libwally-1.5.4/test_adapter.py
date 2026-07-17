import base64
import hashlib
import json
import os
import subprocess
import sys
import unittest

from adapter import (
    SOURCE_REVISION,
    handle_request,
    parse_fixture_commitments,
)
import wallycore as wally


DIGEST = "sha256:deadbeef"
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


def request(operation, payload):
    return {
        "protocol": "psbt-lab.adapter/0.2",
        "id": "test-1",
        "operation": operation,
        "payload": payload,
    }


def hash160(value):
    return hashlib.new("ripemd160", hashlib.sha256(value).digest()).digest()


def p2wpkh_script(pubkey):
    return b"\x00\x14" + hash160(pubkey)


def multisig_script():
    return b"\x52\x21" + PUBKEY_1 + b"\x21" + PUBKEY_2 + b"\x21" + PUBKEY_3 + b"\x53\xae"


def fixture_psbt(fixture_id="p2wpkh", sequence=0xFFFFFFFD):
    psbt = wally.psbt_init(2, 0, 0, 0, 0)
    tx_input = wally.tx_input_init(bytes.fromhex("11" * 32), 0, sequence, None, None)
    wally.psbt_add_tx_input_at(psbt, 0, 0, tx_input)

    output = wally.tx_output_init(90_000, p2wpkh_script(PUBKEY_3))
    wally.psbt_add_tx_output_at(psbt, 0, 0, output)

    if fixture_id in ("p2wpkh", "intent-rich-p2wpkh"):
        funding_script = p2wpkh_script(PUBKEY_1)
    else:
        witness_script = multisig_script()
        funding_script = b"\x00\x20" + hashlib.sha256(witness_script).digest()
        wally.psbt_set_input_witness_script(psbt, 0, witness_script)

    wally.psbt_set_input_witness_utxo(
        psbt, 0, wally.tx_output_init(100_000, funding_script)
    )
    wally.psbt_set_input_sighash(psbt, 0, wally.WALLY_SIGHASH_ALL)
    wally.psbt_set_tx_modifiable_flags(
        psbt, wally.WALLY_PSBT_TXMOD_INPUTS | wally.WALLY_PSBT_TXMOD_OUTPUTS
    )
    return wally.psbt_to_base64(psbt, 0)


def unsigned_tx_bytes(encoded):
    psbt = wally.psbt_from_base64(encoded, wally.WALLY_PSBT_PARSE_FLAG_STRICT)
    tx = wally.psbt_extract(psbt, wally.WALLY_PSBT_EXTRACT_NON_FINAL)
    return bytes(wally.tx_to_bytes(tx, 0))


def fixture_commitments(fixture_id, encoded):
    digest = hashlib.sha256(unsigned_tx_bytes(encoded)).hexdigest()
    return {fixture_id: f"sha256:{digest}"}


def native_sign_with_keypath(psbt, private_key, public_key):
    keypaths = wally.map_keypath_public_key_init(1)
    wally.map_keypath_add(keypaths, public_key, b"\x00" * 4, [0])
    wally.psbt_set_input_keypaths(psbt, 0, keypaths)
    wally.psbt_sign(psbt, private_key, 0)


def ok(operation, payload, commitments=None):
    response = handle_request(request(operation, payload), DIGEST, commitments or {})
    if response["status"] != "ok":
        raise AssertionError(response)
    return response["output"]


class AdapterTests(unittest.TestCase):
    def test_hello_pins_reviewed_libwally_and_complete_protocol(self):
        response = handle_request(request("hello", {}), DIGEST, {})

        self.assertEqual(response["status"], "ok")
        self.assertEqual(response["implementation"]["name"], "libwally-core")
        self.assertEqual(response["implementation"]["version"], "1.5.4")
        self.assertEqual(response["implementation"]["sourceRevision"], SOURCE_REVISION)
        self.assertEqual(
            response["output"]["operations"],
            [
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
        )
        self.assertEqual(response["output"]["psbtVersions"], [0, 2])
        self.assertIn("bip370-unique-id", response["output"]["features"])
        self.assertIn("unsigned-tx-sha256", response["output"]["features"])

    def test_native_parse_inspect_and_roundtrip_use_libwally(self):
        encoded = fixture_psbt()

        parsed = ok("native-parse", {"psbt": encoded})
        inspected = ok("inspect", {"psbt": encoded})
        roundtripped = ok("roundtrip", {"psbt": encoded})

        self.assertEqual(parsed["nativeParser"], "libwally-core")
        self.assertEqual(parsed["psbtVersion"], 2)
        self.assertEqual(inspected["inputs"], 1)
        self.assertEqual(inspected["outputs"], 1)
        self.assertEqual(inspected["transactionModifiableFlags"], 3)
        self.assertEqual(inspected["partialSignatureInputs"], 0)
        self.assertNotEqual(inspected["transactionId"], inspected["bip370UniqueId"])
        self.assertTrue(inspected["unsignedTxSha256"].startswith("sha256:"))
        self.assertEqual(roundtripped["psbt"], encoded)
        self.assertTrue(roundtripped["byteIdentical"])

    def test_strict_parser_and_exact_payload_shape_reject_invalid_input(self):
        invalid = base64.b64encode(b"not a psbt").decode("ascii")
        rejected = handle_request(
            request("native-parse", {"psbt": invalid}), DIGEST, {}
        )
        extra = handle_request(
            request("roundtrip", {"psbt": fixture_psbt(), "command": "unsafe"}),
            DIGEST,
            {},
        )

        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["error"]["class"], "psbt.native_parse_failed")
        self.assertEqual(extra["status"], "rejected")
        self.assertEqual(extra["error"]["class"], "protocol.invalid_payload")

    def test_sign_requires_run_scoped_commitment_and_clears_modifiable_flags(self):
        encoded = fixture_psbt()
        payload = {"psbt": encoded, "network": "regtest", "fixtureId": "p2wpkh"}

        missing = handle_request(request("sign", payload), DIGEST, {})
        signed = ok("sign", payload, fixture_commitments("p2wpkh", encoded))

        self.assertEqual(missing["status"], "rejected")
        self.assertEqual(
            missing["error"]["class"], "adapter.fixture_commitments_missing"
        )
        self.assertEqual(signed["signaturesAdded"], 1)
        self.assertEqual(signed["signedInputs"], [0])
        self.assertEqual(signed["transactionModifiableFlags"], 0)
        self.assertEqual(
            signed["unsignedTxSha256"],
            ok("inspect", {"psbt": encoded})["unsignedTxSha256"],
        )

    def test_two_of_three_directional_handoff_combines_finalizes_and_extracts(self):
        encoded = fixture_psbt("p2wsh-2-of-3")
        commitments = fixture_commitments("p2wsh-2-of-3", encoded)
        scalar_one = wally.psbt_from_base64(
            encoded, wally.WALLY_PSBT_PARSE_FLAG_STRICT
        )
        native_sign_with_keypath(scalar_one, PRIVATE_KEY_1, PUBKEY_1)
        scalar_one_encoded = wally.psbt_to_base64(scalar_one, 0)

        scalar_two = ok(
            "sign",
            {
                "psbt": encoded,
                "network": "regtest",
                "fixtureId": "p2wsh-2-of-3",
            },
            commitments,
        )["psbt"]
        combined = ok("combine", {"psbts": [scalar_one_encoded, scalar_two]})
        finalized = ok(
            "finalize",
            {
                "psbt": combined["psbt"],
                "network": "regtest",
                "fixtureId": "p2wsh-2-of-3",
            },
            commitments,
        )
        extracted = ok("extract", {"psbt": finalized["psbt"]})

        self.assertEqual(combined["partialSignatureInputs"], 1)
        self.assertEqual(finalized["finalizedInputs"], 1)
        self.assertTrue(finalized["finalized"])
        self.assertGreater(len(extracted["transaction"]), 100)
        self.assertEqual(extracted["transactionId"], combined["transactionId"])
        self.assertNotEqual(extracted["witnessTransactionId"], "")

    def test_partial_multisig_cannot_finalize(self):
        encoded = fixture_psbt("p2wsh-2-of-3")
        commitments = fixture_commitments("p2wsh-2-of-3", encoded)
        partial = ok(
            "sign",
            {
                "psbt": encoded,
                "network": "regtest",
                "fixtureId": "p2wsh-2-of-3",
            },
            commitments,
        )["psbt"]

        response = handle_request(
            request(
                "finalize",
                {
                    "psbt": partial,
                    "network": "regtest",
                    "fixtureId": "p2wsh-2-of-3",
                },
            ),
            DIGEST,
            commitments,
        )

        self.assertEqual(response["status"], "rejected")
        self.assertEqual(response["error"]["class"], "finalize.incomplete")

    def test_combine_rejects_bip370_id_collision_with_different_sequences(self):
        first = fixture_psbt(sequence=0xFFFFFFFD)
        second = fixture_psbt(sequence=0xFFFFFFFC)
        first_identity = ok("inspect", {"psbt": first})
        second_identity = ok("inspect", {"psbt": second})

        response = handle_request(
            request("combine", {"psbts": [first, second]}), DIGEST, {}
        )

        self.assertEqual(
            first_identity["bip370UniqueId"], second_identity["bip370UniqueId"]
        )
        self.assertNotEqual(
            first_identity["unsignedTxSha256"], second_identity["unsignedTxSha256"]
        )
        self.assertEqual(response["status"], "rejected")
        self.assertEqual(
            response["error"]["class"], "combine.transaction_intent_mismatch"
        )

    def test_conversion_preserves_intent_and_bip370_identity(self):
        encoded = fixture_psbt()
        before = ok("inspect", {"psbt": encoded})
        v0 = ok("convert", {"psbt": encoded, "targetVersion": 0})
        restored = ok("convert", {"psbt": v0["psbt"], "targetVersion": 2})

        self.assertEqual(v0["sourceVersion"], 2)
        self.assertEqual(v0["psbtVersion"], 0)
        self.assertEqual(restored["sourceVersion"], 0)
        self.assertEqual(restored["psbtVersion"], 2)
        self.assertEqual(before["transactionId"], restored["transactionId"])
        self.assertEqual(before["unsignedTxSha256"], restored["unsignedTxSha256"])
        self.assertEqual(before["bip370UniqueId"], restored["bip370UniqueId"])

    def test_fixture_commitment_configuration_is_bounded_and_allowlisted(self):
        encoded = fixture_psbt()
        configured = fixture_commitments("p2wpkh", encoded)

        self.assertEqual(
            parse_fixture_commitments(json.dumps(configured)), configured
        )
        self.assertEqual(parse_fixture_commitments(None), {})
        for invalid in (
            "{}",
            "[]",
            json.dumps({"unknown": f"sha256:{'a' * 64}"}),
            json.dumps({"p2wpkh": f"sha256:{'A' * 64}"}),
            "x" * 4097,
        ):
            with self.subTest(invalid=invalid[:20]):
                with self.assertRaises(ValueError):
                    parse_fixture_commitments(invalid)

    def test_process_rejects_malformed_fixture_configuration_before_protocol(self):
        env = dict(os.environ)
        env["PSBT_LAB_FIXTURE_COMMITMENTS"] = "not-json"
        result = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(__file__), "adapter.py")],
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"not-json", result.stderr)


if __name__ == "__main__":
    unittest.main()
