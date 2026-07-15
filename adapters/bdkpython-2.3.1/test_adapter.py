import unittest

from adapter import classify_finalize_errors, handle_request


MINIMAL_PSBT = "cHNidP8BADwCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wD/////AQAAAAAAAAAAAAAAAAAAAAA="
DIGEST = "sha256:deadbeef"


def request(operation, payload):
    return {
        "protocol": "psbt-lab.adapter/0.2",
        "id": "test-1",
        "operation": operation,
        "payload": payload,
    }


class FakeInputError(Exception):
    def __init__(self, reason, index):
        self.reason = reason
        self.index = index


class AdapterTests(unittest.TestCase):
    def test_negotiates_bdk_version(self):
        response = handle_request(request("hello", {}), DIGEST)

        self.assertEqual(response["status"], "ok")
        self.assertEqual(response["implementation"]["name"], "bdkpython")
        self.assertEqual(response["implementation"]["version"], "2.3.1")
        self.assertEqual(
            response["output"],
            {
                "operations": ["hello", "inspect", "roundtrip", "finalize"],
                "roles": ["parser", "finalizer"],
                "psbtVersions": [0],
                "scriptTypes": ["p2wsh"],
                "features": ["historical-regression.bdk-wallet-488"],
            },
        )

    def test_known_unsupported_operations_have_a_stable_error(self):
        for operation in ("sign", "combine", "finalize-inputs"):
            with self.subTest(operation=operation):
                response = handle_request(request(operation, {}), DIGEST)

                self.assertEqual(response["status"], "unsupported")
                self.assertEqual(response["error"]["class"], "operation.unsupported")

    def test_removed_fixture_operation_is_unsupported(self):
        response = handle_request(request("fixture-finalize-input", {}), DIGEST)

        self.assertEqual(response["status"], "unsupported")
        self.assertEqual(response["error"]["class"], "operation.unsupported")

    def test_roundtrips_psbt_v0(self):
        response = handle_request(
            request("roundtrip", {"psbt": MINIMAL_PSBT}), DIGEST
        )

        self.assertEqual(response["status"], "ok")
        self.assertEqual(response["output"]["psbt"], MINIMAL_PSBT)
        self.assertTrue(response["output"]["byteIdentical"])

    def test_rejects_unknown_payload_fields(self):
        response = handle_request(
            request("roundtrip", {"psbt": MINIMAL_PSBT, "command": "unsafe"}),
            DIGEST,
        )

        self.assertEqual(response["status"], "rejected")
        self.assertEqual(response["error"]["class"], "protocol.invalid_payload")

    def test_classifies_missing_witness_script_without_leaking_details(self):
        result = classify_finalize_errors(
            [FakeInputError("Missing witness script: secret-like-data", 0)]
        )

        self.assertEqual(result[0], "finalize.missing_witness_script")
        self.assertNotIn("secret-like-data", result[1])


if __name__ == "__main__":
    unittest.main()
