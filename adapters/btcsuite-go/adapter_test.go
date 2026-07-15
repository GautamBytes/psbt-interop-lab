package adapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestHelloAdvertisesOnlyImplementedCapabilities(t *testing.T) {
	response := request(t, "hello", map[string]any{})

	if response.Status != "ok" {
		t.Fatalf("status = %q, want ok", response.Status)
	}
	if response.Implementation.Name != "btcsuite-go" {
		t.Fatalf("implementation name = %q", response.Implementation.Name)
	}
	want := map[string]any{
		"operations":   []any{"hello", "inspect", "roundtrip", "sign", "finalize", "finalize-inputs"},
		"roles":        []any{"parser", "signer", "finalizer"},
		"psbtVersions": []any{float64(0)},
		"scriptTypes":  []any{"p2wsh"},
	}
	if !jsonEqual(response.Output, want) {
		t.Fatalf("hello output = %#v, want %#v", response.Output, want)
	}
}

func TestRoundtripPreservesCanonicalPSBTV0(t *testing.T) {
	encoded := fixturePSBT(t, 1)
	response := request(t, "roundtrip", map[string]any{"psbt": encoded})

	if response.Status != "ok" {
		t.Fatalf("roundtrip status = %q: %#v", response.Status, response.Error)
	}
	if response.Output["psbt"] != encoded || response.Output["byteIdentical"] != true || response.Output["psbtVersion"] != 0 {
		t.Fatalf("roundtrip output = %#v", response.Output)
	}
}

func TestInspectReportsPSBTStructure(t *testing.T) {
	response := request(t, "inspect", map[string]any{"psbt": fixturePSBT(t, 2)})
	if response.Status != "ok" {
		t.Fatalf("inspect status = %q: %#v", response.Status, response.Error)
	}
	if response.Output["inputs"] != 2 || response.Output["outputs"] != 1 || response.Output["finalizedInputs"] != 0 || response.Output["partialSignatureInputs"] != 0 {
		t.Fatalf("inspect output = %#v", response.Output)
	}
}

func TestRejectsNonCanonicalMalformedAndOversizedPSBT(t *testing.T) {
	encoded := fixturePSBT(t, 1)
	for name, value := range map[string]string{
		"noncanonical": encoded + "\n",
		"malformed":    "not-base64",
		"oversized":    base64.StdEncoding.EncodeToString(make([]byte, maxPSBTBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			response := request(t, "roundtrip", map[string]any{"psbt": value})
			assertFailureClass(t, response, "rejected", "psbt.parse_failed")
		})
	}
}

func TestRejectsUnauthorizedSigning(t *testing.T) {
	encoded := fixturePSBT(t, 1)
	for name, payload := range map[string]map[string]any{
		"wrong network":   {"psbt": encoded, "network": "bitcoin", "fixtureId": "happy-path"},
		"unknown fixture": {"psbt": encoded, "network": "regtest", "fixtureId": "other"},
		"wrong script":    {"psbt": untrustedPSBT(t), "network": "regtest", "fixtureId": "happy-path"},
	} {
		t.Run(name, func(t *testing.T) {
			response := request(t, "sign", payload)
			if response.Status != "rejected" {
				t.Fatalf("status = %q", response.Status)
			}
			if response.Error == nil || response.Error.Class == "" || bytes.Contains([]byte(response.Error.Message), []byte("cMahea")) {
				t.Fatalf("unsafe or missing error = %#v", response.Error)
			}
		})
	}
}

func TestSignsAndFinalizesFixtureInputs(t *testing.T) {
	signed := request(t, "sign", signingPayload(fixturePSBT(t, 2), "bdk-finalize-regression"))
	if signed.Status != "ok" || signed.Output["signedInputs"] != 2 {
		t.Fatalf("sign response = %#v", signed)
	}

	partial := request(t, "finalize-inputs", map[string]any{
		"psbt": signed.Output["psbt"], "network": "regtest", "fixtureId": "bdk-finalize-regression", "inputIndexes": []any{1},
	})
	if partial.Status != "ok" || !jsonEqual(partial.Output["finalizedInputs"], []any{float64(1)}) || partial.Output["remainingPartialInputs"] != 1 {
		t.Fatalf("partial finalization response = %#v", partial)
	}
	partialPacket := decodePacket(t, partial.Output["psbt"].(string))
	if partialPacket.Inputs[0].FinalScriptWitness != nil || partialPacket.Inputs[1].FinalScriptWitness == nil || len(partialPacket.Inputs[0].PartialSigs) != 1 || len(partialPacket.Inputs[1].PartialSigs) != 0 {
		t.Fatal("selected finalization changed the wrong inputs")
	}

	complete := request(t, "finalize", signingPayload(partial.Output["psbt"].(string), "bdk-finalize-regression"))
	if complete.Status != "ok" || !jsonEqual(complete.Output["finalizedInputs"], []int{0}) || complete.Output["complete"] != true {
		t.Fatalf("finalization response = %#v", complete)
	}
	packet := decodePacket(t, complete.Output["psbt"].(string))
	if !packet.IsComplete() {
		t.Fatal("finalize did not produce a complete PSBT")
	}
}

func TestRejectsDuplicateAndOutOfRangeFinalizationIndexes(t *testing.T) {
	for name, indexes := range map[string]any{
		"empty":        []any{},
		"duplicate":    []any{0, 0},
		"negative":     []any{-1},
		"fraction":     []any{0.5},
		"string":       []any{"0"},
		"unsafe":       []any{float64(9_007_199_254_740_992)},
		"out of range": []any{2},
	} {
		t.Run(name, func(t *testing.T) {
			response := request(t, "finalize-inputs", map[string]any{
				"psbt": fixturePSBT(t, 2), "network": "regtest", "fixtureId": "bdk-finalize-regression", "inputIndexes": indexes,
			})
			assertFailureClass(t, response, "rejected", "protocol.invalid_payload")
		})
	}
}

func TestStrictPayloadsAndUnsupportedOperations(t *testing.T) {
	invalid := request(t, "sign", map[string]any{"psbt": fixturePSBT(t, 1), "network": "regtest", "fixtureId": "happy-path", "keyWif": "caller-controlled"})
	assertFailureClass(t, invalid, "rejected", "protocol.invalid_payload")
	for _, operation := range []string{"combine", "broadcast", "taproot-sign"} {
		response := request(t, operation, map[string]any{})
		assertFailureClass(t, response, "unsupported", "operation.unsupported")
	}
}

func TestRejectsInvalidRequestAndInvalidJSON(t *testing.T) {
	invalidRequest := HandleJSON([]byte(`{"protocol":"wrong","id":"safe-1","operation":"hello","payload":{}}`), testDigest)
	assertFailureClass(t, invalidRequest, "rejected", "protocol.invalid_request")
	invalidID := HandleJSON([]byte(`{"protocol":"psbt-lab.adapter/0.2","id":"-unsafe","operation":"hello","payload":{}}`), testDigest)
	assertFailureClass(t, invalidID, "rejected", "protocol.invalid_request")
	nonObjectJSON := HandleJSON([]byte(`[]`), testDigest)
	assertFailureClass(t, nonObjectJSON, "rejected", "protocol.invalid_request")
	invalidJSON := HandleJSON([]byte(`{"protocol":`), testDigest)
	assertFailureClass(t, invalidJSON, "rejected", "protocol.invalid_json")
}

func TestResponseHasProtocolSchemaBasics(t *testing.T) {
	response := request(t, "hello", map[string]any{})
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if len(value) != 5 || value["protocol"] != protocol || value["id"] != "test-1" || value["status"] != "ok" || value["error"] != nil {
		t.Fatalf("response schema basics failed: %#v", value)
	}
	implementation, ok := value["implementation"].(map[string]any)
	if !ok || implementation["artifactDigest"] != testDigest || implementation["sourceRevision"] == "" {
		t.Fatalf("implementation schema basics failed: %#v", implementation)
	}
}

func request(t *testing.T, operation string, payload map[string]any) Response {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"protocol": protocol, "id": "test-1", "operation": operation, "payload": payload})
	if err != nil {
		t.Fatal(err)
	}
	return HandleJSON(raw, testDigest)
}

func signingPayload(encoded, fixtureID string) map[string]any {
	return map[string]any{"psbt": encoded, "network": "regtest", "fixtureId": fixtureID}
}

func assertFailureClass(t *testing.T, response Response, status, class string) {
	t.Helper()
	if response.Status != status || response.Error == nil || response.Error.Class != class {
		t.Fatalf("response = %#v, want %s/%s", response, status, class)
	}
}

func fixturePSBT(t *testing.T, inputs int) string {
	t.Helper()
	key := fixtureKey(t)
	witnessScript := witnessScript(t, key)
	pkScript := fixtureP2WSHScript(witnessScript)
	funding := wire.NewMsgTx(2)
	funding.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	for range inputs {
		funding.AddTxOut(&wire.TxOut{Value: 50_000, PkScript: pkScript})
	}
	spend := wire.NewMsgTx(2)
	for index := range inputs {
		spend.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: funding.TxHash(), Index: uint32(index)}, nil, nil))
	}
	spend.AddTxOut(&wire.TxOut{Value: int64(inputs) * 40_000, PkScript: pkScript})
	packet, err := psbt.NewFromUnsignedTx(spend)
	if err != nil {
		t.Fatal(err)
	}
	for index := range packet.Inputs {
		packet.Inputs[index].NonWitnessUtxo = funding.Copy()
		packet.Inputs[index].WitnessUtxo = funding.TxOut[index]
		packet.Inputs[index].WitnessScript = witnessScript
	}
	return encodePacket(t, packet)
}

func untrustedPSBT(t *testing.T) string {
	t.Helper()
	packet := decodePacket(t, fixturePSBT(t, 1))
	packet.Inputs[0].WitnessScript = []byte{txscript.OP_TRUE}
	packet.Inputs[0].WitnessUtxo.PkScript = fixtureP2WSHScript(packet.Inputs[0].WitnessScript)
	packet.Inputs[0].NonWitnessUtxo.TxOut[0].PkScript = packet.Inputs[0].WitnessUtxo.PkScript
	return encodePacket(t, packet)
}

func fixtureKey(t *testing.T) *btcutil.WIF {
	t.Helper()
	key, err := btcutil.DecodeWIF(testWIF)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func witnessScript(t *testing.T, key *btcutil.WIF) []byte {
	t.Helper()
	script, err := txscript.NewScriptBuilder().AddData(key.PrivKey.PubKey().SerializeCompressed()).AddOp(txscript.OP_CHECKSIG).Script()
	if err != nil {
		t.Fatal(err)
	}
	return script
}

func fixtureP2WSHScript(witnessScript []byte) []byte {
	hash := sha256.Sum256(witnessScript)
	return append([]byte{txscript.OP_0, txscript.OP_DATA_32}, hash[:]...)
}

func encodePacket(t *testing.T, packet *psbt.Packet) string {
	t.Helper()
	var serialized bytes.Buffer
	if err := packet.Serialize(&serialized); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(serialized.Bytes())
}

func decodePacket(t *testing.T, encoded string) *psbt.Packet {
	t.Helper()
	packet, err := psbt.NewFromRawBytes(bytes.NewReader([]byte(encoded)), true)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func jsonEqual(actual, expected any) bool {
	actualJSON, _ := json.Marshal(actual)
	expectedJSON, _ := json.Marshal(expected)
	return bytes.Equal(actualJSON, expectedJSON)
}
