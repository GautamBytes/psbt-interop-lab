package adapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	protocol       = "psbt-lab.adapter/0.2"
	maxPSBTBytes   = 4 * 1024 * 1024
	maxSafeInteger = uint64(9_007_199_254_740_991)
	testWIF        = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA"
)

var allowedFixtures = map[string]struct{}{
	"happy-path":              {},
	"bdk-finalize-regression": {},
}

type Implementation struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	ArtifactDigest string `json:"artifactDigest"`
	SourceRevision string `json:"sourceRevision,omitempty"`
}

type Error struct {
	Class     string `json:"class"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type Response struct {
	Protocol       string         `json:"protocol"`
	ID             string         `json:"id"`
	Status         string         `json:"status"`
	Implementation Implementation `json:"implementation"`
	Output         map[string]any `json:"output,omitempty"`
	Error          *Error         `json:"error,omitempty"`
}

type adapterRequest struct {
	Protocol  string                     `json:"protocol"`
	ID        string                     `json:"id"`
	Operation string                     `json:"operation"`
	Payload   map[string]json.RawMessage `json:"payload"`
}

func Handle(raw json.RawMessage, digest string) Response {
	return HandleJSON(raw, digest)
}

func HandleJSON(raw []byte, digest string) Response {
	fallback := fallbackID(raw)
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return failure(fallback, digest, "rejected", "protocol.invalid_json", "Request line is not valid JSON")
	}
	if _, ok := generic.(map[string]any); !ok {
		return failure(fallback, digest, "rejected", "protocol.invalid_request", "Request does not match the adapter protocol")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return failure(fallback, digest, "rejected", "protocol.invalid_request", "Request does not match the adapter protocol")
	}
	if !hasOnlyFields(fields, "protocol", "id", "operation", "payload") {
		return failure(fallback, digest, "rejected", "protocol.invalid_request", "Request does not match the adapter protocol")
	}
	var value adapterRequest
	if err := json.Unmarshal(raw, &value); err != nil || value.Payload == nil || value.Protocol != protocol || !safeID(value.ID) {
		return failure(fallback, digest, "rejected", "protocol.invalid_request", "Request does not match the adapter protocol")
	}

	switch value.Operation {
	case "hello":
		if !hasOnlyFields(value.Payload) {
			return invalidPayload(value.ID, digest, "hello expects an empty payload")
		}
		return success(value.ID, digest, map[string]any{
			"operations":   []string{"hello", "inspect", "roundtrip", "sign", "finalize", "finalize-inputs"},
			"roles":        []string{"parser", "signer", "finalizer"},
			"psbtVersions": []int{0},
			"scriptTypes":  []string{"p2wsh"},
		})
	case "roundtrip":
		return roundtrip(value, digest)
	case "inspect":
		return inspect(value, digest)
	case "sign":
		return sign(value, digest)
	case "finalize":
		return finalize(value, digest)
	case "finalize-inputs":
		return finalizeInputs(value, digest)
	default:
		return failure(value.ID, digest, "unsupported", "operation.unsupported", "Operation is not supported by this adapter")
	}
}

func roundtrip(value adapterRequest, digest string) Response {
	encoded, ok := psbtPayload(value.Payload, "psbt")
	if !ok {
		return invalidPayload(value.ID, digest, "roundtrip expects only a psbt field")
	}
	raw, packet, err := parsePSBT(encoded)
	if err != nil {
		return failure(value.ID, digest, "rejected", "psbt.parse_failed", "PSBT could not be parsed")
	}
	serialized, err := serializePSBT(packet)
	if err != nil {
		return failure(value.ID, digest, "crashed", "adapter.serialize_failed", "PSBT could not be serialized")
	}
	return success(value.ID, digest, map[string]any{
		"psbt":          base64.StdEncoding.EncodeToString(serialized),
		"byteIdentical": bytes.Equal(raw, serialized),
		"psbtVersion":   0,
	})
}

func inspect(value adapterRequest, digest string) Response {
	encoded, ok := psbtPayload(value.Payload, "psbt")
	if !ok {
		return invalidPayload(value.ID, digest, "inspect expects only a psbt field")
	}
	_, packet, err := parsePSBT(encoded)
	if err != nil {
		return failure(value.ID, digest, "rejected", "psbt.parse_failed", "PSBT could not be parsed")
	}
	finalized, partial := 0, 0
	for _, input := range packet.Inputs {
		if input.FinalScriptSig != nil || input.FinalScriptWitness != nil {
			finalized++
		}
		if len(input.PartialSigs) > 0 {
			partial++
		}
	}
	return success(value.ID, digest, map[string]any{
		"psbtVersion":            0,
		"inputs":                 len(packet.Inputs),
		"outputs":                len(packet.Outputs),
		"finalizedInputs":        finalized,
		"partialSignatureInputs": partial,
	})
}

func sign(value adapterRequest, digest string) Response {
	encoded, fixtureID, failureResponse := fixturePayload(value, digest, "psbt", "network", "fixtureId")
	if failureResponse != nil {
		return *failureResponse
	}
	_ = fixtureID
	_, packet, err := parsePSBT(encoded)
	if err != nil {
		return failure(value.ID, digest, "rejected", "psbt.parse_failed", "PSBT could not be parsed")
	}
	key, publicKey, witnessScript, funding, err := authorizeFixture(packet)
	if err != nil {
		return failure(value.ID, digest, "rejected", "policy.psbt_not_authorized", "PSBT is outside the authorized fixture scope")
	}
	updater, err := psbt.NewUpdater(packet)
	if err != nil {
		return failure(value.ID, digest, "rejected", "psbt.parse_failed", "PSBT could not be prepared for signing")
	}
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(packet.Inputs))
	for index, input := range packet.UnsignedTx.TxIn {
		prevOuts[input.PreviousOutPoint] = funding[index]
	}
	sigHashes := txscript.NewTxSigHashes(packet.UnsignedTx, txscript.NewMultiPrevOutFetcher(prevOuts))
	signed := 0
	for index := range packet.Inputs {
		signature, err := txscript.RawTxInWitnessSignature(packet.UnsignedTx, sigHashes, index, funding[index].Value, witnessScript, txscript.SigHashAll, key.PrivKey)
		if err != nil {
			return failure(value.ID, digest, "rejected", "signing.failed", "Fixture signing failed")
		}
		outcome, err := updater.Sign(index, signature, publicKey, nil, nil)
		if err != nil || outcome != psbt.SignSuccesful {
			return failure(value.ID, digest, "rejected", "signing.failed", "Fixture signing failed")
		}
		signed++
	}
	encodedResult, err := encodePSBT(packet)
	if err != nil {
		return failure(value.ID, digest, "crashed", "adapter.serialize_failed", "PSBT could not be serialized")
	}
	return success(value.ID, digest, map[string]any{"psbt": encodedResult, "signedInputs": signed})
}

func finalize(value adapterRequest, digest string) Response {
	encoded, _, failureResponse := fixturePayload(value, digest, "psbt", "network", "fixtureId")
	if failureResponse != nil {
		return *failureResponse
	}
	_, packet, err := parsePSBT(encoded)
	if err != nil {
		return failure(value.ID, digest, "rejected", "psbt.parse_failed", "PSBT could not be parsed")
	}
	_, publicKey, _, _, err := authorizeFixture(packet)
	if err != nil {
		return failure(value.ID, digest, "rejected", "policy.psbt_not_authorized", "PSBT is outside the authorized fixture scope")
	}
	indexes := make([]int, 0, len(packet.Inputs))
	for index, input := range packet.Inputs {
		if input.FinalScriptSig == nil && input.FinalScriptWitness == nil {
			indexes = append(indexes, index)
		}
	}
	return finalizePacket(value.ID, digest, packet, publicKey, indexes)
}

func finalizeInputs(value adapterRequest, digest string) Response {
	encoded, fixtureID, failureResponse := fixturePayload(value, digest, "psbt", "network", "fixtureId", "inputIndexes")
	if failureResponse != nil {
		return *failureResponse
	}
	if fixtureID != "bdk-finalize-regression" {
		return failure(value.ID, digest, "rejected", "policy.fixture_not_allowed", "Selected-input finalization is reserved for the regression fixture")
	}
	_, packet, err := parsePSBT(encoded)
	if err != nil {
		return failure(value.ID, digest, "rejected", "psbt.parse_failed", "PSBT could not be parsed")
	}
	indexes, err := inputIndexes(value.Payload["inputIndexes"], len(packet.Inputs))
	if err != nil {
		return invalidPayload(value.ID, digest, "inputIndexes must be non-empty unique in-range safe integers")
	}
	_, publicKey, _, _, err := authorizeFixture(packet)
	if err != nil {
		return failure(value.ID, digest, "rejected", "policy.psbt_not_authorized", "PSBT is outside the authorized fixture scope")
	}
	return finalizePacket(value.ID, digest, packet, publicKey, indexes)
}

func finalizePacket(id, digest string, packet *psbt.Packet, publicKey []byte, indexes []int) Response {
	for _, index := range indexes {
		input := &packet.Inputs[index]
		if input.FinalScriptSig != nil || input.FinalScriptWitness != nil {
			continue
		}
		var signature []byte
		for _, partial := range input.PartialSigs {
			if bytes.Equal(partial.PubKey, publicKey) {
				signature = partial.Signature
				break
			}
		}
		if signature == nil {
			return failure(id, digest, "rejected", "finalize.missing_signature", fmt.Sprintf("Input %d is missing the fixture signature", index))
		}
		if input.WitnessScript == nil {
			return failure(id, digest, "rejected", "finalize.missing_witness_script", fmt.Sprintf("Input %d is missing its witness script", index))
		}
		witness, err := serializeWitness(wire.TxWitness{signature, input.WitnessScript})
		if err != nil {
			return failure(id, digest, "crashed", "adapter.finalize_failed", "PSBT witness could not be serialized")
		}
		input.FinalScriptWitness = witness
		input.PartialSigs = nil
		input.SighashType = 0
		input.RedeemScript = nil
		input.WitnessScript = nil
		input.Bip32Derivation = nil
	}
	encoded, err := encodePSBT(packet)
	if err != nil {
		return failure(id, digest, "crashed", "adapter.serialize_failed", "PSBT could not be serialized")
	}
	remaining := 0
	for _, input := range packet.Inputs {
		if len(input.PartialSigs) > 0 {
			remaining++
		}
	}
	return success(id, digest, map[string]any{
		"psbt":                   encoded,
		"finalizedInputs":        indexes,
		"remainingPartialInputs": remaining,
		"complete":               packet.IsComplete(),
	})
}

func fixturePayload(value adapterRequest, digest string, fields ...string) (string, string, *Response) {
	if !hasOnlyFields(value.Payload, fields...) {
		response := invalidPayload(value.ID, digest, "Payload has missing or unknown fields")
		return "", "", &response
	}
	encoded, ok := payloadString(value.Payload, "psbt")
	if !ok {
		response := invalidPayload(value.ID, digest, "psbt must be a base64 string")
		return "", "", &response
	}
	network, ok := payloadString(value.Payload, "network")
	if !ok {
		response := invalidPayload(value.ID, digest, "network must be a string")
		return "", "", &response
	}
	if network != "regtest" {
		response := failure(value.ID, digest, "rejected", "policy.network_not_allowed", "Signing is restricted to regtest fixtures")
		return "", "", &response
	}
	fixtureID, ok := payloadString(value.Payload, "fixtureId")
	if !ok {
		response := invalidPayload(value.ID, digest, "fixtureId must be a string")
		return "", "", &response
	}
	if _, ok := allowedFixtures[fixtureID]; !ok {
		response := failure(value.ID, digest, "rejected", "policy.fixture_not_allowed", "Unknown signing fixture")
		return "", "", &response
	}
	return encoded, fixtureID, nil
}

func psbtPayload(payload map[string]json.RawMessage, field string) (string, bool) {
	if !hasOnlyFields(payload, field) {
		return "", false
	}
	return payloadString(payload, field)
}

func payloadString(payload map[string]json.RawMessage, field string) (string, bool) {
	var value string
	if raw, ok := payload[field]; !ok || json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func parsePSBT(encoded string) ([]byte, *psbt.Packet, error) {
	if len(encoded) > base64.StdEncoding.EncodedLen(maxPSBTBytes) {
		return nil, nil, fmt.Errorf("PSBT exceeds limit")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) > maxPSBTBytes || base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, nil, fmt.Errorf("invalid PSBT encoding")
	}
	reader := bytes.NewReader(raw)
	packet, err := psbt.NewFromRawBytes(reader, false)
	if err != nil || reader.Len() != 0 {
		return nil, nil, fmt.Errorf("invalid PSBT data")
	}
	return raw, packet, nil
}

func encodePSBT(packet *psbt.Packet) (string, error) {
	serialized, err := serializePSBT(packet)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(serialized), nil
}

func serializePSBT(packet *psbt.Packet) ([]byte, error) {
	var serialized bytes.Buffer
	if err := packet.Serialize(&serialized); err != nil {
		return nil, err
	}
	if serialized.Len() > maxPSBTBytes {
		return nil, fmt.Errorf("serialized PSBT exceeds limit")
	}
	return serialized.Bytes(), nil
}

func serializeWitness(witness wire.TxWitness) ([]byte, error) {
	var serialized bytes.Buffer
	if err := wire.WriteVarInt(&serialized, 0, uint64(len(witness))); err != nil {
		return nil, err
	}
	for _, item := range witness {
		if err := wire.WriteVarBytes(&serialized, 0, item); err != nil {
			return nil, err
		}
	}
	return serialized.Bytes(), nil
}

func authorizeFixture(packet *psbt.Packet) (*btcutil.WIF, []byte, []byte, []*wire.TxOut, error) {
	if packet == nil || packet.UnsignedTx == nil || len(packet.Inputs) == 0 || len(packet.Inputs) != len(packet.UnsignedTx.TxIn) {
		return nil, nil, nil, nil, fmt.Errorf("missing inputs")
	}
	key, err := btcutil.DecodeWIF(testWIF)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	publicKey := key.PrivKey.PubKey().SerializeCompressed()
	witnessScript, err := txscript.NewScriptBuilder().AddData(publicKey).AddOp(txscript.OP_CHECKSIG).Script()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	expectedPkScript := p2wshScript(witnessScript)
	funding := make([]*wire.TxOut, len(packet.Inputs))
	for index, input := range packet.Inputs {
		previous := packet.UnsignedTx.TxIn[index].PreviousOutPoint
		var full *wire.TxOut
		if input.NonWitnessUtxo != nil {
			if input.NonWitnessUtxo.TxHash() != previous.Hash || int(previous.Index) >= len(input.NonWitnessUtxo.TxOut) {
				return nil, nil, nil, nil, fmt.Errorf("inconsistent non-witness UTXO")
			}
			full = input.NonWitnessUtxo.TxOut[previous.Index]
		}
		if input.WitnessUtxo != nil && full != nil && (input.WitnessUtxo.Value != full.Value || !bytes.Equal(input.WitnessUtxo.PkScript, full.PkScript)) {
			return nil, nil, nil, nil, fmt.Errorf("inconsistent witness UTXO")
		}
		if input.FinalScriptSig != nil || input.FinalScriptWitness != nil {
			if input.FinalScriptSig != nil || !hasExpectedFinalWitness(input.FinalScriptWitness, witnessScript) {
				return nil, nil, nil, nil, fmt.Errorf("unexpected finalized witness")
			}
		} else if input.WitnessScript == nil || !bytes.Equal(input.WitnessScript, witnessScript) {
			return nil, nil, nil, nil, fmt.Errorf("unexpected witness script")
		}
		if input.WitnessUtxo != nil {
			funding[index] = input.WitnessUtxo
		} else {
			funding[index] = full
		}
		if funding[index] == nil || !bytes.Equal(funding[index].PkScript, expectedPkScript) {
			return nil, nil, nil, nil, fmt.Errorf("unexpected funding output")
		}
	}
	return key, publicKey, witnessScript, funding, nil
}

func hasExpectedFinalWitness(serialized, witnessScript []byte) bool {
	reader := bytes.NewReader(serialized)
	count, err := wire.ReadVarInt(reader, 0)
	if err != nil || count != 2 {
		return false
	}
	signature, err := wire.ReadVarBytes(reader, 0, maxPSBTBytes, "witness signature")
	if err != nil || len(signature) == 0 {
		return false
	}
	script, err := wire.ReadVarBytes(reader, 0, maxPSBTBytes, "witness script")
	return err == nil && bytes.Equal(script, witnessScript) && reader.Len() == 0
}

func inputIndexes(raw json.RawMessage, inputCount int) ([]int, error) {
	var values []json.RawMessage
	if json.Unmarshal(raw, &values) != nil || len(values) == 0 {
		return nil, fmt.Errorf("invalid indexes")
	}
	seen := make(map[int]struct{}, len(values))
	indexes := make([]int, 0, len(values))
	for _, value := range values {
		if len(value) == 0 {
			return nil, fmt.Errorf("invalid index")
		}
		for _, character := range value {
			if character < '0' || character > '9' {
				return nil, fmt.Errorf("invalid index")
			}
		}
		rawIndex, err := strconv.ParseUint(string(value), 10, 64)
		if err != nil || rawIndex > maxSafeInteger || rawIndex >= uint64(inputCount) {
			return nil, fmt.Errorf("invalid index")
		}
		index := int(rawIndex)
		if _, exists := seen[index]; exists {
			return nil, fmt.Errorf("duplicate index")
		}
		seen[index] = struct{}{}
		indexes = append(indexes, index)
	}
	return indexes, nil
}

func p2wshScript(witnessScript []byte) []byte {
	hash := sha256.Sum256(witnessScript)
	return append([]byte{txscript.OP_0, txscript.OP_DATA_32}, hash[:]...)
}

func fallbackID(raw []byte) string {
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil {
		return "invalid-1"
	}
	id, ok := payloadString(value, "id")
	if !ok || !safeID(id) {
		return "invalid-1"
	}
	return id
}

func safeID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') {
			continue
		}
		if index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func hasOnlyFields(value map[string]json.RawMessage, fields ...string) bool {
	if len(value) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, ok := value[field]; !ok {
			return false
		}
	}
	return true
}

func invalidPayload(id, digest, message string) Response {
	return failure(id, digest, "rejected", "protocol.invalid_payload", message)
}

func success(id, digest string, output map[string]any) Response {
	return Response{Protocol: protocol, ID: id, Status: "ok", Implementation: implementation(digest), Output: output}
}

func failure(id, digest, status, class, message string) Response {
	return Response{Protocol: protocol, ID: id, Status: status, Implementation: implementation(digest), Error: &Error{Class: class, Message: message, Retryable: false}}
}

func implementation(digest string) Implementation {
	return Implementation{Name: "btcsuite-go", Version: "v1.2.0", ArtifactDigest: digest, SourceRevision: "github.com/btcsuite/btcd/btcutil/psbt@v1.2.0"}
}
