package adapter

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	protocol                   = "psbt-lab.adapter/0.2"
	MaxLineBytes               = 4 * 1024 * 1024
	responseLineReserve        = 4096
	maxPSBTBytes               = ((MaxLineBytes - responseLineReserve) * 3) / 4
	maxFixtureCommitmentsBytes = 4096
	maxPSBTInputs              = 1024
	maxPSBTOutputs             = 1024
	maxPSBTMapEntries          = 1024
	maxSafeInteger             = uint64(9_007_199_254_740_991)
	testWIF                    = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA"
)

var allowedFixtures = map[string]struct{}{
	"happy-path":              {},
	"bdk-finalize-regression": {},
	"p2wpkh":                  {},
	"p2wsh-2-of-3":            {},
	"p2tr-keypath":            {},
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

type Config struct {
	FixtureCommitments map[string]string
}

type Handler struct {
	fixtureCommitments map[string][sha256.Size]byte
	configurationClass string
}

func NewHandler(config Config) *Handler {
	handler := &Handler{fixtureCommitments: make(map[string][sha256.Size]byte)}
	if len(config.FixtureCommitments) == 0 {
		handler.configurationClass = "policy.fixture_commitment_missing"
		return handler
	}
	for fixtureID, commitment := range config.FixtureCommitments {
		decoded, ok := decodeCommitment(commitment)
		if !safeID(fixtureID) || !ok {
			handler.configurationClass = "policy.fixture_commitment_invalid"
			handler.fixtureCommitments = nil
			return handler
		}
		handler.fixtureCommitments[fixtureID] = decoded
	}
	return handler
}

func NewHandlerFromEnvironment(value string) *Handler {
	if len(value) == 0 {
		return NewHandler(Config{})
	}
	if len(value) > maxFixtureCommitmentsBytes {
		return &Handler{configurationClass: "policy.fixture_commitment_invalid"}
	}
	var commitments map[string]string
	if err := json.Unmarshal([]byte(value), &commitments); err != nil || commitments == nil {
		return &Handler{configurationClass: "policy.fixture_commitment_invalid"}
	}
	return NewHandler(Config{FixtureCommitments: commitments})
}

func Handle(raw json.RawMessage, digest string) Response {
	return HandleJSON(raw, digest)
}

func HandleJSON(raw []byte, digest string) Response {
	return NewHandler(Config{}).HandleJSON(raw, digest)
}

func (handler *Handler) HandleJSON(raw []byte, digest string) Response {
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
			"operations":   []string{"hello", "native-parse", "inspect", "roundtrip", "sign", "finalize", "finalize-inputs"},
			"roles":        []string{"parser", "signer", "finalizer"},
			"psbtVersions": []int{0},
			"scriptTypes":  []string{"p2wpkh", "p2wsh", "p2tr-keypath"},
			"operationScriptTypes": map[string]any{
				"inspect":         []string{"p2wpkh", "p2wsh", "p2tr-keypath"},
				"roundtrip":       []string{"p2wpkh", "p2wsh", "p2tr-keypath"},
				"sign":            []string{"p2wpkh", "p2wsh", "p2tr-keypath"},
				"finalize":        []string{"p2wsh"},
				"finalize-inputs": []string{"p2wsh"},
			},
			"features": []string{"fixture-commitment-sha256"},
		})
	case "native-parse":
		return nativeParse(value, digest)
	case "roundtrip":
		return roundtrip(value, digest)
	case "inspect":
		return inspect(value, digest)
	case "sign":
		return handler.sign(value, digest)
	case "finalize":
		return handler.finalize(value, digest)
	case "finalize-inputs":
		return handler.finalizeInputs(value, digest)
	default:
		return failure(value.ID, digest, "unsupported", "operation.unsupported", "Operation is not supported by this adapter")
	}
}

func nativeParse(value adapterRequest, digest string) Response {
	encoded, ok := psbtPayload(value.Payload, "psbt")
	if !ok {
		return invalidPayload(value.ID, digest, "native-parse expects only a psbt field")
	}
	raw, err := decodePSBTBytes(encoded)
	if err != nil {
		return failure(value.ID, digest, "rejected", "psbt.native_parse_failed", "btcsuite rejected the PSBT")
	}
	reader := bytes.NewReader(raw)
	packet, err := psbt.NewFromRawBytes(reader, false)
	if err != nil || reader.Len() != 0 || len(packet.Inputs) > maxPSBTInputs || len(packet.Outputs) > maxPSBTOutputs {
		return failure(value.ID, digest, "rejected", "psbt.native_parse_failed", "btcsuite rejected the PSBT")
	}
	return success(value.ID, digest, map[string]any{
		"nativeParser": "btcsuite-go",
		"psbtVersion":  0,
		"inputs":       len(packet.Inputs),
		"outputs":      len(packet.Outputs),
	})
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

func (handler *Handler) sign(value adapterRequest, digest string) Response {
	fields := []string{"psbt", "network", "fixtureId"}
	if _, selected := value.Payload["inputIndexes"]; selected {
		fields = append(fields, "inputIndexes")
	}
	encoded, fixtureID, failureResponse := fixturePayload(value, digest, fields...)
	if failureResponse != nil {
		return *failureResponse
	}
	_, packet, err := parsePSBT(encoded)
	if err != nil {
		return failure(value.ID, digest, "rejected", "psbt.parse_failed", "PSBT could not be parsed")
	}
	indexes := make([]int, len(packet.Inputs))
	if rawIndexes, selected := value.Payload["inputIndexes"]; selected {
		indexes, err = inputIndexes(rawIndexes, len(packet.Inputs))
		if err != nil {
			return invalidPayload(value.ID, digest, "inputIndexes must be non-empty unique in-range safe integers")
		}
	} else {
		for index := range indexes {
			indexes[index] = index
		}
	}
	if isProfileSigningFixture(fixtureID) {
		return handler.signProfile(value.ID, digest, packet, fixtureID, indexes)
	}
	key, publicKey, witnessScript, funding, class := handler.authorizeFixture(packet, fixtureID)
	if class != "" {
		return failure(value.ID, digest, "rejected", class, authorizationMessage(class))
	}
	if !verifyFixtureSignatures(packet, publicKey, witnessScript, funding) {
		return failure(value.ID, digest, "rejected", "signing.signature_invalid", "An existing fixture signature is invalid")
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
	for _, index := range indexes {
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
	if !verifyFixtureSignatures(packet, publicKey, witnessScript, funding) {
		return failure(value.ID, digest, "rejected", "signing.failed", "Fixture signing failed")
	}
	encodedResult, err := encodePSBT(packet)
	if err != nil {
		return failure(value.ID, digest, "crashed", "adapter.serialize_failed", "PSBT could not be serialized")
	}
	return success(value.ID, digest, map[string]any{"psbt": encodedResult, "signedInputs": signed})
}

type profileKind uint8

const (
	profileP2WPKH profileKind = iota + 1
	profileP2WSHMultisig
	profileP2TRKeyPath
)

type profileAuthorization struct {
	kind              profileKind
	privateKey        *btcec.PrivateKey
	publicKey         []byte
	scriptCode        []byte
	witnessScript     []byte
	internalKey       []byte
	allowedPublicKeys map[string]struct{}
	funding           []*wire.TxOut
	prevOutFetcher    *txscript.MultiPrevOutFetcher
}

func isProfileSigningFixture(fixtureID string) bool {
	switch fixtureID {
	case "p2wpkh", "p2wsh-2-of-3", "p2tr-keypath":
		return true
	default:
		return false
	}
}

func (handler *Handler) signProfile(id, digest string, packet *psbt.Packet, fixtureID string, indexes []int) Response {
	authorization, class := handler.authorizeProfile(packet, fixtureID)
	if class != "" {
		return failure(id, digest, "rejected", class, authorizationMessage(class))
	}
	sigHashes := txscript.NewTxSigHashes(packet.UnsignedTx, authorization.prevOutFetcher)
	if !verifyProfileSignatures(packet, authorization, sigHashes) {
		return failure(id, digest, "rejected", "signing.signature_invalid", "An existing fixture signature is invalid")
	}

	var updater *psbt.Updater
	if authorization.kind != profileP2TRKeyPath {
		var err error
		updater, err = psbt.NewUpdater(packet)
		if err != nil {
			return failure(id, digest, "rejected", "psbt.parse_failed", "PSBT could not be prepared for signing")
		}
	}

	signed := 0
	for _, index := range indexes {
		previous := authorization.funding[index]
		switch authorization.kind {
		case profileP2WPKH, profileP2WSHMultisig:
			if hasPartialSignature(packet.Inputs[index].PartialSigs, authorization.publicKey) {
				signed++
				continue
			}
			signature, err := txscript.RawTxInWitnessSignature(
				packet.UnsignedTx,
				sigHashes,
				index,
				previous.Value,
				authorization.scriptCode,
				txscript.SigHashAll,
				authorization.privateKey,
			)
			if err != nil {
				return failure(id, digest, "rejected", "signing.failed", "Fixture signing failed")
			}
			outcome, err := updater.Sign(index, signature, authorization.publicKey, nil, nil)
			if err != nil || outcome != psbt.SignSuccesful {
				return failure(id, digest, "rejected", "signing.failed", "Fixture signing failed")
			}
		case profileP2TRKeyPath:
			signature, err := txscript.RawTxInTaprootSignature(
				packet.UnsignedTx,
				sigHashes,
				index,
				previous.Value,
				previous.PkScript,
				nil,
				txscript.SigHashDefault,
				authorization.privateKey,
			)
			if err != nil || len(signature) != schnorr.SignatureSize {
				return failure(id, digest, "rejected", "signing.failed", "Fixture signing failed")
			}
			packet.Inputs[index].TaprootKeySpendSig = signature
		default:
			return failure(id, digest, "rejected", "signing.failed", "Fixture signing failed")
		}
		signed++
	}

	if !verifyProfileSignatures(packet, authorization, sigHashes) {
		return failure(id, digest, "rejected", "signing.failed", "Fixture signing failed")
	}
	encodedResult, err := encodePSBT(packet)
	if err != nil {
		return failure(id, digest, "crashed", "adapter.serialize_failed", "PSBT could not be serialized")
	}
	return success(id, digest, map[string]any{"psbt": encodedResult, "signedInputs": signed})
}

func (handler *Handler) authorizeProfile(packet *psbt.Packet, fixtureID string) (*profileAuthorization, string) {
	if class := handler.commitmentClass(fixtureID, packet); class != "" {
		return nil, class
	}
	if packet == nil || packet.UnsignedTx == nil || len(packet.Inputs) == 0 ||
		len(packet.Inputs) != len(packet.UnsignedTx.TxIn) {
		return nil, "policy.psbt_not_authorized"
	}

	authorization, expectedPkScript, err := newProfileAuthorization(fixtureID)
	if err != nil {
		return nil, "policy.psbt_not_authorized"
	}
	authorization.funding = make([]*wire.TxOut, len(packet.Inputs))
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(packet.Inputs))
	for index := range packet.Inputs {
		input := &packet.Inputs[index]
		txIn := packet.UnsignedTx.TxIn[index]
		if txIn == nil || input.WitnessUtxo == nil || input.WitnessUtxo.Value < 0 ||
			input.WitnessUtxo.Value > btcutil.MaxSatoshi ||
			input.FinalScriptSig != nil || input.FinalScriptWitness != nil ||
			!bytes.Equal(input.WitnessUtxo.PkScript, expectedPkScript) ||
			!profileMetadataAuthorized(input, authorization) {
			return nil, "policy.psbt_not_authorized"
		}

		previous := txIn.PreviousOutPoint
		fullOutput, fullOutputPresent, fullOutputValid := referencedNonWitnessOutput(input.NonWitnessUtxo, previous)
		if !fullOutputValid || (authorization.kind != profileP2TRKeyPath && !fullOutputPresent) {
			return nil, "policy.psbt_not_authorized"
		}
		if fullOutputPresent && !txOutEqual(input.WitnessUtxo, fullOutput) {
			return nil, "policy.psbt_not_authorized"
		}

		if existing := prevOuts[previous]; existing != nil && !txOutEqual(existing, input.WitnessUtxo) {
			return nil, "policy.psbt_not_authorized"
		}
		authorization.funding[index] = input.WitnessUtxo
		prevOuts[previous] = input.WitnessUtxo
	}
	authorization.prevOutFetcher = txscript.NewMultiPrevOutFetcher(prevOuts)
	return authorization, ""
}

func newProfileAuthorization(fixtureID string) (*profileAuthorization, []byte, error) {
	key1 := fixtureScalarKey(1)
	publicKey1 := key1.PubKey().SerializeCompressed()
	authorization := &profileAuthorization{allowedPublicKeys: make(map[string]struct{})}

	switch fixtureID {
	case "p2wpkh":
		scriptCode, err := p2wpkhScriptCode(publicKey1)
		if err != nil {
			return nil, nil, err
		}
		authorization.kind = profileP2WPKH
		authorization.privateKey = key1
		authorization.publicKey = publicKey1
		authorization.scriptCode = scriptCode
		authorization.allowedPublicKeys[string(publicKey1)] = struct{}{}
		return authorization, p2wpkhPkScript(publicKey1), nil

	case "p2wsh-2-of-3":
		publicKeys := [][]byte{
			publicKey1,
			fixtureScalarKey(2).PubKey().SerializeCompressed(),
			fixtureScalarKey(3).PubKey().SerializeCompressed(),
		}
		witnessScript, err := orderedMultisigWitnessScript(publicKeys)
		if err != nil {
			return nil, nil, err
		}
		authorization.kind = profileP2WSHMultisig
		authorization.privateKey = fixtureScalarKey(2)
		authorization.publicKey = publicKeys[1]
		authorization.scriptCode = witnessScript
		authorization.witnessScript = witnessScript
		for _, publicKey := range publicKeys {
			authorization.allowedPublicKeys[string(publicKey)] = struct{}{}
		}
		return authorization, p2wshScript(witnessScript), nil

	case "p2tr-keypath":
		internalKey := schnorr.SerializePubKey(key1.PubKey())
		pkScript, err := txscript.PayToTaprootScript(txscript.ComputeTaprootKeyNoScript(key1.PubKey()))
		if err != nil {
			return nil, nil, err
		}
		authorization.kind = profileP2TRKeyPath
		authorization.privateKey = key1
		authorization.publicKey = publicKey1
		authorization.internalKey = internalKey
		return authorization, pkScript, nil

	default:
		return nil, nil, fmt.Errorf("unknown signing profile")
	}
}

func profileMetadataAuthorized(input *psbt.PInput, authorization *profileAuthorization) bool {
	if input == nil || authorization == nil {
		return false
	}
	switch authorization.kind {
	case profileP2WPKH:
		return (input.SighashType == 0 || input.SighashType == txscript.SigHashAll) &&
			input.RedeemScript == nil && input.WitnessScript == nil &&
			!hasTaprootMetadata(input)
	case profileP2WSHMultisig:
		return (input.SighashType == 0 || input.SighashType == txscript.SigHashAll) &&
			input.RedeemScript == nil && bytes.Equal(input.WitnessScript, authorization.witnessScript) &&
			!hasTaprootMetadata(input)
	case profileP2TRKeyPath:
		if input.SighashType != txscript.SigHashDefault || input.RedeemScript != nil || input.WitnessScript != nil ||
			len(input.PartialSigs) != 0 || len(input.Bip32Derivation) != 0 ||
			!bytes.Equal(input.TaprootInternalKey, authorization.internalKey) ||
			len(input.TaprootScriptSpendSig) != 0 || len(input.TaprootLeafScript) != 0 || len(input.TaprootMerkleRoot) != 0 {
			return false
		}
		for _, derivation := range input.TaprootBip32Derivation {
			if derivation == nil || len(derivation.LeafHashes) != 0 || !bytes.Equal(derivation.XOnlyPubKey, authorization.internalKey) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func hasTaprootMetadata(input *psbt.PInput) bool {
	return len(input.TaprootKeySpendSig) != 0 || len(input.TaprootScriptSpendSig) != 0 ||
		len(input.TaprootLeafScript) != 0 || len(input.TaprootBip32Derivation) != 0 ||
		len(input.TaprootInternalKey) != 0 || len(input.TaprootMerkleRoot) != 0
}

func referencedNonWitnessOutput(transaction *wire.MsgTx, previous wire.OutPoint) (*wire.TxOut, bool, bool) {
	if transaction == nil {
		return nil, false, true
	}
	if transaction.TxHash() != previous.Hash || uint64(previous.Index) >= uint64(len(transaction.TxOut)) {
		return nil, true, false
	}
	output := transaction.TxOut[previous.Index]
	if output == nil {
		return nil, true, false
	}
	return output, true, true
}

func txOutEqual(left, right *wire.TxOut) bool {
	return left != nil && right != nil && left.Value == right.Value && bytes.Equal(left.PkScript, right.PkScript)
}

func verifyProfileSignatures(packet *psbt.Packet, authorization *profileAuthorization, sigHashes *txscript.TxSigHashes) bool {
	if packet == nil || packet.UnsignedTx == nil || authorization == nil || sigHashes == nil ||
		len(packet.Inputs) != len(authorization.funding) {
		return false
	}
	for index, input := range packet.Inputs {
		switch authorization.kind {
		case profileP2WPKH, profileP2WSHMultisig:
			hash, err := txscript.CalcWitnessSigHash(
				authorization.scriptCode,
				sigHashes,
				txscript.SigHashAll,
				packet.UnsignedTx,
				index,
				authorization.funding[index].Value,
			)
			if err != nil {
				return false
			}
			for _, partial := range input.PartialSigs {
				if partial == nil || len(partial.Signature) < 2 ||
					partial.Signature[len(partial.Signature)-1] != byte(txscript.SigHashAll) {
					return false
				}
				if _, ok := authorization.allowedPublicKeys[string(partial.PubKey)]; !ok {
					return false
				}
				publicKey, err := btcec.ParsePubKey(partial.PubKey)
				if err != nil {
					return false
				}
				signature, err := ecdsa.ParseDERSignature(partial.Signature[:len(partial.Signature)-1])
				if err != nil || !signature.Verify(hash, publicKey) {
					return false
				}
			}

		case profileP2TRKeyPath:
			if len(input.TaprootKeySpendSig) == 0 {
				continue
			}
			if len(input.TaprootKeySpendSig) != schnorr.SignatureSize {
				return false
			}
			version, witnessProgram, err := txscript.ExtractWitnessProgramInfo(authorization.funding[index].PkScript)
			if err != nil || version != 1 || len(witnessProgram) != schnorr.PubKeyBytesLen {
				return false
			}
			if txscript.VerifyTaprootKeySpend(
				witnessProgram,
				input.TaprootKeySpendSig,
				packet.UnsignedTx,
				index,
				authorization.prevOutFetcher,
				sigHashes,
				nil,
			) != nil {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func hasPartialSignature(partials []*psbt.PartialSig, publicKey []byte) bool {
	for _, partial := range partials {
		if partial != nil && bytes.Equal(partial.PubKey, publicKey) {
			return true
		}
	}
	return false
}

func fixtureScalarKey(value byte) *btcec.PrivateKey {
	scalar := make([]byte, 32)
	scalar[len(scalar)-1] = value
	privateKey, _ := btcec.PrivKeyFromBytes(scalar)
	return privateKey
}

func p2wpkhPkScript(publicKey []byte) []byte {
	return append([]byte{txscript.OP_0, txscript.OP_DATA_20}, btcutil.Hash160(publicKey)...)
}

func p2wpkhScriptCode(publicKey []byte) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_DUP).
		AddOp(txscript.OP_HASH160).
		AddData(btcutil.Hash160(publicKey)).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_CHECKSIG).
		Script()
}

func orderedMultisigWitnessScript(publicKeys [][]byte) ([]byte, error) {
	if len(publicKeys) != 3 {
		return nil, fmt.Errorf("multisig profile requires three keys")
	}
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_2).
		AddData(publicKeys[0]).
		AddData(publicKeys[1]).
		AddData(publicKeys[2]).
		AddOp(txscript.OP_3).
		AddOp(txscript.OP_CHECKMULTISIG).
		Script()
}

func (handler *Handler) finalize(value adapterRequest, digest string) Response {
	encoded, fixtureID, failureResponse := fixturePayload(value, digest, "psbt", "network", "fixtureId")
	if failureResponse != nil {
		return *failureResponse
	}
	if isProfileSigningFixture(fixtureID) {
		return failure(value.ID, digest, "rejected", "policy.fixture_not_allowed", "Finalization is reserved for legacy fixtures")
	}
	_, packet, err := parsePSBT(encoded)
	if err != nil {
		return failure(value.ID, digest, "rejected", "psbt.parse_failed", "PSBT could not be parsed")
	}
	_, publicKey, witnessScript, funding, class := handler.authorizeFixture(packet, fixtureID)
	if class != "" {
		return failure(value.ID, digest, "rejected", class, authorizationMessage(class))
	}
	indexes := make([]int, 0, len(packet.Inputs))
	for index, input := range packet.Inputs {
		if input.FinalScriptSig == nil && input.FinalScriptWitness == nil {
			indexes = append(indexes, index)
		}
	}
	return finalizePacket(value.ID, digest, packet, publicKey, witnessScript, funding, indexes)
}

func (handler *Handler) finalizeInputs(value adapterRequest, digest string) Response {
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
	_, publicKey, witnessScript, funding, class := handler.authorizeFixture(packet, fixtureID)
	if class != "" {
		return failure(value.ID, digest, "rejected", class, authorizationMessage(class))
	}
	return finalizePacket(value.ID, digest, packet, publicKey, witnessScript, funding, indexes)
}

func finalizePacket(id, digest string, packet *psbt.Packet, publicKey, witnessScript []byte, funding []*wire.TxOut, indexes []int) Response {
	if !verifyFixtureSignatures(packet, publicKey, witnessScript, funding) {
		return failure(id, digest, "rejected", "finalize.signature_invalid", "An expected fixture signature is invalid")
	}
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
	if !verifyFixtureSignatures(packet, publicKey, witnessScript, funding) {
		return failure(id, digest, "rejected", "finalize.signature_invalid", "A finalized fixture witness is invalid")
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
	raw, err := decodePSBTBytes(encoded)
	if err != nil {
		return nil, nil, err
	}
	if err := preflightPSBT(raw); err != nil {
		return nil, nil, fmt.Errorf("invalid or unsupported PSBT")
	}
	reader := bytes.NewReader(raw)
	packet, err := psbt.NewFromRawBytes(reader, false)
	if err != nil || reader.Len() != 0 || len(packet.Inputs) > maxPSBTInputs || len(packet.Outputs) > maxPSBTOutputs {
		return nil, nil, fmt.Errorf("invalid PSBT data")
	}
	return raw, packet, nil
}

func decodePSBTBytes(encoded string) ([]byte, error) {
	if len(encoded) > base64.StdEncoding.EncodedLen(maxPSBTBytes) {
		return nil, fmt.Errorf("PSBT exceeds limit")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) > maxPSBTBytes || base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, fmt.Errorf("invalid PSBT encoding")
	}
	return raw, nil
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
	if serialized.Len() > maxPSBTBytes || base64.StdEncoding.EncodedLen(serialized.Len()) > base64.StdEncoding.EncodedLen(maxPSBTBytes) {
		return nil, fmt.Errorf("serialized PSBT exceeds limit")
	}
	return serialized.Bytes(), nil
}

var (
	errInvalidPSBTPreflight  = errors.New("invalid PSBT preflight")
	errInvalidFixtureWitness = errors.New("fixture witness must contain exactly two items")
)

func preflightPSBT(raw []byte) error {
	if len(raw) < 6 || !bytes.Equal(raw[:5], []byte{'p', 's', 'b', 't', 0xff}) {
		return errInvalidPSBTPreflight
	}
	offset := 5
	unsignedTransaction, err := preflightGlobalMap(raw, &offset)
	if err != nil {
		return err
	}
	inputs, outputs, err := preflightUnsignedTransaction(unsignedTransaction)
	if err != nil {
		return err
	}
	for range inputs {
		if err := preflightMap(raw, &offset); err != nil {
			return err
		}
	}
	for range outputs {
		if err := preflightMap(raw, &offset); err != nil {
			return err
		}
	}
	if offset != len(raw) {
		return errInvalidPSBTPreflight
	}
	return nil
}

func preflightGlobalMap(raw []byte, offset *int) ([]byte, error) {
	var unsignedTransaction []byte
	seenUnsignedTransaction := false
	var version uint32
	seenVersion := false
	entries := 0
	for {
		keyLength, err := preflightVarInt(raw, offset)
		if err != nil {
			return nil, err
		}
		if keyLength == 0 {
			break
		}
		entries++
		if entries > maxPSBTMapEntries || keyLength > psbt.MaxPsbtKeyLength {
			return nil, errInvalidPSBTPreflight
		}
		key, ok := preflightTake(raw, offset, keyLength)
		if !ok {
			return nil, errInvalidPSBTPreflight
		}
		valueLength, err := preflightVarInt(raw, offset)
		if err != nil {
			return nil, err
		}
		value, ok := preflightTake(raw, offset, valueLength)
		if !ok {
			return nil, errInvalidPSBTPreflight
		}
		if len(key) != 1 {
			continue
		}
		switch key[0] {
		case 0x00:
			if seenUnsignedTransaction {
				return nil, errInvalidPSBTPreflight
			}
			seenUnsignedTransaction = true
			unsignedTransaction = value
		case 0xfb:
			if seenVersion || len(value) != 4 {
				return nil, errInvalidPSBTPreflight
			}
			seenVersion = true
			version = binary.LittleEndian.Uint32(value)
		}
	}
	if !seenUnsignedTransaction || version != 0 {
		return nil, errInvalidPSBTPreflight
	}
	return unsignedTransaction, nil
}

func preflightUnsignedTransaction(transaction []byte) (int, int, error) {
	offset := 0
	if !preflightSkip(transaction, &offset, 4) {
		return 0, 0, errInvalidPSBTPreflight
	}
	inputCount, err := preflightVarInt(transaction, &offset)
	if err != nil || inputCount > maxPSBTInputs {
		return 0, 0, errInvalidPSBTPreflight
	}
	for range inputCount {
		if !preflightSkip(transaction, &offset, 36) {
			return 0, 0, errInvalidPSBTPreflight
		}
		scriptLength, err := preflightVarInt(transaction, &offset)
		if err != nil || !preflightSkip(transaction, &offset, scriptLength) || !preflightSkip(transaction, &offset, 4) {
			return 0, 0, errInvalidPSBTPreflight
		}
	}
	outputCount, err := preflightVarInt(transaction, &offset)
	if err != nil || outputCount > maxPSBTOutputs {
		return 0, 0, errInvalidPSBTPreflight
	}
	for range outputCount {
		if !preflightSkip(transaction, &offset, 8) {
			return 0, 0, errInvalidPSBTPreflight
		}
		scriptLength, err := preflightVarInt(transaction, &offset)
		if err != nil || !preflightSkip(transaction, &offset, scriptLength) {
			return 0, 0, errInvalidPSBTPreflight
		}
	}
	if !preflightSkip(transaction, &offset, 4) || offset != len(transaction) {
		return 0, 0, errInvalidPSBTPreflight
	}
	return int(inputCount), int(outputCount), nil
}

func preflightMap(raw []byte, offset *int) error {
	entries := 0
	for {
		keyLength, err := preflightVarInt(raw, offset)
		if err != nil {
			return err
		}
		if keyLength == 0 {
			return nil
		}
		entries++
		if entries > maxPSBTMapEntries || keyLength > psbt.MaxPsbtKeyLength || !preflightSkip(raw, offset, keyLength) {
			return errInvalidPSBTPreflight
		}
		valueLength, err := preflightVarInt(raw, offset)
		if err != nil || !preflightSkip(raw, offset, valueLength) {
			return errInvalidPSBTPreflight
		}
	}
}

func preflightVarInt(raw []byte, offset *int) (uint64, error) {
	if *offset < 0 || *offset >= len(raw) {
		return 0, errInvalidPSBTPreflight
	}
	discriminant := raw[*offset]
	*offset += 1
	switch discriminant {
	case 0xff:
		encoded, ok := preflightTake(raw, offset, 8)
		if !ok {
			return 0, errInvalidPSBTPreflight
		}
		value := binary.LittleEndian.Uint64(encoded)
		if value <= uint64(^uint32(0)) {
			return 0, errInvalidPSBTPreflight
		}
		return value, nil
	case 0xfe:
		encoded, ok := preflightTake(raw, offset, 4)
		if !ok {
			return 0, errInvalidPSBTPreflight
		}
		value := uint64(binary.LittleEndian.Uint32(encoded))
		if value <= uint64(^uint16(0)) {
			return 0, errInvalidPSBTPreflight
		}
		return value, nil
	case 0xfd:
		encoded, ok := preflightTake(raw, offset, 2)
		if !ok {
			return 0, errInvalidPSBTPreflight
		}
		value := uint64(binary.LittleEndian.Uint16(encoded))
		if value < 0xfd {
			return 0, errInvalidPSBTPreflight
		}
		return value, nil
	default:
		return uint64(discriminant), nil
	}
}

func preflightTake(raw []byte, offset *int, length uint64) ([]byte, bool) {
	if *offset < 0 || *offset > len(raw) || length > uint64(len(raw)-*offset) {
		return nil, false
	}
	start := *offset
	*offset += int(length)
	return raw[start:*offset], true
}

func preflightSkip(raw []byte, offset *int, length uint64) bool {
	_, ok := preflightTake(raw, offset, length)
	return ok
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

func (handler *Handler) authorizeFixture(packet *psbt.Packet, fixtureID string) (*btcutil.WIF, []byte, []byte, []*wire.TxOut, string) {
	if class := handler.commitmentClass(fixtureID, packet); class != "" {
		return nil, nil, nil, nil, class
	}
	if packet == nil || packet.UnsignedTx == nil || len(packet.Inputs) == 0 || len(packet.Inputs) != len(packet.UnsignedTx.TxIn) {
		return nil, nil, nil, nil, "policy.psbt_not_authorized"
	}
	key, err := btcutil.DecodeWIF(testWIF)
	if err != nil {
		return nil, nil, nil, nil, "policy.psbt_not_authorized"
	}
	publicKey := key.PrivKey.PubKey().SerializeCompressed()
	witnessScript, err := txscript.NewScriptBuilder().AddData(publicKey).AddOp(txscript.OP_CHECKSIG).Script()
	if err != nil {
		return nil, nil, nil, nil, "policy.psbt_not_authorized"
	}
	expectedPkScript := p2wshScript(witnessScript)
	funding := make([]*wire.TxOut, len(packet.Inputs))
	for index, input := range packet.Inputs {
		previous := packet.UnsignedTx.TxIn[index].PreviousOutPoint
		if input.NonWitnessUtxo == nil || input.WitnessUtxo == nil ||
			input.NonWitnessUtxo.TxHash() != previous.Hash || int(previous.Index) >= len(input.NonWitnessUtxo.TxOut) {
			return nil, nil, nil, nil, "policy.psbt_not_authorized"
		}
		full := input.NonWitnessUtxo.TxOut[previous.Index]
		if input.WitnessUtxo.Value != full.Value || !bytes.Equal(input.WitnessUtxo.PkScript, full.PkScript) {
			return nil, nil, nil, nil, "policy.psbt_not_authorized"
		}
		if input.FinalScriptSig != nil || input.FinalScriptWitness != nil {
			if input.FinalScriptSig != nil || !hasExpectedFinalWitness(input.FinalScriptWitness, witnessScript) {
				return nil, nil, nil, nil, "policy.psbt_not_authorized"
			}
		} else if input.WitnessScript == nil || !bytes.Equal(input.WitnessScript, witnessScript) {
			return nil, nil, nil, nil, "policy.psbt_not_authorized"
		}
		funding[index] = full
		if funding[index] == nil || !bytes.Equal(funding[index].PkScript, expectedPkScript) {
			return nil, nil, nil, nil, "policy.psbt_not_authorized"
		}
	}
	return key, publicKey, witnessScript, funding, ""
}

func (handler *Handler) commitmentClass(fixtureID string, packet *psbt.Packet) string {
	if handler == nil || handler.configurationClass != "" {
		if handler != nil && handler.configurationClass != "" {
			return handler.configurationClass
		}
		return "policy.fixture_commitment_missing"
	}
	expected, ok := handler.fixtureCommitments[fixtureID]
	if !ok {
		return "policy.fixture_commitment_missing"
	}
	if packet == nil || packet.UnsignedTx == nil {
		return "policy.psbt_not_authorized"
	}
	var serialized bytes.Buffer
	if err := packet.UnsignedTx.Serialize(&serialized); err != nil {
		return "policy.psbt_not_authorized"
	}
	actual := sha256.Sum256(serialized.Bytes())
	if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
		return "policy.fixture_commitment_mismatch"
	}
	return ""
}

func authorizationMessage(class string) string {
	switch class {
	case "policy.fixture_commitment_missing":
		return "No configured fixture commitment authorizes this operation"
	case "policy.fixture_commitment_invalid":
		return "Configured fixture commitments are invalid"
	case "policy.fixture_commitment_mismatch":
		return "PSBT does not match the configured fixture commitment"
	default:
		return "PSBT is outside the authorized fixture scope"
	}
}

func decodeCommitment(value string) ([sha256.Size]byte, bool) {
	var commitment [sha256.Size]byte
	if len(value) != len("sha256:")+sha256.Size*2 || value[:len("sha256:")] != "sha256:" {
		return commitment, false
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return commitment, false
		}
	}
	decoded, err := hex.DecodeString(value[len("sha256:"):])
	if err != nil || len(decoded) != len(commitment) {
		return commitment, false
	}
	copy(commitment[:], decoded)
	return commitment, true
}

func hasExpectedFinalWitness(serialized, witnessScript []byte) bool {
	witness, err := deserializeWitness(serialized)
	return err == nil && len(witness) == 2 && len(witness[0]) > 0 && bytes.Equal(witness[1], witnessScript)
}

func deserializeWitness(serialized []byte) (wire.TxWitness, error) {
	reader := bytes.NewReader(serialized)
	count, err := wire.ReadVarInt(reader, 0)
	if err != nil || count != 2 {
		return nil, errInvalidFixtureWitness
	}
	witness := make(wire.TxWitness, 2)
	for index := range witness {
		witness[index], err = wire.ReadVarBytes(reader, 0, maxPSBTBytes, "witness item")
		if err != nil {
			return nil, err
		}
	}
	if reader.Len() != 0 {
		return nil, fmt.Errorf("trailing witness data")
	}
	return witness, nil
}

func verifyFixtureSignatures(packet *psbt.Packet, publicKey, witnessScript []byte, funding []*wire.TxOut) bool {
	if packet == nil || packet.UnsignedTx == nil || len(packet.Inputs) != len(funding) {
		return false
	}
	transaction := packet.UnsignedTx.Copy()
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(funding))
	signed := make([]bool, len(packet.Inputs))
	for index, input := range packet.Inputs {
		previous := transaction.TxIn[index].PreviousOutPoint
		prevOuts[previous] = funding[index]
		if input.FinalScriptWitness != nil {
			witness, err := deserializeWitness(input.FinalScriptWitness)
			if err != nil || len(witness) != 2 || len(witness[0]) == 0 || !bytes.Equal(witness[1], witnessScript) {
				return false
			}
			transaction.TxIn[index].Witness = witness
			signed[index] = true
			continue
		}
		if len(input.PartialSigs) == 0 {
			continue
		}
		if len(input.PartialSigs) != 1 || !bytes.Equal(input.PartialSigs[0].PubKey, publicKey) || len(input.PartialSigs[0].Signature) == 0 {
			return false
		}
		transaction.TxIn[index].Witness = wire.TxWitness{input.PartialSigs[0].Signature, witnessScript}
		signed[index] = true
	}

	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(transaction, fetcher)
	for index, shouldVerify := range signed {
		if !shouldVerify {
			continue
		}
		engine, err := txscript.NewEngine(
			funding[index].PkScript,
			transaction,
			index,
			txscript.StandardVerifyFlags,
			nil,
			sigHashes,
			funding[index].Value,
			fetcher,
		)
		if err != nil || engine.Execute() != nil {
			return false
		}
	}
	return true
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
