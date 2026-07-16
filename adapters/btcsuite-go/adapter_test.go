package adapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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
		"operations":   []any{"hello", "native-parse", "inspect", "roundtrip", "sign", "finalize", "finalize-inputs"},
		"roles":        []any{"parser", "signer", "finalizer"},
		"psbtVersions": []any{float64(0)},
		"scriptTypes":  []any{"p2wpkh", "p2wsh", "p2tr-keypath"},
		"operationScriptTypes": map[string]any{
			"inspect":         []any{"p2wpkh", "p2wsh", "p2tr-keypath"},
			"roundtrip":       []any{"p2wpkh", "p2wsh", "p2tr-keypath"},
			"sign":            []any{"p2wpkh", "p2wsh", "p2tr-keypath"},
			"finalize":        []any{"p2wsh"},
			"finalize-inputs": []any{"p2wsh"},
		},
		"features": []any{"fixture-commitment-sha256"},
	}
	if !jsonEqual(response.Output, want) {
		t.Fatalf("hello output = %#v, want %#v", response.Output, want)
	}
}

func TestNativeParseUsesBtcsuiteParserWithoutFixturePolicy(t *testing.T) {
	accepted := request(t, "native-parse", map[string]any{"psbt": fixturePSBT(t, 1)})
	if accepted.Status != "ok" || accepted.Output["nativeParser"] != "btcsuite-go" {
		t.Fatalf("native parse output = %#v", accepted)
	}

	rejected := request(t, "native-parse", map[string]any{
		"psbt": base64.StdEncoding.EncodeToString([]byte("not a psbt")),
	})
	assertFailureClass(t, rejected, "rejected", "psbt.native_parse_failed")
}

func TestExplicitlyAcceptsPSBTV0AndRejectsOtherGlobalVersions(t *testing.T) {
	accepted := request(t, "roundtrip", map[string]any{"psbt": fixturePSBT(t, 1)})
	if accepted.Status != "ok" {
		t.Fatalf("PSBTv0 status = %q", accepted.Status)
	}
	for _, version := range []uint32{1, 2} {
		t.Run("version", func(t *testing.T) {
			response := request(t, "roundtrip", map[string]any{"psbt": versionedFixturePSBT(t, version)})
			assertFailureClass(t, response, "rejected", "psbt.parse_failed")
		})
	}

	canonical := decodeBase64(t, fixturePSBT(t, 1))
	nonMinimalKeyLength := make([]byte, 0, len(canonical)+2)
	nonMinimalKeyLength = append(nonMinimalKeyLength, canonical[:5]...)
	nonMinimalKeyLength = append(nonMinimalKeyLength, 0xfd, 0x01, 0x00)
	nonMinimalKeyLength = append(nonMinimalKeyLength, canonical[6:]...)
	nonCanonical := request(t, "roundtrip", map[string]any{"psbt": base64.StdEncoding.EncodeToString(nonMinimalKeyLength)})
	assertFailureClass(t, nonCanonical, "rejected", "psbt.parse_failed")
}

func TestLineSafePSBTLimitBoundsSuccessfulResponse(t *testing.T) {
	encoded := paddedFixturePSBT(t, maxPSBTBytes)
	response := request(t, "roundtrip", map[string]any{"psbt": encoded})
	if response.Status != "ok" {
		t.Fatalf("line-safe PSBT status = %q: %#v", response.Status, response.Error)
	}
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > MaxLineBytes {
		t.Fatalf("response length = %d, cap = %d", len(raw), MaxLineBytes)
	}
	over := request(t, "roundtrip", map[string]any{"psbt": paddedFixturePSBT(t, maxPSBTBytes+1)})
	assertFailureClass(t, over, "rejected", "psbt.parse_failed")
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

func TestPSBTCardinalityCaps(t *testing.T) {
	const cardinalityCap = 1024

	for name, encoded := range map[string]string{
		"inputs":     cardinalityPSBT(t, cardinalityCap+1, 1, "", 0),
		"outputs":    cardinalityPSBT(t, 1, cardinalityCap+1, "", 0),
		"global map": cardinalityPSBT(t, 1, 1, "global", cardinalityCap),
		"input map":  cardinalityPSBT(t, 1, 1, "input", cardinalityCap+1),
		"output map": cardinalityPSBT(t, 1, 1, "output", cardinalityCap+1),
	} {
		t.Run(name+" overflow", func(t *testing.T) {
			response := request(t, "roundtrip", map[string]any{"psbt": encoded})
			assertFailureClass(t, response, "rejected", "psbt.parse_failed")
		})
	}

	for name, encoded := range map[string]string{
		"inputs":     cardinalityPSBT(t, cardinalityCap, 1, "", 0),
		"outputs":    cardinalityPSBT(t, 1, cardinalityCap, "", 0),
		"global map": cardinalityPSBT(t, 1, 1, "global", cardinalityCap-1),
		"input map":  cardinalityPSBT(t, 1, 1, "input", cardinalityCap),
		"output map": cardinalityPSBT(t, 1, 1, "output", cardinalityCap),
	} {
		t.Run(name+" at cap", func(t *testing.T) {
			response := request(t, "roundtrip", map[string]any{"psbt": encoded})
			if response.Status != "ok" {
				t.Fatalf("response = %#v, want ok", response)
			}
		})
	}
}

func TestPSBTPreflightRejectsHostileCardinalities(t *testing.T) {
	for name, raw := range map[string][]byte{
		"declared inputs":  psbtWithUnsignedTransaction(t, hostileUnsignedTransaction(t, true)),
		"declared outputs": psbtWithUnsignedTransaction(t, hostileUnsignedTransaction(t, false)),
		"global map":       decodeBase64(t, cardinalityPSBT(t, 1, 1, "global", maxPSBTMapEntries)),
		"input map":        decodeBase64(t, cardinalityPSBT(t, 1, 1, "input", maxPSBTMapEntries+1)),
		"output map":       decodeBase64(t, cardinalityPSBT(t, 1, 1, "output", maxPSBTMapEntries+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if err := preflightPSBT(raw); err == nil {
				t.Fatal("hostile PSBT passed bounded preflight")
			}
		})
	}
}

func TestPSBTPreflightDoesNotAllocatePerMapEntry(t *testing.T) {
	raw := decodeBase64(t, cardinalityPSBT(t, 1, 1, "input", maxPSBTMapEntries))
	var preflightErr error
	allocations := testing.AllocsPerRun(100, func() {
		preflightErr = preflightPSBT(raw)
	})
	if preflightErr != nil {
		t.Fatalf("at-cap PSBT failed preflight: %v", preflightErr)
	}
	if allocations != 0 {
		t.Fatalf("preflight allocations = %f, want 0", allocations)
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

func TestFixtureCommitmentsAuthorizeExactUnsignedTransactionOnly(t *testing.T) {
	encoded := fixturePSBT(t, 1)
	regression := fixturePSBT(t, 2)
	handler := testHandler(t, map[string]string{
		"happy-path":              fixtureCommitment(t, encoded),
		"bdk-finalize-regression": fixtureCommitment(t, regression),
	})
	accepted := requestWithHandler(t, handler, "sign", signingPayload(encoded, "happy-path"))
	if accepted.Status != "ok" {
		t.Fatalf("configured commitment was rejected: %#v", accepted)
	}

	mismatchedHappyPath := sameScriptDifferentPSBT(t, encoded)
	for _, operation := range []string{"sign", "finalize"} {
		response := requestWithHandler(t, handler, operation, signingPayload(mismatchedHappyPath, "happy-path"))
		assertFailureClass(t, response, "rejected", "policy.fixture_commitment_mismatch")
	}
	mismatchedRegression := requestWithHandler(t, handler, "finalize-inputs", map[string]any{
		"psbt": sameScriptDifferentPSBT(t, regression), "network": "regtest", "fixtureId": "bdk-finalize-regression", "inputIndexes": []any{0},
	})
	assertFailureClass(t, mismatchedRegression, "rejected", "policy.fixture_commitment_mismatch")
}

func TestFixtureAuthorizationRequiresMatchingWitnessAndNonWitnessUTXOs(t *testing.T) {
	for _, operation := range []string{"sign", "finalize"} {
		t.Run(operation+" missing non-witness UTXO", func(t *testing.T) {
			packet := decodePacket(t, fixturePSBT(t, 1))
			packet.Inputs[0].NonWitnessUtxo = nil

			response := request(t, operation, signingPayload(encodePacket(t, packet), "happy-path"))
			assertFailureClass(t, response, "rejected", "policy.psbt_not_authorized")
		})

		t.Run(operation+" changed witness amount", func(t *testing.T) {
			packet := decodePacket(t, fixturePSBT(t, 1))
			packet.Inputs[0].WitnessUtxo.Value++

			response := request(t, operation, signingPayload(encodePacket(t, packet), "happy-path"))
			assertFailureClass(t, response, "rejected", "policy.psbt_not_authorized")
		})
	}
}

func TestFixtureCommitmentConfigurationRejectsMissingAndInvalidValues(t *testing.T) {
	encoded := fixturePSBT(t, 1)
	payload := signingPayload(encoded, "happy-path")
	missing := requestWithHandler(t, testHandler(t, nil), "sign", payload)
	assertFailureClass(t, missing, "rejected", "policy.fixture_commitment_missing")
	invalid := requestWithHandler(t, testHandler(t, map[string]string{"happy-path": "sha256:INVALID"}), "sign", payload)
	assertFailureClass(t, invalid, "rejected", "policy.fixture_commitment_invalid")
	tooLarge := NewHandlerFromEnvironment(strings.Repeat("x", maxFixtureCommitmentsBytes+1))
	overflow := requestWithHandler(t, tooLarge, "sign", payload)
	assertFailureClass(t, overflow, "rejected", "policy.fixture_commitment_invalid")
	nullConfig := requestWithHandler(t, NewHandlerFromEnvironment("null"), "sign", payload)
	assertFailureClass(t, nullConfig, "rejected", "policy.fixture_commitment_invalid")
	validConfig, err := json.Marshal(map[string]string{"happy-path": fixtureCommitment(t, encoded)})
	if err != nil {
		t.Fatal(err)
	}
	accepted := requestWithHandler(t, NewHandlerFromEnvironment(string(validConfig)), "sign", payload)
	if accepted.Status != "ok" {
		t.Fatalf("environment commitment was rejected: %#v", accepted)
	}
}

func TestSignsP2WPKHProfileWithScalarOne(t *testing.T) {
	encoded := profilePSBT(t, "p2wpkh")
	response := requestWithProfileCommitment(t, "p2wpkh", encoded)
	if response.Status != "ok" || response.Output["signedInputs"] != 1 {
		t.Fatalf("sign response = %#v", response)
	}

	packet := decodePacket(t, response.Output["psbt"].(string))
	input := packet.Inputs[0]
	wantPubKey := scalarKey(1).PubKey().SerializeCompressed()
	if len(input.PartialSigs) != 1 || !bytes.Equal(input.PartialSigs[0].PubKey, wantPubKey) {
		t.Fatalf("partial signatures = %#v, want only scalar-1", input.PartialSigs)
	}
	assertECDSAPartialSignature(t, packet, 0, testP2WPKHScriptCode(t, wantPubKey), input.PartialSigs[0])
}

func TestSignsP2WSHMultisigProfileWithOnlyScalarTwo(t *testing.T) {
	packet := decodePacket(t, profilePSBT(t, "p2wsh-2-of-3"))
	witnessScript := multisigWitnessScript(t)
	existing := profilePartialSignature(t, packet, 0, scalarKey(1), witnessScript)
	packet.Inputs[0].PartialSigs = []*psbt.PartialSig{existing}
	encoded := encodePacket(t, packet)

	response := requestWithProfileCommitment(t, "p2wsh-2-of-3", encoded)
	if response.Status != "ok" || response.Output["signedInputs"] != 1 {
		t.Fatalf("sign response = %#v", response)
	}

	signed := decodePacket(t, response.Output["psbt"].(string))
	partials := partialsByPubKey(signed.Inputs[0].PartialSigs)
	pubKey1 := scalarKey(1).PubKey().SerializeCompressed()
	pubKey2 := scalarKey(2).PubKey().SerializeCompressed()
	pubKey3 := scalarKey(3).PubKey().SerializeCompressed()
	if len(partials) != 2 || partials[hex.EncodeToString(pubKey1)] == nil || partials[hex.EncodeToString(pubKey2)] == nil {
		t.Fatalf("partial signatures = %#v, want scalar-1 and scalar-2", signed.Inputs[0].PartialSigs)
	}
	if partials[hex.EncodeToString(pubKey3)] != nil {
		t.Fatal("btcsuite contributed a scalar-3 signature")
	}
	if !bytes.Equal(partials[hex.EncodeToString(pubKey1)].Signature, existing.Signature) {
		t.Fatal("btcsuite replaced the existing scalar-1 signature")
	}
	assertECDSAPartialSignature(t, signed, 0, witnessScript, partials[hex.EncodeToString(pubKey1)])
	assertECDSAPartialSignature(t, signed, 0, witnessScript, partials[hex.EncodeToString(pubKey2)])
}

func TestSignsTaprootKeyPathProfileWithDefaultSighash(t *testing.T) {
	encoded := profilePSBT(t, "p2tr-keypath")
	response := requestWithProfileCommitment(t, "p2tr-keypath", encoded)
	if response.Status != "ok" || response.Output["signedInputs"] != 1 {
		t.Fatalf("sign response = %#v", response)
	}

	packet := decodePacket(t, response.Output["psbt"].(string))
	input := packet.Inputs[0]
	if len(input.TaprootKeySpendSig) != schnorr.SignatureSize {
		t.Fatalf("Taproot key-spend signature length = %d, want %d", len(input.TaprootKeySpendSig), schnorr.SignatureSize)
	}
	if len(input.PartialSigs) != 0 || len(input.TaprootScriptSpendSig) != 0 {
		t.Fatalf("Taproot signature inserted into the wrong PSBT field: %#v", input)
	}
	assertTaprootKeySpendSignature(t, packet, 0, input.TaprootKeySpendSig)
}

func TestProfileSigningRequiresExactSegWitV0PrevoutsAndScripts(t *testing.T) {
	for _, profileID := range []string{"p2wpkh", "p2wsh-2-of-3"} {
		t.Run(profileID+" missing full previous transaction", func(t *testing.T) {
			packet := decodePacket(t, profilePSBT(t, profileID))
			packet.Inputs[0].NonWitnessUtxo = nil
			assertProfileAuthorizationRejected(t, profileID, packet)
		})

		t.Run(profileID+" inconsistent witness previous output", func(t *testing.T) {
			packet := decodePacket(t, profilePSBT(t, profileID))
			packet.Inputs[0].WitnessUtxo.Value++
			assertProfileAuthorizationRejected(t, profileID, packet)
		})
	}

	t.Run("p2wpkh wrong key script", func(t *testing.T) {
		packet := decodePacket(t, profilePSBT(t, "p2wpkh"))
		rebindProfileFunding(t, packet, p2wpkhScriptPubKey(scalarKey(2).PubKey().SerializeCompressed()))
		assertProfileAuthorizationRejected(t, "p2wpkh", packet)
	})

	t.Run("p2wsh wrong public key order", func(t *testing.T) {
		packet := decodePacket(t, profilePSBT(t, "p2wsh-2-of-3"))
		wrongScript, err := txscript.NewScriptBuilder().
			AddOp(txscript.OP_2).
			AddData(scalarKey(2).PubKey().SerializeCompressed()).
			AddData(scalarKey(1).PubKey().SerializeCompressed()).
			AddData(scalarKey(3).PubKey().SerializeCompressed()).
			AddOp(txscript.OP_3).
			AddOp(txscript.OP_CHECKMULTISIG).
			Script()
		if err != nil {
			t.Fatal(err)
		}
		packet.Inputs[0].WitnessScript = wrongScript
		rebindProfileFunding(t, packet, fixtureP2WSHScript(wrongScript))
		assertProfileAuthorizationRejected(t, "p2wsh-2-of-3", packet)
	})
}

func TestProfileSigningRejectsInvalidExistingECDSASignatures(t *testing.T) {
	for _, profileID := range []string{"p2wpkh", "p2wsh-2-of-3"} {
		t.Run(profileID, func(t *testing.T) {
			packet := decodePacket(t, profilePSBT(t, profileID))
			scriptCode := testP2WPKHScriptCode(t, scalarKey(1).PubKey().SerializeCompressed())
			if profileID == "p2wsh-2-of-3" {
				scriptCode = multisigWitnessScript(t)
			}
			forgedTransaction := packet.UnsignedTx.Copy()
			forgedTransaction.LockTime++
			packet.Inputs[0].PartialSigs = []*psbt.PartialSig{
				profilePartialSignatureForTransaction(t, packet, forgedTransaction, 0, scalarKey(1), scriptCode),
			}
			response := requestWithProfileCommitment(t, profileID, encodePacket(t, packet))
			assertFailureClass(t, response, "rejected", "signing.signature_invalid")
		})
	}
}

func TestTaprootProfileRequiresCompleteExactKeyPathMetadata(t *testing.T) {
	tests := map[string]func(*psbt.Packet){
		"missing witness previous output": func(packet *psbt.Packet) {
			packet.Inputs[0].WitnessUtxo = nil
		},
		"mismatched optional full previous transaction": func(packet *psbt.Packet) {
			packet.Inputs[0].NonWitnessUtxo = decodePacket(t, profilePSBT(t, "p2wpkh")).Inputs[0].NonWitnessUtxo
		},
		"wrong internal key": func(packet *psbt.Packet) {
			packet.Inputs[0].TaprootInternalKey = schnorr.SerializePubKey(scalarKey(2).PubKey())
		},
		"wrong output key": func(packet *psbt.Packet) {
			packet.Inputs[0].WitnessUtxo.PkScript = taprootScriptPubKey(t, scalarKey(2))
		},
		"non-default sighash": func(packet *psbt.Packet) {
			packet.Inputs[0].SighashType = txscript.SigHashAll
		},
		"script-path merkle root": func(packet *psbt.Packet) {
			packet.Inputs[0].TaprootMerkleRoot = bytes.Repeat([]byte{1}, sha256.Size)
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			packet := decodePacket(t, profilePSBT(t, "p2tr-keypath"))
			mutate(packet)
			assertProfileAuthorizationRejected(t, "p2tr-keypath", packet)
		})
	}
}

func TestTaprootProfileRejectsInvalidExistingKeySpendSignature(t *testing.T) {
	packet := decodePacket(t, profilePSBT(t, "p2tr-keypath"))
	forgedTransaction := packet.UnsignedTx.Copy()
	forgedTransaction.LockTime++
	packet.Inputs[0].TaprootKeySpendSig = taprootSignatureForTransaction(t, packet, forgedTransaction, 0)

	response := requestWithProfileCommitment(t, "p2tr-keypath", encodePacket(t, packet))
	assertFailureClass(t, response, "rejected", "signing.signature_invalid")
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

func TestSignsOnlySelectedFixtureInputs(t *testing.T) {
	payload := signingPayload(fixturePSBT(t, 2), "bdk-finalize-regression")
	payload["inputIndexes"] = []any{1}
	signed := request(t, "sign", payload)
	if signed.Status != "ok" || signed.Output["signedInputs"] != 1 {
		t.Fatalf("selected sign response = %#v", signed)
	}

	packet := decodePacket(t, signed.Output["psbt"].(string))
	if len(packet.Inputs[0].PartialSigs) != 0 || len(packet.Inputs[1].PartialSigs) != 1 {
		t.Fatal("selected signing changed the wrong inputs")
	}
}

func TestSelectedInputSigningRejectsInvalidIndexes(t *testing.T) {
	for name, indexes := range map[string]any{
		"empty":        []any{},
		"null":         nil,
		"object":       map[string]any{"input": 0},
		"number":       0,
		"duplicate":    []any{0, 0},
		"negative":     []any{-1},
		"fraction":     []any{0.5},
		"string":       []any{"0"},
		"unsafe":       []any{float64(9_007_199_254_740_992)},
		"out of range": []any{2},
	} {
		t.Run(name, func(t *testing.T) {
			payload := signingPayload(fixturePSBT(t, 2), "bdk-finalize-regression")
			payload["inputIndexes"] = indexes
			response := request(t, "sign", payload)
			assertFailureClass(t, response, "rejected", "protocol.invalid_payload")
		})
	}
}

func TestSelectedInputSigningStillRejectsInvalidExistingSignatures(t *testing.T) {
	signed := request(t, "sign", signingPayload(fixturePSBT(t, 2), "bdk-finalize-regression"))
	if signed.Status != "ok" {
		t.Fatalf("sign response = %#v", signed)
	}
	packet := decodePacket(t, signed.Output["psbt"].(string))
	packet.Inputs[0].PartialSigs[0].Signature = forgedFixtureSignature(t, packet, 0)

	payload := signingPayload(encodePacket(t, packet), "bdk-finalize-regression")
	payload["inputIndexes"] = []any{1}
	response := request(t, "sign", payload)
	assertFailureClass(t, response, "rejected", "signing.signature_invalid")
}

func TestFinalizeRejectsForgedPartialSignature(t *testing.T) {
	signed := request(t, "sign", signingPayload(fixturePSBT(t, 1), "happy-path"))
	if signed.Status != "ok" {
		t.Fatalf("sign response = %#v", signed)
	}
	packet := decodePacket(t, signed.Output["psbt"].(string))
	packet.Inputs[0].PartialSigs[0].Signature = forgedFixtureSignature(t, packet, 0)

	response := request(t, "finalize", signingPayload(encodePacket(t, packet), "happy-path"))
	assertFailureClass(t, response, "rejected", "finalize.signature_invalid")
}

func TestFinalizeRejectsForgedFinalWitness(t *testing.T) {
	signed := request(t, "sign", signingPayload(fixturePSBT(t, 2), "bdk-finalize-regression"))
	if signed.Status != "ok" {
		t.Fatalf("sign response = %#v", signed)
	}
	partiallyFinalized := request(t, "finalize-inputs", map[string]any{
		"psbt": signed.Output["psbt"], "network": "regtest", "fixtureId": "bdk-finalize-regression", "inputIndexes": []any{1},
	})
	if partiallyFinalized.Status != "ok" {
		t.Fatalf("partial finalization response = %#v", partiallyFinalized)
	}
	packet := decodePacket(t, partiallyFinalized.Output["psbt"].(string))
	forgedWitness, err := serializeWitness(wire.TxWitness{
		forgedFixtureSignature(t, packet, 1),
		witnessScript(t, fixtureKey(t)),
	})
	if err != nil {
		t.Fatal(err)
	}
	packet.Inputs[1].FinalScriptWitness = forgedWitness

	response := request(t, "finalize-inputs", map[string]any{
		"psbt": encodePacket(t, packet), "network": "regtest", "fixtureId": "bdk-finalize-regression", "inputIndexes": []any{1, 0},
	})
	assertFailureClass(t, response, "rejected", "finalize.signature_invalid")
}

func TestFinalWitnessRejectsMillionsOfItemsBeforeAllocation(t *testing.T) {
	const itemCount = 2_000_000
	serialized := make([]byte, 5+itemCount)
	serialized[0] = 0xfe
	binary.LittleEndian.PutUint32(serialized[1:5], itemCount)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	witness, err := deserializeWitness(serialized)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Error("oversized witness item count was accepted")
	}
	if witness != nil {
		t.Error("oversized witness returned an allocated witness stack")
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
		t.Fatalf("oversized witness allocated %d bytes, want at most %d", allocated, 1<<20)
	}

	packet := decodePacket(t, fixturePSBT(t, 1))
	packet.Inputs[0].FinalScriptWitness = serialized
	response := request(t, "finalize", signingPayload(encodePacket(t, packet), "happy-path"))
	assertFailureClass(t, response, "rejected", "policy.psbt_not_authorized")
}

func TestFinalizeAcceptsScriptEngineValidMixedState(t *testing.T) {
	signed := request(t, "sign", signingPayload(fixturePSBT(t, 2), "bdk-finalize-regression"))
	if signed.Status != "ok" {
		t.Fatalf("sign response = %#v", signed)
	}
	partiallyFinalized := request(t, "finalize-inputs", map[string]any{
		"psbt": signed.Output["psbt"], "network": "regtest", "fixtureId": "bdk-finalize-regression", "inputIndexes": []any{1},
	})
	if partiallyFinalized.Status != "ok" {
		t.Fatalf("partial finalization response = %#v", partiallyFinalized)
	}

	complete := request(t, "finalize-inputs", map[string]any{
		"psbt": partiallyFinalized.Output["psbt"], "network": "regtest", "fixtureId": "bdk-finalize-regression", "inputIndexes": []any{1, 0},
	})
	if complete.Status != "ok" || complete.Output["complete"] != true {
		t.Fatalf("mixed-state finalization response = %#v", complete)
	}
	assertFinalScriptsValid(t, decodePacket(t, complete.Output["psbt"].(string)))
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
	return requestWithHandler(t, defaultTestHandler(t), operation, payload)
}

func requestWithHandler(t *testing.T, handler *Handler, operation string, payload map[string]any) Response {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"protocol": protocol, "id": "test-1", "operation": operation, "payload": payload})
	if err != nil {
		t.Fatal(err)
	}
	return handler.HandleJSON(raw, testDigest)
}

func defaultTestHandler(t *testing.T) *Handler {
	t.Helper()
	return testHandler(t, map[string]string{
		"happy-path":              fixtureCommitment(t, fixturePSBT(t, 1)),
		"bdk-finalize-regression": fixtureCommitment(t, fixturePSBT(t, 2)),
		"p2wpkh":                  fixtureCommitment(t, profilePSBT(t, "p2wpkh")),
		"p2wsh-2-of-3":            fixtureCommitment(t, profilePSBT(t, "p2wsh-2-of-3")),
		"p2tr-keypath":            fixtureCommitment(t, profilePSBT(t, "p2tr-keypath")),
	})
}

func testHandler(t *testing.T, commitments map[string]string) *Handler {
	t.Helper()
	return NewHandler(Config{FixtureCommitments: commitments})
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

func requestWithProfileCommitment(t *testing.T, profileID, encoded string) Response {
	t.Helper()
	handler := testHandler(t, map[string]string{profileID: fixtureCommitment(t, encoded)})
	return requestWithHandler(t, handler, "sign", signingPayload(encoded, profileID))
}

func assertProfileAuthorizationRejected(t *testing.T, profileID string, packet *psbt.Packet) {
	t.Helper()
	response := requestWithProfileCommitment(t, profileID, encodePacket(t, packet))
	assertFailureClass(t, response, "rejected", "policy.psbt_not_authorized")
}

func profilePSBT(t *testing.T, profileID string) string {
	t.Helper()
	var pkScript, witnessScript []byte
	switch profileID {
	case "p2wpkh":
		pkScript = p2wpkhScriptPubKey(scalarKey(1).PubKey().SerializeCompressed())
	case "p2wsh-2-of-3":
		witnessScript = multisigWitnessScript(t)
		pkScript = fixtureP2WSHScript(witnessScript)
	case "p2tr-keypath":
		pkScript = taprootScriptPubKey(t, scalarKey(1))
	default:
		t.Fatalf("unknown profile %q", profileID)
	}

	funding := wire.NewMsgTx(2)
	funding.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	funding.AddTxOut(&wire.TxOut{Value: 50_000, PkScript: pkScript})
	spend := wire.NewMsgTx(2)
	spend.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: funding.TxHash(), Index: 0}, nil, nil))
	spend.AddTxOut(&wire.TxOut{Value: 40_000, PkScript: pkScript})
	packet, err := psbt.NewFromUnsignedTx(spend)
	if err != nil {
		t.Fatal(err)
	}
	input := &packet.Inputs[0]
	input.WitnessUtxo = funding.TxOut[0]
	switch profileID {
	case "p2wpkh":
		input.NonWitnessUtxo = funding.Copy()
	case "p2wsh-2-of-3":
		input.NonWitnessUtxo = funding.Copy()
		input.WitnessScript = witnessScript
	case "p2tr-keypath":
		input.TaprootInternalKey = schnorr.SerializePubKey(scalarKey(1).PubKey())
	}
	return encodePacket(t, packet)
}

func scalarKey(value byte) *btcec.PrivateKey {
	scalar := make([]byte, 32)
	scalar[len(scalar)-1] = value
	key, _ := btcec.PrivKeyFromBytes(scalar)
	return key
}

func p2wpkhScriptPubKey(publicKey []byte) []byte {
	return append([]byte{txscript.OP_0, txscript.OP_DATA_20}, btcutil.Hash160(publicKey)...)
}

func testP2WPKHScriptCode(t *testing.T, publicKey []byte) []byte {
	t.Helper()
	script, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_DUP).
		AddOp(txscript.OP_HASH160).
		AddData(btcutil.Hash160(publicKey)).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	if err != nil {
		t.Fatal(err)
	}
	return script
}

func multisigWitnessScript(t *testing.T) []byte {
	t.Helper()
	script, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_2).
		AddData(scalarKey(1).PubKey().SerializeCompressed()).
		AddData(scalarKey(2).PubKey().SerializeCompressed()).
		AddData(scalarKey(3).PubKey().SerializeCompressed()).
		AddOp(txscript.OP_3).
		AddOp(txscript.OP_CHECKMULTISIG).
		Script()
	if err != nil {
		t.Fatal(err)
	}
	return script
}

func taprootScriptPubKey(t *testing.T, internalKey *btcec.PrivateKey) []byte {
	t.Helper()
	script, err := txscript.PayToTaprootScript(txscript.ComputeTaprootKeyNoScript(internalKey.PubKey()))
	if err != nil {
		t.Fatal(err)
	}
	return script
}

func rebindProfileFunding(t *testing.T, packet *psbt.Packet, pkScript []byte) {
	t.Helper()
	input := &packet.Inputs[0]
	previous := packet.UnsignedTx.TxIn[0].PreviousOutPoint
	if input.NonWitnessUtxo == nil || int(previous.Index) >= len(input.NonWitnessUtxo.TxOut) {
		t.Fatal("profile lacks a full previous transaction")
	}
	funding := input.NonWitnessUtxo.Copy()
	funding.TxOut[previous.Index].PkScript = pkScript
	packet.UnsignedTx.TxIn[0].PreviousOutPoint.Hash = funding.TxHash()
	input.NonWitnessUtxo = funding
	input.WitnessUtxo = funding.TxOut[previous.Index]
}

func partialsByPubKey(partials []*psbt.PartialSig) map[string]*psbt.PartialSig {
	result := make(map[string]*psbt.PartialSig, len(partials))
	for _, partial := range partials {
		result[hex.EncodeToString(partial.PubKey)] = partial
	}
	return result
}

func profilePartialSignature(t *testing.T, packet *psbt.Packet, inputIndex int, key *btcec.PrivateKey, scriptCode []byte) *psbt.PartialSig {
	t.Helper()
	return profilePartialSignatureForTransaction(t, packet, packet.UnsignedTx, inputIndex, key, scriptCode)
}

func profilePartialSignatureForTransaction(t *testing.T, packet *psbt.Packet, transaction *wire.MsgTx, inputIndex int, key *btcec.PrivateKey, scriptCode []byte) *psbt.PartialSig {
	t.Helper()
	fetcher := profilePrevOutFetcher(t, packet)
	sigHashes := txscript.NewTxSigHashes(transaction, fetcher)
	previous := fetcher.FetchPrevOutput(transaction.TxIn[inputIndex].PreviousOutPoint)
	signature, err := txscript.RawTxInWitnessSignature(
		transaction, sigHashes, inputIndex, previous.Value, scriptCode, txscript.SigHashAll, key,
	)
	if err != nil {
		t.Fatal(err)
	}
	return &psbt.PartialSig{PubKey: key.PubKey().SerializeCompressed(), Signature: signature}
}

func assertECDSAPartialSignature(t *testing.T, packet *psbt.Packet, inputIndex int, scriptCode []byte, partial *psbt.PartialSig) {
	t.Helper()
	if partial == nil || len(partial.Signature) < 2 || partial.Signature[len(partial.Signature)-1] != byte(txscript.SigHashAll) {
		t.Fatalf("input %d has a missing or non-SIGHASH_ALL signature", inputIndex)
	}
	fetcher := profilePrevOutFetcher(t, packet)
	sigHashes := txscript.NewTxSigHashes(packet.UnsignedTx, fetcher)
	previous := fetcher.FetchPrevOutput(packet.UnsignedTx.TxIn[inputIndex].PreviousOutPoint)
	hash, err := txscript.CalcWitnessSigHash(scriptCode, sigHashes, txscript.SigHashAll, packet.UnsignedTx, inputIndex, previous.Value)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := ecdsa.ParseDERSignature(partial.Signature[:len(partial.Signature)-1])
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := btcec.ParsePubKey(partial.PubKey)
	if err != nil {
		t.Fatal(err)
	}
	if !signature.Verify(hash, publicKey) {
		t.Fatalf("input %d ECDSA signature does not verify", inputIndex)
	}
}

func taprootSignatureForTransaction(t *testing.T, packet *psbt.Packet, transaction *wire.MsgTx, inputIndex int) []byte {
	t.Helper()
	fetcher := profilePrevOutFetcher(t, packet)
	sigHashes := txscript.NewTxSigHashes(transaction, fetcher)
	previous := fetcher.FetchPrevOutput(transaction.TxIn[inputIndex].PreviousOutPoint)
	signature, err := txscript.RawTxInTaprootSignature(
		transaction, sigHashes, inputIndex, previous.Value, previous.PkScript, nil, txscript.SigHashDefault, scalarKey(1),
	)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func assertTaprootKeySpendSignature(t *testing.T, packet *psbt.Packet, inputIndex int, signature []byte) {
	t.Helper()
	fetcher := profilePrevOutFetcher(t, packet)
	sigHashes := txscript.NewTxSigHashes(packet.UnsignedTx, fetcher)
	previous := fetcher.FetchPrevOutput(packet.UnsignedTx.TxIn[inputIndex].PreviousOutPoint)
	version, witnessProgram, err := txscript.ExtractWitnessProgramInfo(previous.PkScript)
	if err != nil || version != 1 {
		t.Fatalf("invalid Taproot previous output: version=%d err=%v", version, err)
	}
	if err := txscript.VerifyTaprootKeySpend(witnessProgram, signature, packet.UnsignedTx, inputIndex, fetcher, sigHashes, nil); err != nil {
		t.Fatalf("input %d Taproot signature does not verify: %v", inputIndex, err)
	}
}

func profilePrevOutFetcher(t *testing.T, packet *psbt.Packet) *txscript.MultiPrevOutFetcher {
	t.Helper()
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(packet.Inputs))
	for index, input := range packet.Inputs {
		if input.WitnessUtxo == nil {
			t.Fatalf("input %d has no witness previous output", index)
		}
		prevOuts[packet.UnsignedTx.TxIn[index].PreviousOutPoint] = input.WitnessUtxo
	}
	return txscript.NewMultiPrevOutFetcher(prevOuts)
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

func fixtureCommitment(t *testing.T, encoded string) string {
	t.Helper()
	packet := decodePacket(t, encoded)
	var serialized bytes.Buffer
	if err := packet.UnsignedTx.Serialize(&serialized); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(serialized.Bytes())
	return "sha256:" + fmt.Sprintf("%x", sum)
}

func sameScriptDifferentPSBT(t *testing.T, encoded string) string {
	t.Helper()
	packet := decodePacket(t, encoded)
	packet.UnsignedTx.TxOut[0].Value++
	return encodePacket(t, packet)
}

func forgedFixtureSignature(t *testing.T, packet *psbt.Packet, inputIndex int) []byte {
	t.Helper()
	transaction := packet.UnsignedTx.Copy()
	transaction.LockTime++
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(packet.Inputs))
	for index, input := range packet.Inputs {
		previous := transaction.TxIn[index].PreviousOutPoint
		prevOuts[previous] = input.NonWitnessUtxo.TxOut[previous.Index]
	}
	sigHashes := txscript.NewTxSigHashes(transaction, txscript.NewMultiPrevOutFetcher(prevOuts))
	previous := transaction.TxIn[inputIndex].PreviousOutPoint
	signature, err := txscript.RawTxInWitnessSignature(
		transaction,
		sigHashes,
		inputIndex,
		prevOuts[previous].Value,
		witnessScript(t, fixtureKey(t)),
		txscript.SigHashAll,
		fixtureKey(t).PrivKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func assertFinalScriptsValid(t *testing.T, packet *psbt.Packet) {
	t.Helper()
	transaction := packet.UnsignedTx.Copy()
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(packet.Inputs))
	for index, input := range packet.Inputs {
		previous := transaction.TxIn[index].PreviousOutPoint
		prevOuts[previous] = input.NonWitnessUtxo.TxOut[previous.Index]
		transaction.TxIn[index].Witness = decodeWitness(t, input.FinalScriptWitness)
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(transaction, fetcher)
	for index, input := range transaction.TxIn {
		previous := prevOuts[input.PreviousOutPoint]
		engine, err := txscript.NewEngine(
			previous.PkScript,
			transaction,
			index,
			txscript.StandardVerifyFlags,
			nil,
			sigHashes,
			previous.Value,
			fetcher,
		)
		if err != nil {
			t.Fatalf("input %d engine creation failed: %v", index, err)
		}
		if err := engine.Execute(); err != nil {
			t.Fatalf("input %d script validation failed: %v", index, err)
		}
	}
}

func decodeWitness(t *testing.T, serialized []byte) wire.TxWitness {
	t.Helper()
	reader := bytes.NewReader(serialized)
	count, err := wire.ReadVarInt(reader, 0)
	if err != nil {
		t.Fatal(err)
	}
	witness := make(wire.TxWitness, count)
	for index := range witness {
		witness[index], err = wire.ReadVarBytes(reader, 0, maxPSBTBytes, "witness item")
		if err != nil {
			t.Fatal(err)
		}
	}
	if reader.Len() != 0 {
		t.Fatal("trailing final witness data")
	}
	return witness
}

func versionedFixturePSBT(t *testing.T, version uint32) string {
	t.Helper()
	packet := decodePacket(t, fixturePSBT(t, 1))
	encodedVersion := make([]byte, 4)
	binary.LittleEndian.PutUint32(encodedVersion, version)
	packet.Unknowns = append(packet.Unknowns, &psbt.Unknown{Key: []byte{0xfb}, Value: encodedVersion})
	return encodePacket(t, packet)
}

func paddedFixturePSBT(t *testing.T, targetSize int) string {
	t.Helper()
	packet := decodePacket(t, fixturePSBT(t, 1))
	packet.Unknowns = []*psbt.Unknown{{Key: []byte{0xfc}, Value: []byte{}}}
	for range 4 {
		encoded := encodePacket(t, packet)
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) == targetSize {
			return encoded
		}
		padding := targetSize - len(raw) + len(packet.Unknowns[0].Value)
		if padding < 0 {
			t.Fatal("target PSBT is smaller than fixture")
		}
		packet.Unknowns[0].Value = make([]byte, padding)
	}
	t.Fatal("could not construct target-sized PSBT")
	return ""
}

func cardinalityPSBT(t *testing.T, inputs, outputs int, unknownMap string, unknowns int) string {
	t.Helper()
	transaction := wire.NewMsgTx(2)
	for index := range inputs {
		transaction.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: uint32(index)}, nil, nil))
	}
	for range outputs {
		transaction.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{txscript.OP_TRUE}})
	}
	packet, err := psbt.NewFromUnsignedTx(transaction)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]*psbt.Unknown, unknowns)
	for index := range entries {
		key := make([]byte, 5)
		key[0] = 0xfc
		binary.LittleEndian.PutUint32(key[1:], uint32(index))
		entries[index] = &psbt.Unknown{Key: key, Value: []byte{}}
	}
	switch unknownMap {
	case "":
	case "global":
		packet.Unknowns = entries
	case "input":
		packet.Inputs[0].Unknowns = entries
	case "output":
		packet.Outputs[0].Unknowns = entries
	default:
		t.Fatalf("unknown map %q", unknownMap)
	}
	return encodePacket(t, packet)
}

func hostileUnsignedTransaction(t *testing.T, inputs bool) []byte {
	t.Helper()
	var transaction bytes.Buffer
	if err := binary.Write(&transaction, binary.LittleEndian, uint32(2)); err != nil {
		t.Fatal(err)
	}
	if inputs {
		if err := wire.WriteVarInt(&transaction, 0, maxPSBTInputs+1); err != nil {
			t.Fatal(err)
		}
		return transaction.Bytes()
	}
	if err := wire.WriteVarInt(&transaction, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteVarInt(&transaction, 0, maxPSBTOutputs+1); err != nil {
		t.Fatal(err)
	}
	return transaction.Bytes()
}

func psbtWithUnsignedTransaction(t *testing.T, transaction []byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	raw.Write([]byte{'p', 's', 'b', 't', 0xff})
	if err := wire.WriteVarInt(&raw, 0, 1); err != nil {
		t.Fatal(err)
	}
	raw.WriteByte(0x00)
	if err := wire.WriteVarBytes(&raw, 0, transaction); err != nil {
		t.Fatal(err)
	}
	raw.WriteByte(0x00)
	return raw.Bytes()
}

func decodeBase64(t *testing.T, encoded string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func jsonEqual(actual, expected any) bool {
	actualJSON, _ := json.Marshal(actual)
	expectedJSON, _ := json.Marshal(expected)
	return bytes.Equal(actualJSON, expectedJSON)
}
