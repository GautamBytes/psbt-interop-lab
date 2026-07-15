package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"

	adapter "github.com/psbt-interop-lab/btcsuite-go-adapter"
)

func TestReadBoundedLineAcceptsMaximumLineAndStripsNewline(t *testing.T) {
	input := append(bytes.Repeat([]byte{'a'}, maxLineBytes), '\n')
	line, ok, err := readBoundedLine(bufio.NewReader(bytes.NewReader(input)))
	if err != nil || !ok || len(line) != maxLineBytes {
		t.Fatalf("line result = (%d, %t, %v)", len(line), ok, err)
	}
}

func TestReadBoundedLineRejectsOversizedLine(t *testing.T) {
	input := append(bytes.Repeat([]byte{'a'}, maxLineBytes+1), '\n')
	_, _, err := readBoundedLine(bufio.NewReader(bytes.NewReader(input)))
	if err == nil {
		t.Fatal("oversized line was accepted")
	}
}

func TestProcessLineReturnsSchemaShapedInvalidJSONResponse(t *testing.T) {
	response := processLine(
		[]byte(`{"protocol":`),
		"sha256:"+string(bytes.Repeat([]byte("a"), 64)),
		adapter.NewHandler(adapter.Config{}),
	)
	var value map[string]any
	if err := json.Unmarshal(response, &value); err != nil {
		t.Fatal(err)
	}
	if value["protocol"] != "psbt-lab.adapter/0.2" || value["id"] != "invalid-1" || value["status"] != "rejected" {
		t.Fatalf("response = %#v", value)
	}
	errorValue, ok := value["error"].(map[string]any)
	if !ok || errorValue["class"] != "protocol.invalid_json" {
		t.Fatalf("error = %#v", value["error"])
	}
}
