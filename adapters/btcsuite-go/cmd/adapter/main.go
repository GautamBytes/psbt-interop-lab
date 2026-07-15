package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	adapter "github.com/psbt-interop-lab/btcsuite-go-adapter"
)

const maxLineBytes = adapter.MaxLineBytes

func main() {
	digest := artifactDigest()
	handler := adapter.NewHandlerFromEnvironment(os.Getenv("PSBT_LAB_FIXTURE_COMMITMENTS"))
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()
	for {
		line, ok, err := readBoundedLine(reader)
		if err != nil {
			return
		}
		if !ok {
			return
		}
		_, _ = writer.Write(processLine(line, digest, handler))
		_, _ = writer.Write([]byte{'\n'})
		if err := writer.Flush(); err != nil {
			return
		}
	}
}

func processLine(line []byte, digest string, handler *adapter.Handler) []byte {
	response := handler.HandleJSON(line, digest)
	encoded, err := json.Marshal(response)
	if err != nil {
		return []byte(`{"protocol":"psbt-lab.adapter/0.2","id":"invalid-1","status":"crashed","implementation":{"name":"btcsuite-go","version":"v1.2.0","artifactDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"error":{"class":"adapter.response_encode_failed","message":"Response encoding failed","retryable":false}}`)
	}
	return encoded
}

func readBoundedLine(reader *bufio.Reader) ([]byte, bool, error) {
	line := make([]byte, 0, 1024)
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(line)+len(chunk) > maxLineBytes+1 {
			return nil, false, errors.New("adapter request exceeds the 4 MiB line limit")
		}
		line = append(line, chunk...)
		switch {
		case err == nil:
			return line[:len(line)-1], true, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return line, len(line) > 0, nil
		default:
			return nil, false, err
		}
	}
}

func artifactDigest() string {
	bytes, err := os.ReadFile(os.Args[0])
	if err != nil {
		bytes = []byte("psbt-lab-btcsuite-go-adapter")
	}
	sum := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}
