package bitfs

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// The current BitFS wire helpers only expose deterministic child documents.
var (
	canonicalEnc cbor.EncMode
	strictDec    cbor.DecMode
)

func init() {
	var err error
	canonicalEnc, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	strictDec, err = cbor.DecOptions{IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden, MaxNestedLevels: 16, MaxArrayElements: 64, MaxMapPairs: 16, UTF8: cbor.UTF8RejectInvalid}.DecMode()
	if err != nil {
		panic(err)
	}
}

func encodeArray(values ...any) ([]byte, error) { return canonicalEnc.Marshal(values) }

func decodeArray(data []byte, length int) ([]cbor.RawMessage, error) {
	var values []cbor.RawMessage
	if err := strictDec.Unmarshal(data, &values); err != nil {
		return nil, err
	}
	if len(values) != length {
		return nil, fmt.Errorf("array length is %d, want %d", len(values), length)
	}
	return values, nil
}

func decode(raw cbor.RawMessage, target any) error { return strictDec.Unmarshal(raw, target) }

func bstr(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}
