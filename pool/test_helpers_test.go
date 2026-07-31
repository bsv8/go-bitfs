package pool

import "bytes"

func bytes32(value byte) []byte { return bytes.Repeat([]byte{value}, 32) }
