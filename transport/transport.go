// Package transport 把 BitFS exact Artifact 绑定到 bitcoin-libp2p 的 uvarint
// Stream 分帧。它不增加 JSON envelope、session ID、pool ID、重试或存储语义。
package transport

import (
	"fmt"
	"io"

	"github.com/bsv8/bitcoin-libp2p/streamio"
	"github.com/bsv8/go-bitfs/wire"
)

// ProtocolID 是 Go/TypeScript 节点注册和拨号时共同使用的 libp2p stream ID。
const ProtocolID = "/bitfs/wire/1.0.0"

// Stream 是 bitcoin-libp2p framer 所需的最小读写接口；原生 libp2p
// network.Stream 直接满足此接口。
type Stream interface {
	io.Reader
	io.Writer
}

// Framer 在一个长期 stream 上收发多个 exact BitFS Artifact。
type Framer struct {
	inner *streamio.UvarintFramer
}

// NewFramer 使用 BitFS 最大合法完整报文作为本地单帧上限。长度只用于本地
// 防御，不会发给对端，也不参与握手或协商。
func NewFramer(stream Stream) (*Framer, error) {
	inner, err := streamio.NewUvarintFramer(stream, streamio.WithMaxInboundFrameBytes(wire.MaxWireParseBytes))
	if err != nil {
		return nil, fmt.Errorf("transport.NewFramer: %w", err)
	}
	return &Framer{inner: inner}, nil
}

// WriteArtifact 写入 uvarint(len(exact bytes)) || exact bytes。
func (framer *Framer) WriteArtifact(artifact wire.Artifact) error {
	if framer == nil || framer.inner == nil {
		return fmt.Errorf("transport.WriteArtifact: framer is nil")
	}
	if artifact.IsZero() {
		return fmt.Errorf("transport.WriteArtifact: artifact is zero")
	}
	if err := framer.inner.WriteFrame(artifact.Bytes()); err != nil {
		return fmt.Errorf("transport.WriteArtifact: %w", err)
	}
	return nil
}

// ReadArtifact 读取一帧并立即交给 wire.Parse 严格验证。干净 EOF 原样返回
// io.EOF；调用方可在同一 stream 上循环调用。
func (framer *Framer) ReadArtifact() (wire.Artifact, error) {
	if framer == nil || framer.inner == nil {
		return wire.Artifact{}, fmt.Errorf("transport.ReadArtifact: framer is nil")
	}
	raw, err := framer.inner.ReadFrame()
	if err != nil {
		return wire.Artifact{}, err
	}
	artifact, err := wire.Parse(raw)
	if err != nil {
		return wire.Artifact{}, fmt.Errorf("transport.ReadArtifact: %w", err)
	}
	return artifact, nil
}
