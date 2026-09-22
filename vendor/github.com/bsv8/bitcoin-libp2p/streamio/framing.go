// Package streamio 提供与业务协议无关的字节流辅助工具。
//
// UvarintFramer implements the wire format
//
//	uvarint(payload byte length) || payload
//
// 它只恢复消息边界，不解码或校验 CBOR、JSON、Protobuf、SSP 或其他业务 payload。
package streamio

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
// DefaultMaxInboundFrameBytes 是单个接收 payload 的本地默认上限（1 MiB）。
// 它不编码进 frame，也不会发送给对端。
	DefaultMaxInboundFrameBytes = 1 << 20
	maxUvarintBytes             = binary.MaxVarintLen64
)

var (
// ErrFramePrefix 表示 uvarint 长度前缀溢出、过长或不是最短编码。
	ErrFramePrefix = errors.New("stream frame prefix error")
// ErrFrameTooLarge 表示对端声明的合法长度超过本地接收上限。
	ErrFrameTooLarge = errors.New("stream frame is too large")
// ErrFrameTruncated 表示前缀或 payload 完成前遇到 EOF。
	ErrFrameTruncated = errors.New("stream frame is truncated")
// ErrFrameStream 表示底层 Stream 读写失败，且不属于以上分帧分类。
	ErrFrameStream = errors.New("stream frame stream error")
)

type uvarintFramerConfig struct {
	maxInboundFrameBytes int
}

// UvarintFramerOption 在构造阶段配置 UvarintFramer；选项不会逐条 frame 读取。
type UvarintFramerOption func(*uvarintFramerConfig) error

// WithMaxInboundFrameBytes 覆盖 framer 的本地接收上限。数值在
// NewUvarintFramer 调用时校验，且永远不会发送给对端。
func WithMaxInboundFrameBytes(max int) UvarintFramerOption {
	return func(config *uvarintFramerConfig) error {
		if max <= 0 {
			return fmt.Errorf("max inbound frame bytes must be positive: %d", max)
		}
		config.maxInboundFrameBytes = max
		return nil
	}
}

// UvarintFramer 在 io.ReadWriter 上读写带长度前缀的 payload。
//
// WriteFrame 会串行化并发写入，并处理 short write；ReadFrame 只允许一个读消费者，
// 不支持并发 ReadFrame。framer 不会关闭、reset 或修改调用方 Stream 的 deadline。
type UvarintFramer struct {
	stream               io.ReadWriter
	maxInboundFrameBytes int
	writeMu              sync.Mutex
}

// NewUvarintFramer 创建只在初始化时配置本地接收上限的 framer；不传选项时使用
// DefaultMaxInboundFrameBytes（1 MiB）。
func NewUvarintFramer(stream io.ReadWriter, options ...UvarintFramerOption) (*UvarintFramer, error) {
	if stream == nil {
		return nil, errors.New("stream must not be nil")
	}
	config := uvarintFramerConfig{maxInboundFrameBytes: DefaultMaxInboundFrameBytes}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("uvarint framer option must not be nil")
		}
		if err := option(&config); err != nil {
			return nil, err
		}
	}
	return &UvarintFramer{
		stream:               stream,
		maxInboundFrameBytes: config.maxInboundFrameBytes,
	}, nil
}

// WriteFrame 写入 uvarint(len(payload)) 和 payload 的副本。长度始终由 framer
// 自动计算，调用方不能另传 length。
func (framer *UvarintFramer) WriteFrame(payload []byte) error {
	if framer == nil || framer.stream == nil {
		return newFrameError(ErrFrameStream, "write frame", errors.New("framer is nil"))
	}

	var prefix [maxUvarintBytes]byte
	prefixLength := binary.PutUvarint(prefix[:], uint64(len(payload)))
	frame := make([]byte, prefixLength+len(payload))
	copy(frame, prefix[:prefixLength])
	copy(frame[prefixLength:], payload)

	framer.writeMu.Lock()
	defer framer.writeMu.Unlock()
	if err := writeAll(framer.stream, frame); err != nil {
		return newFrameError(ErrFrameStream, "write frame", err)
	}
	return nil
}

// ReadFrame 返回一条不含长度前缀的完整 payload。尚未读取任何前缀时的干净 EOF
// 返回 io.EOF；已读取部分前缀或 payload 时的 EOF 返回 ErrFrameTruncated。
func (framer *UvarintFramer) ReadFrame() ([]byte, error) {
	if framer == nil || framer.stream == nil {
		return nil, newFrameError(ErrFrameStream, "read frame", errors.New("framer is nil"))
	}

	var prefix [maxUvarintBytes]byte
	first, err := readByte(framer.stream)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, newFrameError(ErrFrameTruncated, "read frame prefix", err)
		}
		return nil, newFrameError(ErrFrameStream, "read frame prefix", err)
	}
	prefix[0] = first
	prefixLength := 1
	for prefix[prefixLength-1]&0x80 != 0 {
		if prefixLength == len(prefix) {
			return nil, newFrameError(ErrFramePrefix, "read frame prefix", errors.New("uvarint is too long"))
		}
		value, readErr := readByte(framer.stream)
		if readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
				return nil, newFrameError(ErrFrameTruncated, "read frame prefix", readErr)
			}
			return nil, newFrameError(ErrFrameStream, "read frame prefix", readErr)
		}
		prefix[prefixLength] = value
		prefixLength++
	}

	length, err := decodeCanonicalUvarint(prefix[:prefixLength])
	if err != nil {
		return nil, newFrameError(ErrFramePrefix, "read frame prefix", err)
	}
	if length > uint64(framer.maxInboundFrameBytes) {
		return nil, newFrameError(
			ErrFrameTooLarge,
			"read frame payload",
			fmt.Errorf("declared payload length %d exceeds local limit %d", length, framer.maxInboundFrameBytes),
		)
	}

	payload := make([]byte, int(length))
	if len(payload) == 0 {
		return payload, nil
	}
	if _, err := io.ReadFull(framer.stream, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, newFrameError(ErrFrameTruncated, "read frame payload", err)
		}
		return nil, newFrameError(ErrFrameStream, "read frame payload", err)
	}
	return payload, nil
}

func decodeCanonicalUvarint(encoded []byte) (uint64, error) {
	value, consumed := binary.Uvarint(encoded)
	if consumed <= 0 {
		if consumed == 0 {
			return 0, errors.New("uvarint prefix is incomplete")
		}
		return 0, errors.New("uvarint prefix overflows uint64")
	}
	var canonical [maxUvarintBytes]byte
	canonicalLength := binary.PutUvarint(canonical[:], value)
	if canonicalLength != len(encoded) || !bytes.Equal(canonical[:canonicalLength], encoded) {
		return 0, errors.New("uvarint prefix is not minimally encoded")
	}
	return value, nil
}

func readByte(reader io.Reader) (byte, error) {
	var one [1]byte
	n, err := reader.Read(one[:])
	if n == 1 {
		return one[0], nil
	}
	if n < 0 || n > 1 {
		return 0, fmt.Errorf("reader returned invalid byte count %d", n)
	}
	if err == nil {
		return 0, io.ErrNoProgress
	}
	return 0, err
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n < 0 || n > len(data) {
			return fmt.Errorf("writer returned invalid byte count %d", n)
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

type frameError struct {
	category  error
	operation string
	cause     error
}

func newFrameError(category error, operation string, cause error) error {
	return &frameError{category: category, operation: operation, cause: cause}
}

func (err *frameError) Error() string {
	if err.cause == nil {
		return fmt.Sprintf("%s: %s", err.operation, err.category)
	}
	return fmt.Sprintf("%s: %s: %v", err.operation, err.category, err.cause)
}

// Unwrap exposes both the stable category and the underlying cause so callers
// can use errors.Is for either one.
func (err *frameError) Unwrap() []error {
	if err.cause == nil {
		return []error{err.category}
	}
	return []error{err.category, err.cause}
}
