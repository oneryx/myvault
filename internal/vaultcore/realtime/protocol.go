package realtime

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/vmihailenco/msgpack/v5"
)

const (
	RecordSeparator  byte   = 0x1e
	HandshakeRequest string = "{\"protocol\":\"messagepack\",\"version\":1}\x1e"

	MsgInvocation = 1
	MsgPing       = 6
	MsgClose      = 7
)

type UpdateType int

const (
	SyncCipherUpdate UpdateType = 0
	SyncCipherCreate UpdateType = 1
	SyncLoginDelete  UpdateType = 2
	SyncFolderDelete UpdateType = 3
	SyncCiphers      UpdateType = 4
	SyncVault        UpdateType = 5
	SyncOrgKeys      UpdateType = 6
	SyncFolderCreate UpdateType = 7
	SyncFolderUpdate UpdateType = 8
	SyncSettings     UpdateType = 10
	LogOut           UpdateType = 11
	SyncSendCreate   UpdateType = 12
	SyncSendUpdate   UpdateType = 13
	SyncSendDelete   UpdateType = 14
)

type Event struct {
	Type      UpdateType
	ContextID string
	ItemID    string
}

var (
	ErrInvalidFrame     = errors.New("realtime: invalid SignalR frame")
	ErrHandshakeFailed  = errors.New("realtime: SignalR handshake failed")
	ErrInvalidMessage   = errors.New("realtime: invalid SignalR message")
	ErrConnectionClosed = errors.New("realtime: server closed SignalR connection")
)

func EncodeFrame(payload []byte) []byte {
	out := binary.AppendUvarint(make([]byte, 0, binary.MaxVarintLen64+len(payload)), uint64(len(payload)))
	return append(out, payload...)
}

func EncodePing() []byte {
	return []byte{0x02, 0x91, 0x06}
}

func DecodeFrames(data []byte) ([][]byte, error) {
	var frames [][]byte
	for len(data) > 0 {
		size, n := binary.Uvarint(data)
		if n <= 0 {
			return nil, ErrInvalidFrame
		}
		data = data[n:]
		if size > uint64(len(data)) {
			return nil, ErrInvalidFrame
		}
		frame := make([]byte, size)
		copy(frame, data[:size])
		frames = append(frames, frame)
		data = data[size:]
	}
	return frames, nil
}

func ParseHandshakeResponse(data []byte) error {
	trimmed := bytes.TrimSuffix(bytes.TrimSpace(data), []byte{RecordSeparator})
	if len(trimmed) == 0 {
		return ErrHandshakeFailed
	}
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(trimmed, &resp); err != nil {
		return fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}
	if resp.Error != "" {
		return fmt.Errorf("%w: %s", ErrHandshakeFailed, resp.Error)
	}
	return nil
}

func DecodeMessage(payload []byte) (int, *Event, error) {
	var raw []any
	if err := msgpack.Unmarshal(payload, &raw); err != nil {
		return 0, nil, fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	if len(raw) == 0 {
		return 0, nil, ErrInvalidMessage
	}

	msgType, ok := asInt(raw[0])
	if !ok {
		return 0, nil, ErrInvalidMessage
	}

	switch msgType {
	case MsgPing:
		return MsgPing, nil, nil
	case MsgClose:
		return MsgClose, nil, nil
	case MsgInvocation:
		// SignalR MessagePack Invocation: [1, headers, invocationId, target, arguments]
		if len(raw) < 5 {
			return MsgInvocation, nil, ErrInvalidMessage
		}
		target, _ := raw[3].(string)
		if target != "ReceiveMessage" {
			return MsgInvocation, nil, nil
		}
		args, ok := raw[4].([]any)
		if !ok || len(args) == 0 {
			return MsgInvocation, nil, nil
		}
		argMap, ok := args[0].(map[string]any)
		if !ok {
			return MsgInvocation, nil, ErrInvalidMessage
		}
		ev, err := parseNotification(argMap)
		if err != nil {
			return MsgInvocation, nil, err
		}
		return MsgInvocation, ev, nil
	default:
		return msgType, nil, nil
	}
}

func parseNotification(m map[string]any) (*Event, error) {
	rawType, ok := m["Type"]
	if !ok {
		return nil, fmt.Errorf("%w: missing notification Type", ErrInvalidMessage)
	}
	typeNum, ok := asInt(rawType)
	if !ok {
		return nil, fmt.Errorf("%w: non-integer notification Type", ErrInvalidMessage)
	}

	ev := &Event{
		Type: UpdateType(typeNum),
	}
	if ctxID, ok := m["ContextId"].(string); ok {
		ev.ContextID = ctxID
	}
	if payload, ok := m["Payload"].(map[string]any); ok {
		if id, ok := payload["Id"].(string); ok {
			ev.ItemID = id
		}
	}
	return ev, nil
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int8:
		return int(n), true
	case int16:
		return int(n), true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case uint:
		if n > math.MaxInt {
			return 0, false
		}
		return int(n), true
	case uint8:
		return int(n), true
	case uint16:
		return int(n), true
	case uint32:
		return int(n), true
	case uint64:
		if n > math.MaxInt {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}
