package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	ttlvTypeStructure   = 0x01
	ttlvTypeInteger     = 0x02
	ttlvTypeLong        = 0x03
	ttlvTypeEnumeration = 0x05
	ttlvTypeBoolean     = 0x06
	ttlvTypeText        = 0x07
	ttlvTypeBytes       = 0x08
	ttlvTypeDateTime    = 0x09
)

const (
	tagRequestMessage  = 0x420078
	tagResponseMessage = 0x42007B
	tagRequestHeader   = 0x420077
	tagResponseHeader  = 0x42007A
	tagBatchItem       = 0x42000F
	tagOperation       = 0x42005C
	tagUniqueID        = 0x420094
	tagResultStatus    = 0x42007F
	tagResultReason    = 0x42007E
	tagResultMessage   = 0x42007D
	tagTimestamp       = 0x420092
	tagProtocolVersion = 0x420069
	tagProtocolMajor   = 0x42006A
	tagProtocolMinor   = 0x42006B
	tagVendorPayload   = 0x540001
	tagRequestID       = 0x540002
)

type TTLV struct {
	Tag      uint32
	Type     uint8
	Value    []byte
	Children []TTLV
}

type KMIPMessage struct {
	Operation string
	RequestID string
	ObjectID  string
	Payload   []byte
}

func ReadTTLV(r io.Reader) (TTLV, int, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(r, header); err != nil {
		return TTLV{}, 0, err
	}
	tag := uint32(header[0])<<16 | uint32(header[1])<<8 | uint32(header[2])
	typ := header[3]
	length := binary.BigEndian.Uint32(header[4:8])
	if length > 64*1024*1024 {
		return TTLV{}, 0, errors.New("ttlv length too large")
	}
	padded := int(length) + pad8(int(length))
	body := make([]byte, padded)
	if _, err := io.ReadFull(r, body); err != nil {
		return TTLV{}, 0, err
	}
	node, err := decodeTTLV(tag, typ, body[:length])
	if err != nil {
		return TTLV{}, 0, err
	}
	return node, 8 + padded, nil
}

func WriteTTLV(w io.Writer, t TTLV) (int, error) {
	raw, err := EncodeTTLV(t)
	if err != nil {
		return 0, err
	}
	return w.Write(raw)
}

func EncodeTTLV(t TTLV) ([]byte, error) {
	var payload []byte
	if t.Type == ttlvTypeStructure {
		var err error
		payload, err = encodeChildren(t.Children)
		if err != nil {
			return nil, err
		}
	} else {
		payload = append([]byte{}, t.Value...)
	}
	length := len(payload)
	out := make([]byte, 8, 8+length+pad8(length))
	out[0] = byte((t.Tag >> 16) & 0xff)
	out[1] = byte((t.Tag >> 8) & 0xff)
	out[2] = byte(t.Tag & 0xff)
	out[3] = t.Type
	binary.BigEndian.PutUint32(out[4:8], uint32(length))
	out = append(out, payload...)
	if p := pad8(length); p > 0 {
		out = append(out, make([]byte, p)...)
	}
	return out, nil
}

func DecodeTTLV(raw []byte) (TTLV, error) {
	if len(raw) < 8 {
		return TTLV{}, errors.New("ttlv too short")
	}
	tag := uint32(raw[0])<<16 | uint32(raw[1])<<8 | uint32(raw[2])
	typ := raw[3]
	length := binary.BigEndian.Uint32(raw[4:8])
	if int(length)+8 > len(raw) {
		return TTLV{}, errors.New("ttlv truncated")
	}
	return decodeTTLV(tag, typ, raw[8:8+length])
}

func decodeTTLV(tag uint32, typ uint8, raw []byte) (TTLV, error) {
	node := TTLV{Tag: tag, Type: typ}
	if typ != ttlvTypeStructure {
		node.Value = append([]byte{}, raw...)
		return node, nil
	}
	r := bytes.NewReader(raw)
	children := make([]TTLV, 0)
	for r.Len() > 0 {
		h := make([]byte, 8)
		if _, err := io.ReadFull(r, h); err != nil {
			return TTLV{}, err
		}
		ctag := uint32(h[0])<<16 | uint32(h[1])<<8 | uint32(h[2])
		ctyp := h[3]
		clen := binary.BigEndian.Uint32(h[4:8])
		if int(clen) > r.Len() {
			return TTLV{}, errors.New("child ttlv truncated")
		}
		craw := make([]byte, int(clen))
		if _, err := io.ReadFull(r, craw); err != nil {
			return TTLV{}, err
		}
		if p := pad8(int(clen)); p > 0 {
			if _, err := io.CopyN(io.Discard, r, int64(p)); err != nil {
				return TTLV{}, err
			}
		}
		child, err := decodeTTLV(ctag, ctyp, craw)
		if err != nil {
			return TTLV{}, err
		}
		children = append(children, child)
	}
	node.Children = children
	return node, nil
}

func encodeChildren(children []TTLV) ([]byte, error) {
	buf := bytes.Buffer{}
	for _, c := range children {
		raw, err := EncodeTTLV(c)
		if err != nil {
			return nil, err
		}
		if _, err := buf.Write(raw); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func (t TTLV) Child(tag uint32) (TTLV, bool) {
	for _, c := range t.Children {
		if c.Tag == tag {
			return c, true
		}
	}
	return TTLV{}, false
}

func (t TTLV) Find(tag uint32) (TTLV, bool) {
	if t.Tag == tag {
		return t, true
	}
	for _, c := range t.Children {
		if n, ok := c.Find(tag); ok {
			return n, true
		}
	}
	return TTLV{}, false
}

func (t TTLV) Text() string {
	return strings.TrimSpace(string(t.Value))
}

func (t TTLV) Bytes() []byte {
	return append([]byte{}, t.Value...)
}

func (t TTLV) Int32() int32 {
	switch len(t.Value) {
	case 4:
		return int32(binary.BigEndian.Uint32(t.Value))
	case 8:
		return int32(binary.BigEndian.Uint64(t.Value))
	default:
		return 0
	}
}

func (t TTLV) Int64() int64 {
	switch len(t.Value) {
	case 8:
		return int64(binary.BigEndian.Uint64(t.Value))
	case 4:
		return int64(binary.BigEndian.Uint32(t.Value))
	default:
		return 0
	}
}

func TTLVStructure(tag uint32, children ...TTLV) TTLV {
	return TTLV{Tag: tag, Type: ttlvTypeStructure, Children: append([]TTLV{}, children...)}
}

func TTLVText(tag uint32, v string) TTLV {
	return TTLV{Tag: tag, Type: ttlvTypeText, Value: []byte(v)}
}

func TTLVBytes(tag uint32, v []byte) TTLV {
	return TTLV{Tag: tag, Type: ttlvTypeBytes, Value: append([]byte{}, v...)}
}

func TTLVInt(tag uint32, v int32) TTLV {
	raw := make([]byte, 4)
	binary.BigEndian.PutUint32(raw, uint32(v))
	return TTLV{Tag: tag, Type: ttlvTypeInteger, Value: raw}
}

func TTLVEnum(tag uint32, v int32) TTLV {
	raw := make([]byte, 4)
	binary.BigEndian.PutUint32(raw, uint32(v))
	return TTLV{Tag: tag, Type: ttlvTypeEnumeration, Value: raw}
}

func TTLVDateTime(tag uint32, ts time.Time) TTLV {
	raw := make([]byte, 8)
	binary.BigEndian.PutUint64(raw, uint64(ts.UTC().Unix()))
	return TTLV{Tag: tag, Type: ttlvTypeDateTime, Value: raw}
}

func ParseKMIPRequest(msg TTLV) (KMIPMessage, error) {
	if msg.Tag != tagRequestMessage && msg.Type == ttlvTypeStructure {
		// Allow direct BatchItem/Structure for testing.
		if op, ok := msg.Find(tagOperation); ok {
			return parseKMIPMessageFromNode(msg, op)
		}
	}
	if msg.Tag != tagRequestMessage {
		return KMIPMessage{}, fmt.Errorf("unexpected root tag 0x%06x", msg.Tag)
	}
	opNode, ok := msg.Find(tagOperation)
	if !ok {
		return KMIPMessage{}, errors.New("operation not found")
	}
	return parseKMIPMessageFromNode(msg, opNode)
}

func parseKMIPMessageFromNode(root TTLV, opNode TTLV) (KMIPMessage, error) {
	out := KMIPMessage{}
	switch opNode.Type {
	case ttlvTypeText:
		out.Operation = normalizeOperation(opNode.Text())
	case ttlvTypeEnumeration, ttlvTypeInteger:
		out.Operation = operationFromCode(opNode.Int32())
	default:
		return KMIPMessage{}, errors.New("unsupported operation encoding")
	}
	if out.Operation == "" {
		return KMIPMessage{}, errors.New("unsupported operation")
	}
	if rid, ok := root.Find(tagRequestID); ok {
		out.RequestID = rid.Text()
	}
	if uid, ok := root.Find(tagUniqueID); ok {
		out.ObjectID = uid.Text()
	}
	if payload, ok := root.Find(tagVendorPayload); ok {
		out.Payload = payload.Bytes()
	}
	return out, nil
}

func BuildKMIPResponse(req KMIPMessage, status string, reason string, payload interface{}) (TTLV, []byte, error) {
	statusCode := int32(0)
	if strings.ToLower(strings.TrimSpace(status)) != "success" {
		statusCode = 1
	}
	payloadRaw := []byte("{}")
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return TTLV{}, nil, err
		}
		payloadRaw = raw
	}
	msg := TTLVStructure(tagResponseMessage,
		TTLVStructure(tagResponseHeader,
			TTLVStructure(tagProtocolVersion,
				TTLVInt(tagProtocolMajor, 2),
				TTLVInt(tagProtocolMinor, 1),
			),
			TTLVDateTime(tagTimestamp, time.Now().UTC()),
			TTLVText(tagRequestID, req.RequestID),
		),
		TTLVStructure(tagBatchItem,
			TTLVText(tagOperation, req.Operation),
			TTLVText(tagUniqueID, req.ObjectID),
			TTLVEnum(tagResultStatus, statusCode),
			TTLVText(tagResultReason, reason),
			TTLVText(tagResultMessage, reason),
			TTLVBytes(tagVendorPayload, payloadRaw),
		),
	)
	raw, err := EncodeTTLV(msg)
	if err != nil {
		return TTLV{}, nil, err
	}
	return msg, raw, nil
}

func DecodePayload[T any](raw []byte, out *T) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func pad8(v int) int {
	if v%8 == 0 {
		return 0
	}
	return 8 - (v % 8)
}

func normalizeOperation(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "create":
		return "Create"
	case "register":
		return "Register"
	case "get":
		return "Get"
	case "getattributes", "get_attributes":
		return "GetAttributes"
	case "locate":
		return "Locate"
	case "activate":
		return "Activate"
	case "revoke":
		return "Revoke"
	case "destroy":
		return "Destroy"
	case "re-key", "rekey", "re_key":
		return "ReKey"
	case "encrypt":
		return "Encrypt"
	case "decrypt":
		return "Decrypt"
	case "sign":
		return "Sign"
	case "mac":
		return "MAC"
	case "query":
		return "Query"
	default:
		return ""
	}
}

func operationFromCode(v int32) string {
	switch v {
	case 1:
		return "Create"
	case 3:
		return "Register"
	case 4:
		return "ReKey"
	case 8:
		return "Locate"
	case 10:
		return "Get"
	case 11:
		return "GetAttributes"
	case 18:
		return "Activate"
	case 19:
		return "Revoke"
	case 20:
		return "Destroy"
	case 24:
		return "Query"
	case 31:
		return "Encrypt"
	case 32:
		return "Decrypt"
	case 33:
		return "Sign"
	case 34:
		return "MAC"
	default:
		return ""
	}
}
