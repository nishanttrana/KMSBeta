package main

import (
	"crypto/aes"
	"crypto/des"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type serviceError struct {
	Code       string
	Message    string
	HTTPStatus int
}

func (e serviceError) Error() string {
	if strings.TrimSpace(e.Message) == "" {
		return e.Code
	}
	return e.Message
}

func newServiceError(status int, code string, message string) serviceError {
	return serviceError{
		Code:       strings.TrimSpace(code),
		Message:    strings.TrimSpace(message),
		HTTPStatus: status,
	}
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func defaultString(v string, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
}

func normalizeTR31Version(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "", "B":
		return "B"
	case "C":
		return "C"
	case "D":
		return "D"
	case "A":
		return "A"
	default:
		return ""
	}
}

func normalizeTR31Format(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", TR31FormatVariant:
		return TR31FormatVariant
	case TR31FormatB:
		return TR31FormatB
	case TR31FormatC:
		return TR31FormatC
	case TR31FormatD:
		return TR31FormatD
	case TR31FormatAESKWP:
		return TR31FormatAESKWP
	default:
		return ""
	}
}

func normalizePINFormat(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "0", "ISO0", "ISO-0":
		return "ISO-0"
	case "1", "ISO1", "ISO-1":
		return "ISO-1"
	case "3", "ISO3", "ISO-3":
		return "ISO-3"
	case "4", "ISO4", "ISO-4":
		return "ISO-4"
	default:
		return ""
	}
}

func normalizeModeOfUse(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "", "B":
		return "B"
	case "E":
		return "E"
	case "D":
		return "D"
	case "N":
		return "N"
	default:
		return ""
	}
}

func normalizeExportability(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "", "E":
		return "E"
	case "N":
		return "N"
	case "S":
		return "S"
	default:
		return ""
	}
}

func parseTimeValue(v interface{}) time.Time {
	switch x := v.(type) {
	case time.Time:
		return x.UTC()
	case string:
		return parseTimeString(x)
	case []byte:
		return parseTimeString(string(x))
	default:
		return time.Time{}
	}
}

func parseTimeString(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, f := range formats {
		if ts, err := time.Parse(f, v); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func nullableTime(v time.Time) interface{} {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
}

func validJSONOr(v string, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	if json.Valid([]byte(v)) {
		return v
	}
	return fallback
}

func extractInt(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case int32:
		return int(x)
	case int64:
		return int(x)
	case float64:
		return int(x)
	default:
		return 0
	}
}

func decodeB64(input string, field string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(input))
	if err != nil {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", field+" must be base64")
	}
	if len(raw) == 0 {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", field+" cannot be empty")
	}
	return raw, nil
}

func firstString(values ...interface{}) string {
	for _, v := range values {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func decimalize(sum []byte, digits int) string {
	if digits <= 0 {
		digits = 4
	}
	out := make([]byte, 0, digits)
	for _, b := range sum {
		hi := (b >> 4) & 0x0F
		lo := b & 0x0F
		if hi <= 9 {
			out = append(out, byte('0'+hi))
		}
		if len(out) == digits {
			break
		}
		if lo <= 9 {
			out = append(out, byte('0'+lo))
		}
		if len(out) == digits {
			break
		}
	}
	for len(out) < digits {
		out = append(out, '0')
	}
	return string(out)
}

func normalizeTDESKey(raw []byte) ([]byte, error) {
	switch len(raw) {
	case 16:
		out := make([]byte, 24)
		copy(out[:16], raw)
		copy(out[16:], raw[:8])
		return out, nil
	case 24:
		out := make([]byte, 24)
		copy(out, raw)
		return out, nil
	default:
		return nil, errors.New("3DES key must be 16 or 24 bytes")
	}
}

func tdesECBEncrypt(key24 []byte, block8 []byte) ([]byte, error) {
	if len(block8) != 8 {
		return nil, errors.New("block must be 8 bytes")
	}
	c, err := des.NewTripleDESCipher(key24)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8)
	c.Encrypt(out, block8)
	return out, nil
}

func tdesECBDecrypt(key24 []byte, block8 []byte) ([]byte, error) {
	if len(block8) != 8 {
		return nil, errors.New("block must be 8 bytes")
	}
	c, err := des.NewTripleDESCipher(key24)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8)
	c.Decrypt(out, block8)
	return out, nil
}

func sanitizeDigits(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", errors.New("value is required")
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return "", errors.New("value must be numeric")
		}
	}
	return v, nil
}

func extractPAN12(pan string) (string, error) {
	pan, err := sanitizeDigits(pan)
	if err != nil {
		return "", errors.New("pan is required and must be numeric")
	}
	if len(pan) < 13 {
		return "", errors.New("pan must be at least 13 digits")
	}
	noCheck := pan[:len(pan)-1]
	if len(noCheck) < 12 {
		return "", errors.New("pan must contain at least 12 digits excluding check digit")
	}
	return noCheck[len(noCheck)-12:], nil
}

func xorHexString(a string, b string) (string, error) {
	a = strings.ToUpper(strings.TrimSpace(a))
	b = strings.ToUpper(strings.TrimSpace(b))
	if len(a) != len(b) || len(a)%2 != 0 {
		return "", errors.New("hex values must have equal even length")
	}
	ab, err := hex.DecodeString(a)
	if err != nil {
		return "", errors.New("invalid hex value")
	}
	bb, err := hex.DecodeString(b)
	if err != nil {
		return "", errors.New("invalid hex value")
	}
	out := make([]byte, len(ab))
	for i := range ab {
		out[i] = ab[i] ^ bb[i]
	}
	return strings.ToUpper(hex.EncodeToString(out)), nil
}

func buildPINClearBlock(format string, pin string, pan string) ([]byte, error) {
	format = normalizePINFormat(format)
	pin, err := sanitizeDigits(pin)
	if err != nil {
		return nil, errors.New("pin is required and must be numeric")
	}
	if len(pin) < 4 || len(pin) > 12 {
		return nil, errors.New("pin length must be between 4 and 12")
	}
	var formatNibble string
	switch format {
	case "ISO-0":
		formatNibble = "0"
	case "ISO-1":
		formatNibble = "1"
	case "ISO-3":
		formatNibble = "3"
	default:
		return nil, errors.New("unsupported pin format for block construction")
	}
	pinField := formatNibble + strings.ToUpper(fmt.Sprintf("%X", len(pin))) + pin
	fill := "F"
	if format == "ISO-3" {
		fill = "A"
	}
	for len(pinField) < 16 {
		pinField += fill
	}
	clearHex := pinField
	if format == "ISO-0" || format == "ISO-3" {
		pan12, err := extractPAN12(pan)
		if err != nil {
			return nil, err
		}
		panField := "0000" + pan12
		clearHex, err = xorHexString(pinField, panField)
		if err != nil {
			return nil, err
		}
	}
	block, err := hex.DecodeString(clearHex)
	if err != nil {
		return nil, errors.New("failed to construct pin block")
	}
	return block, nil
}

func decodePINFromClearBlock(format string, clear []byte, pan string) (string, error) {
	format = normalizePINFormat(format)
	if len(clear) != 8 {
		return "", errors.New("clear pin block must be 8 bytes")
	}
	clearHex := strings.ToUpper(hex.EncodeToString(clear))
	pinField := clearHex
	if format == "ISO-0" || format == "ISO-3" {
		pan12, err := extractPAN12(pan)
		if err != nil {
			return "", err
		}
		pinField, err = xorHexString(clearHex, "0000"+pan12)
		if err != nil {
			return "", err
		}
	}
	if len(pinField) != 16 {
		return "", errors.New("invalid pin field length")
	}
	formatNibble := pinField[:1]
	switch format {
	case "ISO-0":
		if formatNibble != "0" {
			return "", errors.New("pin field format nibble mismatch")
		}
	case "ISO-1":
		if formatNibble != "1" {
			return "", errors.New("pin field format nibble mismatch")
		}
	case "ISO-3":
		if formatNibble != "3" {
			return "", errors.New("pin field format nibble mismatch")
		}
	default:
		return "", errors.New("unsupported pin format for parsing")
	}
	pinLenNibble := pinField[1:2]
	pinLen, err := strconv.ParseInt(pinLenNibble, 16, 0)
	if err != nil {
		return "", errors.New("invalid pin length nibble")
	}
	if pinLen < 4 || pinLen > 12 {
		return "", errors.New("invalid pin length")
	}
	pin := pinField[2 : 2+pinLen]
	for _, c := range pin {
		if c < '0' || c > '9' {
			return "", errors.New("decoded pin is not numeric")
		}
	}
	return pin, nil
}

func computePVVWithTDES(key []byte, pin string, pan string, pvki string) (string, error) {
	pin, err := sanitizeDigits(pin)
	if err != nil {
		return "", errors.New("pin is required and must be numeric")
	}
	if len(pin) < 4 {
		return "", errors.New("pin must contain at least 4 digits")
	}
	pan, err = sanitizeDigits(pan)
	if err != nil {
		return "", errors.New("pan is required and must be numeric")
	}
	if len(pan) < 12 {
		return "", errors.New("pan must be at least 12 digits")
	}
	pvki, err = sanitizeDigits(defaultString(pvki, "1"))
	if err != nil {
		return "", errors.New("pvki must be numeric")
	}
	if len(pvki) != 1 {
		return "", errors.New("pvki must be one digit")
	}
	tdesKey, err := normalizeTDESKey(key)
	if err != nil {
		return "", err
	}
	noCheck := pan
	if len(noCheck) > 0 {
		noCheck = pan[:len(pan)-1]
	}
	if len(noCheck) < 11 {
		return "", errors.New("pan must contain at least 11 digits excluding check digit")
	}
	pan11 := noCheck[len(noCheck)-11:]
	input := pan11 + pvki + pin[:4]
	if len(input) != 16 {
		return "", errors.New("invalid pvv input data length")
	}
	in, err := hex.DecodeString(input)
	if err != nil {
		return "", errors.New("invalid pvv input")
	}
	out, err := tdesECBEncrypt(tdesKey, in)
	if err != nil {
		return "", err
	}
	hexOut := strings.ToUpper(hex.EncodeToString(out))
	dec := make([]byte, 0, 4)
	for i := 0; i < len(hexOut) && len(dec) < 4; i++ {
		c := hexOut[i]
		if c >= '0' && c <= '9' {
			dec = append(dec, c)
		}
	}
	for i := 0; i < len(hexOut) && len(dec) < 4; i++ {
		c := hexOut[i]
		if c >= 'A' && c <= 'F' {
			dec = append(dec, byte('0'+(c-'A')))
		}
	}
	for len(dec) < 4 {
		dec = append(dec, '0')
	}
	return string(dec), nil
}

func computeCVVWithTDES(cvk []byte, pan string, expiryYYMM string, serviceCode string) (string, error) {
	pan, err := sanitizeDigits(pan)
	if err != nil {
		return "", errors.New("pan is required and must be numeric")
	}
	expiryYYMM, err = sanitizeDigits(expiryYYMM)
	if err != nil {
		return "", errors.New("expiry_yymm is required and must be numeric")
	}
	if len(expiryYYMM) != 4 {
		return "", errors.New("expiry_yymm must be 4 digits")
	}
	serviceCode, err = sanitizeDigits(serviceCode)
	if err != nil {
		return "", errors.New("service_code is required and must be numeric")
	}
	if len(serviceCode) != 3 {
		return "", errors.New("service_code must be 3 digits")
	}
	key24, err := normalizeTDESKey(cvk)
	if err != nil {
		return "", err
	}
	data := pan + expiryYYMM + serviceCode
	for len(data) < 32 {
		data += "0"
	}
	if len(data) > 32 {
		data = data[:32]
	}
	left, err := hex.DecodeString(data[:16])
	if err != nil {
		return "", errors.New("invalid cvv input block")
	}
	right, err := hex.DecodeString(data[16:])
	if err != nil {
		return "", errors.New("invalid cvv input block")
	}
	iRes, err := tdesECBEncrypt(key24, left)
	if err != nil {
		return "", err
	}
	x := make([]byte, 8)
	for i := 0; i < 8; i++ {
		x[i] = iRes[i] ^ right[i]
	}
	oRes, err := tdesECBEncrypt(key24, x)
	if err != nil {
		return "", err
	}
	hexOut := strings.ToUpper(hex.EncodeToString(oRes))
	out := make([]byte, 0, 3)
	for i := 0; i < len(hexOut) && len(out) < 3; i++ {
		c := hexOut[i]
		if c >= '0' && c <= '9' {
			out = append(out, c)
		}
	}
	for i := 0; i < len(hexOut) && len(out) < 3; i++ {
		c := hexOut[i]
		if c >= 'A' && c <= 'F' {
			out = append(out, byte('0'+(c-'A')))
		}
	}
	for len(out) < 3 {
		out = append(out, '0')
	}
	return string(out), nil
}

func generatePVV(key []byte, pin string, pan string, pvki string) (string, error) {
	return computePVVWithTDES(key, pin, pan, pvki)
}

func generatePINOffset(pin string, referencePIN string) (string, error) {
	pin = strings.TrimSpace(pin)
	referencePIN = strings.TrimSpace(referencePIN)
	if pin == "" || referencePIN == "" {
		return "", errors.New("pin and reference_pin are required")
	}
	if len(pin) != len(referencePIN) {
		return "", errors.New("pin and reference_pin must have same length")
	}
	offset := make([]byte, len(pin))
	for i := 0; i < len(pin); i++ {
		if pin[i] < '0' || pin[i] > '9' || referencePIN[i] < '0' || referencePIN[i] > '9' {
			return "", errors.New("pin and reference_pin must be numeric")
		}
		d := int(pin[i]-'0') - int(referencePIN[i]-'0')
		if d < 0 {
			d += 10
		}
		offset[i] = byte('0' + d)
	}
	return string(offset), nil
}

func verifyPINOffset(pin string, referencePIN string, offset string) bool {
	gen, err := generatePINOffset(pin, referencePIN)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(gen), []byte(strings.TrimSpace(offset))) == 1
}

func iso9797Alg1MAC(key []byte, msg []byte) ([]byte, error) {
	if len(key) != 8 {
		return nil, errors.New("iso9797 alg1 key must be 8 bytes")
	}
	blk, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := iso9797Method2Pad(msg, 8)
	state := make([]byte, 8)
	tmp := make([]byte, 8)
	for i := 0; i < len(padded); i += 8 {
		copy(tmp, padded[i:i+8])
		for j := 0; j < 8; j++ {
			tmp[j] ^= state[j]
		}
		blk.Encrypt(state, tmp)
	}
	return append([]byte{}, state...), nil
}

func iso9797Method2Pad(data []byte, blockSize int) []byte {
	out := append([]byte{}, data...)
	out = append(out, 0x80)
	for len(out)%blockSize != 0 {
		out = append(out, 0x00)
	}
	return out
}

func aesCMAC(key []byte, msg []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("cmac key must be 16/24/32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	constRb := byte(0x87)
	zero := make([]byte, 16)
	l := make([]byte, 16)
	block.Encrypt(l, zero)
	k1 := leftShiftOne(l)
	if (l[0] & 0x80) != 0 {
		k1[15] ^= constRb
	}
	k2 := leftShiftOne(k1)
	if (k1[0] & 0x80) != 0 {
		k2[15] ^= constRb
	}

	m := iso9797Method2Pad(msg, 16)
	lastComplete := len(msg) > 0 && len(msg)%16 == 0
	if lastComplete {
		m = append([]byte{}, msg...)
		xorInPlace(m[len(m)-16:], k1)
	} else {
		xorInPlace(m[len(m)-16:], k2)
	}

	x := make([]byte, 16)
	tmp := make([]byte, 16)
	for i := 0; i < len(m); i += 16 {
		copy(tmp, m[i:i+16])
		xorInPlace(tmp, x)
		block.Encrypt(x, tmp)
	}
	return append([]byte{}, x...), nil
}

func leftShiftOne(in []byte) []byte {
	out := make([]byte, len(in))
	carry := byte(0)
	for i := len(in) - 1; i >= 0; i-- {
		nextCarry := (in[i] >> 7) & 0x01
		out[i] = (in[i] << 1) | carry
		carry = nextCarry
	}
	return out
}

func xorInPlace(dst []byte, src []byte) {
	for i := 0; i < len(dst) && i < len(src); i++ {
		dst[i] ^= src[i]
	}
}

func buildTR31Block(version string, algorithm string, usageCode string, key []byte, kcv string) (string, string, error) {
	version = normalizeTR31Version(version)
	if version == "" {
		return "", "", errors.New("unsupported tr31_version")
	}
	if version != "A" && version != "B" && version != "C" && version != "D" {
		return "", "", errors.New("unsupported tr31_version")
	}
	if strings.TrimSpace(kcv) == "" {
		var err error
		kcv, err = computePaymentKCV(key, algorithm)
		if err != nil {
			return "", "", err
		}
	}
	payload := base64.StdEncoding.EncodeToString(key)
	block := version + "|" + strings.ToUpper(defaultString(algorithm, "AES")) + "|" + strings.ToUpper(defaultString(usageCode, "D0")) + "|" + payload + "|" + strings.ToUpper(strings.TrimSpace(kcv))
	header := version + strings.ToUpper(defaultString(usageCode, "D0")) + defaultString(strings.ToUpper(algorithm), "AES")
	return block, header, nil
}

func computePaymentKCV(key []byte, algorithmHint string) (string, error) {
	if len(key) == 0 {
		return "", errors.New("empty key material")
	}
	algo := strings.ToUpper(strings.TrimSpace(algorithmHint))
	var first []byte

	switch {
	case strings.Contains(algo, "AES"):
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return "", errors.New("aes key must be 16/24/32 bytes for kcv")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}
		out := make([]byte, aes.BlockSize)
		block.Encrypt(out, make([]byte, aes.BlockSize))
		first = out[:3]
	case strings.Contains(algo, "TDES"), strings.Contains(algo, "3DES"), strings.Contains(algo, "DES"), len(key) == 8, len(key) == 16:
		if len(key) == 8 {
			block, err := des.NewCipher(key)
			if err != nil {
				return "", err
			}
			out := make([]byte, 8)
			block.Encrypt(out, make([]byte, 8))
			first = out[:3]
			break
		}
		tdesKey, err := normalizeTDESKey(key)
		if err != nil {
			return "", err
		}
		out, err := tdesECBEncrypt(tdesKey, make([]byte, 8))
		if err != nil {
			return "", err
		}
		first = out[:3]
	default:
		if len(key) == 24 || len(key) == 32 {
			if len(key) == 24 {
				tdesKey, err := normalizeTDESKey(key)
				if err != nil {
					return "", err
				}
				out, err := tdesECBEncrypt(tdesKey, make([]byte, 8))
				if err != nil {
					return "", err
				}
				first = out[:3]
			} else {
				block, err := aes.NewCipher(key)
				if err != nil {
					return "", err
				}
				out := make([]byte, aes.BlockSize)
				block.Encrypt(out, make([]byte, aes.BlockSize))
				first = out[:3]
			}
		} else {
			return "", errors.New("unsupported key length for kcv")
		}
	}
	return strings.ToUpper(hex.EncodeToString(first)), nil
}

func normalizeISOXML(v string) string {
	return strings.TrimSpace(strings.ReplaceAll(v, "\r\n", "\n"))
}

func parseKCVHex(v string) []byte {
	raw, err := hex.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return nil
	}
	return raw
}

func formatKCVHex(v []byte) string {
	if len(v) == 0 {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(v))
}

func mustJSON(v interface{}) string {
	raw, _ := json.Marshal(v)
	if len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}

func boolValue(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case []byte:
		s := strings.TrimSpace(string(x))
		return s == "1" || strings.EqualFold(s, "true")
	case string:
		s := strings.TrimSpace(x)
		return s == "1" || strings.EqualFold(s, "true")
	default:
		return false
	}
}

func httpStatusForErr(err error) int {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		return svcErr.HTTPStatus
	}
	if errors.Is(err, errNotFound) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}
