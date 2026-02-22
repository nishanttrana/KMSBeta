package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerPaymentKeyEndpoints(t *testing.T) {
	h, _, _, _ := newPaymentHandler(t)

	createReq := httptest.NewRequest(http.MethodPost, "/payment/keys", bytes.NewReader([]byte(`{
		"tenant_id":"t1",
		"key_id":"kc-1",
		"payment_type":"ZMK",
		"usage_code":"K0",
		"mode_of_use":"B",
		"exportability":"E",
		"iso20022_msg_types":["pacs.008"]
	}`)))
	createRR := httptest.NewRecorder()
	h.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", createRR.Code, createRR.Body.String())
	}

	var createResp struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	_ = json.Unmarshal(createRR.Body.Bytes(), &createResp)
	if createResp.Item.ID == "" {
		t.Fatalf("missing payment key id response=%s", createRR.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/payment/keys?tenant_id=t1", nil)
	listRR := httptest.NewRecorder()
	h.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listRR.Code, listRR.Body.String())
	}
	if !strings.Contains(listRR.Body.String(), "\"key_id\":\"kc-1\"") {
		t.Fatalf("unexpected list body=%s", listRR.Body.String())
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/payment/keys/"+createResp.Item.ID, bytes.NewReader([]byte(`{
		"tenant_id":"t1",
		"payment_type":"TPK",
		"usage_code":"P0",
		"mode_of_use":"E",
		"exportability":"N"
	}`)))
	updateRR := httptest.NewRecorder()
	h.ServeHTTP(updateRR, updateReq)
	if updateRR.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updateRR.Code, updateRR.Body.String())
	}

	rotateReq := httptest.NewRequest(http.MethodPost, "/payment/keys/"+createResp.Item.ID+"/rotate", bytes.NewReader([]byte(`{
		"tenant_id":"t1",
		"reason":"policy"
	}`)))
	rotateRR := httptest.NewRecorder()
	h.ServeHTTP(rotateRR, rotateReq)
	if rotateRR.Code != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", rotateRR.Code, rotateRR.Body.String())
	}
	if !strings.Contains(rotateRR.Body.String(), "\"version_id\":\"ver_") {
		t.Fatalf("unexpected rotate body=%s", rotateRR.Body.String())
	}
}

func TestHandlerTR31AndPinEndpoints(t *testing.T) {
	h, _, keycore, _ := newPaymentHandler(t)

	tr31CreateReq := httptest.NewRequest(http.MethodPost, "/payment/tr31/create", bytes.NewReader([]byte(`{
		"tenant_id":"t2",
		"key_id":"kc-2",
		"tr31_version":"D",
		"algorithm":"AES",
		"usage_code":"D0",
		"kbpk_key_b64":"MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUY=",
		"material_b64":"MTIzNDU2Nzg5MEFCQ0RFRg=="
	}`)))
	tr31CreateRR := httptest.NewRecorder()
	h.ServeHTTP(tr31CreateRR, tr31CreateReq)
	if tr31CreateRR.Code != http.StatusOK {
		t.Fatalf("tr31 create status=%d body=%s", tr31CreateRR.Code, tr31CreateRR.Body.String())
	}
	var tr31CreateResp struct {
		Result struct {
			KeyBlock string `json:"key_block"`
		} `json:"result"`
	}
	_ = json.Unmarshal(tr31CreateRR.Body.Bytes(), &tr31CreateResp)
	if tr31CreateResp.Result.KeyBlock == "" {
		t.Fatalf("missing key block body=%s", tr31CreateRR.Body.String())
	}

	validateReq := httptest.NewRequest(http.MethodPost, "/payment/tr31/validate", bytes.NewReader([]byte(`{
		"tenant_id":"t2",
		"kbpk_key_b64":"MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUY=",
		"key_block":"`+tr31CreateResp.Result.KeyBlock+`"
	}`)))
	validateRR := httptest.NewRecorder()
	h.ServeHTTP(validateRR, validateReq)
	if validateRR.Code != http.StatusOK || !strings.Contains(validateRR.Body.String(), "\"valid\":true") {
		t.Fatalf("tr31 validate status=%d body=%s", validateRR.Code, validateRR.Body.String())
	}

	sourcePINKey := []byte("1234567890ABCDEF")
	targetPINKey := []byte("FEDCBA0987654321")
	keycore.materials["t2:zpk-src"] = append([]byte{}, sourcePINKey...)
	keycore.materials["t2:zpk-dst"] = append([]byte{}, targetPINKey...)
	pan := "4111111111111111"
	clearISO0, err := buildPINClearBlock("ISO-0", "1234", pan)
	if err != nil {
		t.Fatal(err)
	}
	sourceTDES, err := normalizeTDESKey(sourcePINKey)
	if err != nil {
		t.Fatal(err)
	}
	encryptedISO0, err := tdesECBEncrypt(sourceTDES, clearISO0)
	if err != nil {
		t.Fatal(err)
	}
	pinReq := httptest.NewRequest(http.MethodPost, "/payment/pin/translate", bytes.NewReader([]byte(`{
		"tenant_id":"t2",
		"source_format":"ISO-0",
		"target_format":"ISO-1",
		"pin_block":"`+strings.ToUpper(hex.EncodeToString(encryptedISO0))+`",
		"pan":"`+pan+`",
		"source_zpk_key_id":"zpk-src",
		"target_zpk_key_id":"zpk-dst"
	}`)))
	pinRR := httptest.NewRecorder()
	h.ServeHTTP(pinRR, pinReq)
	if pinRR.Code != http.StatusOK || !strings.Contains(pinRR.Body.String(), "\"pin_block\":\"") {
		t.Fatalf("pin translate status=%d body=%s", pinRR.Code, pinRR.Body.String())
	}
}

func TestHandlerMACISOAndLAUEndpoints(t *testing.T) {
	h, _, _, _ := newPaymentHandler(t)

	macReq := httptest.NewRequest(http.MethodPost, "/payment/mac/retail", bytes.NewReader([]byte(`{
		"tenant_id":"t3",
		"key_b64":"`+base64.StdEncoding.EncodeToString([]byte("12345678ABCDEFGH"))+`",
		"data_b64":"`+base64.StdEncoding.EncodeToString([]byte("hello-payment"))+`"
	}`)))
	macRR := httptest.NewRecorder()
	h.ServeHTTP(macRR, macReq)
	if macRR.Code != http.StatusOK {
		t.Fatalf("mac status=%d body=%s", macRR.Code, macRR.Body.String())
	}

	var macResp struct {
		MACB64 string `json:"mac_b64"`
	}
	_ = json.Unmarshal(macRR.Body.Bytes(), &macResp)
	if macResp.MACB64 == "" {
		t.Fatalf("missing mac in response=%s", macRR.Body.String())
	}

	verifyReq := httptest.NewRequest(http.MethodPost, "/payment/mac/verify", bytes.NewReader([]byte(`{
		"tenant_id":"t3",
		"key_b64":"`+base64.StdEncoding.EncodeToString([]byte("12345678ABCDEFGH"))+`",
		"data_b64":"`+base64.StdEncoding.EncodeToString([]byte("hello-payment"))+`",
		"mac_b64":"`+macResp.MACB64+`",
		"type":"retail"
	}`)))
	verifyRR := httptest.NewRecorder()
	h.ServeHTTP(verifyRR, verifyReq)
	if verifyRR.Code != http.StatusOK || !strings.Contains(verifyRR.Body.String(), "\"verified\":true") {
		t.Fatalf("mac verify status=%d body=%s", verifyRR.Code, verifyRR.Body.String())
	}

	signReq := httptest.NewRequest(http.MethodPost, "/payment/iso20022/sign", bytes.NewReader([]byte(`{
		"tenant_id":"t3",
		"key_id":"iso-k1",
		"xml":"<Document><A>1</A></Document>"
	}`)))
	signRR := httptest.NewRecorder()
	h.ServeHTTP(signRR, signReq)
	if signRR.Code != http.StatusOK || !strings.Contains(signRR.Body.String(), "signature_b64") {
		t.Fatalf("iso sign status=%d body=%s", signRR.Code, signRR.Body.String())
	}

	lauReq := httptest.NewRequest(http.MethodPost, "/payment/iso20022/lau/generate", bytes.NewReader([]byte(`{
		"tenant_id":"t3",
		"lau_key_b64":"`+base64.StdEncoding.EncodeToString([]byte("lau-secret-123456"))+`",
		"message":"msg",
		"context":"ctx"
	}`)))
	lauRR := httptest.NewRecorder()
	h.ServeHTTP(lauRR, lauReq)
	if lauRR.Code != http.StatusOK || !strings.Contains(lauRR.Body.String(), "lau_b64") {
		t.Fatalf("lau generate status=%d body=%s", lauRR.Code, lauRR.Body.String())
	}
}
