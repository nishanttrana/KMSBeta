package main

import (
	"context"
	"testing"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
)

func TestRecoverMiddlewareTurnsPanicIntoKMIPError(t *testing.T) {
	h, _, _ := newKMIPHandler(t)
	bi := &kmip.RequestBatchItem{Operation: kmip.OperationEncrypt}
	resp, err := h.recoverMiddleware(func(context.Context, *kmip.RequestBatchItem) (*kmip.ResponseBatchItem, error) {
		panic("handler bug")
	}, context.Background(), bi)
	if err == nil || resp == nil || resp.Operation != kmip.OperationEncrypt {
		t.Fatalf("a panic must become a failed batch item with an error, got %+v %v", resp, err)
	}
}

func TestAuthorizationDenialReturnsResponseItem(t *testing.T) {
	h, _, _ := newKMIPHandler(t)
	bi := &kmip.RequestBatchItem{Operation: kmip.OperationDestroy}
	next := func(context.Context, *kmip.RequestBatchItem) (*kmip.ResponseBatchItem, error) {
		t.Fatal("a denied operation must not reach its handler")
		return nil, nil
	}
	ctx := context.WithValue(context.Background(), kmipConnContextKey{}, kmipConnectionContext{
		Principal: Principal{TenantID: "t1", Role: "kmip-client"}, SessionID: "s1",
	})
	resp, err := h.authorizationMiddleware(next, ctx, bi)
	if err != kmipserver.ErrPermissionDenied || resp == nil {
		t.Fatalf("denial must return a non-nil item and ErrPermissionDenied, got %+v %v", resp, err)
	}
}

func TestOperationAllowedInState(t *testing.T) {
	cases := []struct {
		op   kmip.Operation
		st   kmip.State
		want bool
	}{
		{kmip.OperationEncrypt, kmip.StateActive, true},
		{kmip.OperationEncrypt, kmip.StateDeactivated, false},
		{kmip.OperationSign, kmip.StateCompromised, false},
		{kmip.OperationDecrypt, kmip.StateDeactivated, true},
		{kmip.OperationSignatureVerify, kmip.StateCompromised, true},
		{kmip.OperationDecrypt, kmip.StateDestroyed, false},
		{kmip.OperationEncrypt, kmip.StatePreActive, false},
	}
	for _, tc := range cases {
		if got := operationAllowedInState(tc.op, tc.st); got != tc.want {
			t.Errorf("%v in state %v: got %v, want %v", tc.op, tc.st, got, tc.want)
		}
	}
}
