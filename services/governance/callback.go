package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type CallbackExecutor interface {
	Execute(ctx context.Context, req ApprovalRequest) error
}

type GRPCCallbackExecutor struct {
	timeout time.Duration
}

func NewGRPCCallbackExecutor(timeout time.Duration) *GRPCCallbackExecutor {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &GRPCCallbackExecutor{timeout: timeout}
}

func (e *GRPCCallbackExecutor) Execute(ctx context.Context, req ApprovalRequest) error {
	service := strings.TrimSpace(req.CallbackService)
	action := strings.TrimSpace(req.CallbackAction)
	if service == "" || action == "" {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	conn, err := grpc.DialContext(cctx, service, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck

	payload := req.CallbackPayload
	if payload == nil {
		payload = map[string]interface{}{}
	}
	payload["approval_request_id"] = req.ID
	msg, err := structpb.NewStruct(payload)
	if err != nil {
		return err
	}
	method := action
	if !strings.HasPrefix(method, "/") {
		method = "/" + method
	}
	var out emptypb.Empty
	if err := conn.Invoke(cctx, method, msg, &out); err != nil {
		return err
	}
	return nil
}

type NoopCallbackExecutor struct{}

func (NoopCallbackExecutor) Execute(_ context.Context, _ ApprovalRequest) error { return nil }

func callbackPayloadFromRaw(raw []byte) (map[string]interface{}, error) {
	if len(raw) == 0 {
		return map[string]interface{}{}, nil
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, errors.New("callback payload must be object")
	}
	return out, nil
}
