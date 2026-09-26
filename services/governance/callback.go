package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"

	pkgsvctls "vecta-kms/pkg/svctls"
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
	// Callbacks go only to platform services, over internal mTLS
	// (docs/SECURITY/INTERNAL_TLS.md); the address comes from the request.
	host, _, err := net.SplitHostPort(service)
	if err != nil || !pkgsvctls.IsInternalHost(host) {
		return fmt.Errorf("callback service %q is not a platform service", service)
	}
	id := pkgsvctls.Current()
	if id == nil {
		return errors.New("callback: no internal mTLS identity")
	}
	tlsCfg := id.ClientConfig()
	tlsCfg.ServerName = host
	conn, err := grpc.DialContext(cctx, service, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)), grpc.WithBlock())
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
