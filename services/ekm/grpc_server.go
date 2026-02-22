package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type ekmProvisioningService interface {
	RegisterAgent(ctx context.Context, req *structpb.Struct) (*structpb.Struct, error)
	AgentHeartbeat(ctx context.Context, req *structpb.Struct) (*structpb.Struct, error)
	CreateTDEKey(ctx context.Context, req *structpb.Struct) (*structpb.Struct, error)
}

type ekmGRPCServer struct {
	svc *Service
}

func registerProvisioningGRPCServer(server *grpc.Server, svc *Service) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "vecta.ekm.v1.EkmService",
		HandlerType: (*ekmProvisioningService)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "RegisterAgent",
				Handler:    registerAgentGRPCHandler,
			},
			{
				MethodName: "AgentHeartbeat",
				Handler:    agentHeartbeatGRPCHandler,
			},
			{
				MethodName: "CreateTDEKey",
				Handler:    provisionTDEKeyGRPCHandler,
			},
		},
		Streams:  []grpc.StreamDesc{},
		Metadata: "proto/ekm.proto",
	}, &ekmGRPCServer{svc: svc})
}

func (s *ekmGRPCServer) RegisterAgent(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	m := in.AsMap()
	req := RegisterAgentRequest{
		TenantID:             mapString(m, "tenant_id"),
		AgentID:              mapString(m, "agent_id"),
		Name:                 mapString(m, "name"),
		Role:                 mapString(m, "role"),
		DBEngine:             mapString(m, "db_engine"),
		Host:                 mapString(m, "host"),
		Version:              mapString(m, "version"),
		HeartbeatIntervalSec: mapInt(m, "heartbeat_interval_sec"),
		MetadataJSON:         mapString(m, "metadata_json"),
	}
	if v, ok := m["auto_provision_tde"]; ok {
		b := mapBoolValue(v)
		req.AutoProvisionTDE = &b
	}
	agent, key, err := s.svc.RegisterAgent(ctx, req, "")
	if err != nil {
		return nil, grpcError(err)
	}
	out := map[string]interface{}{
		"agent": mapAgent(agent),
	}
	if key != nil {
		out["auto_provisioned_key"] = mapKey(*key)
	}
	return structpb.NewStruct(out)
}

func (s *ekmGRPCServer) AgentHeartbeat(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	m := in.AsMap()
	req := AgentHeartbeatRequest{
		TenantID:         mapString(m, "tenant_id"),
		Status:           mapString(m, "status"),
		TDEState:         mapString(m, "tde_state"),
		ActiveKeyID:      mapString(m, "active_key_id"),
		ActiveKeyVersion: mapString(m, "active_key_version"),
		ConfigVersionAck: mapInt(m, "config_version_ack"),
		MetadataJSON:     mapString(m, "metadata_json"),
	}
	agentID := mapString(m, "agent_id")
	agent, err := s.svc.AgentHeartbeat(ctx, agentID, req, "")
	if err != nil {
		return nil, grpcError(err)
	}
	return structpb.NewStruct(map[string]interface{}{"agent": mapAgent(agent)})
}

func (s *ekmGRPCServer) CreateTDEKey(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	m := in.AsMap()
	req := CreateTDEKeyRequest{
		TenantID:        mapString(m, "tenant_id"),
		Name:            mapString(m, "name"),
		Algorithm:       mapString(m, "algorithm"),
		CreatedBy:       mapString(m, "created_by"),
		AgentID:         mapString(m, "agent_id"),
		DatabaseID:      mapString(m, "database_id"),
		MetadataJSON:    mapString(m, "metadata_json"),
		AutoProvisioned: mapBool(m, "auto_provisioned"),
	}
	key, err := s.svc.CreateTDEKey(ctx, req)
	if err != nil {
		return nil, grpcError(err)
	}
	return structpb.NewStruct(map[string]interface{}{"key": mapKey(key)})
}

func registerAgentGRPCHandler(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	in := &structpb.Struct{}
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ekmProvisioningService).RegisterAgent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/vecta.ekm.v1.EkmService/RegisterAgent",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ekmProvisioningService).RegisterAgent(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, in, info, handler)
}

func agentHeartbeatGRPCHandler(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	in := &structpb.Struct{}
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ekmProvisioningService).AgentHeartbeat(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/vecta.ekm.v1.EkmService/AgentHeartbeat",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ekmProvisioningService).AgentHeartbeat(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, in, info, handler)
}

func provisionTDEKeyGRPCHandler(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	in := &structpb.Struct{}
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ekmProvisioningService).CreateTDEKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/vecta.ekm.v1.EkmService/CreateTDEKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ekmProvisioningService).CreateTDEKey(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, in, info, handler)
}

func grpcError(err error) error {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		switch svcErr.HTTPStatus {
		case http.StatusBadRequest:
			return status.Error(codes.InvalidArgument, svcErr.Message)
		case http.StatusUnauthorized:
			return status.Error(codes.Unauthenticated, svcErr.Message)
		case http.StatusForbidden:
			return status.Error(codes.PermissionDenied, svcErr.Message)
		case http.StatusNotFound:
			return status.Error(codes.NotFound, svcErr.Message)
		case http.StatusFailedDependency:
			return status.Error(codes.FailedPrecondition, svcErr.Message)
		default:
			return status.Error(codes.Internal, svcErr.Message)
		}
	}
	if errors.Is(err, errNotFound) {
		return status.Error(codes.NotFound, err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

func mapString(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}

func mapInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		return extractInt(v)
	}
	return 0
}

func mapBool(m map[string]interface{}, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	return mapBoolValue(v)
}

func mapBoolValue(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(strings.TrimSpace(x), "true") || strings.TrimSpace(x) == "1"
	case float64:
		return x != 0
	default:
		return false
	}
}

func mapAgent(a Agent) map[string]interface{} {
	return map[string]interface{}{
		"id":                     a.ID,
		"tenant_id":              a.TenantID,
		"name":                   a.Name,
		"role":                   a.Role,
		"db_engine":              a.DBEngine,
		"host":                   a.Host,
		"version":                a.Version,
		"status":                 a.Status,
		"tde_state":              a.TDEState,
		"heartbeat_interval_sec": a.HeartbeatIntervalSec,
		"last_heartbeat_at":      a.LastHeartbeatAt.UTC().Format(time.RFC3339Nano),
		"assigned_key_id":        a.AssignedKeyID,
		"assigned_key_version":   a.AssignedKeyVersion,
		"config_version":         a.ConfigVersion,
		"config_version_ack":     a.ConfigVersionAck,
		"metadata_json":          a.MetadataJSON,
		"tls_client_cn":          a.TLSClientCN,
		"created_at":             a.CreatedAt.UTC().Format(time.RFC3339Nano),
		"updated_at":             a.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func mapKey(k TDEKeyRecord) map[string]interface{} {
	return map[string]interface{}{
		"id":                k.ID,
		"tenant_id":         k.TenantID,
		"keycore_key_id":    k.KeyCoreKeyID,
		"name":              k.Name,
		"algorithm":         k.Algorithm,
		"status":            k.Status,
		"current_version":   k.CurrentVersion,
		"public_key":        k.PublicKey,
		"public_key_format": k.PublicKeyFormat,
		"created_by":        k.CreatedBy,
		"auto_provisioned":  k.AutoProvisioned,
		"metadata_json":     k.MetadataJSON,
	}
}
