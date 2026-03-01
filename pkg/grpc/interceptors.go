package grpc

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"time"

	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	health "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"

	"vecta-kms/pkg/tlsprofile"
)

func MTLSUnaryInterceptor() ggrpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *ggrpc.UnaryServerInfo, handler ggrpc.UnaryHandler) (interface{}, error) {
		p, ok := peer.FromContext(ctx)
		if !ok {
			return nil, errors.New("missing peer")
		}
		ti, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok {
			return nil, errors.New("non-tls client")
		}
		if len(ti.State.VerifiedChains) == 0 {
			return nil, errors.New("unverified tls chain")
		}
		return handler(ctx, req)
	}
}

func LoggingUnaryInterceptor(logger *log.Logger) ggrpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *ggrpc.UnaryServerInfo, handler ggrpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		logger.Printf("grpc method=%s duration=%s err=%v", info.FullMethod, time.Since(start), err)
		return resp, err
	}
}

func NewServer(tlsConfig *tls.Config, logger *log.Logger) *ggrpc.Server {
	tlsConfig = tlsprofile.ApplyServerDefaults(tlsConfig)
	opts := []ggrpc.ServerOption{
		ggrpc.Creds(credentials.NewTLS(tlsConfig)),
		ggrpc.ChainUnaryInterceptor(MTLSUnaryInterceptor(), LoggingUnaryInterceptor(logger)),
	}
	s := ggrpc.NewServer(opts...)
	h := health.NewServer()
	h.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(s, h)
	return s
}
