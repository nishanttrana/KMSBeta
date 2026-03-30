package otel

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/grpc/stats"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Config holds OpenTelemetry exporter configuration.
// Values are populated from environment variables when using ConfigFromEnv.
type Config struct {
	Endpoint   string  // OTLP gRPC collector endpoint (e.g. "localhost:4317")
	Insecure   bool    // Use insecure gRPC connection (no TLS)
	SampleRate float64 // Trace sampling ratio: 0.0 (none) to 1.0 (all)
}

var (
	globalTP   *sdktrace.TracerProvider
	globalMu   sync.Mutex
)

// ConfigFromEnv builds a Config from standard environment variables.
//
//	OTEL_EXPORTER_OTLP_ENDPOINT — collector address (default "localhost:4317")
//	OTEL_INSECURE                — "true" to disable TLS (default false)
//	OTEL_SAMPLE_RATE             — sampling ratio 0.0–1.0 (default 1.0)
func ConfigFromEnv() Config {
	cfg := Config{
		Endpoint:   "localhost:4317",
		Insecure:   false,
		SampleRate: 1.0,
	}
	if v := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); v != "" {
		cfg.Endpoint = v
	}
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_INSECURE"))); v == "true" || v == "1" {
		cfg.Insecure = true
	}
	if v := os.Getenv("OTEL_SAMPLE_RATE"); v != "" {
		if r, err := strconv.ParseFloat(v, 64); err == nil && r >= 0 && r <= 1 {
			cfg.SampleRate = r
		}
	}
	return cfg
}

// InitTracer initialises the global OpenTelemetry TracerProvider with an OTLP
// gRPC exporter, batch span processor, and W3C Trace Context propagation.
// The returned TracerProvider is also registered as the global provider.
func InitTracer(serviceName string, cfg Config) (*sdktrace.TracerProvider, error) {
	ctx := context.Background()

	// Build OTLP exporter options.
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
	}
	if cfg.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("otel: create OTLP trace exporter: %w", err)
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(serviceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("otel: build resource: %w", err)
	}

	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRate))

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Register global provider and W3C propagator.
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	globalMu.Lock()
	globalTP = tp
	globalMu.Unlock()

	return tp, nil
}

// Shutdown flushes remaining spans and shuts down the global TracerProvider.
// It should be called once during application shutdown (typically via defer).
func Shutdown(ctx context.Context) error {
	globalMu.Lock()
	tp := globalTP
	globalMu.Unlock()

	if tp == nil {
		return nil
	}
	return tp.Shutdown(ctx)
}

// HTTPMiddleware wraps an http.Handler with OpenTelemetry tracing and metrics.
// Each inbound request gets a span named after the HTTP route.
func HTTPMiddleware(next http.Handler) http.Handler {
	return otelhttp.NewHandler(next, "http.request",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)
}

// GRPCServerStatsHandler returns a gRPC stats.Handler that creates spans for
// every inbound RPC, propagating the W3C trace context from metadata.
// Use with grpc.NewServer(grpc.StatsHandler(otel.GRPCServerStatsHandler())).
func GRPCServerStatsHandler() stats.Handler {
	return otelgrpc.NewServerHandler()
}

// GRPCClientStatsHandler returns a gRPC stats.Handler for outbound RPCs.
func GRPCClientStatsHandler() stats.Handler {
	return otelgrpc.NewClientHandler()
}

// SpanFromContext extracts the current trace.Span from the context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// TraceIDFromContext returns the W3C trace ID as a hex string, or an empty
// string when the context has no active span.
func TraceIDFromContext(ctx context.Context) string {
	sc := trace.SpanFromContext(ctx).SpanContext()
	if !sc.HasTraceID() {
		return ""
	}
	return sc.TraceID().String()
}

// Tracer returns a named tracer from the global provider.
// Use this in application code to start custom spans:
//
//	ctx, span := otel.Tracer("vecta-kms/crypto").Start(ctx, "Encrypt")
//	defer span.End()
func Tracer(name string) trace.Tracer {
	return otel.GetTracerProvider().Tracer(name)
}
