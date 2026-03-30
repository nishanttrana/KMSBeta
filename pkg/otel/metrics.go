package otel

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

var (
	globalMP *sdkmetric.MeterProvider
	metricMu sync.Mutex

	// RED metrics — HTTP layer
	httpRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests received.",
	}, []string{"method", "path", "status"})

	httpRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "HTTP request latency in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path", "status"})

	httpRequestErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_request_errors_total",
		Help: "Total number of HTTP requests that resulted in an error (status >= 400).",
	}, []string{"method", "path", "status"})

	// KMS-specific metrics
	kmsCryptoOpsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kms_crypto_operations_total",
		Help: "Total number of cryptographic operations performed.",
	}, []string{"operation", "algorithm", "tenant"})

	kmsKeyCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kms_key_count",
		Help: "Current number of managed cryptographic keys.",
	})

	kmsActiveSessions = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kms_active_sessions",
		Help: "Current number of active client sessions.",
	})
)

func init() {
	prometheus.MustRegister(
		httpRequestsTotal,
		httpRequestDuration,
		httpRequestErrors,
		kmsCryptoOpsTotal,
		kmsKeyCount,
		kmsActiveSessions,
	)
}

// InitMeter creates a MeterProvider with both a Prometheus exporter (for
// scraping) and an OTLP metric exporter (for pushing to a collector).
// The Prometheus exporter makes metrics available via MetricsHandler().
func InitMeter(serviceName string, cfg Config) (*sdkmetric.MeterProvider, error) {
	ctx := context.Background()

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(serviceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("otel: build metric resource: %w", err)
	}

	// Prometheus exporter for /metrics scraping.
	promExporter, err := otelprom.New()
	if err != nil {
		return nil, fmt.Errorf("otel: create Prometheus metric exporter: %w", err)
	}

	// OTLP metric exporter for pushing to collector.
	otlpOpts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(cfg.Endpoint),
	}
	if cfg.Insecure {
		otlpOpts = append(otlpOpts, otlpmetricgrpc.WithInsecure())
	}

	otlpExporter, err := otlpmetricgrpc.New(ctx, otlpOpts...)
	if err != nil {
		return nil, fmt.Errorf("otel: create OTLP metric exporter: %w", err)
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(promExporter),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(otlpExporter)),
	)

	metricMu.Lock()
	globalMP = mp
	metricMu.Unlock()

	return mp, nil
}

// ShutdownMeter flushes and shuts down the global MeterProvider.
func ShutdownMeter(ctx context.Context) error {
	metricMu.Lock()
	mp := globalMP
	metricMu.Unlock()

	if mp == nil {
		return nil
	}
	return mp.Shutdown(ctx)
}

// MetricsHandler returns an http.Handler that serves Prometheus metrics at
// the /metrics endpoint. Mount this on your HTTP mux.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// RecordHTTPRequest records standard RED metrics for an HTTP request.
// Typically called from HTTP middleware after the response is written.
func RecordHTTPRequest(method, path, status string, durationSec float64) {
	httpRequestsTotal.WithLabelValues(method, path, status).Inc()
	httpRequestDuration.WithLabelValues(method, path, status).Observe(durationSec)

	// Count 4xx and 5xx as errors.
	if len(status) > 0 && (status[0] == '4' || status[0] == '5') {
		httpRequestErrors.WithLabelValues(method, path, status).Inc()
	}
}

// RecordCryptoOp increments the crypto operations counter.
// operation: "encrypt", "decrypt", "sign", "verify", "wrap", "unwrap", etc.
// algorithm: "AES-256-GCM", "RSA-OAEP", "ECDSA-P256", etc.
// tenantID: the tenant that owns the key.
func RecordCryptoOp(_ context.Context, operation, algorithm, tenantID string) {
	kmsCryptoOpsTotal.WithLabelValues(operation, algorithm, tenantID).Inc()
}

// SetKeyCount sets the current total managed key count gauge.
func SetKeyCount(n float64) {
	kmsKeyCount.Set(n)
}

// SetActiveSessions sets the current active session gauge.
func SetActiveSessions(n float64) {
	kmsActiveSessions.Set(n)
}
